package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	log "charm.land/log/v2"
	"github.com/charmbracelet/x/term"
)

// `weeb view [FILE|-]` turns the response pane into a local file viewer (a
// jless/fx alternative): the same pretty, foldable rendering, fed from a file
// or stdin instead of a request. Files are as untrusted as response bodies —
// people view what they download — so they take the same paths: the TUI shows
// them through setResp, and piped output is the plain bytes, like a response.

// viewTypeContentTypes maps each --type name to the Content-Type handed to
// detectFormat. A file has no Content-Type, so the extension or --type stands
// in for one; "" leaves detectFormat to sniff the content.
var viewTypeContentTypes = map[string]string{
	"json": "application/json",
	"xml":  "application/xml",
	"html": "text/html",
	"yaml": "application/yaml",
	"md":   "text/markdown",
}

// viewExtTypes maps a lowercased file extension to its --type name. --type
// accepts these spellings too, so "--type yml" and "--type markdown" work.
var viewExtTypes = map[string]string{
	".json":     "json",
	".xml":      "xml",
	".svg":      "xml",
	".html":     "html",
	".htm":      "html",
	".yaml":     "yaml",
	".yml":      "yaml",
	".md":       "md",
	".markdown": "md",
}

// viewQuit is the viewer's extra quit key. The request builder can't use a
// bare q (it would be typed into a field), but the viewer has no fields.
var viewQuit = key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "quit"))

type viewArgs struct {
	file    string // "" or "-" reads stdin
	typ     string // --type, normalized to a viewTypeContentTypes key
	raw     bool   // --raw: piped, the bytes unchanged; at a TTY, start in the raw view
	maxBody string // --max-body: input cap (overrides WEEB_MAX_BODY)
	help    bool
}

// viewDoc is the document being viewed.
type viewDoc struct {
	name        string // base file name, or "stdin"; for display only
	body        []byte
	contentType string // synthesized from --type or the extension; "" = sniff
	format      bodyFormat
}

func parseViewArgs(args []string) (viewArgs, error) {
	var a viewArgs
	fileSet := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--type":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			t, ok := viewTypeName(val)
			if !ok {
				return a, fmt.Errorf("bad --type %q (want json, xml, html, yaml or md)", val)
			}
			a.typ = t
		case arg == "--raw":
			a.raw = true
		case arg == "--max-body":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			a.maxBody = val
		case arg == "-h" || arg == "--help":
			a.help = true
		case strings.HasPrefix(arg, "-") && arg != "-":
			return a, fmt.Errorf("unknown flag %q", arg)
		default:
			if fileSet {
				return a, fmt.Errorf("unexpected argument %q (view takes one FILE)", arg)
			}
			a.file, fileSet = arg, true
		}
	}
	return a, nil
}

// viewTypeName normalizes a --type value: a type name or any extension
// viewExtTypes knows.
func viewTypeName(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if _, ok := viewTypeContentTypes[s]; ok {
		return s, true
	}
	t, ok := viewExtTypes["."+s]
	return t, ok
}

// newViewDoc decides how body renders: --type wins, then the file extension,
// both expressed as a Content-Type for detectFormat, which sniffs when neither
// says anything (so YAML needs one of them, as with responses).
func newViewDoc(file, typ string, body []byte) viewDoc {
	name := "stdin"
	if file != "" && file != "-" {
		name = filepath.Base(file)
	}
	if typ == "" && file != "" && file != "-" {
		typ = viewExtTypes[strings.ToLower(filepath.Ext(file))]
	}
	ct := viewTypeContentTypes[typ]
	return viewDoc{name: name, body: body, contentType: ct, format: detectFormat(ct, "", body, true)}
}

// loadViewDoc reads the document under the buffered-body cap: everything the
// viewer does needs it in memory, so a huge file (or /dev/zero) must fail
// cleanly instead of exhausting memory.
func loadViewDoc(a viewArgs, stdin io.Reader) (viewDoc, error) {
	r, name := stdin, "stdin"
	if a.file != "" && a.file != "-" {
		f, err := os.Open(a.file)
		if err != nil {
			return viewDoc{}, err
		}
		defer f.Close()
		r, name = f, a.file
	}
	body, err := io.ReadAll(io.LimitReader(r, maxBodyBytes+1))
	if err != nil {
		return viewDoc{}, fmt.Errorf("reading %s: %w", name, err)
	}
	if int64(len(body)) > maxBodyBytes {
		return viewDoc{}, fmt.Errorf("%s is larger than the %s cap; raise it with --max-body SIZE (0 = no cap)",
			name, humanSize(int(maxBodyBytes)))
	}
	return newViewDoc(a.file, a.typ, body), nil
}

// summary goes where a response's Body summary does: name · size · format.
func (d viewDoc) summary() string {
	return displayName(d.name) + " · " + humanSize(len(d.body)) + " · " + formatName(d.format)
}

// displayName quotes a file name holding anything a terminal could act on or
// that would break the summary line (controls, newlines, bidi overrides,
// invalid UTF-8). sanitizeTTY would strip the escape sequences anyway, but a
// quoted name shows what the file is really called.
func displayName(s string) string {
	if !utf8.ValidString(s) {
		return strconv.Quote(s)
	}
	for _, r := range s {
		if !strconv.IsPrint(r) {
			return strconv.Quote(s)
		}
	}
	return s
}

func formatName(f bodyFormat) string {
	switch f {
	case fmtJSON:
		return "json"
	case fmtXML:
		return "xml"
	case fmtHTML:
		return "html"
	case fmtYAML:
		return "yaml"
	case fmtMarkdown:
		return "markdown"
	default:
		return "text"
	}
}

// runView handles `weeb view [FILE|-]`: the foldable TUI at a terminal, and an
// uncolored pretty-print (or, with --raw, the bytes as-is) when piped.
func runView(args []string) int {
	a, err := parseViewArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		fmt.Fprintln(os.Stderr, "run 'weeb --help' for usage")
		return 2
	}
	if a.help {
		printHelp(os.Stdout)
		return 0
	}
	if err := applyMaxBody(a.maxBody); err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 2
	}
	// With no FILE and stdin a terminal there's nothing to view; reading would
	// just sit waiting for typed input.
	if a.file == "" && term.IsTerminal(os.Stdin.Fd()) {
		fmt.Fprintln(os.Stderr, "weeb: view needs a FILE or piped input, e.g. 'weeb view data.json' or 'cat data.json | weeb view'")
		return 2
	}

	doc, err := loadViewDoc(a, os.Stdin)
	if err != nil {
		fmt.Fprintln(errW, "weeb:", err) // errW: the path is user/file-controlled
		return 1
	}

	if !stdoutIsTTY() {
		if err := writeView(outW, doc, a.raw); err != nil {
			fmt.Fprintln(errW, "weeb:", err)
			return 1
		}
		return 0
	}
	return runViewTUI(doc, a.raw)
}

// writeView is the piped form: the pretty render without color, so `weeb view
// x.json > pretty.json` works as a formatter. That is renderBody's uncolored
// output — JSON and XML reindented; HTML, YAML and Markdown as their source,
// since their pretty forms are color-only. --raw writes the bytes unchanged.
func writeView(w io.Writer, d viewDoc, raw bool) error {
	if raw {
		_, err := w.Write(d.body)
		return err
	}
	if len(d.body) == 0 {
		return nil
	}
	out := renderBody(d.body, d.contentType, "", newStyles(), false, true, 0)
	if !strings.HasSuffix(out, "\n") {
		out += "\n" // json.Indent drops the source's final newline
	}
	_, err := io.WriteString(w, out)
	return err
}

// runViewTUI opens the viewer: the response pane on its own, with no form.
func runViewTUI(d viewDoc, raw bool) int {
	opts, closeTTY, err := viewInput()
	if err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 1
	}
	defer closeTTY()

	if _, err := tea.NewProgram(newViewerModel(d, raw), opts...).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 1
	}
	return 0
}

// viewInput picks the viewer's keyboard source. With the document piped in,
// stdin is spent, so keys come from the controlling terminal: tea.OpenTTY
// opens /dev/tty, or CONIN$ on Windows. Bubble Tea's Run falls back to the
// same when stdin isn't a terminal, but doing it here keeps the viewer from
// depending on that default and gives a clear error when there is no terminal.
func viewInput() ([]tea.ProgramOption, func(), error) {
	if term.IsTerminal(os.Stdin.Fd()) {
		return nil, func() {}, nil
	}
	in, out, err := tea.OpenTTY()
	if err != nil {
		return nil, nil, fmt.Errorf("view needs a terminal for keyboard input: %w", err)
	}
	return []tea.ProgramOption{tea.WithInput(in)}, func() {
		_ = in.Close()
		if out != in { // one *os.File for both on Unix; CONIN$/CONOUT$ on Windows
			_ = out.Close()
		}
	}, nil
}

// newViewerModel builds the viewer-only TUI: the regular model with its focus
// parked on the response pane for good (viewerKey swallows every key that
// would move it). Nothing is sent, so the client only satisfies the model, and
// logs are dropped.
func newViewerModel(d viewDoc, raw bool) model {
	logger := log.New(io.Discard)
	m := newModel(newClient(logger, newErrorChan()), logger, nil)
	m.viewer = &d
	if raw {
		m.pretty = false
	}
	m.focusIdx = len(m.focusList()) - 1
	m.applyFocus()
	return m
}

// viewerKey handles the keys that differ in the viewer; ok=false hands the key
// on to the shared handling (scroll, folding, 🌈, ctrl+c).
func (m *model) viewerKey(msg tea.KeyPressMsg) (cmd tea.Cmd, ok bool) {
	switch {
	case key.Matches(msg, viewQuit):
		return tea.Quit, true
	case key.Matches(msg, m.keys.TogglePretty):
		m.pretty = !m.pretty
		m.renderView()
		return nil, true
	case key.Matches(msg, m.keys.Send, m.keys.InspectCert, m.keys.Probe, m.keys.ExportCurl,
		m.keys.NextField, m.keys.PrevField, m.keys.AddHeader, m.keys.DelHeader,
		m.keys.ToggleDebug):
		return nil, true // request-form actions: nothing to act on here
	}
	return nil, false
}

// viewerResized renders the document on the first WindowSizeMsg, once the
// wrap width is known, and afterwards re-wraps it without rebuilding, so node
// folds and the scroll position survive a resize.
func (m *model) viewerResized() {
	if len(m.respSections) == 0 {
		m.renderView()
		return
	}
	m.setResp(m.composeResponse())
}

// renderView fills the pane with the document as its Body section, through
// the same rendering, folding and sanitizing as a response body.
func (m *model) renderView() {
	m.pane = paneResponse
	m.respHeading = "📄 View"
	m.respPreamble = ""
	m.respSections = nil
	m.respErr = ""
	m.addRenderedBody(m.viewer.body, m.viewer.contentType, "", m.viewer.summary())
	if m.respCursor >= len(m.foldTargets()) {
		m.respCursor = 0
	}
	m.setResp(m.composeResponse())
	m.resp.GotoTop()
}

// renderViewerTop stands in for the request form above the pane: the title
// bar and the viewer's own key hints (the pane title lists the fold keys).
func (m model) renderViewerTop() string {
	pairs := [][2]string{{"ctrl+p", "pretty/raw"}, {"ctrl+y", "🌈"}, {"q", "quit"}}
	segs := make([]string, 0, len(pairs))
	for _, p := range pairs {
		segs = append(segs, m.styles.keycap.Render(p[0])+" "+m.styles.hint.Render(p[1]))
	}
	return m.renderHeader() + "\n\n" + strings.Join(segs, m.styles.hint.Render("  ·  "))
}
