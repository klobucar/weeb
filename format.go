package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"charm.land/glamour/v2"
	"github.com/charmbracelet/x/ansi"
)

// bodyFormat is a normalized content kind weeb knows how to pretty-print.
type bodyFormat int

const (
	fmtText bodyFormat = iota
	fmtJSON
	fmtXML
	fmtHTML
	fmtMarkdown
	fmtYAML
)

// detectFormat decides how to render a body. It trusts the Content-Type first;
// when that is missing or generic it falls back to the URL's file extension
// (the only reliable signal for, e.g., a GitHub raw .md served as text/plain),
// and finally — when sniff is true — to the bytes themselves.
func detectFormat(contentType, url string, body []byte, sniff bool) bodyFormat {
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "json"): // application/json, application/vnd.x+json
		return fmtJSON
	case strings.Contains(ct, "markdown"): // text/markdown, text/x-markdown
		return fmtMarkdown
	case strings.Contains(ct, "yaml"): // application/yaml, text/yaml, application/x-yaml
		return fmtYAML
	case strings.Contains(ct, "html"):
		return fmtHTML
	case strings.Contains(ct, "xml"): // application/xml, text/xml, image/svg+xml
		return fmtXML
	}

	generic := ct == "" || strings.Contains(ct, "text/plain") || strings.Contains(ct, "octet-stream")
	if !generic {
		return fmtText
	}

	// A generic Content-Type — APIs and raw file hosts (GitHub!) routinely serve
	// markdown/json/etc. as text/plain. The URL extension is the trustworthy hint.
	switch urlExt(url) {
	case "md", "markdown":
		return fmtMarkdown
	case "yaml", "yml":
		return fmtYAML
	case "json":
		return fmtJSON
	case "xml":
		return fmtXML
	case "html", "htm":
		return fmtHTML
	}

	if sniff {
		switch t := bytes.TrimSpace(body); {
		case len(t) > 0 && (t[0] == '{' || t[0] == '['):
			return fmtJSON
		case bytes.HasPrefix(t, []byte("<?xml")):
			return fmtXML
		case len(t) > 0 && t[0] == '<':
			return fmtHTML
		case looksLikeMarkdown(t):
			return fmtMarkdown
		}
	}
	return fmtText
}

// urlExt returns the lowercased file extension of a URL's last path segment
// (without the dot), or "" if there is none.
func urlExt(rawurl string) string {
	if i := strings.IndexAny(rawurl, "?#"); i >= 0 {
		rawurl = rawurl[:i]
	}
	if i := strings.LastIndexByte(rawurl, '/'); i >= 0 {
		rawurl = rawurl[i+1:]
	}
	if i := strings.LastIndexByte(rawurl, '.'); i >= 0 {
		return strings.ToLower(rawurl[i+1:])
	}
	return ""
}

// looksLikeMarkdown is a conservative content sniff for markdown served with a
// generic Content-Type and no .md URL. It requires a clear structural signal (a
// heading, fenced code block, or table) or two weaker ones, so plain text/logs
// don't get reflowed through glamour by accident.
func looksLikeMarkdown(body []byte) bool {
	lines := strings.Split(string(body), "\n")
	if len(lines) > 60 {
		lines = lines[:60]
	}
	weak := 0
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "```"), strings.HasPrefix(t, "~~~"): // fenced code
			return true
		case isATXHeading(t): // # Heading
			return true
		case isTableSep(t): // |---|---|
			return true
		case strings.HasPrefix(t, "- "), strings.HasPrefix(t, "* "), strings.HasPrefix(t, "+ "):
			weak++
		case strings.HasPrefix(t, "> "): // blockquote
			weak++
		case strings.Contains(t, "](") && strings.Contains(t, "["): // [text](link)
			weak++
		}
		if weak >= 2 {
			return true
		}
	}
	return false
}

func isATXHeading(t string) bool {
	n := 0
	for n < len(t) && t[n] == '#' {
		n++
	}
	return n >= 1 && n <= 6 && n < len(t) && t[n] == ' '
}

func isTableSep(t string) bool {
	if !strings.Contains(t, "|") || !strings.Contains(t, "-") {
		return false
	}
	for _, r := range t {
		if !strings.ContainsRune("|-: ", r) {
			return false
		}
	}
	return true
}

// renderBody renders a response body for DISPLAY. pretty is the master switch:
// when false, the body is shown exactly as the server sent it — no reindenting,
// no syntax color (this is the "raw" view). When true, weeb pretty-prints,
// syntax-highlights (if color), and sniffs mislabeled bodies (see detectFormat).
// width is the wrap width for full renders (markdown); <=0 means a sane default.
func renderBody(body []byte, contentType, url string, st styles, color, pretty bool, width int) string {
	if !pretty {
		return string(body)
	}
	switch detectFormat(contentType, url, body, true) {
	case fmtJSON:
		out := prettyBody(body, "application/json")
		if color {
			return colorizeJSON(out, st)
		}
		return out
	case fmtXML:
		out, ok := prettyXML(body)
		if !ok {
			out = string(body)
		}
		if color {
			return colorizeMarkup(out, st)
		}
		return out
	case fmtHTML:
		// Render via the real HTML parser's tree when coloring; otherwise raw.
		if color {
			if root := parseHTMLTree(body, contentType, url, true); root != nil {
				return renderXMLTree(root, st, nil)
			}
		}
		return string(body)
	case fmtMarkdown:
		// Markdown is a full styled render (glamour), which is inherently ANSI;
		// only do it when color is wanted, else fall back to the raw source.
		if !color {
			return string(body)
		}
		if out, err := renderMarkdown(body, width); err == nil {
			return out
		}
		return string(body)
	case fmtYAML:
		// The colorized render comes from the tree (fully expanded here); without
		// color, show the source as-is.
		if !color {
			return string(body)
		}
		if root := parseYAMLTree(body, contentType, url, true); root != nil {
			return renderYAMLTree(root, st, nil)
		}
		return string(body)
	default:
		return string(body)
	}
}

// glamour's cost grows exponentially with blockquote depth and polynomially
// with list depth: a 96-byte body of 90 nested '>' took 5s and rendered 5.8 MB,
// ~100 levels took minutes and gigabytes, and the TUI renders synchronously.
// Real documents nest a handful of levels, so a body past either limit is
// shown as its raw source instead.
const (
	maxMarkdownNesting = 16
	maxMarkdownBytes   = 1 << 20
)

var errMarkdownTooComplex = errors.New("weeb: markdown too large or deeply nested to render")

// renderMarkdown renders a markdown body to ANSI-styled terminal text via
// glamour, wrapped to width (clamped to a readable range).
func renderMarkdown(body []byte, width int) (out string, err error) {
	if len(body) > maxMarkdownBytes || markdownTooDeep(body, maxMarkdownNesting) {
		return "", errMarkdownTooComplex
	}
	// glamour and lipgloss run on a hostile server's bytes; a panic in them
	// (lipgloss's WrapWriter has nil-derefed on a 10-byte body) must cost the
	// styled render, not crash weeb.
	defer func() {
		if p := recover(); p != nil {
			out, err = "", fmt.Errorf("weeb: markdown renderer panicked: %v", p)
		}
	}()
	if width <= 0 || width > 120 {
		width = 100
	}
	r, err := glamour.NewTermRenderer(
		glamour.WithStandardStyle("dark"),
		glamour.WithWordWrap(width),
		glamour.WithEmoji(),
	)
	if err != nil {
		return "", err
	}
	s, err := r.Render(string(body))
	if err != nil {
		return "", err
	}
	return strings.Trim(s, "\n"), nil
}

// markdownTooDeep reports whether some line of body opens more than limit
// nested containers (blockquotes, list items, definition descriptions).
// CommonMark puts a line k containers deep only if it carries all k prefixes —
// a '>' per blockquote, a marker or at least two columns of indentation per
// list item — and a line with no marker can't open a container, so counting a
// marker line's markers plus half its indentation never undercounts. It can
// overcount (wide list indents, list-like lines in code), which only costs a
// raw render.
func markdownTooDeep(body []byte, limit int) bool {
	for len(body) > 0 {
		line := body
		if i := bytes.IndexByte(body, '\n'); i >= 0 {
			line, body = body[:i], body[i+1:]
		} else {
			body = nil
		}
		markers, cols := 0, 0
		afterMarker := false // the one space after a marker belongs to it
	scan:
		for i := 0; i < len(line); {
			switch c := line[i]; {
			case c == ' ':
				if !afterMarker {
					cols++
				}
				afterMarker = false
				i++
			case c == '\t':
				cols += 4 // reaches the next tab stop: at most 4 columns
				afterMarker = false
				i++
			case c == '>':
				markers++
				afterMarker = true
				i++
			default:
				n := mdMarkerLen(line[i:])
				if n == 0 {
					break scan
				}
				markers++
				afterMarker = true
				i += n
			}
		}
		if markers > 0 && markers+cols/2 > limit {
			return true
		}
	}
	return false
}

// mdMarkerLen returns the length of the list-item marker ("-", "*", "+", or
// 1–9 digits then "." or ")") or definition marker (":") at the start of s
// when whitespace or the end of the line follows it, else 0.
func mdMarkerLen(s []byte) int {
	n := 0
	switch {
	case s[0] == '-' || s[0] == '*' || s[0] == '+' || s[0] == ':':
		n = 1
	default:
		for n < len(s) && n < 9 && s[n] >= '0' && s[n] <= '9' {
			n++
		}
		if n == 0 || n == len(s) || (s[n] != '.' && s[n] != ')') {
			return 0
		}
		n++
	}
	if n < len(s) && s[n] != ' ' && s[n] != '\t' && s[n] != '\r' {
		return 0
	}
	return n
}

// lenientXMLDecoder builds the decoder shared by the flat pretty-print and the
// fold tree. The leniency knobs here define which real-world documents weeb
// accepts — keeping them in one place keeps the two render paths agreeing on
// what parses (a tweak applied to only one would make the same response render
// in one mode and fall back to raw in the other).
func lenientXMLDecoder(body []byte) *xml.Decoder {
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity
	return dec
}

// Pretty-printing repeats each line's indentation, so a deeply nested body's
// indented form grows as lines × depth (a 21 KB XML body indented to 18 MB; a
// 1 MB one would need tens of GB). Real documents grow a few times at most, so
// past prettyCap the flat renderers show the body raw. The floor keeps small
// bodies with legitimately deep structure pretty.
const (
	maxPrettyGrowth = 8
	minPrettyCap    = 1 << 20
)

// prettyCap is the most bytes a pretty-printed body of n bytes may take.
func prettyCap(n int) int { return max(minPrettyCap, maxPrettyGrowth*n) }

var errPrettyTooBig = errors.New("weeb: pretty-printed body exceeds its size cap")

// capWriter passes writes through to w until n bytes are used up, then fails,
// so an encoder producing runaway output stops early instead of allocating it.
type capWriter struct {
	w io.Writer
	n int // bytes still allowed
}

func (c *capWriter) Write(p []byte) (int, error) {
	if len(p) > c.n {
		return 0, errPrettyTooBig
	}
	c.n -= len(p)
	return c.w.Write(p)
}

// prettyXML reindents XML/HTML using a tokenizer. It is lenient (HTML autoclose
// and entities) so it survives most real-world HTML; it returns ok=false if the
// input can't be tokenized or its indented form would pass prettyCap, so the
// caller can fall back to raw.
func prettyXML(body []byte) (string, bool) {
	dec := lenientXMLDecoder(body)

	var out bytes.Buffer
	enc := xml.NewEncoder(&capWriter{w: &out, n: prettyCap(len(body))})
	enc.Indent("", "  ")

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", false
		}
		// Skip whitespace-only char data so the encoder's own indentation wins.
		if cd, ok := tok.(xml.CharData); ok {
			if len(bytes.TrimSpace(cd)) == 0 {
				continue
			}
		}
		if err := enc.EncodeToken(tok); err != nil {
			return "", false
		}
	}
	if err := enc.Flush(); err != nil {
		return "", false
	}
	if out.Len() == 0 {
		return "", false
	}
	return out.String(), true
}

// colorizeMarkup adds light syntax color to indented XML/HTML: tag delimiters
// dim, tag names cyan, quoted attribute values green, comments faint.
func colorizeMarkup(s string, st styles) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '<' {
			j := strings.IndexByte(s[i:], '<')
			if j < 0 {
				b.WriteString(s[i:])
				break
			}
			b.WriteString(s[i : i+j])
			i += j
			continue
		}
		// A tag (or comment) from '<' to the matching '>'.
		j := strings.IndexByte(s[i:], '>')
		if j < 0 {
			b.WriteString(st.jsonPunct.Render(s[i:]))
			break
		}
		b.WriteString(colorizeTag(s[i:i+j+1], st))
		i += j + 1
	}
	return b.String()
}

func colorizeTag(tag string, st styles) string {
	if strings.HasPrefix(tag, "<!--") {
		return st.jsonNull.Render(tag) // comments: faint grey
	}
	var b strings.Builder
	inner := tag
	// Leading "<" or "</".
	b.WriteString(st.jsonPunct.Render("<"))
	inner = inner[1:]
	if strings.HasPrefix(inner, "/") {
		b.WriteString(st.jsonPunct.Render("/"))
		inner = inner[1:]
	}
	// Trailing ">" (and optional "/").
	closeTok := ">"
	body := strings.TrimSuffix(inner, ">")
	if strings.HasSuffix(body, "/") {
		body = strings.TrimSuffix(body, "/")
		closeTok = "/>"
	}
	// Tag name then attributes.
	name, attrs, _ := strings.Cut(body, " ")
	b.WriteString(st.jsonKey.Render(name))
	if attrs != "" {
		b.WriteString(" " + colorizeAttrs(attrs, st))
	}
	b.WriteString(st.jsonPunct.Render(closeTok))
	return b.String()
}

// colorizeAttrs colors quoted attribute values green, leaving names as-is.
func colorizeAttrs(s string, st styles) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			j := i + 1
			for j < len(s) && s[j] != q {
				j++
			}
			if j < len(s) {
				j++ // include closing quote
			}
			b.WriteString(st.jsonStr.Render(s[i:j]))
			i = j
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// sanitizeTTY neutralizes terminal control sequences in server-influenced
// text before it reaches a TTY. A hostile body could otherwise write the
// clipboard (OSC 52), retitle the window, or move the cursor to spoof output.
// Only what weeb's own renderers emit is kept: SGR color (CSI…m whose
// parameters are just digits, ';' and ':') and terminated OSC 8 hyperlinks
// whose params/URI are valid UTF-8 free of controls. Everything else (other
// CSI, private/intermediate CSI…m forms, other OSC, DCS/APC/PM/SOS payloads,
// two-byte escapes, stray C0 controls, and the 8-bit C1 forms of all of
// these) is dropped, and invalid UTF-8 in text becomes U+FFFD. Decoding goes
// through ansi.DecodeSequence rather than a byte scanner so multibyte UTF-8
// text is never corrupted — continuation bytes share the 0x80–0x9F range
// with C1 controls and only a real decoder can tell them apart. Piped output
// never goes through here: pipes get the exact server bytes.
func sanitizeTTY(s string) string {
	var b *strings.Builder // nil until the first change: clean input is returned as-is
	var state byte
	for i := 0; i < len(s); {
		// No Parser: sequence boundaries don't depend on it, and with one,
		// x/ansi v0.11.7's DecodeSequence indexes past its 32-entry params
		// buffer on a CSI with more than 32 ';'/':' separators and panics.
		seq, width, n, newState := ansi.DecodeSequence(s[i:], state, nil)
		if n == 0 { // decoder can't advance; drop the remainder
			if b == nil {
				b = new(strings.Builder)
				b.WriteString(s[:i])
			}
			break
		}
		out, keep := seq, keepOnTTY(seq, width)
		if keep && width > 0 && !utf8.ValidString(seq) {
			out = repairInvalidUnit(seq)
		}
		if b == nil && (!keep || out != seq) {
			b = new(strings.Builder)
			b.Grow(len(s))
			b.WriteString(s[:i])
		}
		if b != nil && keep {
			b.WriteString(out)
		}
		i += n
		state = newState
	}
	if b == nil {
		return s // fast path: nothing changed (weeb's own SGR-styled output)
	}
	return b.String()
}

// keepOnTTY reports whether one decoded unit may pass through to a terminal:
// a printable grapheme, newline/tab, an SGR sequence, or a terminated OSC 8
// hyperlink with a clean payload (7- or 8-bit form either way).
func keepOnTTY(seq string, width int) bool {
	if width > 0 || seq == "\n" || seq == "\t" {
		return true
	}
	if ansi.HasCsiPrefix(seq) && seq[len(seq)-1] == 'm' {
		// A final 'm' alone doesn't make it SGR: CSI > 4;2 m (XTMODKEYS) changes
		// keyboard modes that outlive weeb, and CSI ? 4 m (XTQMODKEYS) makes the
		// terminal type a reply into tty input. The 'm' does prove the sequence
		// is complete.
		params := seq[1 : len(seq)-1] // 8-bit CSI (0x9b)
		if seq[0] == 0x1b {
			params = seq[2 : len(seq)-1] // 7-bit ESC [
		}
		return isSGRParams(params)
	}
	if ansi.HasOscPrefix(seq) {
		body := seq[1:] // 8-bit OSC (0x9d)
		if seq[0] == 0x1b {
			body = seq[2:] // 7-bit ESC ]
		}
		if !strings.HasPrefix(body, "8;") {
			return false
		}
		// Unterminated OSCs are dropped even for 8;… — kept, they would make
		// the terminal swallow whatever weeb prints next as payload.
		payload, ok := trimOscTerminator(body)
		// Terminals differ on whether a control inside an OSC string aborts it
		// (and then act on what follows); a real link never needs one.
		return ok && isCleanOscPayload(payload)
	}
	return false
}

// repairInvalidUnit rewrites a "printable" unit that isn't valid UTF-8. The
// decoder can fold the bytes after a truncated multibyte lead into the unit:
// a 0x80–0x9F byte ("\xe6\x9b"), which a terminal in 8-bit C1 mode acts on
// (0x9b is CSI), or a trailing ESC ("\xe8\x1b" at the end of a write), which
// the terminal would join with whatever is printed next. So take what a UTF-8
// terminal would decode (U+FFFD for the invalid bytes) and sanitize that like
// any other text; it is valid UTF-8, so this recurses at most once.
func repairInvalidUnit(seq string) string {
	return sanitizeTTY(strings.ToValidUTF8(seq, "�"))
}

// isSGRParams reports whether the bytes between a CSI introducer and its
// final 'm' are plain SGR parameters.
func isSGRParams(p string) bool {
	for i := 0; i < len(p); i++ {
		if c := p[i]; (c < '0' || c > '9') && c != ';' && c != ':' {
			return false
		}
	}
	return true
}

// trimOscTerminator strips the BEL or ST ending an OSC string; ok is false
// when there is none.
func trimOscTerminator(body string) (payload string, ok bool) {
	for _, term := range []string{
		"\x07",   // BEL
		"\x1b\\", // 7-bit ST
		"\x9c",   // 8-bit ST
	} {
		if payload, ok = strings.CutSuffix(body, term); ok {
			return payload, true
		}
	}
	return body, false
}

// isCleanOscPayload reports whether an OSC payload is valid UTF-8 without C0,
// DEL or C1 controls (raw C1 bytes are invalid UTF-8, so they fail too).
func isCleanOscPayload(p string) bool {
	if !utf8.ValidString(p) {
		return false
	}
	for _, r := range p {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return false
		}
	}
	return true
}

// sanitizingWriter passes every Write through sanitizeTTY. It is the output
// boundary wrapped around stdout/stderr when they are terminals (see outW/
// errW in main.go), so every print path — current and future — neutralizes
// server-influenced control sequences without each call site remembering to.
// weeb's printers write whole strings/lines per call (fmt.Fprint*), so an
// escape sequence is never sliced across two Writes.
type sanitizingWriter struct{ w io.Writer }

func (sw sanitizingWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(sw.w, sanitizeTTY(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil // report p fully consumed, even when bytes were dropped
}
