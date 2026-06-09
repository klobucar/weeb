package main

import (
	"fmt"
	"image/color"
	"os"
	"strings"
	"time"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	log "charm.land/log/v2"
)

// resultMsg carries a finished request back into the event loop. The request
// itself runs in a tea.Cmd so Update never blocks.
type resultMsg Result

// certMsg carries a finished TLS inspection back into the event loop.
type certMsg struct {
	rep *certReport
	err error
}

// frameMsg drives the animated rainbow. It fires on a steady tick so the colors
// keep flowing regardless of user input.
type frameMsg struct{}

func animate() tea.Cmd {
	return tea.Tick(time.Second/12, func(time.Time) tea.Msg { return frameMsg{} })
}

// paneView selects what the shared response viewport is currently showing.
type paneView int

const (
	paneResponse paneView = iota
	paneCert
	paneCurl
)

// focusKind enumerates the kinds of focusable widgets in the form.
type focusKind int

const (
	focMethod focusKind = iota
	focURL
	focHeaderKey
	focHeaderVal
	focBody
	focResponse
)

// focusRef points at one focusable widget; row is meaningful only for headers.
type focusRef struct {
	kind focusKind
	row  int
}

type headerRow struct {
	key textinput.Model
	val textinput.Model
}

func newHeaderRow(k, v string) headerRow {
	kt := textinput.New()
	kt.Prompt = ""
	kt.Placeholder = "Header"
	kt.SetValue(k)

	vt := textinput.New()
	vt.Prompt = ""
	vt.Placeholder = "value"
	vt.SetValue(v)

	return headerRow{key: kt, val: vt}
}

type model struct {
	keys   keyMap
	styles styles

	client *Client
	logger *log.Logger
	debug  *safeBuffer

	methods   []string
	methodIdx int

	url     textinput.Model
	headers []headerRow
	body    textarea.Model

	resp      viewport.Model
	debugView viewport.Model
	spinner   spinner.Model

	focusIdx    int
	inFlight    bool
	flightLabel string
	showDebug   bool
	rainbow     bool // 🌈 mode (WEEB_RAINBOW / ctrl+y)
	animating   bool // whether the frame ticker is currently running
	frame       int  // rainbow animation counter
	pretty      bool // sniff & prettify mislabeled bodies (WEEB_PRETTY / ctrl+p)

	pane        paneView
	respHeading string
	lastResult  *Result

	// Collapsible response sections (Connection / Headers / Body). respPreamble
	// (status badge) and respErr always show; respCursor is the fold cursor;
	// foldState is sticky per-title so folds survive re-renders and cert swaps.
	respPreamble string
	respSections []respSection
	respErr      string
	respCursor   int
	foldState    map[string]bool

	width, height int
	ready         bool
}

func newModel(client *Client, logger *log.Logger, dbg *safeBuffer) model {
	url := textinput.New()
	url.Prompt = ""
	url.Placeholder = "https://api.example.com/path   (or /path with WEEB_BASE_URL)"

	body := textarea.New()
	body.Placeholder = "request body…"
	body.ShowLineNumbers = false

	sp := spinner.New()
	sp.Spinner = spinner.Dot

	// Prefill header rows from the env so the defaults are visible in the form.
	var rows []headerRow
	have := map[string]bool{}
	for _, h := range parseHeaderList(os.Getenv("WEEB_HEADERS")) {
		rows = append(rows, newHeaderRow(h.Key, h.Value))
		have[strings.ToLower(h.Key)] = true
	}
	if tok := os.Getenv("WEEB_TOKEN"); tok != "" && !have["authorization"] {
		rows = append(rows, newHeaderRow("Authorization", "Bearer "+tok))
	}
	if len(rows) == 0 {
		rows = append(rows, newHeaderRow("", ""))
	}

	m := model{
		keys:        defaultKeyMap(),
		styles:      newStyles(),
		client:      client,
		logger:      logger,
		debug:       dbg,
		methods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		url:         url,
		headers:     rows,
		body:        body,
		resp:        viewport.New(),
		debugView:   viewport.New(),
		spinner:     sp,
		focusIdx:    0, // method selector
		respHeading: "📡 Response",
		foldState:   map[string]bool{},
		rainbow:     envTruthy("WEEB_RAINBOW"),
		animating:   envTruthy("WEEB_RAINBOW"),
		pretty:      envBool("WEEB_PRETTY", true), // pretty on by default; ctrl+p / WEEB_PRETTY=0 turns it off (raw)
	}
	// The response pane is hang-indent wrapped by setResp (continuation lines stay
	// nested under their entry), so its own soft-wrap is off. The debug pane just
	// soft-wraps log lines flush.
	m.resp.SoftWrap = false
	m.debugView.SoftWrap = true
	m.applyFocus()
	return m
}

// prefill seeds the form from a parsed CLI request so `weeb METHOD URL …` opens
// the interactive builder ready to send.
func (m *model) prefill(a cliArgs) {
	if a.url != "" {
		m.url.SetValue(a.url)
	}
	want := strings.ToUpper(strings.TrimSpace(a.method))
	for i, mth := range m.methods {
		if mth == want {
			m.methodIdx = i
			break
		}
	}
	if len(a.headers) > 0 {
		// Drop the lone empty placeholder row if that's all there is.
		if len(m.headers) == 1 &&
			strings.TrimSpace(m.headers[0].key.Value()) == "" &&
			strings.TrimSpace(m.headers[0].val.Value()) == "" {
			m.headers = m.headers[:0]
		}
		for _, h := range a.headers {
			m.headers = append(m.headers, newHeaderRow(h.Key, h.Value))
		}
	}
	if len(a.body) > 0 {
		m.body.SetValue(string(a.body))
	}
	m.onMethodChange() // sync body enabled/disabled for the chosen method
}

func (m model) Init() tea.Cmd {
	cmds := []tea.Cmd{textinput.Blink}
	if m.rainbow {
		cmds = append(cmds, animate())
	}
	return tea.Batch(cmds...)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.ready = true
		m.layout()
		return m, nil

	case frameMsg:
		if !m.rainbow {
			m.animating = false // let the ticker die when rainbow is off
			return m, nil
		}
		m.frame++
		return m, animate()

	case spinner.TickMsg:
		if m.inFlight {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil

	case resultMsg:
		m.inFlight = false
		r := Result(msg)
		m.lastResult = &r
		m.layout() // body-enabled / sizes may have shifted; keep viewport correct
		m.renderResult(r)
		return m, nil

	case certMsg:
		m.inFlight = false
		m.renderCert(msg)
		return m, nil

	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit

		case key.Matches(msg, m.keys.ToggleDebug):
			m.showDebug = !m.showDebug
			m.layout()
			return m, nil

		case key.Matches(msg, m.keys.ToggleRainbow):
			m.rainbow = !m.rainbow
			if m.rainbow && !m.animating {
				m.animating = true
				return m, animate()
			}
			return m, nil

		case key.Matches(msg, m.keys.TogglePretty):
			m.pretty = !m.pretty
			// Re-render the last response with the new setting.
			if m.lastResult != nil && m.pane == paneResponse {
				m.renderResult(*m.lastResult)
			}
			return m, nil

		case key.Matches(msg, m.keys.Send):
			if !m.inFlight {
				m.inFlight = true
				m.flightLabel = "sending…"
				return m, tea.Batch(m.sendCmd(), m.spinner.Tick)
			}
			return m, nil

		case key.Matches(msg, m.keys.InspectCert):
			if m.inFlight {
				return m, nil
			}
			if m.pane == paneCert {
				m.showResponse() // toggle back to the HTTP response view
				return m, nil
			}
			m.inFlight = true
			m.flightLabel = "inspecting TLS…"
			return m, tea.Batch(m.certCmd(), m.spinner.Tick)

		case key.Matches(msg, m.keys.ExportCurl):
			if m.pane == paneCurl {
				m.showResponse() // toggle back to the HTTP response view
				return m, nil
			}
			m.pane = paneCurl
			m.respHeading = "curl ⤵  (ctrl+x back)"
			m.setResp(renderCurl(resolveSpec(m.specFromForm()), m.styles, true, true))
			m.resp.GotoTop()
			return m, nil

		case key.Matches(msg, m.keys.NextField):
			m.cycleFocus(1)
			return m, textinput.Blink

		case key.Matches(msg, m.keys.PrevField):
			m.cycleFocus(-1)
			return m, textinput.Blink

		case key.Matches(msg, m.keys.AddHeader):
			m.addHeader()
			return m, textinput.Blink

		case key.Matches(msg, m.keys.DelHeader):
			m.delHeaderIfFocused()
			return m, nil
		}

		// ↑/↓ move between form fields. The response pane keeps them for
		// scrolling, and the body textarea keeps them for line editing until the
		// cursor is at its top/bottom edge — then they step to the next field.
		if s := msg.String(); s == "up" || s == "down" {
			dir := 1
			if s == "up" {
				dir = -1
			}
			switch m.currentFocus().kind {
			case focResponse:
				// fall through to viewport scrolling below
			case focBody:
				atEdge := !m.bodyEnabled() ||
					(dir < 0 && m.body.Line() == 0) ||
					(dir > 0 && m.body.Line() == m.body.LineCount()-1)
				if atEdge {
					m.cycleFocus(dir)
					return m, textinput.Blink
				}
				// otherwise let the textarea move the cursor between lines
			default:
				m.cycleFocus(dir)
				return m, textinput.Blink
			}
		}

		// Field-specific keys that should not reach the text widgets.
		switch m.currentFocus().kind {
		case focMethod:
			if key.Matches(msg, m.keys.MethodNext) {
				m.methodIdx = (m.methodIdx + 1) % len(m.methods)
				m.onMethodChange()
				return m, nil
			}
			if key.Matches(msg, m.keys.MethodPrev) {
				m.methodIdx = (m.methodIdx - 1 + len(m.methods)) % len(m.methods)
				m.onMethodChange()
				return m, nil
			}
			return m, nil
		case focResponse:
			// Fold controls take precedence over viewport scrolling, whenever the
			// pane has foldable sections (HTTP response or the TLS cert view).
			if m.hasSections() {
				switch {
				case key.Matches(msg, m.keys.SectionPrev):
					m.moveFoldCursor(-1)
					return m, nil
				case key.Matches(msg, m.keys.SectionNext):
					m.moveFoldCursor(1)
					return m, nil
				case key.Matches(msg, m.keys.FoldSection):
					m.toggleFold()
					return m, nil
				case key.Matches(msg, m.keys.FoldAll):
					m.setAllFolded(true)
					return m, nil
				case key.Matches(msg, m.keys.UnfoldAll):
					m.setAllFolded(false)
					return m, nil
				}
			}
			var cmd tea.Cmd
			m.resp, cmd = m.resp.Update(msg)
			return m, cmd
		}
	}

	// Anything else (typing, cursor blink) goes to the focused text widget.
	if cmd := m.updateFocusedInput(msg); cmd != nil {
		cmds = append(cmds, cmd)
	}
	return m, tea.Batch(cmds...)
}

func (m model) View() tea.View {
	if !m.ready {
		v := tea.NewView("starting weeb…")
		v.AltScreen = true
		return v
	}

	parts := []string{m.renderForm(), m.renderResponsePane()}
	if m.showDebug {
		// Refresh the debug pane from the live log sink for this render.
		if m.debug != nil {
			m.debugView.SetContent(m.debug.String())
			m.debugView.GotoBottom()
		}
		parts = append(parts, m.renderDebugPane())
	}
	// AltScreen replaces the v1 tea.WithAltScreen() program option.
	v := tea.NewView(m.styles.app.Render(lipgloss.JoinVertical(lipgloss.Left, parts...)))
	v.AltScreen = true
	return v
}

// ---- focus management ------------------------------------------------------

func (m *model) focusList() []focusRef {
	refs := []focusRef{{kind: focMethod}, {kind: focURL}}
	for i := range m.headers {
		refs = append(refs, focusRef{kind: focHeaderKey, row: i}, focusRef{kind: focHeaderVal, row: i})
	}
	refs = append(refs, focusRef{kind: focBody}, focusRef{kind: focResponse})
	return refs
}

func (m *model) currentFocus() focusRef {
	list := m.focusList()
	if m.focusIdx < 0 || m.focusIdx >= len(list) {
		return focusRef{kind: focMethod}
	}
	return list[m.focusIdx]
}

func (m *model) cycleFocus(dir int) {
	list := m.focusList()
	n := len(list)
	m.focusIdx = (m.focusIdx%n + dir + n) % n
	m.applyFocus()
	// The fold-cursor highlight only shows while the response pane is focused,
	// so re-render whenever focus crosses that boundary (response or cert view).
	if m.hasSections() {
		m.setResp(m.composeResponse())
	}
}

// applyFocus blurs every text widget, then focuses the current one.
func (m *model) applyFocus() {
	m.url.Blur()
	for i := range m.headers {
		m.headers[i].key.Blur()
		m.headers[i].val.Blur()
	}
	m.body.Blur()

	switch ref := m.currentFocus(); ref.kind {
	case focURL:
		m.url.Focus()
	case focHeaderKey:
		m.headers[ref.row].key.Focus()
	case focHeaderVal:
		m.headers[ref.row].val.Focus()
	case focBody:
		if m.bodyEnabled() {
			m.body.Focus()
		}
	}
}

func (m *model) updateFocusedInput(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch ref := m.currentFocus(); ref.kind {
	case focURL:
		m.url, cmd = m.url.Update(msg)
	case focHeaderKey:
		m.headers[ref.row].key, cmd = m.headers[ref.row].key.Update(msg)
	case focHeaderVal:
		m.headers[ref.row].val, cmd = m.headers[ref.row].val.Update(msg)
	case focBody:
		if m.bodyEnabled() {
			m.body, cmd = m.body.Update(msg)
		}
	}
	return cmd
}

// ---- header rows -----------------------------------------------------------

func (m *model) addHeader() {
	m.headers = append(m.headers, newHeaderRow("", ""))
	// Focus the new row's key field.
	for i, r := range m.focusList() {
		if r.kind == focHeaderKey && r.row == len(m.headers)-1 {
			m.focusIdx = i
			break
		}
	}
	m.applyFocus()
	m.layout()
}

func (m *model) delHeaderIfFocused() {
	ref := m.currentFocus()
	if ref.kind != focHeaderKey && ref.kind != focHeaderVal {
		return
	}
	m.headers = append(m.headers[:ref.row], m.headers[ref.row+1:]...)
	if len(m.headers) == 0 {
		m.headers = append(m.headers, newHeaderRow("", ""))
	}
	if list := m.focusList(); m.focusIdx >= len(list) {
		m.focusIdx = len(list) - 1
	}
	m.applyFocus()
	m.layout()
}

// ---- method / body ---------------------------------------------------------

func (m *model) currentMethod() string { return m.methods[m.methodIdx] }
func (m *model) bodyEnabled() bool     { return methodAllowsBody(m.currentMethod()) }

func (m *model) onMethodChange() {
	if !m.bodyEnabled() {
		m.body.Blur()
	} else if m.currentFocus().kind == focBody {
		m.body.Focus()
	}
	// The body field collapses/expands with the method, changing the form's
	// height, so re-flow the response viewport to claim (or yield) the rows.
	m.layout()
}

// ---- sending ---------------------------------------------------------------

func (m model) specFromForm() RequestSpec {
	var hs []Header
	for _, r := range m.headers {
		k := strings.TrimSpace(r.key.Value())
		if k == "" {
			continue
		}
		hs = append(hs, Header{Key: k, Value: r.val.Value()})
	}
	var body []byte
	if m.bodyEnabled() {
		if v := m.body.Value(); v != "" {
			body = []byte(v)
		}
	}
	return RequestSpec{
		Method:  m.currentMethod(),
		URL:     strings.TrimSpace(m.url.Value()),
		Headers: hs,
		Body:    body,
		// The form rows started from the env prefills, so they are the user's
		// final say — a deleted Authorization row must not be re-injected.
		HeadersResolved: true,
	}
}

func (m model) sendCmd() tea.Cmd {
	spec := m.specFromForm()
	client := m.client
	return func() tea.Msg {
		return resultMsg(client.Do(spec))
	}
}

// certCmd inspects the TLS certificate of the current URL's host (resolved
// against WEEB_BASE_URL like a real request would be). It runs off the event
// loop and reports back via certMsg.
func (m model) certCmd() tea.Cmd {
	spec := resolveSpec(RequestSpec{URL: strings.TrimSpace(m.url.Value())})
	target := spec.URL
	logger := m.logger
	return func() tea.Msg {
		logger.Info("tls inspect", "target", target)
		rep, err := fetchCertReport(target, certOptions{timeout: defaultTimeout})
		if err != nil {
			logger.Error("tls inspect failed", "kind", KindTransport.String(), "err", err)
		} else {
			logger.Info("tls ok", "version", rep.TLSVersion, "verified", rep.Verified, "chain", len(rep.Chain))
		}
		return certMsg{rep: rep, err: err}
	}
}

// ---- layout ----------------------------------------------------------------

func (m *model) layout() {
	if !m.ready || m.width == 0 {
		return
	}
	inner := m.width - 2 // app horizontal padding
	if inner < 10 {
		inner = 10
	}

	m.url.SetWidth(inner - 2)
	keyW := inner / 3
	for i := range m.headers {
		m.headers[i].key.SetWidth(keyW)
		m.headers[i].val.SetWidth(inner - keyW - 5)
	}
	m.body.SetWidth(inner)
	m.body.SetHeight(5)

	// The form is rendered to a string and measured, so the response viewport
	// always gets exactly the remaining height — correct on every resize.
	formH := lipgloss.Height(m.renderForm())

	debugH := 0
	if m.showDebug {
		debugH = m.height / 4
		if debugH < 4 {
			debugH = 4
		}
	}

	contentH := m.height - formH - debugH
	if contentH < 3 {
		contentH = 3
	}

	// Each pane is: 1 title line + a rounded border (2 rows / 2 cols) + viewport.
	respH := contentH - 3
	if respH < 1 {
		respH = 1
	}
	m.resp.SetWidth(inner - 2)
	m.resp.SetHeight(respH)

	if m.showDebug {
		dh := debugH - 3
		if dh < 1 {
			dh = 1
		}
		m.debugView.SetWidth(inner - 2)
		m.debugView.SetHeight(dh)
	}
}

// ---- rendering -------------------------------------------------------------

// renderHeader is the title plus a colored divider. The divider is a static
// pink→blue gradient normally, and an animated rainbow in 🌈 mode.
func (m model) renderHeader() string {
	dw := m.width - 2
	if dw < 1 {
		dw = 1
	}
	const wordmark = "✦ weeb ⚡ terminal http client ✦"
	if m.rainbow {
		return rainbowText(wordmark, m.frame) + "\n" +
			rainbowStep(strings.Repeat("━", dw), m.frame, 360.0/float64(dw), false)
	}
	return gradientText(wordmark, titleHue0, titleHue1, true) + "\n" +
		gradientText(strings.Repeat("━", dw), titleHue0, titleHue1, false)
}

// sectionColors gives each form section its own vivid hue; sectionIcons a glyph.
var sectionColors = map[string]color.Color{
	"Method":  lipgloss.Color("#FF5FAF"),
	"URL":     lipgloss.Color("#FFB000"),
	"Headers": lipgloss.Color("#5FFF87"),
	"Body":    lipgloss.Color("#5FD7FF"),
}

var sectionIcons = map[string]string{
	"Method":  "⚡",
	"URL":     "🔗",
	"Headers": "📋",
	"Body":    "📦",
}

// label renders a section heading as an icon plus a colored chip: a filled badge
// (in the section's hue) when focused, an outlined accent bar otherwise.
func (m model) label(text string, active bool) string {
	col := sectionColors[text]
	if col == nil {
		col = cMauve
	}
	icon := sectionIcons[text]
	name := strings.ToUpper(text)

	if active {
		marker := lipgloss.NewStyle().Bold(true).Foreground(col).Render("▸")
		var chip string
		if m.rainbow {
			chip = rainbowText(" "+name+" ", m.frame)
		} else {
			chip = lipgloss.NewStyle().Bold(true).Foreground(cInk).
				Background(col).Padding(0, 1).Render(name)
		}
		return marker + " " + icon + " " + chip
	}
	body := lipgloss.NewStyle().Bold(true).Foreground(col).Render("▎ " + name)
	return "  " + icon + " " + body
}

func (m model) renderMethodSelector() string {
	active := m.currentFocus().kind == focMethod
	parts := make([]string, 0, len(m.methods))
	for i, mth := range m.methods {
		var st lipgloss.Style
		switch {
		case i == m.methodIdx && active:
			// Focused selection: bold ink on the verb's color.
			st = lipgloss.NewStyle().Bold(true).Foreground(cInk).
				Background(methodColor(mth)).Padding(0, 1)
		case i == m.methodIdx:
			// Selected but not focused: the verb's color as foreground.
			st = lipgloss.NewStyle().Bold(true).Foreground(methodColor(mth)).Padding(0, 1)
		default:
			// Idle verbs keep a faint tint of their own signature color.
			st = lipgloss.NewStyle().Faint(true).Foreground(methodColor(mth)).Padding(0, 1)
		}
		parts = append(parts, st.Render(mth))
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func (m model) renderForm() string {
	cur := m.currentFocus()
	var b strings.Builder

	b.WriteString(m.renderHeader() + "\n\n")

	b.WriteString(m.label("Method", cur.kind == focMethod) + "\n")
	b.WriteString(m.renderMethodSelector() + "\n")

	b.WriteString(m.label("URL", cur.kind == focURL) + "\n")
	b.WriteString(m.url.View() + "\n")

	headersActive := cur.kind == focHeaderKey || cur.kind == focHeaderVal
	b.WriteString(m.label("Headers", headersActive) + "  ")
	b.WriteString(m.styles.help.Render("(ctrl+o add · ctrl+r remove)") + "\n")
	for _, hr := range m.headers {
		line := lipgloss.JoinHorizontal(lipgloss.Top,
			m.styles.headerKey.Render(hr.key.View()),
			m.styles.help.Render("  :  "),
			hr.val.View(),
		)
		b.WriteString(line + "\n")
	}

	if m.bodyEnabled() {
		b.WriteString(m.label("Body", cur.kind == focBody) + "\n")
		b.WriteString(m.body.View() + "\n")
	} else {
		// Body-less method: collapse to a single dim line instead of a tall,
		// greyed-out textarea that would just waste rows.
		b.WriteString(m.styles.disabled.Render("  📦 body — not sent for "+m.currentMethod()) + "\n")
	}

	b.WriteString("\n")
	b.WriteString(m.renderHelpLine())
	return b.String()
}

func (m model) renderHelpLine() string {
	if m.inFlight {
		label := m.flightLabel
		if label == "" {
			label = "working…"
		}
		return m.spinner.View() + " " + m.styles.hint.Render(label)
	}

	pairs := [][2]string{
		{"ctrl+s", "send"}, {"ctrl+t", "cert"}, {"ctrl+x", "curl"}, {"ctrl+p", "pretty"},
		{"ctrl+y", "🌈"}, {"ctrl+g", "debug"}, {"ctrl+c", "quit"},
	}
	sep := m.styles.hint.Render("  ·  ")
	segs := make([]string, 0, len(pairs))
	for _, p := range pairs {
		segs = append(segs, m.styles.keycap.Render(p[0])+" "+m.styles.hint.Render(p[1]))
	}
	return strings.Join(segs, sep)
}

// paneHeading renders a pane title (rainbow when 🌈 mode is on).
func (m model) paneHeading(title string) string {
	if m.rainbow {
		return rainbowText(title, m.frame)
	}
	return m.styles.paneTitle.Render(title)
}

// borderColor is the pane border color: animated rainbow in 🌈 mode, else static.
func (m model) borderColor(offset float64) color.Color {
	if m.rainbow {
		return rainbowHue(m.frame, offset)
	}
	return cMauve
}

func (m model) renderResponsePane() string {
	title := m.respHeading
	if m.currentFocus().kind == focResponse {
		if m.hasSections() {
			title += "  (↑↓ scroll · ←→ select · enter fold · ± all)"
		} else {
			title += "  (↑↓ scroll)"
		}
	}
	inner := m.resp.View()
	if m.pane == paneResponse && m.lastResult == nil && !m.inFlight {
		inner = m.emptyState() // nothing sent yet: show a placeholder, not a blank box
	}
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(m.responseBorderColor()).
		Render(inner)
	return m.paneHeading(title) + "\n" + box
}

// responseBorderColor tints the response box: animated in 🌈 mode, by HTTP status
// class once a response has landed, else the neutral accent.
func (m model) responseBorderColor() color.Color {
	if m.rainbow {
		return rainbowHue(m.frame, 0)
	}
	if m.pane == paneResponse && m.lastResult != nil && m.lastResult.Status != 0 {
		return statusColor(m.lastResult.Status)
	}
	return cMauve
}

// emptyState is the centered placeholder shown in the response box before the
// first request, so it reads as an affordance instead of dead space.
func (m model) emptyState() string {
	w, h := m.resp.Width(), m.resp.Height()
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	var glyph string
	if m.rainbow {
		glyph = rainbowText("⚡ weeb", m.frame)
	} else {
		glyph = gradientText("⚡ weeb", titleHue0, titleHue1, true)
	}
	lines := lipgloss.JoinVertical(lipgloss.Center,
		glyph,
		"",
		m.styles.hint.Render("compose a request above, then"),
		m.styles.keycap.Render("ctrl+s")+m.styles.hint.Render("  to send"),
		"",
		m.styles.hint.Render("ctrl+t cert · ctrl+p pretty · ctrl+y 🌈"),
	)
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, lines)
}

func (m model) renderDebugPane() string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(m.borderColor(140)).
		Render(m.debugView.View())
	return m.paneHeading("🪵 Debug log  (charm/log)") + "\n" + box
}

// renderResult fills the response viewport with the status line, response
// headers, the (pretty-printed) body, and any human-facing weeb error.
func (m *model) renderResult(r Result) {
	m.pane = paneResponse
	m.respHeading = "📡 Response"
	m.respPreamble = ""
	m.respSections = nil
	m.respErr = ""

	if r.Status != 0 {
		m.respPreamble = statusBadge(r, m.styles)

		// Connection: negotiated TLS + the per-phase timing breakdown.
		var conn strings.Builder
		if r.TLS != nil {
			conn.WriteString(renderConnTLS(r.TLS, m.styles) + "\n")
		}
		conn.WriteString(renderTiming(r.Timing, m.styles, m.resp.Width()))
		m.addSection("Connection", fmt.Sprintf("%d ms", r.Timing.Total.Milliseconds()),
			strings.TrimRight(conn.String(), "\n"))

		// Headers: one "key: value" line each.
		keys := sortedHeaderKeys(r.Headers)
		var hb strings.Builder
		for _, k := range keys {
			hb.WriteString(m.styles.headerKey.Render(k + ": "))
			hb.WriteString(m.styles.headerVal.Render(strings.Join(r.Headers[k], ", ")))
			hb.WriteString("\n")
		}
		m.addSection("Headers", fmt.Sprintf("%d", len(keys)), strings.TrimRight(hb.String(), "\n"))

		// Body: the response payload. With pretty on, JSON/XML/HTML get a fold
		// tree for structural collapsing and colorized rendering. With pretty off
		// the body is shown raw (no tree, no reformat) — see renderBody.
		if len(r.Body) > 0 {
			var tree *bnode
			var xtree *xnode
			var ytree *ynode
			if m.pretty {
				switch detectFormat(r.ContentType, r.URL, r.Body, true) {
				case fmtJSON:
					tree = parseJSONTree(r.Body, r.ContentType, r.URL, true)
				case fmtXML:
					xtree = parseXMLTree(r.Body, r.ContentType, r.URL, true)
				case fmtHTML:
					xtree = parseHTMLTree(r.Body, r.ContentType, r.URL, true)
				case fmtYAML:
					ytree = parseYAMLTree(r.Body, r.ContentType, r.URL, true)
				}
			}
			m.addBodySection(bodySummary(len(r.Body), r.ContentType),
				renderBody(r.Body, r.ContentType, r.URL, m.styles, true, m.pretty, m.resp.Width()), tree, xtree, ytree)
		}
	}

	if r.DisplayErr != "" {
		m.respErr = m.styles.errText.Render(r.DisplayErr)
	}

	if m.respCursor >= len(m.respSections) {
		m.respCursor = 0
	}
	m.setResp(m.composeResponse())
	m.resp.GotoTop()
}

// renderCert fills the response viewport with a TLS report (or the errorchan
// voice on dial failure), reusing the response pane and its persona seam. The
// report's blocks become foldable sections — the leaf shows on load while the
// CA certs above it start folded, so the chain reads as an overview by default.
func (m *model) renderCert(msg certMsg) {
	m.pane = paneCert
	m.respPreamble = ""
	m.respSections = nil
	m.respErr = ""
	if msg.err != nil {
		m.respHeading = "🔒 TLS"
		m.setResp(m.styles.errText.Render(m.client.voice.Render(KindTransport, 0, msg.err)))
		m.resp.GotoTop()
		return
	}
	m.respHeading = fmt.Sprintf("🔒 TLS  %s:%s", msg.rep.Host, msg.rep.Port)
	for _, s := range certSections(msg.rep, m.styles, true, m.resp.Width(), true) {
		m.addSectionDefault(s.title, s.summary, s.body, s.defaultFold)
	}
	if m.respCursor >= len(m.foldTargets()) {
		m.respCursor = 0
	}
	m.setResp(m.composeResponse())
	m.resp.GotoTop()
}

// showResponse returns the pane to the last HTTP response, rebuilding its
// sections so a cert/curl detour never leaves their content under the Response
// heading. With no response yet, it clears to an empty response pane.
func (m *model) showResponse() {
	if m.lastResult != nil {
		m.renderResult(*m.lastResult)
		return
	}
	m.pane = paneResponse
	m.respHeading = "📡 Response"
	m.respPreamble = ""
	m.respSections = nil
	m.respErr = ""
	m.setResp(m.composeResponse())
	m.resp.GotoTop()
}
