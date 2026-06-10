package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// wrapIndent hard-wraps each line of s to width, ANSI-aware, with a hanging
// indent: continuation rows are indented two columns past the line's own
// leading indentation so wrapped tree/JSON entries stay visually nested instead
// of snapping back to column 0. Lines that already fit are left untouched.
func wrapIndent(s string, width int) string {
	if width < 8 {
		return s
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if ansi.StringWidth(line) <= width {
			out = append(out, line)
			continue
		}
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		hang := indent + 2
		contBudget := width - hang
		if contBudget < 8 { // too deeply nested to hang nicely — wrap flush
			hang, contBudget = 0, width
		}
		pad := strings.Repeat(" ", hang)

		// One Cut for the first row, one for the remainder, one Hardwrap pass
		// for the continuation rows — linear in the line length. The old loop
		// called ansi.Cut(line, pos, …) per chunk, and Cut rescans from byte 0
		// every call, which made wrapping a single long line (a minified JSON
		// body in raw view) quadratic — a multi-second freeze per render.
		out = append(out, ansi.Cut(line, 0, width)) // first row keeps native indent
		rest := ansi.Cut(line, width, ansi.StringWidth(line))
		for _, seg := range strings.Split(ansi.Hardwrap(rest, contBudget, true), "\n") {
			out = append(out, pad+seg)
		}
	}
	return strings.Join(out, "\n")
}

// setResp sets the response viewport's content, hang-indent wrapped to its
// width. Everything the pane shows funnels through here, so it doubles as the
// TUI's sanitizing boundary: server-influenced text (bodies, cert fields, TLS
// names) is stripped of hostile control sequences — Bubble Tea's renderer
// drops mid-content escapes on its own, but a trailing OSC would survive it —
// while weeb's own SGR/OSC 8 styling passes through sanitizeTTY intact.
func (m *model) setResp(content string) {
	m.resp.SetContent(wrapIndent(sanitizeTTY(content), m.resp.Width()))
}

// respSection is one collapsible block of the response pane. When folded, only
// the heading line shows (with its summary); when expanded, body follows. The
// fold state lives in model.foldState keyed by title so it survives re-renders
// (e.g. toggling pretty mode) and the cert ⇄ response swap.
//
// The Body section additionally carries a parsed JSON tree; when tree != nil the
// body is rendered from it with per-node structural folding, otherwise the flat
// body string is used.
type respSection struct {
	title   string
	summary string // shown in parens on the heading, e.g. "14" or "1.2 KB · json"
	body    string // flat rendered content (fallback when no tree)
	tree    *bnode // JSON fold tree for the Body section; nil otherwise
	xtree   *xnode // XML/HTML fold tree for the Body section; nil otherwise
	ytree   *ynode // YAML fold tree for the Body section; nil otherwise
	folded  bool
}

// foldRoot returns the section's structural tree as a foldNode, or nil. The
// explicit field checks matter: a nil typed pointer wrapped in an interface is
// not itself nil, so we must not wrap a nil tree.
func (s *respSection) foldRoot() foldNode {
	switch {
	case s.tree != nil:
		return s.tree
	case s.xtree != nil:
		return s.xtree
	case s.ytree != nil:
		return s.ytree
	default:
		return nil
	}
}

// addSection appends a section, seeding its fold state from the sticky map.
func (m *model) addSection(title, summary, body string) {
	m.respSections = append(m.respSections, respSection{
		title:   title,
		summary: summary,
		body:    body,
		folded:  m.foldState[title],
	})
}

// addSectionDefault appends a section like addSection, but seeds an unseen
// section's fold state from defFold instead of always-expanded — used by the cert
// view so per-cert detail blocks start collapsed the first time, while still
// honoring the user's sticky choice on later renders.
func (m *model) addSectionDefault(title, summary, body string, defFold bool) {
	folded, seen := m.foldState[title]
	if !seen {
		folded = defFold
	}
	m.respSections = append(m.respSections, respSection{
		title:   title,
		summary: summary,
		body:    body,
		folded:  folded,
	})
	m.foldState[title] = folded
}

// addBodySection appends the Body section, attaching whichever structural tree
// was parsed (JSON or XML/HTML); both may be nil for a plain-text body.
func (m *model) addBodySection(summary, body string, tree *bnode, xtree *xnode, ytree *ynode) {
	m.respSections = append(m.respSections, respSection{
		title:   "Body",
		summary: summary,
		body:    body,
		tree:    tree,
		xtree:   xtree,
		ytree:   ytree,
		folded:  m.foldState["Body"],
	})
}

// foldNode is a collapsible node in a parsed body tree — a JSON value (*bnode)
// or an XML/HTML element (*xnode). The fold-cursor machinery walks bodies through
// this interface so it never has to know which kind of tree it's stepping over.
type foldNode interface {
	foldable() bool // can this node be collapsed (a non-empty container)?
	getFolded() bool
	setFolded(bool)
	kids() []foldNode
}

// asFoldNodes boxes a typed child slice as []foldNode so each tree type's
// kids() is a one-liner instead of three copies of the same loop.
func asFoldNodes[T foldNode](cs []T) []foldNode {
	out := make([]foldNode, len(cs))
	for i, c := range cs {
		out[i] = c
	}
	return out
}

// visibleNodes returns the foldable nodes in visual (pre-order) order, skipping
// the root and anything hidden inside a collapsed ancestor. This is exactly the
// set the fold cursor steps through, and it matches the renderers' line order.
func visibleNodes(root foldNode) []foldNode {
	var out []foldNode
	if root == nil {
		return out
	}
	var walk func(n foldNode)
	walk = func(n foldNode) {
		for _, c := range n.kids() {
			if c.foldable() {
				out = append(out, c)
				if !c.getFolded() {
					walk(c)
				}
			}
		}
	}
	walk(root)
	return out
}

// eachContainer visits every foldable node except the root (used by fold-all).
func eachContainer(root foldNode, fn func(foldNode)) {
	if root == nil {
		return
	}
	var walk func(n foldNode)
	walk = func(n foldNode) {
		for _, c := range n.kids() {
			if c.foldable() {
				fn(c)
			}
			walk(c)
		}
	}
	walk(root)
}

// foldTarget addresses one collapsible thing in the response pane: a section
// heading (node == nil) or a structural node inside the Body's tree.
type foldTarget struct {
	sec  int
	node foldNode
}

// foldTargets lists every collapsible thing currently visible, top to bottom:
// each section heading, and — when the Body section is expanded and has a tree —
// its visible JSON nodes right after it. The fold cursor indexes into this list,
// and the order matches what composeResponse renders.
func (m *model) foldTargets() []foldTarget {
	var ts []foldTarget
	for i := range m.respSections {
		s := &m.respSections[i]
		ts = append(ts, foldTarget{sec: i})
		if root := s.foldRoot(); root != nil && !s.folded {
			for _, n := range visibleNodes(root) {
				ts = append(ts, foldTarget{sec: i, node: n})
			}
		}
	}
	return ts
}

// clampCursor keeps the fold cursor inside the current target list (it shrinks
// when nodes get hidden under a collapse).
func (m *model) clampCursor() {
	n := len(m.foldTargets())
	switch {
	case n == 0:
		m.respCursor = 0
	case m.respCursor >= n:
		m.respCursor = n - 1
	case m.respCursor < 0:
		m.respCursor = 0
	}
}

// composeResponse flattens the always-visible preamble (status badge), every
// section honoring its fold state and the fold cursor, and any trailing error
// into the single string the response viewport scrolls.
func (m *model) composeResponse() string {
	focused := m.currentFocus().kind == focResponse
	m.clampCursor()

	// Resolve what the cursor currently points at.
	selSec := -1
	var selNode foldNode
	if focused {
		if ts := m.foldTargets(); m.respCursor < len(ts) {
			t := ts[m.respCursor]
			if t.node == nil {
				selSec = t.sec
			} else {
				selNode = t.node
			}
		}
	}

	var blocks []string
	if m.respPreamble != "" {
		blocks = append(blocks, m.respPreamble)
	}

	for i, s := range m.respSections {
		marker := "▾"
		if s.folded {
			marker = "▸"
		}
		head := marker + " " + s.title
		if i == selSec {
			head = m.styles.foldHeadSel.Render(head)
		} else {
			head = m.styles.foldHead.Render(head)
		}
		if s.summary != "" {
			head += "  " + m.styles.meta.Render("("+s.summary+")")
		}

		block := head
		if !s.folded {
			switch {
			case s.tree != nil:
				block += "\n" + renderTree(s.tree, m.styles, selNode)
			case s.xtree != nil:
				block += "\n" + renderXMLTree(s.xtree, m.styles, selNode)
			case s.ytree != nil:
				block += "\n" + renderYAMLTree(s.ytree, m.styles, selNode)
			default:
				block += "\n" + s.body
			}
		}
		blocks = append(blocks, block)
	}

	if m.respErr != "" {
		blocks = append(blocks, m.respErr)
	}

	return strings.Join(blocks, "\n\n")
}

// ---- fold cursor / toggles -------------------------------------------------

// hasSections reports whether the pane currently shows foldable content — true
// for both the HTTP response and the TLS cert view, which share the section model.
func (m *model) hasSections() bool {
	return (m.pane == paneResponse || m.pane == paneCert) && len(m.respSections) > 0
}

func (m *model) moveFoldCursor(dir int) {
	n := len(m.foldTargets())
	if n == 0 {
		return
	}
	m.respCursor = (m.respCursor%n + dir + n) % n
	m.setResp(m.composeResponse())
}

// toggleFold collapses/expands whatever the cursor points at — a section or a
// single JSON node. Section folds are sticky (by title); node folds live with
// the current response's tree.
func (m *model) toggleFold() {
	ts := m.foldTargets()
	if m.respCursor < 0 || m.respCursor >= len(ts) {
		return
	}
	t := ts[m.respCursor]
	if t.node == nil {
		s := &m.respSections[t.sec]
		s.folded = !s.folded
		m.foldState[s.title] = s.folded
	} else {
		t.node.setFolded(!t.node.getFolded())
	}
	m.clampCursor()
	m.setResp(m.composeResponse())
}

// setAllFolded folds or unfolds everything — every section (sticky) and every
// node of the Body tree — so "fold all" collapses the whole world and "unfold
// all" expands it fully.
func (m *model) setAllFolded(folded bool) {
	for i := range m.respSections {
		m.respSections[i].folded = folded
		m.foldState[m.respSections[i].title] = folded
		if root := m.respSections[i].foldRoot(); root != nil {
			eachContainer(root, func(n foldNode) { n.setFolded(folded) })
		}
	}
	m.clampCursor()
	m.setResp(m.composeResponse())
}

// ---- summaries -------------------------------------------------------------

// humanSize renders a byte count as a short human string for fold summaries.
func humanSize(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// bodySummary describes a body block: its size and a short content-type tag.
func bodySummary(n int, contentType string) string {
	tag := shortContentType(contentType)
	if tag == "" {
		return humanSize(n)
	}
	return humanSize(n) + " · " + tag
}

// shortContentType pulls a compact label out of a Content-Type header value
// ("application/json; charset=utf-8" -> "json").
func shortContentType(ct string) string {
	ct = strings.TrimSpace(strings.ToLower(ct))
	if ct == "" {
		return ""
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if i := strings.IndexByte(ct, '/'); i >= 0 {
		sub := ct[i+1:]
		// "vnd.api+json" -> "json"; "svg+xml" -> "xml".
		if j := strings.LastIndexByte(sub, '+'); j >= 0 {
			sub = sub[j+1:]
		}
		return sub
	}
	return ct
}
