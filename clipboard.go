package main

import (
	"bytes"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"go.yaml.in/yaml/v3"
	"golang.org/x/net/html"
)

// maxClipboardText caps the text one copy sends. Terminals bound the OSC 52
// sequence they accept (several stop near 100 KB of base64) and drop an
// oversize one whole rather than truncating it, so a bigger copy would just
// vanish. 75,000 bytes of text is 100,000 once base64-encoded.
const maxClipboardText = 75_000

// statusTTL is how long a status message stays in place of the key help.
const statusTTL = 3 * time.Second

// statusClearMsg ends a status message. seq ties it to the flash that
// scheduled it, so an older timer can't wipe a newer message early.
type statusClearMsg struct{ seq int }

// flash shows text in the status line and returns the timer that clears it.
// The form isn't rendered through setResp, and text can carry server names
// (JSON keys, element names, cert titles), so it is stripped here and kept to
// one line.
func (m *model) flash(text string) tea.Cmd {
	m.status = oneLine.Replace(stripForClipboard(text))
	m.statusSeq++
	seq := m.statusSeq
	return tea.Tick(statusTTL, func(time.Time) tea.Msg { return statusClearMsg{seq: seq} })
}

var oneLine = strings.NewReplacer("\n", " ", "\t", " ")

// statusLine renders the current status message, cut to the terminal width so
// it stays one line and the measured form height holds.
func (m model) statusLine() string {
	return m.styles.keycap.Render("📋") + " " +
		m.styles.headerVal.Render(ansi.Truncate(m.status, max(m.width-6, 10), "…"))
}

// copyText puts s on the system clipboard via OSC 52 (tea.SetClipboard), which
// works over SSH and needs no OS clipboard tool, and flashes what was copied.
func (m *model) copyText(what, s string) tea.Cmd {
	text, truncated := clipboardText(s)
	if text == "" {
		// An empty OSC 52 payload clears the clipboard instead of copying.
		return m.flash("nothing to copy: " + what + " is empty")
	}
	status := "copied " + what + " to clipboard"
	if truncated {
		status += fmt.Sprintf(" (truncated to %s of %s)", humanSize(len(text)), humanSize(len(s)))
	}
	return tea.Batch(tea.SetClipboard(text), m.flash(status))
}

// clipboardText readies s for the clipboard: stripped (see stripForClipboard)
// and capped at maxClipboardText bytes on a rune boundary. truncated reports
// whether anything was cut.
func clipboardText(s string) (text string, truncated bool) {
	// Stripping mostly shrinks text, so a few caps of input is plenty to fill
	// the cap; don't sanitize a whole 64 MB body to send 75 KB of it.
	if lim := 4 * maxClipboardText; len(s) > lim {
		s, truncated = s[:runeCut(s, lim)], true
	}
	s = stripForClipboard(s)
	if len(s) > maxClipboardText {
		s, truncated = s[:runeCut(s, maxClipboardText)], true
	}
	return s, truncated
}

// stripForClipboard drops escape sequences (weeb's own styling and anything
// hostile in server text) and every control character left after them except
// newline and tab, and repairs invalid UTF-8. A paste must not replay a
// sequence into the next terminal or a stray CR into a shell.
func stripForClipboard(s string) string {
	return strings.Map(func(r rune) rune {
		if r != '\n' && r != '\t' && isControl(r) {
			return -1
		}
		return r
	}, ansi.Strip(s))
}

// isControl reports C0, DEL, and C1 control characters.
func isControl(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) }

// runeCut returns the largest cut point <= n that doesn't split a UTF-8
// sequence in s.
func runeCut(s string, n int) int {
	for n > 0 && n < len(s) && !utf8.RuneStart(s[n]) {
		n--
	}
	return n
}

// ---- response-pane copy ----------------------------------------------------

// copySelection copies what the fold cursor is on: its path, or its value when
// value is set. Update only calls it with the response pane focused.
func (m *model) copySelection(value bool) tea.Cmd {
	if m.pane == paneCurl {
		return m.flash("ctrl+x copies the curl command")
	}
	ts := m.foldTargets()
	if !m.hasSections() || m.respCursor < 0 || m.respCursor >= len(ts) {
		return m.flash("nothing to copy yet")
	}
	t := ts[m.respCursor]
	sec := &m.respSections[t.sec]

	var body []byte
	isHTML := false
	if m.pane == paneResponse && m.lastResult != nil {
		r := m.lastResult
		body = r.Body
		isHTML = sec.xtree != nil && detectFormat(r.ContentType, r.URL, r.Body, true) == fmtHTML
	}

	if t.node == nil {
		return m.copySection(sec, body, value)
	}
	root := sec.foldRoot()
	if value {
		s, ok := nodeValue(root, t.node, body, isHTML)
		if !ok {
			return m.flash("couldn't recover that node's value from the body")
		}
		return m.copyText("value", s)
	}
	p, ok := nodePath(root, t.node, body)
	if !ok {
		return m.flash("couldn't work out that node's path")
	}
	return m.copyText("path "+p, p)
}

// copySection handles the cursor on a section heading. The Body heading stands
// for the whole document: its path is the root and its value is the body as
// received. Other sections have no path; their value is their plain text
// (e.g. "Key: value" lines for Headers).
func (m *model) copySection(sec *respSection, body []byte, value bool) tea.Cmd {
	if !value {
		switch sec.foldRoot().(type) {
		case *bnode, *ynode:
			return m.copyText("path .", ".")
		case *xnode:
			return m.copyText("path /", "/")
		}
		return m.flash("nothing to copy: " + sec.title + " has no path")
	}
	if sec.title == "Body" && body != nil {
		return m.copyText("body", string(body))
	}
	return m.copyText(sec.title, ansi.Strip(sec.body))
}

// indexPath finds target under root and returns the child positions leading
// to it. The trees keep no parent links, so this is one depth-first search per
// keypress, bounded in depth by maxTreeDepth like the builders.
func indexPath(root, target foldNode) ([]int, bool) {
	var path []int
	var walk func(n foldNode) bool
	walk = func(n foldNode) bool {
		if n == target {
			return true
		}
		for i, c := range n.kids() {
			path = append(path, i)
			if walk(c) {
				return true
			}
			path = path[:len(path)-1]
		}
		return false
	}
	if root == nil || !walk(root) {
		return nil, false
	}
	return path, true
}

// nodePath addresses target: jq-style for JSON and YAML, XPath-like for
// XML/HTML. YAML re-parses body for the raw keys (the fold tree only keeps
// display keys).
func nodePath(root, target foldNode, body []byte) (string, bool) {
	idx, ok := indexPath(root, target)
	if !ok {
		return "", false
	}
	switch r := root.(type) {
	case *bnode:
		return jqPath(jsonSegs(r, idx)), true
	case *ynode:
		_, segs, ok := yamlNodeAt(body, idx)
		return jqPath(segs), ok
	case *xnode:
		return xPath(r, idx), true
	}
	return "", false
}

// nodeValue is target's value: compact JSON for a JSON node, the re-emitted
// YAML fragment for YAML, the exact source bytes for XML, and the element's
// outer HTML for HTML.
func nodeValue(root, target foldNode, body []byte, isHTML bool) (string, bool) {
	switch n := target.(type) {
	case *bnode:
		var b strings.Builder
		compactJSON(n, &b)
		return b.String(), true
	case *ynode:
		idx, ok := indexPath(root, target)
		if !ok {
			return "", false
		}
		yn, _, ok := yamlNodeAt(body, idx)
		if !ok {
			return "", false
		}
		return yamlFragment(yn)
	case *xnode:
		if isHTML {
			idx, ok := indexPath(root, target)
			if !ok {
				return "", false
			}
			return htmlOuter(body, idx, n)
		}
		if n.end <= n.start || n.end > len(body) || body[n.start] != '<' {
			return "", false
		}
		return string(body[n.start:n.end]), true
	}
	return "", false
}

// ---- jq paths ---------------------------------------------------------------

// pathSeg is one step of a jq path: an object key, or an array index.
type pathSeg struct {
	key   string
	index int
	isIdx bool
}

// jqPath renders segs as a jq path (.items[3].id, .["weird key"], .[0]); the
// empty path is the identity ".".
func jqPath(segs []pathSeg) string {
	if len(segs) == 0 {
		return "."
	}
	var b strings.Builder
	for i, s := range segs {
		switch {
		case !s.isIdx && jqIdent(s.key):
			b.WriteString("." + s.key)
			continue
		case i == 0:
			b.WriteByte('.') // a path can't start with a bare [
		}
		if s.isIdx {
			fmt.Fprintf(&b, "[%d]", s.index)
		} else {
			b.WriteString("[" + jqString(s.key) + "]")
		}
	}
	return b.String()
}

// jqKeywords can't follow a bare "." before jq 1.7, so keys spelled like them
// are bracket-quoted; over-quoting is always valid jq, under-quoting isn't.
var jqKeywords = map[string]bool{
	"__loc__": true, "and": true, "as": true, "break": true, "catch": true,
	"def": true, "elif": true, "else": true, "end": true, "foreach": true,
	"if": true, "import": true, "include": true, "label": true, "module": true,
	"or": true, "reduce": true, "then": true, "try": true,
}

// jqIdent reports whether k can be written as .k in jq.
func jqIdent(k string) bool {
	if k == "" || jqKeywords[k] {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		alpha := c == '_' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
		if !alpha && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// jqString quotes k as a jq string literal. JSON escaping covers C0, quotes,
// and backslashes (so "\(" can't become interpolation); DEL and C1 are left
// raw by JSON, so they get \u escapes too. Stripping them at the clipboard
// instead would silently change the key the path names.
func jqString(k string) string {
	q := jsonToken(k)
	if !strings.ContainsFunc(q, isControl) {
		return q
	}
	var b strings.Builder
	for _, r := range q {
		if isControl(r) {
			fmt.Fprintf(&b, `\u%04x`, r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// jsonSegs turns an index path through a JSON tree into jq steps.
func jsonSegs(root *bnode, idx []int) []pathSeg {
	segs := make([]pathSeg, 0, len(idx))
	n := root
	for _, i := range idx {
		c := n.children[i]
		if n.kind == bArray {
			segs = append(segs, pathSeg{index: i, isIdx: true})
		} else {
			segs = append(segs, pathSeg{key: c.key})
		}
		n = c
	}
	return segs
}

// compactJSON writes n as compact JSON. Scalars already hold their encoded
// token (numbers keep their source text via UseNumber), so this concatenates
// rather than re-marshaling through a map, which would reorder keys and drop
// duplicates.
func compactJSON(n *bnode, b *strings.Builder) {
	if n.kind == bScalar {
		b.WriteString(n.scalar)
		return
	}
	open, close := byte('{'), byte('}')
	if n.kind == bArray {
		open, close = '[', ']'
	}
	b.WriteByte(open)
	for i, c := range n.children {
		if i > 0 {
			b.WriteByte(',')
		}
		if n.kind == bObject {
			b.WriteString(quoteKey(c.key) + ":")
		}
		compactJSON(c, b)
	}
	b.WriteByte(close)
}

// ---- YAML ------------------------------------------------------------------

// yamlNodeAt re-parses body and follows idx (child positions in the ynode
// tree, which buildYNode lays out 1:1 with the yaml.Node tree) to the matching
// node, collecting jq steps with the raw keys on the way.
func yamlNodeAt(body []byte, idx []int) (*yaml.Node, []pathSeg, bool) {
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil || len(doc.Content) == 0 {
		return nil, nil, false
	}
	n := doc.Content[0]
	segs := make([]pathSeg, 0, len(idx))
	for _, i := range idx {
		switch {
		case n.Kind == yaml.MappingNode && 2*i+1 < len(n.Content):
			k := n.Content[2*i]
			if k.Kind == yaml.AliasNode && k.Alias != nil {
				k = k.Alias
			}
			segs = append(segs, pathSeg{key: k.Value})
			n = n.Content[2*i+1]
		case n.Kind == yaml.SequenceNode && i < len(n.Content):
			segs = append(segs, pathSeg{index: i, isIdx: true})
			n = n.Content[i]
		default:
			return nil, nil, false
		}
	}
	return n, segs, true
}

// yamlFragment re-emits n as YAML. The parse keeps no end offsets to slice the
// source with, but it does keep key order, quoting, block styles, anchors and
// comments, so the copy reads like the source with normalized indentation.
func yamlFragment(n *yaml.Node) (string, bool) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		return "", false
	}
	if err := enc.Close(); err != nil {
		return "", false
	}
	return strings.TrimSuffix(b.String(), "\n"), true
}

// ---- XML / HTML --------------------------------------------------------------

// xPath renders an index path through an XML/HTML tree as an XPath-like path
// (/root/item[3]/name). Like browser devtools, a step gets a 1-based position
// only when same-named siblings make it ambiguous. Names are local (namespace
// prefixes aren't kept by the tree).
func xPath(root *xnode, idx []int) string {
	if len(idx) == 0 {
		return "/"
	}
	var b strings.Builder
	n := root
	for _, i := range idx {
		c := n.children[i]
		switch c.kind {
		case xText:
			b.WriteString("/text()")
		case xComment:
			b.WriteString("/comment()")
		case xElem:
			b.WriteString("/" + c.name)
			pos, count := 0, 0
			for j, s := range n.children {
				if s.kind == xElem && s.name == c.name {
					count++
					if j == i {
						pos = count
					}
				}
			}
			if count > 1 {
				fmt.Fprintf(&b, "[%d]", pos)
			}
		default:
			b.WriteString("/node()")
		}
		n = c
	}
	return b.String()
}

// htmlOuter re-parses an HTML body, follows idx to the element the fold tree
// selected, and renders its outer HTML. The HTML5 parser restructures input
// and reports no offsets, so this serialization is the closest thing to the
// source fragment. The name check guards against the walk drifting.
func htmlOuter(body []byte, idx []int, want *xnode) (string, bool) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return "", false
	}
	n := doc
	for _, i := range idx {
		kids := htmlKids(n)
		if i >= len(kids) {
			return "", false
		}
		n = kids[i]
	}
	if n.Type != html.ElementNode || n.Data != want.name {
		return "", false
	}
	var b strings.Builder
	if err := html.Render(&b, n); err != nil {
		return "", false
	}
	return b.String(), true
}

// htmlKids lists n's children the way buildHTMLNode keeps them (elements,
// non-blank text, comments, doctypes), so a fold-tree index path walks the
// re-parsed document in step.
func htmlKids(n *html.Node) []*html.Node {
	var out []*html.Node
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		switch c.Type {
		case html.ElementNode, html.CommentNode, html.DoctypeNode:
			out = append(out, c)
		case html.TextNode:
			if strings.TrimSpace(c.Data) != "" {
				out = append(out, c)
			}
		}
	}
	return out
}

// specHasCredentials reports whether a request carries a credential header
// (the same name test history uses to redact), so a copy can say so.
func specHasCredentials(spec RequestSpec) bool {
	for _, h := range spec.Headers {
		if strings.TrimSpace(h.Value) != "" && redactedHeaderKey(h.Key) {
			return true
		}
	}
	return false
}
