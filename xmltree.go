package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// xKind classifies a node in the XML/HTML fold tree.
type xKind int

const (
	xElem xKind = iota
	xText
	xComment
	xProcInst // <?xml ... ?>
	xDirective
)

// xnode is one node of a parsed XML/HTML body. Elements carry attributes and
// child nodes (which may be elements, text, comments, …) in document order so
// mixed content survives; non-element nodes carry their text. Each element with
// child elements is an independently collapsible fold node.
type xnode struct {
	kind     xKind
	name     string     // element name / proc-inst target
	attrs    []xml.Attr // element attributes
	text     string     // text / comment / proc-inst / directive content
	children []*xnode
	folded   bool
}

// parseXMLTree parses a body into a fold tree when it is (or sniffs as)
// XML/HTML. It uses the same lenient decoder as prettyXML so it survives most
// real-world HTML; it returns nil on anything it can't tokenize so the caller
// falls back to the flat render.
func parseXMLTree(body []byte, contentType, url string, sniff bool) *xnode {
	if f := detectFormat(contentType, url, body, sniff); f != fmtXML && f != fmtHTML {
		return nil
	}
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity

	root := &xnode{kind: xElem}
	stack := []*xnode{root}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil
		}
		cur := stack[len(stack)-1]
		switch t := tok.(type) {
		case xml.StartElement:
			n := &xnode{kind: xElem, name: t.Name.Local, attrs: append([]xml.Attr(nil), t.Attr...)}
			cur.children = append(cur.children, n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if s := strings.TrimSpace(string(t)); s != "" {
				cur.children = append(cur.children, &xnode{kind: xText, text: s})
			}
		case xml.Comment:
			cur.children = append(cur.children, &xnode{kind: xComment, text: strings.TrimSpace(string(t))})
		case xml.ProcInst:
			cur.children = append(cur.children, &xnode{kind: xProcInst, name: t.Target, text: strings.TrimSpace(string(t.Inst))})
		case xml.Directive:
			cur.children = append(cur.children, &xnode{kind: xDirective, text: strings.TrimSpace(string(t))})
		}
	}
	if len(root.children) == 0 {
		return nil
	}
	return root
}

// foldable: an element is collapsible when it has child content beyond a single
// text run (folding "<title>Hi</title>" would gain nothing).
func (n *xnode) foldable() bool {
	if n.kind != xElem || len(n.children) == 0 {
		return false
	}
	if len(n.children) == 1 && n.children[0].kind == xText {
		return false
	}
	return true
}

func (n *xnode) getFolded() bool  { return n.folded }
func (n *xnode) setFolded(v bool) { n.folded = v }
func (n *xnode) kids() []foldNode {
	out := make([]foldNode, len(n.children))
	for i, c := range n.children {
		out[i] = c
	}
	return out
}

func (n *xnode) elemCount() int {
	c := 0
	for _, k := range n.children {
		if k.kind == xElem {
			c++
		}
	}
	return c
}

// ---- rendering -------------------------------------------------------------

// renderXMLTree renders the XML/HTML tree to indented, syntax-colored text
// honoring each element's fold state. sel, if non-nil, highlights the matching
// node's head line.
func renderXMLTree(root *xnode, st styles, sel foldNode) string {
	if root == nil {
		return ""
	}
	var lines []string
	for _, c := range root.children {
		renderXNode(c, 0, sel, st, &lines)
	}
	return strings.Join(lines, "\n")
}

func renderXNode(n *xnode, depth int, sel foldNode, st styles, out *[]string) {
	indent := strings.Repeat("  ", depth)

	switch n.kind {
	case xText:
		*out = append(*out, indent+st.headerVal.Render(n.text))
		return
	case xComment:
		*out = append(*out, indent+st.jsonNull.Render("<!-- "+n.text+" -->"))
		return
	case xProcInst:
		*out = append(*out, indent+st.jsonNull.Render("<?"+n.name+" "+n.text+"?>"))
		return
	case xDirective:
		*out = append(*out, indent+st.jsonNull.Render("<!"+n.text+">"))
		return
	}

	selected := foldNode(n) == sel

	// Empty element: <name .../>.
	if len(n.children) == 0 {
		if selected {
			*out = append(*out, st.foldSel.Render(indent+xmlOpenPlain(n, " />")))
		} else {
			*out = append(*out, indent+xmlOpenColored(n, st, " />"))
		}
		return
	}

	// Single text child: <name ...>text</name> on one line.
	if len(n.children) == 1 && n.children[0].kind == xText {
		txt := n.children[0].text
		if selected {
			*out = append(*out, st.foldSel.Render(indent+xmlOpenPlain(n, ">")+txt+"</"+n.name+">"))
		} else {
			line := indent + xmlOpenColored(n, st, ">") +
				st.headerVal.Render(txt) + xmlCloseColored(n, st)
			*out = append(*out, line)
		}
		return
	}

	// Collapsed: <name ...>…</name>  N children.
	if n.folded {
		if selected {
			*out = append(*out, st.foldSel.Render(indent+xmlOpenPlain(n, ">")+"…</"+n.name+">  "+xmlFoldCount(n)))
		} else {
			line := indent + xmlOpenColored(n, st, ">") + st.jsonNull.Render("…") +
				xmlCloseColored(n, st) + "  " + st.meta.Render(xmlFoldCount(n))
			*out = append(*out, line)
		}
		return
	}

	// Expanded: open line, children, close line.
	if selected {
		*out = append(*out, st.foldSel.Render(indent+xmlOpenPlain(n, ">")))
	} else {
		*out = append(*out, indent+xmlOpenColored(n, st, ">"))
	}
	for _, c := range n.children {
		renderXNode(c, depth+1, sel, st, out)
	}
	*out = append(*out, indent+xmlCloseColored(n, st))
}

// xmlOpenColored builds a colored opening tag ending in end (">" or " />").
func xmlOpenColored(n *xnode, st styles, end string) string {
	var b strings.Builder
	b.WriteString(st.jsonPunct.Render("<"))
	b.WriteString(st.jsonKey.Render(n.name))
	for _, a := range n.attrs {
		b.WriteString(" " + st.meta.Render(a.Name.Local))
		b.WriteString(st.jsonPunct.Render("="))
		b.WriteString(st.jsonStr.Render(`"` + a.Value + `"`))
	}
	b.WriteString(st.jsonPunct.Render(end))
	return b.String()
}

func xmlCloseColored(n *xnode, st styles) string {
	return st.jsonPunct.Render("</") + st.jsonKey.Render(n.name) + st.jsonPunct.Render(">")
}

// xmlOpenPlain is the uncolored opening tag, for the selection highlight bar.
func xmlOpenPlain(n *xnode, end string) string {
	var b strings.Builder
	b.WriteString("<" + n.name)
	for _, a := range n.attrs {
		b.WriteString(" " + a.Name.Local + `="` + a.Value + `"`)
	}
	b.WriteString(end)
	return b.String()
}

func xmlFoldCount(n *xnode) string {
	if e := n.elemCount(); e > 0 {
		if e == 1 {
			return "1 child"
		}
		return fmt.Sprintf("%d children", e)
	}
	if len(n.children) == 1 {
		return "1 node"
	}
	return fmt.Sprintf("%d nodes", len(n.children))
}
