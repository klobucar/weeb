package main

import (
	"bytes"
	"encoding/xml"
	"strings"

	"golang.org/x/net/html"
)

// parseHTMLTree parses an HTML body into the shared xnode fold tree using a real
// HTML5 parser (golang.org/x/net/html), so it survives the messy reality that
// the lenient encoding/xml tokenizer can't — <script>/<style> with bare '<',
// <!DOCTYPE>, unquoted attributes, unclosed void elements, and so on.
func parseHTMLTree(body []byte, contentType, url string, sniff bool) *xnode {
	if detectFormat(contentType, url, body, sniff) != fmtHTML {
		return nil
	}
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	root := &xnode{kind: xElem}
	for c := doc.FirstChild; c != nil; c = c.NextSibling {
		if n := buildHTMLNode(c); n != nil {
			root.children = append(root.children, n)
		}
	}
	if len(root.children) == 0 {
		return nil
	}
	return root
}

func buildHTMLNode(n *html.Node) *xnode {
	switch n.Type {
	case html.ElementNode:
		x := &xnode{kind: xElem, name: n.Data}
		for _, a := range n.Attr {
			x.attrs = append(x.attrs, xml.Attr{Name: xml.Name{Local: a.Key}, Value: a.Val})
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if cn := buildHTMLNode(c); cn != nil {
				x.children = append(x.children, cn)
			}
		}
		return x
	case html.TextNode:
		// HTML collapses runs of whitespace, so do the same for display — this
		// also flattens multi-line <script>/<style>/<pre> text onto one line.
		if s := strings.Join(strings.Fields(n.Data), " "); s != "" {
			return &xnode{kind: xText, text: s}
		}
		return nil
	case html.CommentNode:
		return &xnode{kind: xComment, text: strings.TrimSpace(n.Data)}
	case html.DoctypeNode:
		return &xnode{kind: xDirective, text: "DOCTYPE " + n.Data}
	default:
		return nil
	}
}
