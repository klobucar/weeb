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
		n, err := buildHTMLNode(c, 0)
		if err != nil {
			return nil
		}
		if n != nil {
			root.children = append(root.children, n)
		}
	}
	if len(root.children) == 0 {
		return nil
	}
	return root
}

// buildHTMLNode converts n and its subtree; a nil node with a nil error means n
// has nothing to show. html.Parse rejects nesting past 512 elements today, but
// the depth check keeps this recursion bounded without relying on that.
func buildHTMLNode(n *html.Node, depth int) (*xnode, error) {
	if depth > maxTreeDepth {
		return nil, errTooDeep
	}
	switch n.Type {
	case html.ElementNode:
		x := &xnode{kind: xElem, name: n.Data}
		for _, a := range n.Attr {
			x.attrs = append(x.attrs, xml.Attr{Name: xml.Name{Local: a.Key}, Value: a.Val})
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			cn, err := buildHTMLNode(c, depth+1)
			if err != nil {
				return nil, err
			}
			if cn != nil {
				x.children = append(x.children, cn)
			}
		}
		return x, nil
	case html.TextNode:
		// HTML collapses runs of whitespace, so do the same for display — this
		// also flattens multi-line <script>/<style>/<pre> text onto one line.
		if s := strings.Join(strings.Fields(n.Data), " "); s != "" {
			return &xnode{kind: xText, text: s}, nil
		}
		return nil, nil
	case html.CommentNode:
		return &xnode{kind: xComment, text: strings.TrimSpace(n.Data)}, nil
	case html.DoctypeNode:
		return &xnode{kind: xDirective, text: "DOCTYPE " + n.Data}, nil
	default:
		return nil, nil
	}
}
