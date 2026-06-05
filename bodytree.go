package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// bKind classifies a JSON value for the fold tree.
type bKind int

const (
	bScalar bKind = iota // string / number / bool / null
	bObject
	bArray
)

// bnode is one value in a parsed JSON body. Containers (objects/arrays) carry
// children and a per-node folded flag; scalars carry their already-formatted
// token text. The tree is what structural folding operates on: each non-empty
// container is an independently collapsible node.
type bnode struct {
	key      string // object-member key (raw, unquoted); "" for array elements / root
	kind     bKind
	scalar   string // formatted token for scalars, e.g. `"hi"`, `42`, `true`, `null`
	children []*bnode
	folded   bool
}

// parseJSONTree parses a body into a fold tree when it is (or sniffs as) JSON.
// It returns nil for anything it can't represent as a single JSON document, so
// the caller falls back to the flat colored render.
func parseJSONTree(body []byte, contentType, url string, sniff bool) *bnode {
	if detectFormat(contentType, url, body, sniff) != fmtJSON {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	root, err := parseValue(dec, "")
	if err != nil {
		return nil
	}
	// Reject trailing junk so we only tree-render a clean single document.
	if _, err := dec.Token(); err != io.EOF {
		return nil
	}
	return root
}

func parseValue(dec *json.Decoder, key string) (*bnode, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); ok {
		switch d {
		case '{':
			n := &bnode{kind: bObject, key: key}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("weeb: object key was not a string")
				}
				child, err := parseValue(dec, k)
				if err != nil {
					return nil, err
				}
				n.children = append(n.children, child)
			}
			if _, err := dec.Token(); err != nil { // closing '}'
				return nil, err
			}
			return n, nil
		case '[':
			n := &bnode{kind: bArray, key: key}
			for dec.More() {
				child, err := parseValue(dec, "")
				if err != nil {
					return nil, err
				}
				n.children = append(n.children, child)
			}
			if _, err := dec.Token(); err != nil { // closing ']'
				return nil, err
			}
			return n, nil
		}
	}
	// Scalar: re-marshal the token so the formatting matches the original kind.
	raw, err := json.Marshal(tok)
	if err != nil {
		return nil, err
	}
	return &bnode{kind: bScalar, key: key, scalar: string(raw)}, nil
}

// bnode satisfies foldNode so the shared fold-cursor machinery can walk it.
func (n *bnode) foldable() bool   { return n.kind != bScalar && len(n.children) > 0 }
func (n *bnode) getFolded() bool  { return n.folded }
func (n *bnode) setFolded(v bool) { n.folded = v }
func (n *bnode) kids() []foldNode {
	out := make([]foldNode, len(n.children))
	for i, c := range n.children {
		out[i] = c
	}
	return out
}

// ---- rendering -------------------------------------------------------------

// renderTree renders the JSON tree to indented, syntax-colored text honoring
// each node's fold state. sel, if non-nil, is the node whose head line gets the
// fold-cursor highlight.
func renderTree(root *bnode, st styles, sel foldNode) string {
	if root == nil {
		return ""
	}
	var lines []string
	renderNode(root, 0, true, true, sel, st, &lines)
	return strings.Join(lines, "\n")
}

// renderNode appends the rendered lines for n. isRoot suppresses folding/keys on
// the top-level value (the Body section heading already collapses the whole body).
func renderNode(n *bnode, depth int, last, isRoot bool, sel foldNode, st styles, out *[]string) {
	indent := strings.Repeat("  ", depth)
	comma := ""
	if !last {
		comma = ","
	}

	if n.kind == bScalar {
		line := indent
		if n.key != "" {
			line += colorKey(n.key, st) + st.jsonPunct.Render(": ")
		}
		line += colorScalar(n.scalar, st) + st.jsonPunct.Render(comma)
		*out = append(*out, line)
		return
	}

	open, close := "{", "}"
	if n.kind == bArray {
		open, close = "[", "]"
	}

	// Empty container: render inline as "{}" / "[]".
	if len(n.children) == 0 {
		line := indent
		if n.key != "" {
			line += colorKey(n.key, st) + st.jsonPunct.Render(": ")
		}
		line += st.jsonPunct.Render(open + close + comma)
		*out = append(*out, line)
		return
	}

	selected := !isRoot && foldNode(n) == sel

	// Collapsed: a single "key: {…} N keys" line.
	if !isRoot && n.folded {
		if selected {
			plain := indent
			if n.key != "" {
				plain += quoteKey(n.key) + ": "
			}
			plain += open + "…" + close + comma + "  " + foldCount(n)
			*out = append(*out, st.foldSel.Render(plain))
			return
		}
		line := indent
		if n.key != "" {
			line += colorKey(n.key, st) + st.jsonPunct.Render(": ")
		}
		line += st.jsonPunct.Render(open) + st.jsonNull.Render("…") +
			st.jsonPunct.Render(close+comma) + "  " + st.meta.Render(foldCount(n))
		*out = append(*out, line)
		return
	}

	// Expanded: head line, children, close line.
	if selected {
		plain := indent
		if n.key != "" {
			plain += quoteKey(n.key) + ": "
		}
		plain += open
		*out = append(*out, st.foldSel.Render(plain))
	} else {
		head := indent
		if n.key != "" {
			head += colorKey(n.key, st) + st.jsonPunct.Render(": ")
		}
		head += st.jsonPunct.Render(open)
		*out = append(*out, head)
	}
	for i, c := range n.children {
		renderNode(c, depth+1, i == len(n.children)-1, false, sel, st, out)
	}
	*out = append(*out, indent+st.jsonPunct.Render(close+comma))
}

func foldCount(n *bnode) string {
	c := len(n.children)
	unit := "keys"
	if n.kind == bArray {
		unit = "items"
	}
	if c == 1 {
		unit = strings.TrimSuffix(unit, "s")
	}
	return fmt.Sprintf("%d %s", c, unit)
}

func quoteKey(k string) string {
	b, err := json.Marshal(k)
	if err != nil {
		return `"` + k + `"`
	}
	return string(b)
}

func colorKey(k string, st styles) string { return st.jsonKey.Render(quoteKey(k)) }

// colorScalar colors a JSON scalar token by its type (inferred from the text).
func colorScalar(raw string, st styles) string {
	switch {
	case strings.HasPrefix(raw, `"`):
		return st.jsonStr.Render(raw)
	case raw == "true" || raw == "false":
		return st.jsonBool.Render(raw)
	case raw == "null":
		return st.jsonNull.Render(raw)
	default:
		return st.jsonNum.Render(raw)
	}
}
