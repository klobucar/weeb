package main

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// yKind classifies a node in the YAML fold tree.
type yKind int

const (
	yScalar yKind = iota
	yMap
	ySeq
)

// ynode is one node of a parsed YAML document. Mappings and sequences carry
// children (each map child keeps its rendered key); scalars carry a display
// value. Every non-empty mapping/sequence is an independently collapsible node.
type ynode struct {
	key      string // rendered map key; "" for sequence items / the root
	kind     yKind
	scalar   string // rendered scalar for leaves
	children []*ynode
	folded   bool
}

// parseYAMLTree parses a body into a fold tree when it is YAML (decided by
// detectFormat — Content-Type or .yaml/.yml extension only; YAML is never
// sniffed since plain text and JSON are both valid YAML). It returns nil for a
// bare scalar or a parse error, so the caller falls back to the flat render.
func parseYAMLTree(body []byte, contentType, url string, sniff bool) *ynode {
	if detectFormat(contentType, url, body, sniff) != fmtYAML {
		return nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return nil
	}
	root := buildYNode(doc.Content[0], "")
	if root == nil || root.kind == yScalar {
		return nil // nothing structural to fold
	}
	return root
}

func buildYNode(n *yaml.Node, key string) *ynode {
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil
		}
		return buildYNode(n.Content[0], key)
	case yaml.MappingNode:
		yn := &ynode{kind: yMap, key: key}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := yamlKey(n.Content[i])
			yn.children = append(yn.children, buildYNode(n.Content[i+1], k))
		}
		return yn
	case yaml.SequenceNode:
		yn := &ynode{kind: ySeq, key: key}
		for _, item := range n.Content {
			yn.children = append(yn.children, buildYNode(item, ""))
		}
		return yn
	case yaml.AliasNode:
		return &ynode{kind: yScalar, key: key, scalar: "*" + n.Value}
	default: // ScalarNode (and anything unexpected)
		return &ynode{kind: yScalar, key: key, scalar: yamlScalar(n)}
	}
}

func yamlKey(n *yaml.Node) string {
	if n.Value == "" {
		return `""`
	}
	return n.Value
}

func yamlScalar(n *yaml.Node) string {
	v := n.Value
	switch n.Style {
	case yaml.DoubleQuotedStyle:
		return strconv.Quote(v)
	case yaml.SingleQuotedStyle:
		return "'" + strings.ReplaceAll(v, "'", "''") + "'"
	}
	if n.Tag == "!!null" {
		return "null"
	}
	if v == "" {
		return `""`
	}
	// Block/literal scalars (and any embedded newline) get collapsed to a single
	// quoted line so the tree stays line-addressable for folding.
	if strings.ContainsAny(v, "\n") {
		return strconv.Quote(v)
	}
	return v
}

// ynode satisfies foldNode.
func (n *ynode) foldable() bool   { return n.kind != yScalar && len(n.children) > 0 }
func (n *ynode) getFolded() bool  { return n.folded }
func (n *ynode) setFolded(v bool) { n.folded = v }
func (n *ynode) kids() []foldNode {
	out := make([]foldNode, len(n.children))
	for i, c := range n.children {
		out[i] = c
	}
	return out
}

// ---- rendering -------------------------------------------------------------

// renderYAMLTree renders the YAML tree to indented, syntax-colored text honoring
// each node's fold state. sel, if non-nil, highlights the matching node's head.
func renderYAMLTree(root *ynode, st styles, sel foldNode) string {
	if root == nil {
		return ""
	}
	var lines []string
	seqCtx := root.kind == ySeq
	for _, c := range root.children {
		renderYNode(c, 0, seqCtx, sel, st, &lines)
	}
	return strings.Join(lines, "\n")
}

func renderYNode(n *ynode, depth int, inSeq bool, sel foldNode, st styles, out *[]string) {
	indent := strings.Repeat("  ", depth)
	dash, dashPlain := "", ""
	if inSeq {
		dash, dashPlain = st.jsonPunct.Render("- "), "- "
	}
	keyColored, keyPlain := "", ""
	if n.key != "" {
		keyColored = colorYKey(n.key, st) + st.jsonPunct.Render(":")
		keyPlain = n.key + ":"
	}
	selected := foldNode(n) == sel

	// Scalar leaf.
	if n.kind == yScalar {
		line := indent + dash
		if n.key != "" {
			line += keyColored + " "
		}
		*out = append(*out, line+colorYScalar(n.scalar, st))
		return
	}

	// Empty container.
	if len(n.children) == 0 {
		empty := "[]"
		if n.kind == yMap {
			empty = "{}"
		}
		line := indent + dash
		if n.key != "" {
			line += keyColored + " "
		}
		*out = append(*out, line+st.jsonPunct.Render(empty))
		return
	}

	// Collapsed container: "key: …  N keys" / "- …  N items".
	if n.folded {
		sum := yFoldCount(n)
		if selected {
			p := indent + dashPlain
			if n.key != "" {
				p += keyPlain + " "
			}
			*out = append(*out, st.foldSel.Render(p+"… "+sum))
			return
		}
		line := indent + dash
		if n.key != "" {
			line += keyColored + " "
		}
		*out = append(*out, line+st.jsonNull.Render("…")+"  "+st.meta.Render(sum))
		return
	}

	// Expanded container.
	childSeq := n.kind == ySeq
	switch {
	case n.key != "":
		// Mapping entry whose value is a container: "key:" then children indented.
		head := indent + dash + keyColored
		if selected {
			head = st.foldSel.Render(indent + dashPlain + keyPlain)
		}
		*out = append(*out, head)
		for _, c := range n.children {
			renderYNode(c, depth+1, childSeq, sel, st, out)
		}
	case inSeq:
		// Sequence item that is itself a container: a dash on its own line, with
		// the block indented beneath it (valid YAML, and keeps lines 1:1 with nodes).
		head := indent + st.jsonPunct.Render("-")
		if selected {
			head = st.foldSel.Render(indent + "-")
		}
		*out = append(*out, head)
		for _, c := range n.children {
			renderYNode(c, depth+1, childSeq, sel, st, out)
		}
	default:
		for _, c := range n.children {
			renderYNode(c, depth, childSeq, sel, st, out)
		}
	}
}

func yFoldCount(n *ynode) string {
	c := len(n.children)
	unit := "keys"
	if n.kind == ySeq {
		unit = "items"
	}
	if c == 1 {
		unit = strings.TrimSuffix(unit, "s")
	}
	return fmt.Sprintf("%d %s", c, unit)
}

func colorYKey(k string, st styles) string { return st.jsonKey.Render(k) }

// colorYScalar colors a YAML scalar by inferred type. Plain (unquoted) scalars
// default to the string color, since in YAML an unquoted token is usually a string.
func colorYScalar(s string, st styles) string {
	if s == "" {
		return s
	}
	if s[0] == '"' || s[0] == '\'' {
		return st.jsonStr.Render(s)
	}
	switch strings.ToLower(s) {
	case "true", "false", "yes", "no", "on", "off":
		return st.jsonBool.Render(s)
	case "null", "~":
		return st.jsonNull.Render(s)
	}
	if yamlNumeric(s) {
		return st.jsonNum.Render(s)
	}
	return st.jsonStr.Render(s)
}

func yamlNumeric(s string) bool {
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return true
	}
	if _, err := strconv.ParseInt(s, 0, 64); err == nil {
		return true
	}
	return false
}
