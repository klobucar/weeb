package main

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"golang.org/x/net/html"
)

// A legal empty-string object key must render with its key and colon; key==""
// used to double as the "array element" marker, so {"": "v"} displayed as a
// bare value indistinguishable from an array element.
func TestRenderTreeEmptyStringKey(t *testing.T) {
	root := parseJSONTree([]byte(`{"":"secret","b":1}`), "application/json", "", false)
	if root == nil {
		t.Fatal("parseJSONTree returned nil for valid JSON")
	}
	out := ansi.Strip(renderTree(root, newStyles(), nil))
	if !strings.Contains(out, `"": "secret"`) {
		t.Errorf("empty-string key lost its key/colon:\n%s", out)
	}

	// Array elements and the root still render without a key.
	arr := parseJSONTree([]byte(`["x"]`), "application/json", "", false)
	out = ansi.Strip(renderTree(arr, newStyles(), nil))
	if strings.Contains(out, ":") {
		t.Errorf("array elements must not grow keys:\n%s", out)
	}
}

// parseValue recursed once per level, and before Go 1.27 json.Decoder.Token
// has no depth limit, so 4.5M '[' (9 MB, under the 64 MiB body cap) overflowed
// the 1 GB goroutine stack: a fatal crash that left the terminal in the alt
// screen. Every tree builder now refuses bodies nested past maxTreeDepth, and
// the flat render takes over.
func TestParseTreesRejectDeepNesting(t *testing.T) {
	nest := func(open, mid, close string, n int) []byte {
		return []byte(strings.Repeat(open, n) + mid + strings.Repeat(close, n))
	}
	for _, n := range []int{maxTreeDepth, maxTreeDepth + 1} {
		want := n <= maxTreeDepth
		if got := parseJSONTree(nest("[", "1", "]", n), "application/json", "", false) != nil; got != want {
			t.Errorf("JSON nested %d deep: tree=%v, want %v", n, got, want)
		}
		if got := parseXMLTree(nest("<a>", "", "</a>", n), "application/xml", "", false) != nil; got != want {
			t.Errorf("XML nested %d deep: tree=%v, want %v", n, got, want)
		}
		if got := parseYAMLTree(nest("[", "1", "]", n), "application/yaml", "", false) != nil; got != want {
			t.Errorf("YAML nested %d deep: tree=%v, want %v", n, got, want)
		}
	}

	start := time.Now()
	if parseJSONTree(nest("[", "", "]", 4_500_000), "application/json", "", false) != nil {
		t.Error("JSON nested 4.5M deep: got a tree")
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("rejecting the 9 MB nested body took %v", took)
	}

	// html.Parse stops at 512 levels itself, so drive buildHTMLNode directly.
	root := &html.Node{Type: html.ElementNode, Data: "div"}
	cur := root
	for i := 0; i <= maxTreeDepth; i++ {
		c := &html.Node{Type: html.ElementNode, Data: "div"}
		cur.AppendChild(c)
		cur = c
	}
	if _, err := buildHTMLNode(root, 0); err == nil {
		t.Error("HTML nested past maxTreeDepth: want an error")
	}
}

// Each rendered line repeated its depth's indentation, so a deeply nested body
// rendered as lines × depth bytes (14 KB of JSON became 28 MB in the fold
// tree). Indentation now stops at maxIndentDepth, keeping output linear.
func TestTreeRenderIndentIsClamped(t *testing.T) {
	const depth, sibs = 200, 2000
	ones := strings.TrimSuffix(strings.Repeat("1,", sibs), ",")
	st := newStyles()
	cases := []struct {
		name   string
		body   string
		render func([]byte) string
	}{
		{"json", strings.Repeat("[", depth) + ones + strings.Repeat("]", depth), func(b []byte) string {
			return renderTree(parseJSONTree(b, "application/json", "", false), st, nil)
		}},
		{"xml", strings.Repeat("<a>", depth) + strings.Repeat("<b/>", sibs) + strings.Repeat("</a>", depth), func(b []byte) string {
			return renderXMLTree(parseXMLTree(b, "application/xml", "", false), st, nil)
		}},
		{"yaml", strings.Repeat("[", depth) + ones + strings.Repeat("]", depth), func(b []byte) string {
			return renderYAMLTree(parseYAMLTree(b, "application/yaml", "", false), st, nil)
		}},
	}
	for _, c := range cases {
		out := ansi.Strip(c.render([]byte(c.body)))
		if out == "" {
			t.Fatalf("%s: no tree", c.name)
		}
		widest := 0
		for _, ln := range strings.Split(out, "\n") {
			widest = max(widest, len(ln)-len(strings.TrimLeft(ln, " ")))
		}
		if widest != 2*maxIndentDepth {
			t.Errorf("%s: deepest indent is %d columns, want %d", c.name, widest, 2*maxIndentDepth)
		}
		if ratio := len(out) / len(c.body); ratio > 50 {
			t.Errorf("%s: render amplifies the body ×%d", c.name, ratio)
		}
	}
}
