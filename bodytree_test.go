package main

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
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
