package main

import (
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestColorizeJSONMalformedInput(t *testing.T) {
	st := newStyles()
	// Invalid JSON still reaches colorizeJSON when json.Indent fails and the
	// raw bytes are colorized as-is; none of these may panic or alter content.
	cases := []string{
		`{"a\`,          // string ending in a lone backslash at EOF
		`{"a": "b\`,     // lone backslash in a value
		`"`,             // bare unterminated string
		`\`,             // single backslash
		`{"a": "b\\"}`,  // escaped backslash before closing quote
		`{"a": "b\""}`,  // escaped quote
		`{"key": 12e+}`, // malformed number
	}
	for _, in := range cases {
		if got := ansi.Strip(colorizeJSON(in, st)); got != in {
			t.Errorf("colorizeJSON(%q) altered content: %q", in, got)
		}
	}
}
