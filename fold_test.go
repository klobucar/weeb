package main

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

// wrapIndentRef is the original quadratic implementation, kept as the
// behavioral reference for plain (unstyled) input.
func wrapIndentRef(s string, width int) string {
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
		if contBudget < 8 {
			hang, contBudget = 0, width
		}
		pad := strings.Repeat(" ", hang)
		out = append(out, ansi.Cut(line, 0, width))
		total := ansi.StringWidth(line)
		for pos := width; pos < total; pos += contBudget {
			out = append(out, pad+ansi.Cut(line, pos, pos+contBudget))
		}
	}
	return strings.Join(out, "\n")
}

func TestWrapIndentMatchesReference(t *testing.T) {
	cases := []struct{ name, in string }{
		{"short line untouched", "hello"},
		{"exact width", strings.Repeat("a", 80)},
		{"long flat line", strings.Repeat("abcdefghij", 30)},
		{"long indented line", "    " + strings.Repeat("x", 300)},
		{"deeply nested falls flush", strings.Repeat(" ", 75) + strings.Repeat("y", 200)},
		{"multiline mixed", "short\n" + strings.Repeat("z", 200) + "\nshort again"},
		{"multibyte runes", "  " + strings.Repeat("héllo wörld ", 30)},
	}
	for _, c := range cases {
		if got, want := wrapIndent(c.in, 80), wrapIndentRef(c.in, 80); got != want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, want)
		}
	}
}

// Styled input: the new Hardwrap path carries SGR state across rows (an
// improvement over per-chunk Cut), so compare content and row widths rather
// than exact bytes.
func TestWrapIndentStyled(t *testing.T) {
	styled := "  \x1b[31m" + strings.Repeat("r", 250) + "\x1b[0m"
	out := wrapIndent(styled, 80)
	for i, row := range strings.Split(out, "\n") {
		if w := ansi.StringWidth(row); w > 80 {
			t.Errorf("row %d is %d cells wide, want <= 80", i, w)
		}
	}
	stripped := strings.ReplaceAll(ansi.Strip(out), "\n", "")
	stripped = strings.ReplaceAll(stripped, " ", "")
	if want := strings.Repeat("r", 250); stripped != want {
		t.Errorf("styled content mangled: got %d r's, want 250", len(stripped))
	}
}

func BenchmarkWrapIndentLongLine(b *testing.B) {
	line := strings.Repeat(`{"key":"value"},`, 12_500) // ~200 KB single line
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wrapIndent(line, 80)
	}
}
