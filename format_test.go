package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDetectFormat(t *testing.T) {
	md := []byte("# Title\n\nbody\n")
	js := []byte(`{"a":1}`)
	yml := []byte("name: weeb\nkey: val\n")
	html := []byte("<html><body>hi</body></html>")
	xml := []byte("<?xml version=\"1.0\"?><a/>")
	log := []byte("2026-06-05 starting\nconnected\nrequest ok\n")

	cases := []struct {
		name string
		ct   string
		url  string
		body []byte
		want bodyFormat
	}{
		{"json content-type", "application/json", "", js, fmtJSON},
		{"markdown content-type", "text/markdown", "", md, fmtMarkdown},
		{"yaml content-type", "application/yaml", "", yml, fmtYAML},
		{"x-yaml content-type", "application/x-yaml", "", yml, fmtYAML},
		{"html content-type", "text/html", "", html, fmtHTML},
		{"xml content-type", "application/xml", "", xml, fmtXML},

		{"md by url ext (text/plain)", "text/plain", "https://x/README.md", md, fmtMarkdown},
		{"yaml by url ext", "text/plain", "https://x/cfg.yaml", yml, fmtYAML},
		{"yml by url ext", "text/plain", "https://x/cfg.yml", yml, fmtYAML},
		{"json by url ext", "", "https://x/data.json", js, fmtJSON},

		{"json by sniff", "text/plain", "", js, fmtJSON},
		{"html by sniff", "text/plain", "", html, fmtHTML},
		{"markdown by sniff (heading)", "text/plain", "", md, fmtMarkdown},

		{"plain stays text", "text/plain", "", log, fmtText},
		{"yaml is NOT sniffed", "text/plain", "", yml, fmtText},

		{"content-type beats url ext", "application/json", "https://x/weird.yaml", js, fmtJSON},
		{"empty body, yaml url", "", "https://x/cfg.yaml", []byte{}, fmtYAML},
	}
	for _, c := range cases {
		if got := detectFormat(c.ct, c.url, c.body, true); got != c.want {
			t.Errorf("%s: detectFormat=%d want=%d", c.name, got, c.want)
		}
	}
}

func TestLooksLikeMarkdown(t *testing.T) {
	yes := [][]byte{
		[]byte("# Heading\ntext"),
		[]byte("intro\n\n```\ncode\n```"),
		[]byte("| a | b |\n|---|---|\n| 1 | 2 |"),
		[]byte("- one\n- two\n- three"),
	}
	no := [][]byte{
		[]byte("just some prose with no structure at all"),
		[]byte("log line 1\nlog line 2\n"),
		[]byte("see [a link](http://x) once"), // single weak signal isn't enough
	}
	for _, b := range yes {
		if !looksLikeMarkdown(b) {
			t.Errorf("looksLikeMarkdown(%q) = false, want true", b)
		}
	}
	for _, b := range no {
		if looksLikeMarkdown(b) {
			t.Errorf("looksLikeMarkdown(%q) = true, want false", b)
		}
	}
}

func TestURLExt(t *testing.T) {
	cases := map[string]string{
		"https://x/a/b/README.md?ref=1": "md",
		"https://x/data.JSON":           "json",
		"https://x/cfg.yaml#frag":       "yaml",
		"https://x/noext":               "",
		"https://x/dir/":                "",
		"":                              "",
	}
	for in, want := range cases {
		if got := urlExt(in); got != want {
			t.Errorf("urlExt(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShortContentType(t *testing.T) {
	cases := map[string]string{
		"application/json; charset=utf-8": "json",
		"text/html":                       "html",
		"application/vnd.api+json":        "json",
		"image/svg+xml":                   "xml",
		"":                                "",
	}
	for in, want := range cases {
		if got := shortContentType(in); got != want {
			t.Errorf("shortContentType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHumanSizeAndBodySummary(t *testing.T) {
	if humanSize(500) != "500 B" {
		t.Errorf("humanSize(500) = %q", humanSize(500))
	}
	if humanSize(2048) != "2.0 KB" {
		t.Errorf("humanSize(2048) = %q", humanSize(2048))
	}
	if humanSize(5*1024*1024) != "5.0 MB" {
		t.Errorf("humanSize(5MB) = %q", humanSize(5*1024*1024))
	}
	if got := bodySummary(44, "application/json"); got != "44 B · json" {
		t.Errorf("bodySummary = %q, want '44 B · json'", got)
	}
	if got := bodySummary(0, ""); got != "0 B" {
		t.Errorf("bodySummary(0,'') = %q, want '0 B'", got)
	}
}

func TestRenderBodyRawVsPretty(t *testing.T) {
	st := newStyles()
	body := []byte(`{"a":1,"b":2}`)

	// pretty off -> exact bytes, no reformat, no color.
	if got := renderBody(body, "application/json", "", st, true, false, 0); got != string(body) {
		t.Errorf("raw render changed the body: %q", got)
	}
	// pretty on -> reindented (multi-line).
	pretty := renderBody(body, "application/json", "", st, true, true, 0)
	if !strings.Contains(pretty, "\n") {
		t.Errorf("pretty JSON should be multi-line, got %q", pretty)
	}
}

func TestSanitizeTTY(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain text untouched", "hello\nworld\ttab", "hello\nworld\ttab"},
		{"SGR color kept", "\x1b[31mred\x1b[0m", "\x1b[31mred\x1b[0m"},
		{"OSC 52 clipboard dropped", "\x1b]52;c;ZXZpbA==\x07stolen", "stolen"},
		{"OSC title dropped (BEL)", "\x1b]0;evil title\x07text", "text"},
		{"OSC title dropped (ST)", "\x1b]2;evil\x1b\\text", "text"},
		{"OSC 8 hyperlink kept", "\x1b]8;;https://x\x07link\x1b]8;;\x07", "\x1b]8;;https://x\x07link\x1b]8;;\x07"},
		{"cursor/clear CSI dropped", "\x1b[2J\x1b[Hspoof", "spoof"},
		{"scroll region dropped", "\x1b[1;10rtext", "text"},
		{"DCS payload dropped", "\x1bPq#evil\x1b\\after", "after"},
		{"APC payload dropped", "\x1b_payload\x1b\\after", "after"},
		{"BEL and CR dropped", "ding\x07dong\rline", "dingdongline"},
		{"DEL dropped", "a\x7fb", "ab"},
		{"lone trailing ESC dropped", "text\x1b", "text"},
		{"unterminated OSC dropped", "\x1b]52;c;steal", ""},
		{"unterminated CSI dropped", "text\x1b[12;34", "text"},
		{"8-bit C1 OSC 52 dropped", "\x9d52;c;ZXZpbA==\x9cstolen", "stolen"},
		{"8-bit C1 CSI dropped", "\x9b2Jtext", "text"},
		{"CSI-smuggled OSC dropped", "\x1b[\x9d0;1\x07m", "m"},
		{"unterminated OSC 8 dropped", "\x1b]8;;https://x", ""},
		{"multibyte UTF-8 kept intact", "café ▾█ 日本語", "café ▾█ 日本語"},
		{"UTF-8 around dropped sequence", "é\x1b]52;c;x\x07ñ", "éñ"},
	}
	for _, c := range cases {
		if got := sanitizeTTY(c.in); got != c.want {
			t.Errorf("%s: sanitizeTTY(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// TestSanitizingWriter proves the TTY output boundary: hostile sequences are
// stripped, weeb's own SGR styling survives, and the reported byte count
// covers the full input so fmt.Fprint* callers never see a short write.
func TestSanitizingWriter(t *testing.T) {
	var buf strings.Builder
	in := "hi\x1b]52;c;ZXZpbA==\x07 \x1b[31mred\x1b[0m"
	n, err := sanitizingWriter{w: &buf}.Write([]byte(in))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(in) {
		t.Errorf("Write reported %d bytes, want %d", n, len(in))
	}
	if got, want := buf.String(), "hi \x1b[31mred\x1b[0m"; got != want {
		t.Errorf("sanitizingWriter wrote %q, want %q", got, want)
	}
}

// glamour's cost is exponential in blockquote depth and polynomial in list
// depth: the first body below (96 bytes) took 5s and rendered 5.8 MB. Bodies
// nested past maxMarkdownNesting, or over maxMarkdownBytes, now skip glamour
// and render as their raw source.
func TestRenderMarkdownTooDeepFallsBackToRaw(t *testing.T) {
	var indented strings.Builder
	for i := 0; i < 200; i++ {
		indented.WriteString(strings.Repeat("  ", i) + "- x\n")
	}
	cases := map[string]string{
		"nested blockquotes": "# t\n" + strings.Repeat(">", 90) + " x",
		"spaced blockquotes": "# t\n" + strings.Repeat("> ", 90) + "x",
		"inline list nest":   "# t\n" + strings.Repeat("- ", 400) + "x",
		"indented list nest": "# t\n" + indented.String(),
		"oversized":          "# t\n" + strings.Repeat("a", maxMarkdownBytes),
	}
	st := newStyles()
	for name, body := range cases {
		start := time.Now()
		out := renderBody([]byte(body), "text/plain", "http://h/", st, true, true, 0)
		if took := time.Since(start); took > time.Second {
			t.Errorf("%s: render took %v", name, took)
		}
		if out != body {
			t.Errorf("%s: want the raw body back, got %d bytes from %d", name, len(out), len(body))
		}
	}

	// Ordinary nesting still goes through glamour.
	body := "# Title\n\n- a\n    - b\n        - c\n\n> > quoted\n"
	if out := renderBody([]byte(body), "text/markdown", "", st, true, true, 0); out == body {
		t.Error("modestly nested markdown was not rendered")
	}
}

func TestMarkdownTooDeep(t *testing.T) {
	indented := func(levels int) string {
		var b strings.Builder
		for i := 0; i < levels; i++ {
			b.WriteString(strings.Repeat("  ", i) + "- x\n")
		}
		return b.String()
	}
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"prose", "# Title\n\nSome text > here.\n", false},
		{"modest blockquotes", "> > > quoted\n", false},
		{"4-space list indent", "- a\n    - b\n        - c\n            - d\n", false},
		{"thematic breaks", "***\n---\n", false},
		{"deep code, no markers", "```\n" + strings.Repeat(" ", 80) + "x\n```\n", false},
		{"blockquotes at limit", strings.Repeat(">", maxMarkdownNesting) + " x", false},
		{"blockquotes past limit", strings.Repeat(">", maxMarkdownNesting+1) + " x", true},
		{"list indent at limit", indented(maxMarkdownNesting), false},
		{"list indent past limit", indented(maxMarkdownNesting + 1), true},
		{"bullet markers", strings.Repeat("* ", maxMarkdownNesting+1) + "x", true},
		{"ordered markers", strings.Repeat("1. ", maxMarkdownNesting+1) + "x", true},
		{"tab indent", ">" + strings.Repeat("\t", 8) + "- x", true},
	}
	for _, c := range cases {
		if got := markdownTooDeep([]byte(c.body), maxMarkdownNesting); got != c.want {
			t.Errorf("%s: markdownTooDeep = %v, want %v", c.name, got, c.want)
		}
	}
}

// Indentation repeats on every line, so a deeply nested body's pretty form
// grows as lines × depth: this 14 KB of JSON once indented to 28 MB and the 21
// KB of XML to 18 MB. Past prettyCap the flat render shows the body raw.
func TestRenderBodyKeepsDeepBodiesRaw(t *testing.T) {
	const depth, sibs = 2000, 5000
	js := strings.Repeat("[", depth) + strings.TrimSuffix(strings.Repeat("1,", sibs), ",") + strings.Repeat("]", depth)
	xb := `<?xml version="1.0"?>` + strings.Repeat("<a>", 3000) + strings.Repeat("</a>", 3000)
	st := newStyles()
	for _, c := range []struct{ ct, body string }{{"application/json", js}, {"application/xml", xb}} {
		if out := renderBody([]byte(c.body), c.ct, "", st, false, true, 0); out != c.body {
			t.Errorf("%s: want the raw body back, got %d bytes from %d", c.ct, len(out), len(c.body))
		}
	}
}

// prettyBody trusts jsonIndentFits to bound json.Indent before running it, so
// the estimate must never come in under what Indent actually writes.
func TestJSONIndentFitsNeverUndercounts(t *testing.T) {
	for _, s := range []string{
		`{"a":[1,{"b":null}],"c":{},"d":[]}`,
		`[[[[1]]],[2,3]]`,
		` { "s" : "a,b:{c}[d]\"e\\" , "t" : [ ] } `,
		`"x"`,
		`[]`,
	} {
		var buf bytes.Buffer
		if err := json.Indent(&buf, []byte(s), "", "  "); err != nil {
			t.Fatalf("bad sample %q: %v", s, err)
		}
		if jsonIndentFits([]byte(s), buf.Len()-1) {
			t.Errorf("jsonIndentFits(%q) undercounts: Indent wrote %d bytes", s, buf.Len())
		}
	}
}
