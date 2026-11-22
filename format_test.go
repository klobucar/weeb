package main

import (
	"strings"
	"testing"
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
		{"SGR colon and 256/truecolor params kept", "\x1b[38:2::1:2:3m\x1b[38;5;208mx\x1b[m", "\x1b[38:2::1:2:3m\x1b[38;5;208mx\x1b[m"},
		{"8-bit SGR kept", "\x9b31mred\x9b0m", "\x9b31mred\x9b0m"},
		{"XTMODKEYS (CSI > m) dropped", "A\x1b[>4;2mB", "AB"},
		{"XTQMODKEYS query (CSI ? m) dropped", "A\x1b[?4mB", "AB"},
		{"8-bit private CSI m dropped", "A\x9b>4;2mB", "AB"},
		{"CSI m with intermediate dropped", "A\x1b[1 mB", "AB"},
		{"truncated UTF-8 swallowing 8-bit CSI replaced", "\xe6\x9b2J", "�2J"},
		{"truncated UTF-8 at end replaced", "ok\xe6\x97", "ok�"},
		{"truncated UTF-8 swallowing trailing ESC neutralized", "ok\xe8\x1b", "ok�"},
		{"truncated UTF-8 before CSI", "\xe8\x1b[2Jspoof", "�spoof"},
		{"SGR with >32 params kept without panic", "\x1b[" + strings.Repeat("1;", 40) + "0mX", "\x1b[" + strings.Repeat("1;", 40) + "0mX"},
		{"unterminated CSI with >32 params dropped without panic", "X\x9b" + strings.Repeat(":", 40) + "0", "X"},
		{"OSC 8 with id and UTF-8 URI kept", "\x1b]8;id=1;https://例え.jp/ü\x1b\\link\x1b]8;;\x1b\\", "\x1b]8;id=1;https://例え.jp/ü\x1b\\link\x1b]8;;\x1b\\"},
		{"OSC 8 with UTF-8 C1 CSI dropped", "\x1b]8;;https://x\xc2\x9b2J\x07link", "link"},
		{"OSC 8 with UTF-8 C1 OSC dropped", "\x1b]8;;https://x\xc2\x9d0;t\x07link", "link"},
		{"OSC 8 with raw 8-bit CSI dropped", "\x1b]8;;https://x\x9b2J\x07link", "link"},
		{"OSC 8 with ENQ dropped", "\x1b]8;;https://x\x05\x07link", "link"},
		{"OSC 8 with CR/BS dropped", "\x1b]8;;https://x\r\b\x1b\\link", "link"},
		{"OSC 8 with invalid UTF-8 dropped", "\x1b]8;;https://x\xff\x07link", "link"},
	}
	for _, c := range cases {
		if got := sanitizeTTY(c.in); got != c.want {
			t.Errorf("%s: sanitizeTTY(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// TestSanitizeTTYKeepsOwnStyling: weeb's own colored renders — lipgloss SGR
// and glamour's OSC 8 links — must survive the TTY boundary byte for byte.
func TestSanitizeTTYKeepsOwnStyling(t *testing.T) {
	st := newStyles()
	for name, out := range map[string]string{
		"json":     renderBody([]byte(`{"a":[1,true,null,"s"]}`), "application/json", "", st, true, true, 0),
		"xml":      renderBody([]byte(`<a x="1"><!-- c --><b>t</b></a>`), "application/xml", "", st, true, true, 0),
		"markdown": renderBody([]byte("# T\n\nsee [docs](https://example.com/p?q=1) and **bold**\n"), "text/markdown", "", st, true, true, 80),
	} {
		if !strings.Contains(out, "\x1b[") {
			t.Errorf("%s: expected colored output, got %q", name, out)
		}
		if name == "markdown" && !strings.Contains(out, "\x1b]8;") {
			t.Errorf("markdown: expected an OSC 8 link, got %q", out)
		}
		if got := sanitizeTTY(out); got != out {
			t.Errorf("%s: sanitizeTTY changed weeb's own output:\n in: %q\nout: %q", name, out, got)
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
