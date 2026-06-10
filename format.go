package main

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"

	"charm.land/glamour/v2"
	"github.com/charmbracelet/x/ansi"
)

// bodyFormat is a normalized content kind weeb knows how to pretty-print.
type bodyFormat int

const (
	fmtText bodyFormat = iota
	fmtJSON
	fmtXML
	fmtHTML
	fmtMarkdown
	fmtYAML
)

// detectFormat decides how to render a body. It trusts the Content-Type first;
// when that is missing or generic it falls back to the URL's file extension
// (the only reliable signal for, e.g., a GitHub raw .md served as text/plain),
// and finally — when sniff is true — to the bytes themselves.
func detectFormat(contentType, url string, body []byte, sniff bool) bodyFormat {
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "json"): // application/json, application/vnd.x+json
		return fmtJSON
	case strings.Contains(ct, "markdown"): // text/markdown, text/x-markdown
		return fmtMarkdown
	case strings.Contains(ct, "yaml"): // application/yaml, text/yaml, application/x-yaml
		return fmtYAML
	case strings.Contains(ct, "html"):
		return fmtHTML
	case strings.Contains(ct, "xml"): // application/xml, text/xml, image/svg+xml
		return fmtXML
	}

	generic := ct == "" || strings.Contains(ct, "text/plain") || strings.Contains(ct, "octet-stream")
	if !generic {
		return fmtText
	}

	// A generic Content-Type — APIs and raw file hosts (GitHub!) routinely serve
	// markdown/json/etc. as text/plain. The URL extension is the trustworthy hint.
	switch urlExt(url) {
	case "md", "markdown":
		return fmtMarkdown
	case "yaml", "yml":
		return fmtYAML
	case "json":
		return fmtJSON
	case "xml":
		return fmtXML
	case "html", "htm":
		return fmtHTML
	}

	if sniff {
		switch t := bytes.TrimSpace(body); {
		case len(t) > 0 && (t[0] == '{' || t[0] == '['):
			return fmtJSON
		case bytes.HasPrefix(t, []byte("<?xml")):
			return fmtXML
		case len(t) > 0 && t[0] == '<':
			return fmtHTML
		case looksLikeMarkdown(t):
			return fmtMarkdown
		}
	}
	return fmtText
}

// urlExt returns the lowercased file extension of a URL's last path segment
// (without the dot), or "" if there is none.
func urlExt(rawurl string) string {
	if i := strings.IndexAny(rawurl, "?#"); i >= 0 {
		rawurl = rawurl[:i]
	}
	if i := strings.LastIndexByte(rawurl, '/'); i >= 0 {
		rawurl = rawurl[i+1:]
	}
	if i := strings.LastIndexByte(rawurl, '.'); i >= 0 {
		return strings.ToLower(rawurl[i+1:])
	}
	return ""
}

// looksLikeMarkdown is a conservative content sniff for markdown served with a
// generic Content-Type and no .md URL. It requires a clear structural signal (a
// heading, fenced code block, or table) or two weaker ones, so plain text/logs
// don't get reflowed through glamour by accident.
func looksLikeMarkdown(body []byte) bool {
	lines := strings.Split(string(body), "\n")
	if len(lines) > 60 {
		lines = lines[:60]
	}
	weak := 0
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "```"), strings.HasPrefix(t, "~~~"): // fenced code
			return true
		case isATXHeading(t): // # Heading
			return true
		case isTableSep(t): // |---|---|
			return true
		case strings.HasPrefix(t, "- "), strings.HasPrefix(t, "* "), strings.HasPrefix(t, "+ "):
			weak++
		case strings.HasPrefix(t, "> "): // blockquote
			weak++
		case strings.Contains(t, "](") && strings.Contains(t, "["): // [text](link)
			weak++
		}
		if weak >= 2 {
			return true
		}
	}
	return false
}

func isATXHeading(t string) bool {
	n := 0
	for n < len(t) && t[n] == '#' {
		n++
	}
	return n >= 1 && n <= 6 && n < len(t) && t[n] == ' '
}

func isTableSep(t string) bool {
	if !strings.Contains(t, "|") || !strings.Contains(t, "-") {
		return false
	}
	for _, r := range t {
		if !strings.ContainsRune("|-: ", r) {
			return false
		}
	}
	return true
}

// renderBody renders a response body for DISPLAY. pretty is the master switch:
// when false, the body is shown exactly as the server sent it — no reindenting,
// no syntax color (this is the "raw" view). When true, weeb pretty-prints,
// syntax-highlights (if color), and sniffs mislabeled bodies (see detectFormat).
// width is the wrap width for full renders (markdown); <=0 means a sane default.
func renderBody(body []byte, contentType, url string, st styles, color, pretty bool, width int) string {
	if !pretty {
		return string(body)
	}
	switch detectFormat(contentType, url, body, true) {
	case fmtJSON:
		out := prettyBody(body, "application/json")
		if color {
			return colorizeJSON(out, st)
		}
		return out
	case fmtXML:
		out, ok := prettyXML(body)
		if !ok {
			out = string(body)
		}
		if color {
			return colorizeMarkup(out, st)
		}
		return out
	case fmtHTML:
		// Render via the real HTML parser's tree when coloring; otherwise raw.
		if color {
			if root := parseHTMLTree(body, contentType, url, true); root != nil {
				return renderXMLTree(root, st, nil)
			}
		}
		return string(body)
	case fmtMarkdown:
		// Markdown is a full styled render (glamour), which is inherently ANSI;
		// only do it when color is wanted, else fall back to the raw source.
		if !color {
			return string(body)
		}
		if out, err := renderMarkdown(body, width); err == nil {
			return out
		}
		return string(body)
	case fmtYAML:
		// The colorized render comes from the tree (fully expanded here); without
		// color, show the source as-is.
		if !color {
			return string(body)
		}
		if root := parseYAMLTree(body, contentType, url, true); root != nil {
			return renderYAMLTree(root, st, nil)
		}
		return string(body)
	default:
		return string(body)
	}
}

// renderMarkdown renders a markdown body to ANSI-styled terminal text via
// glamour, wrapped to width (clamped to a readable range).
func renderMarkdown(body []byte, width int) (string, error) {
	if width <= 0 || width > 120 {
		width = 100
	}
	r, err := glamour.NewTermRenderer(
		glamour.WithStandardStyle("dark"),
		glamour.WithWordWrap(width),
		glamour.WithEmoji(),
	)
	if err != nil {
		return "", err
	}
	out, err := r.Render(string(body))
	if err != nil {
		return "", err
	}
	return strings.Trim(out, "\n"), nil
}

// lenientXMLDecoder builds the decoder shared by the flat pretty-print and the
// fold tree. The leniency knobs here define which real-world documents weeb
// accepts — keeping them in one place keeps the two render paths agreeing on
// what parses (a tweak applied to only one would make the same response render
// in one mode and fall back to raw in the other).
func lenientXMLDecoder(body []byte) *xml.Decoder {
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity
	return dec
}

// prettyXML reindents XML/HTML using a tokenizer. It is lenient (HTML autoclose
// and entities) so it survives most real-world HTML; it returns ok=false if the
// input can't be tokenized, so the caller can fall back to raw.
func prettyXML(body []byte) (string, bool) {
	dec := lenientXMLDecoder(body)

	var out bytes.Buffer
	enc := xml.NewEncoder(&out)
	enc.Indent("", "  ")

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", false
		}
		// Skip whitespace-only char data so the encoder's own indentation wins.
		if cd, ok := tok.(xml.CharData); ok {
			if len(bytes.TrimSpace(cd)) == 0 {
				continue
			}
		}
		if err := enc.EncodeToken(tok); err != nil {
			return "", false
		}
	}
	if err := enc.Flush(); err != nil {
		return "", false
	}
	if out.Len() == 0 {
		return "", false
	}
	return out.String(), true
}

// colorizeMarkup adds light syntax color to indented XML/HTML: tag delimiters
// dim, tag names cyan, quoted attribute values green, comments faint.
func colorizeMarkup(s string, st styles) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '<' {
			j := strings.IndexByte(s[i:], '<')
			if j < 0 {
				b.WriteString(s[i:])
				break
			}
			b.WriteString(s[i : i+j])
			i += j
			continue
		}
		// A tag (or comment) from '<' to the matching '>'.
		j := strings.IndexByte(s[i:], '>')
		if j < 0 {
			b.WriteString(st.jsonPunct.Render(s[i:]))
			break
		}
		b.WriteString(colorizeTag(s[i:i+j+1], st))
		i += j + 1
	}
	return b.String()
}

func colorizeTag(tag string, st styles) string {
	if strings.HasPrefix(tag, "<!--") {
		return st.jsonNull.Render(tag) // comments: faint grey
	}
	var b strings.Builder
	inner := tag
	// Leading "<" or "</".
	b.WriteString(st.jsonPunct.Render("<"))
	inner = inner[1:]
	if strings.HasPrefix(inner, "/") {
		b.WriteString(st.jsonPunct.Render("/"))
		inner = inner[1:]
	}
	// Trailing ">" (and optional "/").
	closeTok := ">"
	body := strings.TrimSuffix(inner, ">")
	if strings.HasSuffix(body, "/") {
		body = strings.TrimSuffix(body, "/")
		closeTok = "/>"
	}
	// Tag name then attributes.
	name, attrs, _ := strings.Cut(body, " ")
	b.WriteString(st.jsonKey.Render(name))
	if attrs != "" {
		b.WriteString(" " + colorizeAttrs(attrs, st))
	}
	b.WriteString(st.jsonPunct.Render(closeTok))
	return b.String()
}

// colorizeAttrs colors quoted attribute values green, leaving names as-is.
func colorizeAttrs(s string, st styles) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			j := i + 1
			for j < len(s) && s[j] != q {
				j++
			}
			if j < len(s) {
				j++ // include closing quote
			}
			b.WriteString(st.jsonStr.Render(s[i:j]))
			i = j
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// sanitizeTTY neutralizes terminal control sequences in server-influenced
// text before it reaches a TTY. A hostile body could otherwise write the
// clipboard (OSC 52), retitle the window, or move the cursor to spoof output.
// SGR color (CSI…m) and OSC 8 hyperlinks — the only sequences weeb's own
// renderers emit — are kept; everything else (other CSI, other OSC, DCS/APC/
// PM/SOS payloads, two-byte escapes, stray C0 controls, and the 8-bit C1
// forms of all of these) is dropped. Decoding goes through ansi.DecodeSequence
// rather than a byte scanner so multibyte UTF-8 text is never corrupted —
// continuation bytes share the 0x80–0x9F range with C1 controls and only a
// real decoder can tell them apart. Piped output never goes through here:
// pipes get the exact server bytes.
func sanitizeTTY(s string) string {
	var b *strings.Builder // nil until the first drop: clean input is returned as-is
	var state byte
	p := ansi.NewParser()
	for i := 0; i < len(s); {
		seq, width, n, newState := ansi.DecodeSequence(s[i:], state, p)
		if n == 0 { // decoder can't advance; drop the remainder
			if b == nil {
				b = new(strings.Builder)
				b.WriteString(s[:i])
			}
			break
		}
		if keepOnTTY(seq, width) {
			if b != nil {
				b.WriteString(seq)
			}
		} else if b == nil {
			b = new(strings.Builder)
			b.Grow(len(s))
			b.WriteString(s[:i])
		}
		i += n
		state = newState
	}
	if b == nil {
		return s // fast path: nothing dropped (weeb's own SGR-styled output)
	}
	return b.String()
}

// keepOnTTY reports whether one decoded unit may pass through to a terminal:
// a printable grapheme, newline/tab, an SGR sequence, or a terminated OSC 8
// hyperlink (7- or 8-bit form either way).
func keepOnTTY(seq string, width int) bool {
	if width > 0 || seq == "\n" || seq == "\t" {
		return true
	}
	if ansi.HasCsiPrefix(seq) && seq[len(seq)-1] == 'm' {
		return true // SGR — a final 'm' also proves the sequence is complete
	}
	if ansi.HasOscPrefix(seq) {
		body := seq[1:] // 8-bit OSC (0x9d)
		if seq[0] == 0x1b {
			body = seq[2:] // 7-bit ESC ]
		}
		// Unterminated OSCs are dropped even for 8;… — kept, they would make
		// the terminal swallow whatever weeb prints next as payload.
		return strings.HasPrefix(body, "8;") && hasOscTerminator(seq)
	}
	return false
}

func hasOscTerminator(seq string) bool {
	return strings.HasSuffix(seq, "\x07") || // BEL
		strings.HasSuffix(seq, "\x1b\\") || // 7-bit ST
		strings.HasSuffix(seq, "\x9c") // 8-bit ST
}

// sanitizingWriter passes every Write through sanitizeTTY. It is the output
// boundary wrapped around stdout/stderr when they are terminals (see outW/
// errW in main.go), so every print path — current and future — neutralizes
// server-influenced control sequences without each call site remembering to.
// weeb's printers write whole strings/lines per call (fmt.Fprint*), so an
// escape sequence is never sliced across two Writes.
type sanitizingWriter struct{ w io.Writer }

func (sw sanitizingWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(sw.w, sanitizeTTY(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil // report p fully consumed, even when bytes were dropped
}
