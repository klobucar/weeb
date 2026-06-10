package main

import (
	"fmt"
	"image/color"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

// colorizeJSON adds syntax color to a JSON document (already pretty-indented).
// It is a small hand-rolled scanner: it distinguishes object keys from string
// values by peeking for a following ':', and colors numbers, booleans, null,
// and punctuation. Whitespace and structure are passed through untouched so the
// indentation is preserved exactly.
func colorizeJSON(s string, st styles) string {
	var b strings.Builder
	b.Grow(len(s) * 2)

	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"':
			j := i + 1
			for j < len(s) {
				if s[j] == '\\' && j+1 < len(s) {
					j += 2
					continue
				}
				if s[j] == '"' {
					j++
					break
				}
				j++
			}
			lit := s[i:j]
			// A string is a key if the next non-space byte is ':'.
			k := j
			for k < len(s) && isSpaceByte(s[k]) {
				k++
			}
			if k < len(s) && s[k] == ':' {
				b.WriteString(st.jsonKey.Render(lit))
			} else {
				b.WriteString(st.jsonStr.Render(lit))
			}
			i = j

		case c == '-' || (c >= '0' && c <= '9'):
			j := i
			for j < len(s) && isNumberByte(s[j]) {
				j++
			}
			b.WriteString(st.jsonNum.Render(s[i:j]))
			i = j

		case hasWord(s, i, "true"):
			b.WriteString(st.jsonBool.Render("true"))
			i += 4
		case hasWord(s, i, "false"):
			b.WriteString(st.jsonBool.Render("false"))
			i += 5
		case hasWord(s, i, "null"):
			b.WriteString(st.jsonNull.Render("null"))
			i += 4

		case c == '{' || c == '}' || c == '[' || c == ']' || c == ',' || c == ':':
			b.WriteString(st.jsonPunct.Render(string(c)))
			i++

		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

func isSpaceByte(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
func isNumberByte(c byte) bool {
	return (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E'
}

func hasWord(s string, i int, word string) bool {
	return strings.HasPrefix(s[i:], word)
}

type timingSeg struct {
	label string
	d     time.Duration
	col   color.Color
}

// renderTiming shows the per-phase breakdown as a labeled line plus a colored
// proportional bar (DNS / TCP / TLS / server-wait / download).
func renderTiming(t Timing, st styles, width int) string {
	segs := []timingSeg{
		{"dns", t.DNS, cBlue},
		{"tcp", t.TCP, cCyan},
		{"tls", t.TLS, cViolet},
		{"send", t.Send, cPink},
		{"wait", t.Server, cOrange},
		{"recv", t.Transfer, cGreen},
	}

	var parts []string
	for _, s := range segs {
		if s.d <= 0 {
			continue
		}
		parts = append(parts, lipgloss.NewStyle().Foreground(s.col).Render(
			fmt.Sprintf("%s %dms", s.label, s.d.Milliseconds())))
	}
	parts = append(parts, st.meta.Render(fmt.Sprintf("total %dms", t.Total.Milliseconds())))
	if t.Reused {
		parts = append(parts, st.meta.Render("(reused conn)"))
	}
	line := "⏱  " + strings.Join(parts, st.meta.Render(" · "))

	if bar := timingBar(segs, t.Total, width); bar != "" {
		return line + "\n" + bar
	}
	return line
}

func timingBar(segs []timingSeg, total time.Duration, width int) string {
	cells := width
	if cells > 60 {
		cells = 60
	}
	if total <= 0 || cells < 4 {
		return ""
	}
	var b strings.Builder
	used := 0
	for _, s := range segs {
		if s.d <= 0 {
			continue
		}
		n := int(float64(s.d)/float64(total)*float64(cells) + 0.5)
		if n < 1 {
			n = 1
		}
		if used+n > cells {
			n = cells - used
		}
		if n <= 0 {
			break
		}
		b.WriteString(lipgloss.NewStyle().Foreground(s.col).Render(strings.Repeat("█", n)))
		used += n
	}
	if used < cells {
		b.WriteString(lipgloss.NewStyle().Foreground(cFaint).Render(strings.Repeat("░", cells-used)))
	}
	return b.String()
}

// renderConnTLS shows the negotiated TLS for a request on one or two lines.
func renderConnTLS(c *connTLS, st styles) string {
	if c == nil {
		return ""
	}
	parts := []string{
		lipgloss.NewStyle().Bold(true).Foreground(cGreen).Render("🔒 " + c.Version),
		st.headerVal.Render(c.Cipher),
	}
	if c.ALPN != "" {
		parts = append(parts, st.meta.Render("ALPN "+c.ALPN))
	}
	line := strings.Join(parts, st.meta.Render(" · "))
	if c.Leaf != nil {
		line += "\n" + st.meta.Render("   cert ") + c.Leaf.name() +
			"  " + expiryPhrase(c.Leaf.DaysUntilExpiry, true)
	}
	return line
}

// statusBadge renders a colored " 200 OK " badge plus a dim timing/size suffix.
func statusBadge(r Result, st styles) string {
	col := statusColor(r.Status)
	badge := lipgloss.NewStyle().Bold(true).Foreground(cInk).Background(col).Padding(0, 1).
		Render(fmt.Sprintf("%d %s", r.Status, r.StatusText))
	meta := st.meta.Render(fmt.Sprintf("  %s  ·  %d ms  ·  %d bytes", r.Proto, r.Timing.Total.Milliseconds(), r.bodySize()))
	return badge + meta
}
