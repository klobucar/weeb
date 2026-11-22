package main

import (
	"strconv"
	"testing"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"
)

// Fuzz targets for the terminal-output paths that handle attacker-influenced
// response bodies. Run one with
//
//	go test -run '^$' -fuzz '^FuzzSanitizeTTY$' -fuzztime 60s .
//
// Without -fuzz, `go test` replays the seed corpus (and testdata/fuzz) as
// ordinary regression tests.

// FuzzSanitizeTTY checks sanitizeTTY's security contract with an independent
// byte-level scanner (not the ansi decoder sanitizeTTY itself uses): the only
// escapes that may survive are SGR (params of digits, ';' and ':') and
// terminated OSC 8 hyperlinks with a control-free UTF-8 payload, and no other
// C0/C1 control may reach the terminal.
func FuzzSanitizeTTY(f *testing.F) {
	for _, s := range []string{
		"plain text", "\x1b[31mred\x1b[0m", "\x1b]52;c;aGk=\x07", "\x1b[2J\x1b[H",
		"\x1b]8;;https://x\x1b\\link\x1b]8;;\x1b\\", "\x9b2J", "\xc2\x9b2J",
		"\x1bP+q\x1b\\", "a\rb", "\x1b]0;title\x07", "日本語\x1b[1m", "\x1b",
		"\x1b[>4;2m", "\x1b[?4m", "\x9b>4;2m", "\x9b31m", "\xe6\x9b2J",
		"\x1b]8;;https://x\xc2\x9b2J\x07", "\x1b]8;;https://x\x05\x07", "\x9d8;;https://x\x9c",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out := sanitizeTTY(in)
		if bad := ttyUnsafe(out); bad != "" {
			t.Fatalf("sanitizeTTY(%q) = %q: %s", in, out, bad)
		}
		if again := sanitizeTTY(out); again != out {
			t.Fatalf("sanitizeTTY not idempotent: %q -> %q -> %q", in, out, again)
		}
	})
}

// ttyUnsafe returns a description of the first thing in s a terminal would
// act on beyond printing text, SGR color, and OSC 8 links; "" if none. The
// 8-bit introducers (raw 0x9b CSI, 0x9d OSC) follow the same rules as their
// 7-bit forms, since sanitizeTTY keeps both.
func ttyUnsafe(s string) string {
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == 0x1b:
			n, ok := safeEscapeLen(s[i+1:])
			if !ok {
				return "unsafe ESC sequence at byte " + strconv.Itoa(i)
			}
			i += 1 + n
			continue
		case c < 0x20 && c != '\n' && c != '\t', c == 0x7f:
			return "C0 control at byte " + strconv.Itoa(i)
		case c >= 0x80:
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size == 1 {
				// A lone byte: 0x9b/0x9d may open an 8-bit SGR/OSC 8; any other
				// is a C1 control (0x80–0x9F) or invalid UTF-8 that sanitizeTTY
				// should have turned into U+FFFD.
				var n int
				ok := false
				switch c {
				case 0x9b:
					n, ok = sgrLen(s[i+1:])
				case 0x9d:
					n, ok = osc8Len(s[i+1:])
				}
				if !ok {
					if c <= 0x9f {
						return "raw C1 byte at " + strconv.Itoa(i)
					}
					return "invalid UTF-8 at byte " + strconv.Itoa(i)
				}
				i += 1 + n
				continue
			} else if r >= 0x80 && r <= 0x9f {
				return "UTF-8 encoded C1 control at byte " + strconv.Itoa(i)
			}
			i += size
			continue
		}
		i++
	}
	return ""
}

// safeEscapeLen validates the bytes after an ESC: either an SGR "[params m" or
// an OSC 8 "]8;…" with a clean payload, terminated by BEL or ST. It returns
// how many bytes it spans.
func safeEscapeLen(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	var n int
	var ok bool
	switch s[0] {
	case '[':
		n, ok = sgrLen(s[1:])
	case ']':
		n, ok = osc8Len(s[1:])
	}
	return 1 + n, ok
}

// sgrLen validates the bytes after a CSI introducer: SGR parameters (digits,
// ';', ':') and a final 'm'.
func sgrLen(s string) (int, bool) {
	for j := 0; j < len(s); j++ {
		switch c := s[j]; {
		case c >= '0' && c <= '9', c == ';', c == ':':
			continue
		case c == 'm':
			return j + 1, true
		default:
			return 0, false
		}
	}
	return 0, false
}

// osc8Len validates the bytes after an OSC introducer: "8;" and a payload of
// valid UTF-8 free of C0, DEL and C1 controls, ended by BEL, ESC \ or a raw
// 0x9c ST.
func osc8Len(s string) (int, bool) {
	if len(s) < 2 || s[:2] != "8;" {
		return 0, false
	}
	for j := 2; j < len(s); {
		r, size := utf8.DecodeRuneInString(s[j:])
		switch {
		case s[j] == 0x07, s[j] == 0x9c && size == 1:
			return j + 1, true
		case s[j] == 0x1b:
			if j+1 < len(s) && s[j+1] == '\\' {
				return j + 2, true
			}
			return 0, false
		case r == utf8.RuneError && size == 1, r < 0x20, r >= 0x7f && r <= 0x9f:
			return 0, false
		}
		j += size
	}
	return 0, false
}

// FuzzColorizeJSON: syntax coloring must only add SGR around tokens — never
// drop, duplicate, or reorder the text itself — and must not panic.
func FuzzColorizeJSON(f *testing.F) {
	for _, s := range []string{`{"a":1}`, `["x", true, null, -1.5e3]`, `"\\`, `{"k":"v\"}`, `{`, ``} {
		f.Add(s)
	}
	st := newStyles()
	f.Fuzz(func(t *testing.T, in string) {
		for i := 0; i < len(in); i++ {
			if c := in[i]; (c < 0x20 && c != '\n' && c != '\t') || c >= 0x7f {
				return // keep to the printable ASCII JSON alphabet; controls are sanitizeTTY's job
			}
		}
		if got := ansi.Strip(colorizeJSON(in, st)); got != in {
			t.Fatalf("colorizeJSON changed the text:\n in: %q\nout: %q", in, got)
		}
	})
}
