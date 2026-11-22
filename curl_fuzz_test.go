package main

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// FuzzCurlRoundTrip: whatever a pasted curl command imports as, exporting it
// with toCurl (what --to-curl and ctrl+x print for the user to paste into a
// shell) must parse back to the same request, with nothing outside quotes that
// a shell would interpret. A mismatch means the exported command is not what
// weeb shows — at worst, shell syntax leaking out of quoting. Run it with
//
//	go test -run '^$' -fuzz FuzzCurlRoundTrip -fuzztime 60s
//
// Plain `go test` replays the seeds and testdata/fuzz as regression cases.
func FuzzCurlRoundTrip(f *testing.F) {
	for _, s := range []string{
		`curl https://x`,
		`curl -X POST https://api.example.com/u -H "Content-Type: application/json" -d '{"a":1}'`,
		`curl -u alice:secret -G -d q=1 https://x/search`,
		`curl -X 'GET;id' https://x`,
		`curl -H 'X-A: it'\''s' https://x --data-raw $'a'`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		argv, err := tokenizeShell(cmd)
		if err != nil {
			return
		}
		for _, a := range argv {
			if strings.Contains(a, "@") {
				return // @file / @- would read the disk or block on stdin
			}
		}
		spec, err := parseCurl(argv)
		if err != nil {
			return
		}
		for _, multiline := range []bool{false, true} {
			exported := toCurl(spec, multiline)
			if bad := shellUnquotedUnsafe(exported); bad != "" {
				t.Fatalf("exported curl has %s\nimported: %q\nexported: %s", bad, cmd, exported)
			}
			argv2, err := tokenizeShell(exported)
			if err != nil {
				t.Fatalf("exported curl does not tokenize: %v\nimported: %q\nexported: %s", err, cmd, exported)
			}
			spec2, err := parseCurl(argv2)
			if err != nil {
				t.Fatalf("exported curl does not parse: %v\nimported: %q\nexported: %s", err, cmd, exported)
			}
			if d := specDiff(spec, spec2); d != "" {
				t.Fatalf("round trip changed the request (%s)\nimported: %q\nexported: %s", d, cmd, exported)
			}
		}
	})
}

// shellUnquotedUnsafe scans s the way a POSIX shell (or zsh) would and reports
// the first character outside single quotes that the shell could interpret —
// a command separator, expansion, glob, redirect — rather than pass to curl.
// weeb's own tokenizer doesn't treat these as special, so the round trip alone
// can't catch them. The allowed set is deliberately narrow.
func shellUnquotedUnsafe(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return "an unterminated single quote"
			}
			i += j + 1
		case c == '\\' && i+1 < len(s) && (s[i+1] == '\n' || s[i+1] == '\''):
			i++ // line continuation, or the \' in the '\'' quote dance
		case c == ' ', c == '\n':
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("._-/:@", c) >= 0:
		default:
			return "unquoted shell metacharacter " + strconv.Quote(string(c)) + " at byte " + strconv.Itoa(i)
		}
	}
	return ""
}

func specDiff(a, b RequestSpec) string {
	norm := func(m string) string {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" {
			return "GET"
		}
		return m
	}
	ma, mb := norm(a.Method), norm(b.Method)
	if ma != mb {
		return "method " + ma + " vs " + mb
	}
	if a.URL != b.URL {
		return "url"
	}
	// Surrounding whitespace in a header value is not significant in HTTP.
	keep := func(hs []Header) []Header {
		var out []Header
		for _, h := range hs {
			if strings.TrimSpace(h.Key) != "" {
				out = append(out, Header{Key: h.Key, Value: strings.TrimSpace(h.Value)})
			}
		}
		return out
	}
	if !slices.Equal(keep(a.Headers), keep(b.Headers)) {
		return "headers"
	}
	if methodAllowsBody(ma) && string(a.Body) != string(b.Body) {
		return "body"
	}
	return ""
}
