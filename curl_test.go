package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestTokenizeShell(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`curl https://x -H "Accept: application/json"`, []string{"curl", "https://x", "-H", "Accept: application/json"}},
		{`curl 'https://x?a=1&b=2' -d '{"k":"v"}'`, []string{"curl", "https://x?a=1&b=2", "-d", `{"k":"v"}`}},
		{"curl https://x \\\n  -H 'A: 1'", []string{"curl", "https://x", "-H", "A: 1"}},
		{`a "" b`, []string{"a", "", "b"}}, // empty quoted token survives
		{`x -d "he said \"hi\""`, []string{"x", "-d", `he said "hi"`}},
	}
	for _, c := range cases {
		got, err := tokenizeShell(c.in)
		if err != nil {
			t.Fatalf("tokenize(%q): %v", c.in, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("tokenize(%q)\n got %#v\nwant %#v", c.in, got, c.want)
		}
	}

	if _, err := tokenizeShell(`curl 'unterminated`); err == nil {
		t.Error("expected error on unterminated quote")
	}
}

func TestParseCurlBasics(t *testing.T) {
	argv, _ := tokenizeShell(`curl -X POST https://api.example.com/u -H "Content-Type: application/json" -d '{"a":1}'`)
	spec, err := parseCurl(argv)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Method != "POST" {
		t.Errorf("method = %q, want POST", spec.Method)
	}
	if spec.URL != "https://api.example.com/u" {
		t.Errorf("url = %q", spec.URL)
	}
	if string(spec.Body) != `{"a":1}` {
		t.Errorf("body = %q", spec.Body)
	}
	if len(spec.Headers) != 1 || spec.Headers[0].Key != "Content-Type" {
		t.Errorf("headers = %+v", spec.Headers)
	}
}

func TestParseCurlInference(t *testing.T) {
	// Data without -X implies POST.
	s, _ := parseCurl([]string{"curl", "https://x", "-d", "a=1"})
	if s.Method != "POST" {
		t.Errorf("data should imply POST, got %q", s.Method)
	}
	// -I implies HEAD.
	s, _ = parseCurl([]string{"curl", "-I", "https://x"})
	if s.Method != "HEAD" {
		t.Errorf("-I should imply HEAD, got %q", s.Method)
	}
	// Bare URL defaults to GET.
	s, _ = parseCurl([]string{"https://x"})
	if s.Method != "GET" {
		t.Errorf("bare url should be GET, got %q", s.Method)
	}
}

func TestParseCurlAuthAndIgnoredFlags(t *testing.T) {
	argv, _ := tokenizeShell(`curl -sSL -k --compressed -u alice:secret -XPOST https://x -o out.txt`)
	spec, err := parseCurl(argv)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Method != "POST" { // -XPOST attached form
		t.Errorf("method = %q, want POST", spec.Method)
	}
	if spec.URL != "https://x" { // -o value consumed, not treated as URL
		t.Errorf("url = %q, want https://x", spec.URL)
	}
	// alice:secret -> base64
	want := "Basic YWxpY2U6c2VjcmV0"
	if len(spec.Headers) != 1 || spec.Headers[0].Value != want {
		t.Errorf("auth header = %+v, want %q", spec.Headers, want)
	}
}

// An unrecognized flag must error rather than be skipped: skipping an unknown
// value-taking flag used to leave its value to be mistaken for the URL
// (`--max-redirs 5 https://x` requested http://5 and dropped the real URL).
func TestParseCurlUnknownFlag(t *testing.T) {
	// Known value-taking flag: value consumed, URL survives.
	s, err := parseCurl([]string{"curl", "--max-redirs", "5", "https://x"})
	if err != nil || s.URL != "https://x" {
		t.Errorf("--max-redirs: url = %q, err = %v, want https://x", s.URL, err)
	}
	// Unknown flags error instead of eating the URL.
	for _, argv := range [][]string{
		{"curl", "--doesnotexist", "https://x"},
		{"curl", "-sSLZ", "https://x"}, // cluster with an unknown letter
	} {
		if _, err := parseCurl(argv); err == nil {
			t.Errorf("parseCurl(%v) should error on the unknown flag", argv)
		}
	}
	// Clustered known bools still work, including method-setting -I.
	s, err = parseCurl([]string{"curl", "-sIk", "https://x"})
	if err != nil || s.Method != "HEAD" || s.URL != "https://x" {
		t.Errorf("-sIk: method = %q, url = %q, err = %v; want HEAD https://x", s.Method, s.URL, err)
	}
}

// -G must send -d data as the URL query, like curl: it used to leave the data
// in the body, which buildRequest then dropped for GET — the parameters
// vanished from the request entirely.
func TestParseCurlGetWithData(t *testing.T) {
	s, err := parseCurl([]string{"curl", "-G", "-d", "limit=10", "-d", "q=foo", "https://x/search"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Method != "GET" || s.URL != "https://x/search?limit=10&q=foo" || len(s.Body) != 0 {
		t.Errorf("got method=%q url=%q body=%q; want GET https://x/search?limit=10&q=foo with no body",
			s.Method, s.URL, s.Body)
	}

	// An existing query string is extended, not duplicated.
	s, _ = parseCurl([]string{"curl", "-G", "-d", "b=2", "https://x?a=1"})
	if s.URL != "https://x?a=1&b=2" {
		t.Errorf("url = %q, want https://x?a=1&b=2", s.URL)
	}

	// -G with -I keeps HEAD but still moves the data into the query.
	s, _ = parseCurl([]string{"curl", "-G", "-I", "-d", "a=1", "https://x"})
	if s.Method != "HEAD" || s.URL != "https://x?a=1" {
		t.Errorf("got method=%q url=%q, want HEAD https://x?a=1", s.Method, s.URL)
	}
}

func TestParseCurlMultipleData(t *testing.T) {
	s, _ := parseCurl([]string{"curl", "https://x", "-d", "a=1", "-d", "b=2"})
	if string(s.Body) != "a=1&b=2" {
		t.Errorf("joined body = %q, want a=1&b=2", s.Body)
	}
}

// curl's empty-value header syntax: "X-Empty;" sends the header with an empty
// value, and "X-Name:" means don't send the header at all. The importer used
// to drop "X-Empty;" silently (no colon to Cut on) and send "X-Name:" with an
// empty value.
func TestParseCurlEmptyValueHeaders(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []Header
	}{
		{"trailing ; sends an empty value", "X-Empty;", []Header{{Key: "X-Empty", Value: ""}}},
		{"trailing : drops the header", "X-Gone:", nil},
		{"trailing : with only spaces drops the header", "X-Gone:   ", nil},
		{"normal header unchanged", "X-Keep: v", []Header{{Key: "X-Keep", Value: "v"}}},
	}
	for _, c := range cases {
		s, err := parseCurl([]string{"curl", "-H", c.in, "https://x"})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !reflect.DeepEqual(s.Headers, c.want) {
			t.Errorf("%s: headers = %+v, want %+v", c.name, s.Headers, c.want)
		}
	}
}

// curl strips CR and LF from -d/--data/--data-ascii @file content; only
// --data-binary keeps the bytes as-is. The importer used to keep newlines
// for all of them.
func TestParseCurlDataFileNewlines(t *testing.T) {
	f := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(f, []byte("a=1\r\nb=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ flag, want string }{
		{"-d", "a=1b=2"},
		{"--data", "a=1b=2"},
		{"--data-ascii", "a=1b=2"},
		{"--data-binary", "a=1\r\nb=2\n"},
	}
	for _, c := range cases {
		s, err := parseCurl([]string{"curl", "https://x", c.flag, "@" + f})
		if err != nil {
			t.Fatalf("%s: %v", c.flag, err)
		}
		if string(s.Body) != c.want {
			t.Errorf("%s: body = %q, want %q", c.flag, s.Body, c.want)
		}
	}
}

// -F/--form gets a dedicated error pointing at --data instead of the generic
// "unsupported flag", and errors immediately so its value can't be mistaken
// for the URL.
func TestParseCurlFormUnsupported(t *testing.T) {
	for _, argv := range [][]string{
		{"curl", "-F", "a=b", "https://x"},
		{"curl", "--form", "a=b", "https://x"},
		{"curl", "--form-string", "a=b", "https://x"},
	} {
		_, err := parseCurl(argv)
		if err == nil || !strings.Contains(err.Error(), "multipart") || !strings.Contains(err.Error(), "--data") {
			t.Errorf("parseCurl(%v) err = %v, want the multipart/--data hint", argv, err)
		}
	}
}

// --data-urlencode must encode the content part like curl does — passing it
// through raw changes what the server parses (an & in the value becomes a
// field separator) with no signal the import was unfaithful.
func TestParseCurlDataURLEncode(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"name=content encodes content", "q=a&b=c d", "q=a%26b%3Dc%20d"},
		{"name passes through", "q=hello world", "q=hello%20world"},
		{"=content strips the leading =", "=a b", "a%20b"},
		{"bare content encodes all of it", "a b&c d", "a%20b%26c%20d"},
		{"unreserved chars untouched", "k=a-b.c_d~e", "k=a-b.c_d~e"},
	}
	for _, c := range cases {
		s, err := parseCurl([]string{"curl", "https://x", "--data-urlencode", c.in})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if string(s.Body) != c.want {
			t.Errorf("%s: body = %q, want %q", c.name, s.Body, c.want)
		}
		if s.Method != "POST" {
			t.Errorf("%s: method = %q, want POST", c.name, s.Method)
		}
	}

	t.Run("name@file encodes file contents", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "payload.txt")
		if err := os.WriteFile(f, []byte("hello world&more"), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := parseCurl([]string{"curl", "https://x", "--data-urlencode", "n@" + f})
		if err != nil {
			t.Fatal(err)
		}
		if want := "n=hello%20world%26more"; string(s.Body) != want {
			t.Errorf("body = %q, want %q", s.Body, want)
		}
	})

	t.Run("missing @file errors", func(t *testing.T) {
		if _, err := parseCurl([]string{"curl", "https://x", "--data-urlencode", "n@/no/such/file"}); err == nil {
			t.Error("missing file should error")
		}
	})

	t.Run("mixes with -d and -G", func(t *testing.T) {
		s, err := parseCurl([]string{"curl", "-G", "https://x", "-d", "a=1", "--data-urlencode", "q=b c"})
		if err != nil {
			t.Fatal(err)
		}
		if s.URL != "https://x?a=1&q=b%20c" {
			t.Errorf("url = %q, want https://x?a=1&q=b%%20c", s.URL)
		}
	})
}

// -d @- is curl's "read the body from stdin", not a file named "-"; treating
// it as a file made every imported `curl -d @-` command error.
func TestParseCurlDataFromStdin(t *testing.T) {
	t.Run("-d @- reads stdin", func(t *testing.T) {
		pipeStdin(t, "piped body")
		s, err := parseCurl([]string{"curl", "https://x", "-d", "@-"})
		if err != nil {
			t.Fatal(err)
		}
		if string(s.Body) != "piped body" {
			t.Errorf("body = %q, want %q", s.Body, "piped body")
		}
		if s.Method != "POST" {
			t.Errorf("method = %q, want POST", s.Method)
		}
	})

	t.Run("--data-urlencode @- encodes stdin", func(t *testing.T) {
		pipeStdin(t, "a b&c")
		s, err := parseCurl([]string{"curl", "https://x", "--data-urlencode", "n@-"})
		if err != nil {
			t.Fatal(err)
		}
		if want := "n=a%20b%26c"; string(s.Body) != want {
			t.Errorf("body = %q, want %q", s.Body, want)
		}
	})
}

func TestToCurlAndRoundTrip(t *testing.T) {
	spec := RequestSpec{
		Method: "POST",
		URL:    "https://api.example.com/users?q=1&r=2",
		Headers: []Header{
			{Key: "Content-Type", Value: "application/json"},
			{Key: "Authorization", Value: "Bearer abc"},
		},
		Body: []byte(`{"name":"weeb"}`),
	}

	oneLine := toCurl(spec, false)
	if strings.Contains(oneLine, "\n") {
		t.Error("single-line form should have no newlines")
	}
	if !strings.Contains(oneLine, "-X POST") || !strings.Contains(oneLine, "--data") {
		t.Errorf("export missing pieces: %s", oneLine)
	}
	// The query string must be quoted so & doesn't background the shell.
	if !strings.Contains(oneLine, "'https://api.example.com/users?q=1&r=2'") {
		t.Errorf("url not quoted: %s", oneLine)
	}

	// Round-trip: export -> tokenize -> import yields the same request.
	argv, err := tokenizeShell(toCurl(spec, true)) // multiline must tokenize too
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseCurl(argv)
	if err != nil {
		t.Fatal(err)
	}
	if got.Method != spec.Method || got.URL != spec.URL || string(got.Body) != string(spec.Body) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, spec)
	}
	if !reflect.DeepEqual(got.Headers, spec.Headers) {
		t.Errorf("round-trip headers:\n got %+v\nwant %+v", got.Headers, spec.Headers)
	}
}
