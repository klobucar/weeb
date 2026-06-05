package main

import (
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

func TestParseCurlMultipleData(t *testing.T) {
	s, _ := parseCurl([]string{"curl", "https://x", "-d", "a=1", "-d", "b=2"})
	if string(s.Body) != "a=1&b=2" {
		t.Errorf("joined body = %q, want a=1&b=2", s.Body)
	}
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
