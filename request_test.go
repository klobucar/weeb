package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	log "charm.land/log/v2"
)

func testClient() *Client {
	return newClient(log.New(io.Discard), plainErrorChan{})
}

func TestClientDoSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	res := testClient().Do(RequestSpec{Method: "GET", URL: srv.URL})

	if res.Status != 200 {
		t.Fatalf("status = %d, want 200", res.Status)
	}
	if !res.OK() {
		t.Errorf("OK() = false, want true (err=%v)", res.Err)
	}
	if string(res.Body) != `{"ok":true}` {
		t.Errorf("body = %q", res.Body)
	}
	if res.ContentType != "application/json" {
		t.Errorf("content-type = %q", res.ContentType)
	}
	if res.DisplayErr != "" {
		t.Errorf("DisplayErr should be empty on success, got %q", res.DisplayErr)
	}
}

// Credentials — including env-injected custom headers Go's default policy
// never strips — must not follow a redirect to another origin.
func TestRedirectStripsCredentialsCrossOrigin(t *testing.T) {
	t.Setenv("WEEB_BASE_URL", "")
	t.Setenv("WEEB_HEADERS", "X-Api-Key:sekrit")
	t.Setenv("WEEB_TOKEN", "tok")

	var gotAuth, gotKey, gotAccept string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotKey = r.Header.Get("X-Api-Key")
		gotAccept = r.Header.Get("Accept")
	}))
	defer target.Close()
	// A second loopback server has a different port: a different origin.
	hopper := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer hopper.Close()

	res := testClient().Do(RequestSpec{
		Method:  "GET",
		URL:     hopper.URL,
		Headers: []Header{{Key: "Accept", Value: "application/json"}},
	})
	if !res.OK() {
		t.Fatalf("request failed: %v", res.Err)
	}
	if gotAuth != "" || gotKey != "" {
		t.Errorf("credentials followed a cross-origin redirect: Authorization=%q X-Api-Key=%q", gotAuth, gotKey)
	}
	// Non-credential headers still follow the redirect.
	if gotAccept != "application/json" {
		t.Errorf("Accept should survive the redirect, got %q", gotAccept)
	}
}

func TestRedirectKeepsCredentialsSameOrigin(t *testing.T) {
	t.Setenv("WEEB_BASE_URL", "")
	t.Setenv("WEEB_HEADERS", "")
	t.Setenv("WEEB_TOKEN", "tok")

	var gotAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := testClient().Do(RequestSpec{Method: "GET", URL: srv.URL + "/start"})
	if !res.OK() {
		t.Fatalf("request failed: %v", res.Err)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("same-origin redirect should keep Authorization, got %q", gotAuth)
	}
}

// keepsCredentials compares effective ports regardless of scheme: a redirect
// that changes both scheme AND port (http://h:8080 → https://h:8443) is a
// different service on the host and must strip credentials, while the plain
// default-port http→https upgrade stays credentialed.
func TestKeepsCredentials(t *testing.T) {
	cases := []struct {
		name string
		orig string
		next string
		want bool
	}{
		{"same origin", "https://api.example.com/a", "https://api.example.com/b", true},
		{"same origin explicit default port", "https://api.example.com", "https://api.example.com:443", true},
		{"apex to www stripped", "https://example.com", "https://www.example.com", false},
		{"https to http downgrade stripped", "https://example.com", "http://example.com", false},
		{"http to https default upgrade kept", "http://example.com", "https://example.com", true},
		{"http to https same explicit port kept", "http://example.com:8443", "https://example.com:8443", true},
		{"same scheme different port stripped", "http://example.com:8080", "http://example.com:9090", false},
		{"cross-scheme port change stripped", "http://example.com:8080", "https://example.com:8443", false},
		{"cross-scheme to default https port stripped", "http://example.com:8080", "https://example.com", false},
		{"host case-insensitive", "https://API.example.com", "https://api.example.com", true},
	}
	for _, c := range cases {
		orig, err := url.Parse(c.orig)
		if err != nil {
			t.Fatalf("%s: parse %q: %v", c.name, c.orig, err)
		}
		next, err := url.Parse(c.next)
		if err != nil {
			t.Fatalf("%s: parse %q: %v", c.name, c.next, err)
		}
		if got := keepsCredentials(orig, next); got != c.want {
			t.Errorf("%s: keepsCredentials(%q, %q) = %v, want %v", c.name, c.orig, c.next, got, c.want)
		}
	}
}

func TestClientDoStatusErrorSetsBothSeams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	res := testClient().Do(RequestSpec{Method: "GET", URL: srv.URL})

	if res.Status != 404 {
		t.Fatalf("status = %d, want 404", res.Status)
	}
	if res.OK() {
		t.Error("OK() = true, want false for 4xx")
	}
	if res.Err == nil {
		t.Error("Err should be set on a 4xx (the record seam)")
	}
	if res.DisplayErr == "" {
		t.Error("DisplayErr should be set on a 4xx (the voice seam)")
	}
	if string(res.Body) != "nope" {
		t.Errorf("body should still be captured on 4xx, got %q", res.Body)
	}
}

func TestClientDoSendsMethodHeadersBody(t *testing.T) {
	var gotMethod, gotHeader string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotHeader = r.Header.Get("X-Test")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	testClient().Do(RequestSpec{
		Method:  "POST",
		URL:     srv.URL,
		Headers: []Header{{Key: "X-Test", Value: "hi"}},
		Body:    []byte("payload"),
	})

	if gotMethod != "POST" {
		t.Errorf("server saw method %q, want POST", gotMethod)
	}
	if gotHeader != "hi" {
		t.Errorf("server saw X-Test %q, want hi", gotHeader)
	}
	if string(gotBody) != "payload" {
		t.Errorf("server saw body %q, want payload", gotBody)
	}
}

// An over-limit body must not be buffered unboundedly: the read is capped,
// the kept prefix is surfaced, and the truncation is reported as an error.
func TestClientDoCapsBodySize(t *testing.T) {
	old := maxBodyBytes
	maxBodyBytes = 1024
	t.Cleanup(func() { maxBodyBytes = old })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("a"), 4096))
	}))
	defer srv.Close()

	res := testClient().Do(RequestSpec{Method: "GET", URL: srv.URL})

	if int64(len(res.Body)) != maxBodyBytes {
		t.Errorf("body length = %d, want capped at %d", len(res.Body), maxBodyBytes)
	}
	if res.Err == nil || res.DisplayErr == "" {
		t.Error("an over-limit body should surface a read error on both seams")
	}
	// The truncation notice is the only signal the body was cut, so it must
	// name the real cap — a sub-MiB cap used to be floored to "0 MiB".
	if res.Err != nil {
		if strings.Contains(res.Err.Error(), "0 MiB") {
			t.Errorf("over-cap message floors the cap to zero: %q", res.Err)
		}
		if !strings.Contains(res.Err.Error(), "1.0 KB") {
			t.Errorf("over-cap message should name the 1.0 KB cap, got %q", res.Err)
		}
	}

	// An exactly-at-limit body passes untouched.
	exact := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("a"), 1024))
	}))
	defer exact.Close()
	if res := testClient().Do(RequestSpec{Method: "GET", URL: exact.URL}); !res.OK() || len(res.Body) != 1024 {
		t.Errorf("at-limit body should succeed: err=%v len=%d", res.Err, len(res.Body))
	}
}

// A BodySink streams the body uncapped — maxBodyBytes protects only buffered
// bodies weeb has to hold in memory to render.
func TestClientDoStreamsToSinkUncapped(t *testing.T) {
	old := maxBodyBytes
	maxBodyBytes = 1024
	t.Cleanup(func() { maxBodyBytes = old })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("a"), 4096))
	}))
	defer srv.Close()

	var sink bytes.Buffer
	res := testClient().Do(RequestSpec{Method: "GET", URL: srv.URL, BodySink: &sink})

	if !res.OK() {
		t.Fatalf("streamed request failed: %v", res.Err)
	}
	if sink.Len() != 4096 {
		t.Errorf("sink got %d bytes, want all 4096 (cap must not apply)", sink.Len())
	}
	if len(res.Body) != 0 {
		t.Errorf("streamed body should not also be buffered, got %d bytes", len(res.Body))
	}
	if res.BodySize != 4096 {
		t.Errorf("BodySize = %d, want 4096", res.BodySize)
	}
}

func TestParseSize(t *testing.T) {
	good := map[string]int64{
		"1048576": 1 << 20,
		"64m":     64 << 20,
		"1G":      1 << 30,
		"512KiB":  512 << 10,
		"2kb":     2 << 10,
		"100b":    100,
		"0":       0,
	}
	for in, want := range good {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = (%d, %v), want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "abc", "-1", "12q", "9999999999g"} {
		if _, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) should error", in)
		}
	}
}

func TestApplyMaxBody(t *testing.T) {
	old := maxBodyBytes
	t.Cleanup(func() { maxBodyBytes = old })

	// Default stands when neither flag nor env is set.
	t.Setenv("WEEB_MAX_BODY", "")
	maxBodyBytes = old
	if err := applyMaxBody(""); err != nil || maxBodyBytes != old {
		t.Errorf("no overrides: cap = %d, err = %v; want default %d", maxBodyBytes, err, old)
	}

	// Env applies; flag wins over env.
	t.Setenv("WEEB_MAX_BODY", "1m")
	if err := applyMaxBody(""); err != nil || maxBodyBytes != 1<<20 {
		t.Errorf("env: cap = %d, err = %v; want 1MiB", maxBodyBytes, err)
	}
	if err := applyMaxBody("2m"); err != nil || maxBodyBytes != 2<<20 {
		t.Errorf("flag should beat env: cap = %d, err = %v; want 2MiB", maxBodyBytes, err)
	}

	// 0 disables the cap.
	if err := applyMaxBody("0"); err != nil || maxBodyBytes != 1<<62 {
		t.Errorf("0: cap = %d, err = %v; want uncapped", maxBodyBytes, err)
	}

	if err := applyMaxBody("nope"); err == nil {
		t.Error("bad size should error")
	}
}

// -o streams the body to a file, uncapped, with a zero exit.
func TestRunCLIOutputFile(t *testing.T) {
	t.Setenv("WEEB_BASE_URL", "")
	t.Setenv("WEEB_HEADERS", "")
	t.Setenv("WEEB_TOKEN", "")
	t.Setenv("WEEB_MAX_BODY", "")

	payload := bytes.Repeat([]byte("weeb"), 1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "body.bin")
	if code := runCLI(cliArgs{method: "GET", url: srv.URL, output: out}); code != 0 {
		t.Fatalf("runCLI exit = %d, want 0", code)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("output file has %d bytes, want %d", len(got), len(payload))
	}
}

func TestClientDoTransportError(t *testing.T) {
	// 127.0.0.1:1 refuses fast — no network round-trip, no hang.
	res := testClient().Do(RequestSpec{Method: "GET", URL: "http://127.0.0.1:1"})

	if res.Status != 0 {
		t.Errorf("status = %d, want 0 (no response)", res.Status)
	}
	if res.Err == nil {
		t.Error("Err should be set on a transport failure")
	}
	if res.DisplayErr == "" {
		t.Error("DisplayErr should be set on a transport failure")
	}
}

func TestClientDoBadRequest(t *testing.T) {
	res := testClient().Do(RequestSpec{Method: "GET", URL: ""})
	if res.Err == nil || res.DisplayErr == "" {
		t.Error("empty URL should produce a bad-request error on both seams")
	}
}

func TestBuildRequestBodyOnlyForBodyMethods(t *testing.T) {
	// GET ignores a body; POST keeps it.
	get, err := buildRequest(RequestSpec{Method: "GET", URL: "http://x", Body: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if get.Body != nil {
		t.Error("GET should not carry a body")
	}

	post, err := buildRequest(RequestSpec{Method: "POST", URL: "http://x", Body: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if post.Body == nil {
		t.Error("POST should carry a body")
	}

	if _, err := buildRequest(RequestSpec{Method: "GET", URL: ""}); err == nil {
		t.Error("empty URL should error")
	}

	// Default method is GET.
	def, err := buildRequest(RequestSpec{URL: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	if def.Method != "GET" {
		t.Errorf("default method = %q, want GET", def.Method)
	}
}

func TestResolveSpecNoEnvIsNoop(t *testing.T) {
	t.Setenv("WEEB_BASE_URL", "")
	t.Setenv("WEEB_HEADERS", "")
	t.Setenv("WEEB_TOKEN", "")
	in := RequestSpec{Method: "GET", URL: "https://x/y", Headers: []Header{{Key: "A", Value: "1"}}}
	got := resolveSpec(in)
	if got.URL != "https://x/y" || len(got.Headers) != 1 {
		t.Errorf("resolveSpec changed a fully-specified spec: %+v", got)
	}
	// A relative URL with no base is left alone.
	if got := resolveSpec(RequestSpec{URL: "/me"}); got.URL != "/me" {
		t.Errorf("relative URL without base should be untouched, got %q", got.URL)
	}
}

func TestResolveSpecBareHostDefaultsHTTP(t *testing.T) {
	t.Setenv("WEEB_BASE_URL", "")
	t.Setenv("WEEB_HEADERS", "")
	t.Setenv("WEEB_TOKEN", "")

	// A schemeless host (with or without an explicit port) defaults to http.
	if got := resolveSpec(RequestSpec{URL: "example.com:8080/p"}); got.URL != "http://example.com:8080/p" {
		t.Errorf("bare host should default to http, got %q", got.URL)
	}
	// Already-schemed URLs are untouched (https stays https).
	if got := resolveSpec(RequestSpec{URL: "https://example.com"}); got.URL != "https://example.com" {
		t.Errorf("https URL should be untouched, got %q", got.URL)
	}
}
