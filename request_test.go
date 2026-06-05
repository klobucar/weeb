package main

import (
	"io"
	"net/http"
	"net/http/httptest"
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
