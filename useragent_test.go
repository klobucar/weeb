package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"charm.land/log/v2"
)

// weeb names itself on every request unless the user set a User-Agent; an
// empty -H "User-Agent:" sends none at all, like curl.
func TestDefaultUserAgent(t *testing.T) {
	if ua := userAgent(); !strings.HasPrefix(ua, "weeb/") || strings.HasPrefix(ua, "weeb/v") {
		t.Fatalf("userAgent() = %q, want weeb/VERSION", ua)
	}

	var (
		mu   sync.Mutex
		seen []string // User-Agent per request; "<none>" when absent
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if _, ok := r.Header["User-Agent"]; ok {
			seen = append(seen, r.UserAgent())
		} else {
			seen = append(seen, "<none>")
		}
	}))
	defer srv.Close()
	last := func() string {
		mu.Lock()
		defer mu.Unlock()
		return seen[len(seen)-1]
	}

	c := newClient(log.New(io.Discard), plainErrorChan{})
	c.noHistory = true
	tests := []struct {
		name    string
		headers []Header
		want    string
	}{
		{"default", nil, userAgent()},
		{"user set", []Header{{Key: "User-Agent", Value: "probe-bot/1"}}, "probe-bot/1"},
		{"lowercase key", []Header{{Key: "user-agent", Value: "lower/1"}}, "lower/1"},
		{"empty sends none", []Header{{Key: "User-Agent", Value: ""}}, "<none>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := c.Do(RequestSpec{Method: "GET", URL: srv.URL, Headers: tt.headers, HeadersResolved: true})
			if res.Err != nil {
				t.Fatal(res.Err)
			}
			if got := last(); got != tt.want {
				t.Errorf("User-Agent = %q, want %q", got, tt.want)
			}
		})
	}

	// The probe's plain-http walk sends no headers of its own, so it now
	// carries weeb's name instead of Go's.
	probeRedirects(c, srv.URL+"/")
	if got := last(); got != userAgent() {
		t.Errorf("probe redirect walk User-Agent = %q, want %q", got, userAgent())
	}
}
