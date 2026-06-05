package main

import (
	"crypto/tls"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSplitHostPort(t *testing.T) {
	cases := []struct{ in, host, port string }{
		{"example.com", "example.com", "443"},
		{"example.com:8443", "example.com", "8443"},
		{"https://example.com:8443/x", "example.com", "8443"},
		{"https://example.com/x", "example.com", "443"},
		{"example.com/", "example.com", "443"},
	}
	for _, c := range cases {
		h, p := splitHostPort(c.in)
		if h != c.host || p != c.port {
			t.Errorf("splitHostPort(%q) = (%q,%q), want (%q,%q)", c.in, h, p, c.host, c.port)
		}
	}
}

func TestTLSVersionName(t *testing.T) {
	cases := map[uint16]string{
		tls.VersionTLS13: "TLS 1.3",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS10: "TLS 1.0",
	}
	for v, want := range cases {
		if got := tlsVersionName(v); got != want {
			t.Errorf("tlsVersionName(%d) = %q, want %q", v, got, want)
		}
	}
	if got := tlsVersionName(0x9999); !strings.HasPrefix(got, "0x") {
		t.Errorf("unknown version should be hex, got %q", got)
	}
}

func TestCertExit(t *testing.T) {
	trusted := &certReport{Verified: true, Chain: []certInfo{{DaysUntilExpiry: 30}}}
	untrusted := &certReport{Verified: false, Chain: []certInfo{{DaysUntilExpiry: 30}}}
	expired := &certReport{Verified: true, Chain: []certInfo{{DaysUntilExpiry: -1}}}

	if certExit(trusted, false) != 0 {
		t.Error("trusted, valid -> 0")
	}
	if certExit(untrusted, false) != 1 {
		t.Error("untrusted -> 1")
	}
	if certExit(untrusted, true) != 0 {
		t.Error("untrusted + insecure -> 0")
	}
	if certExit(expired, false) != 1 {
		t.Error("expired -> 1")
	}
}

func TestFormatSerial(t *testing.T) {
	cases := map[int64]string{0: "0", 255: "FF", 0x0a0b: "0A:0B"}
	for n, want := range cases {
		if got := formatSerial(big.NewInt(n)); got != want {
			t.Errorf("formatSerial(%d) = %q, want %q", n, got, want)
		}
	}
	if formatSerial(nil) != "0" {
		t.Error("nil serial -> 0")
	}
}

func TestFingerprintSHA256(t *testing.T) {
	fp := fingerprintSHA256([]byte("weeb"))
	// 32 bytes -> 32 hex pairs joined by 31 colons.
	if got := strings.Count(fp, ":"); got != 31 {
		t.Errorf("fingerprint should have 31 colons, got %d (%q)", got, fp)
	}
	if fp != strings.ToUpper(fp) {
		t.Errorf("fingerprint should be uppercase hex: %q", fp)
	}
}

func TestFetchCertReport(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	rep, err := fetchCertReport(srv.URL, 5*time.Second, false)
	if err != nil {
		t.Fatalf("fetchCertReport: %v", err)
	}
	if len(rep.Chain) == 0 {
		t.Fatal("expected a certificate chain")
	}
	if rep.TLSVersion == "" || rep.Cipher == "" {
		t.Errorf("connection details missing: %+v", rep)
	}
	// httptest's cert is a self-signed test cert: untrusted by the system roots.
	if rep.Verified {
		t.Error("expected the self-signed test cert to be untrusted")
	}
	if certExit(rep, false) != 1 {
		t.Error("untrusted cert should exit non-zero without -k")
	}
	if certExit(rep, true) != 0 {
		t.Error("-k should make an untrusted cert pass")
	}
}
