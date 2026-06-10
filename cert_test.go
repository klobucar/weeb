package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
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
		{"http://example.com/x", "example.com", "443"}, // cert keeps 443 regardless of scheme
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

// A cert expired by less than a day must report a negative day count so
// certExit catches it even with --insecure (int truncation used to round
// -0.5 up to 0 and monitors stayed green for up to 24h after expiry).
func TestDaysUntilExpiryJustExpired(t *testing.T) {
	expired := describeCert(&x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(-12 * time.Hour),
	})
	if expired.DaysUntilExpiry >= 0 {
		t.Errorf("cert expired 12h ago: DaysUntilExpiry = %d, want < 0", expired.DaysUntilExpiry)
	}
	rep := &certReport{Verified: true, Chain: []certInfo{expired}}
	if certExit(rep, true) != 1 {
		t.Error("just-expired cert with --insecure -> want exit 1")
	}

	expiring := describeCert(&x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(12 * time.Hour),
	})
	if expiring.DaysUntilExpiry != 0 {
		t.Errorf("cert valid 12h more: DaysUntilExpiry = %d, want 0", expiring.DaysUntilExpiry)
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

	rep, err := fetchCertReport(srv.URL, certOptions{timeout: 5 * time.Second})
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
	if len(rep.rawCerts) != len(rep.Chain) {
		t.Errorf("rawCerts (%d) should match chain length (%d)", len(rep.rawCerts), len(rep.Chain))
	}
	if pemOut := certPEM(rep); !strings.Contains(pemOut, "BEGIN CERTIFICATE") {
		t.Errorf("certPEM should emit PEM blocks, got %q", pemOut)
	}
	if rep.SNI == "" {
		t.Error("SNI should default to the dial host")
	}
}

func TestSplitHostPortDefault(t *testing.T) {
	if h, p := splitHostPortDefault("mail.example.com", "25"); h != "mail.example.com" || p != "25" {
		t.Errorf("bare host should take default port: got (%q,%q)", h, p)
	}
	if _, p := splitHostPortDefault("mail.example.com:587", "25"); p != "587" {
		t.Errorf("explicit port should win over default: got %q", p)
	}
}

func TestDefaultCertPort(t *testing.T) {
	cases := map[string]string{"smtp": "587", "imap": "143", "pop3": "110", "ftp": "21", "": "443", "weird": "443"}
	for in, want := range cases {
		if got := defaultCertPort(in); got != want {
			t.Errorf("defaultCertPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseTLSVersion(t *testing.T) {
	cases := map[string]uint16{
		"1.0": tls.VersionTLS10, "1.1": tls.VersionTLS11,
		"1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13,
		"tls1.2": tls.VersionTLS12, "TLS1.3": tls.VersionTLS13,
	}
	for in, want := range cases {
		got, err := parseTLSVersion(in)
		if err != nil || got != want {
			t.Errorf("parseTLSVersion(%q) = (%d,%v), want %d", in, got, err, want)
		}
	}
	if _, err := parseTLSVersion("9.9"); err == nil {
		t.Error("parseTLSVersion should reject unknown versions")
	}
}

func TestSplitList(t *testing.T) {
	got := splitList(" h2, http/1.1 ,, ")
	if want := []string{"h2", "http/1.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("splitList = %v, want %v", got, want)
	}
	if got := splitList("  "); got != nil {
		t.Errorf("splitList of blanks should be nil, got %v", got)
	}
}

func TestRenderCertReportDetail(t *testing.T) {
	rep := &certReport{
		Host: "example.com", Port: "443", SNI: "example.com",
		TLSVersion: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", Verified: true,
		Chain: []certInfo{
			{SubjectCN: "example.com", Issuer: "CN=R3", KeyType: "RSA 2048", Serial: "AB"},
			{SubjectCN: "R3", Issuer: "CN=Root", KeyType: "RSA 4096", Serial: "CD"},
		},
	}
	st := newStyles()

	full := renderCertReport(rep, st, false, 100, true)
	if !strings.Contains(full, "RSA 2048") || !strings.Contains(full, "RSA 4096") {
		t.Errorf("full report should detail every cert:\n%s", full)
	}

	brief := renderCertReport(rep, st, false, 100, false)
	if !strings.Contains(brief, "RSA 2048") {
		t.Errorf("brief report should still show the leaf:\n%s", brief)
	}
	if strings.Contains(brief, "RSA 4096") {
		t.Errorf("brief report should omit intermediate detail:\n%s", brief)
	}
	// The chain overview ladder shows regardless of brief.
	if !strings.Contains(brief, "Chain") {
		t.Errorf("brief report should still show the chain ladder:\n%s", brief)
	}
}

func TestStartTLS(t *testing.T) {
	cases := []struct {
		proto string
		serve func(*bufio.Reader, net.Conn)
	}{
		{"smtp", func(r *bufio.Reader, c net.Conn) {
			fmt.Fprint(c, "220 mx ready\r\n")
			_, _ = r.ReadString('\n') // EHLO
			fmt.Fprint(c, "250-mx greets\r\n250 STARTTLS\r\n")
			_, _ = r.ReadString('\n') // STARTTLS
			fmt.Fprint(c, "220 go ahead\r\n")
		}},
		{"ftp", func(r *bufio.Reader, c net.Conn) {
			fmt.Fprint(c, "220 ftp ready\r\n")
			_, _ = r.ReadString('\n') // AUTH TLS
			fmt.Fprint(c, "234 proceed\r\n")
		}},
		{"imap", func(r *bufio.Reader, c net.Conn) {
			fmt.Fprint(c, "* OK ready\r\n")
			_, _ = r.ReadString('\n') // a STARTTLS
			fmt.Fprint(c, "a OK begin TLS\r\n")
		}},
		{"pop3", func(r *bufio.Reader, c net.Conn) {
			fmt.Fprint(c, "+OK ready\r\n")
			_, _ = r.ReadString('\n') // STLS
			fmt.Fprint(c, "+OK begin\r\n")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.proto, func(t *testing.T) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				tc.serve(bufio.NewReader(server), server)
			}()
			_ = client.SetDeadline(time.Now().Add(2 * time.Second))
			if err := startTLS(client, tc.proto); err != nil {
				t.Fatalf("startTLS(%s): %v", tc.proto, err)
			}
			client.Close()
		})
	}
}

func TestStartTLSErrors(t *testing.T) {
	// Unknown protocol fails before touching the connection.
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := startTLS(client, "gopher"); err == nil {
		t.Error("unknown protocol should error")
	}

	// A rejected upgrade (wrong status code) surfaces an error.
	c2, s2 := net.Pipe()
	go func() {
		defer s2.Close()
		fmt.Fprint(s2, "554 no service\r\n")
	}()
	_ = c2.SetDeadline(time.Now().Add(2 * time.Second))
	if err := startTLS(c2, "smtp"); err == nil {
		t.Error("a non-220 greeting should error")
	}
	c2.Close()
}
