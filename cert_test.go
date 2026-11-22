package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
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

// The STARTTLS exchange runs before any certificate check, so the server is
// untrusted. An endless reply line, or an endless run of continuation/untagged
// lines, must fail at a fixed cap instead of being buffered until the deadline
// (one 128 MiB greeting line used to cost ~260 MiB). net.Pipe is synchronous,
// so the bytes the server got written are exactly the bytes weeb read.
func TestStartTLSCapsReplySize(t *testing.T) {
	flood := func(c net.Conn, sent *atomic.Int64, head, unit string) {
		fmt.Fprint(c, head)
		b := []byte(unit)
		for {
			n, err := c.Write(b)
			sent.Add(int64(n))
			if err != nil {
				return
			}
		}
	}
	long := strings.Repeat("A", 1<<10)
	cases := []struct {
		name, proto, want string
		serve             func(*bufio.Reader, net.Conn, *atomic.Int64)
	}{
		{"smtp endless greeting line", "smtp", "longer than", func(r *bufio.Reader, c net.Conn, s *atomic.Int64) {
			flood(c, s, "220", long)
		}},
		{"smtp endless EHLO lines", "smtp", "lines", func(r *bufio.Reader, c net.Conn, s *atomic.Int64) {
			fmt.Fprint(c, "220 mx ready\r\n")
			_, _ = r.ReadString('\n') // EHLO
			flood(c, s, "", "250-EXT\r\n")
		}},
		{"ftp endless greeting lines", "ftp", "lines", func(r *bufio.Reader, c net.Conn, s *atomic.Int64) {
			flood(c, s, "", "220-hello\r\n")
		}},
		{"imap endless greeting line", "imap", "longer than", func(r *bufio.Reader, c net.Conn, s *atomic.Int64) {
			flood(c, s, "* OK ", long)
		}},
		{"imap endless untagged lines", "imap", "lines", func(r *bufio.Reader, c net.Conn, s *atomic.Int64) {
			fmt.Fprint(c, "* OK ready\r\n")
			_, _ = r.ReadString('\n') // a STARTTLS
			flood(c, s, "", "* CAPABILITY x\r\n")
		}},
		{"pop3 endless greeting line", "pop3", "longer than", func(r *bufio.Reader, c net.Conn, s *atomic.Int64) {
			flood(c, s, "+OK ", long)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			var sent atomic.Int64
			go func() {
				defer server.Close()
				tc.serve(bufio.NewReader(server), server, &sent)
			}()
			_ = client.SetDeadline(time.Now().Add(2 * time.Second))
			err := startTLS(client, tc.proto)
			client.Close()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("startTLS(%s) err = %v, want the %q cap error", tc.proto, err, tc.want)
			}
			if n := sent.Load(); n > 64<<10 {
				t.Errorf("read %d bytes of an endless reply before giving up", n)
			}
		})
	}

	// Replies right at both caps still upgrade.
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		r := bufio.NewReader(server)
		fmt.Fprint(server, "220 "+strings.Repeat("A", starttlsMaxLine-len("220 \r\n"))+"\r\n")
		_, _ = r.ReadString('\n') // EHLO
		fmt.Fprint(server, strings.Repeat("250-EXT\r\n", starttlsMaxLines-1)+"250 STARTTLS\r\n")
		_, _ = r.ReadString('\n') // STARTTLS
		fmt.Fprint(server, "220 go ahead\r\n")
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if err := startTLS(client, "smtp"); err != nil {
		t.Errorf("replies at the caps should pass: %v", err)
	}
	client.Close()
}

// A self-signed peer controls every string in its certificate — Subject and
// Issuer CNs, SANs — and the verify-error text quotes them. runCert prints the
// report through outW, whose TTY form is sanitizingWriter; this proves a CN
// carrying OSC 52 (clipboard write) is neutralized at that boundary while the
// surrounding text survives.
func TestCertReportSanitizedAtTTYBoundary(t *testing.T) {
	const osc52 = "\x1b]52;c;ZXZpbA==\x07"
	evil := osc52 + "evil-cn"
	rep := &certReport{
		Host: "victim.test", Port: "443",
		TLSVersion: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256",
		VerifyErr: "x509: certificate signed by unknown authority: " + evil,
		Chain: []certInfo{{
			SubjectCN: evil, Subject: "CN=" + evil,
			IssuerCN: evil, Issuer: "CN=" + evil,
			DNSNames:  []string{evil},
			NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour),
			DaysUntilExpiry: 1,
		}},
	}

	var buf strings.Builder
	fmt.Fprint(sanitizingWriter{w: &buf}, renderCertReport(rep, newStyles(), true, 100, true))
	out := buf.String()
	if strings.Contains(out, "]52;") {
		t.Errorf("OSC 52 from cert fields reached the terminal:\n%q", out)
	}
	if !strings.Contains(out, "evil-cn") {
		t.Errorf("cert CN text should survive sanitization:\n%q", out)
	}
}

// The stats block prints the TLS leaf CN (peer-controlled) to stderr at a TTY;
// emitResult goes through errW, whose TTY form is sanitizingWriter.
func TestConnTLSSanitizedAtTTYBoundary(t *testing.T) {
	const osc52 = "\x1b]52;c;ZXZpbA==\x07"
	c := &connTLS{
		Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256",
		Leaf: &certInfo{SubjectCN: osc52 + "leaf-cn", DaysUntilExpiry: 10},
	}

	var buf strings.Builder
	fmt.Fprintln(sanitizingWriter{w: &buf}, renderConnTLS(c, newStyles()))
	out := buf.String()
	if strings.Contains(out, "]52;") {
		t.Errorf("OSC 52 from the TLS leaf CN reached the terminal:\n%q", out)
	}
	if !strings.Contains(out, "leaf-cn") {
		t.Errorf("leaf CN text should survive sanitization:\n%q", out)
	}
}

// ---- weeb cert FILE ----------------------------------------------------------

var testCertSerial atomic.Int64

// newTestCert signs tmpl with parent/parentKey, or self-signs it when parent
// is nil, under a fresh P-256 key, so tests build whole hierarchies offline.
func newTestCert(t *testing.T, tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func testCATemplate(cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(testCertSerial.Add(1)),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

func testLeafTemplate(cn string, ttl time.Duration, eku ...x509.ExtKeyUsage) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(testCertSerial.Add(1)),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
}

// testPKI is a root → intermediate → leaf hierarchy plus some strays: a leaf
// that is client-auth only, an expired leaf, and an unrelated self-signed root.
type testPKI struct {
	root, inter, leaf, clientLeaf, expiredLeaf, otherRoot *x509.Certificate
}

// testLeafTTL leaves the leaf 20 whole days, inside the default --check
// warning window (30) but outside the critical one (14).
const testLeafTTL = 20*24*time.Hour + time.Hour

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	var p testPKI
	var rootKey, interKey *ecdsa.PrivateKey
	p.root, rootKey = newTestCert(t, testCATemplate("weeb test root"), nil, nil)
	p.inter, interKey = newTestCert(t, testCATemplate("weeb test inter"), p.root, rootKey)
	p.leaf, _ = newTestCert(t, testLeafTemplate("leaf.example.test", testLeafTTL, x509.ExtKeyUsageServerAuth), p.inter, interKey)
	p.clientLeaf, _ = newTestCert(t, testLeafTemplate("client.example.test", testLeafTTL, x509.ExtKeyUsageClientAuth), p.inter, interKey)
	p.expiredLeaf, _ = newTestCert(t, testLeafTemplate("old.example.test", -24*time.Hour, x509.ExtKeyUsageServerAuth), p.inter, interKey)
	p.otherRoot, _ = newTestCert(t, testCATemplate("weeb other root"), nil, nil)
	return p
}

func pemOf(certs ...*x509.Certificate) []byte {
	var b bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.Bytes()
}

// testKeyMaterial stands in for a private key in a bundle; it must never
// appear in any output, raw or base64 (as it sits in the PEM).
const testKeyMaterial = "weeb-secret-key-material"

func testKeyBlock() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte(testKeyMaterial)})
}

func assertNoKeyMaterial(t *testing.T, where, out string) {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString([]byte(testKeyMaterial))
	if strings.Contains(out, testKeyMaterial) || strings.Contains(out, b64) {
		t.Errorf("%s leaked private key material:\n%s", where, out)
	}
}

func certCNs(certs []*x509.Certificate) []string {
	var out []string
	for _, c := range certs {
		out = append(out, c.Subject.CommonName)
	}
	return out
}

func TestIsCertFileTarget(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for _, f := range []string{"example.com", "chain.pem", "UPPER.CRT", "certs/noext"} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		arg  string
		want bool
	}{
		{"-", true},
		{"example.com", false}, // a bare hostname dials even though the file exists
		{"./example.com", true},
		{"chain.pem", true},
		{"UPPER.CRT", true},
		{"missing.pem", false},
		{"certs/noext", true},
		{"certs", false},
		{"certs/", false}, // a directory is never a cert file
		{filepath.Join(dir, "chain.pem"), true},
		{"https://example.com/chain.pem", false},
		{"example.com:443", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isCertFileTarget(c.arg); got != c.want {
			t.Errorf("isCertFileTarget(%q) = %v, want %v", c.arg, got, c.want)
		}
	}
}

func TestParseCertBundle(t *testing.T) {
	p := newTestPKI(t)
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")})
	cases := []struct {
		name           string
		data           []byte
		wantCNs        []string
		wantFormat     string
		wantSkipped    []string
		wantUnreadable string // substring of the one unreadable-block note
		wantErr        string
	}{
		{"pem single", pemOf(p.leaf), []string{"leaf.example.test"}, "PEM", nil, "", ""},
		{"pem bundle with key", bytes.Join([][]byte{pemOf(p.inter), testKeyBlock(), pemOf(p.leaf)}, nil),
			[]string{"weeb test inter", "leaf.example.test"}, "PEM", []string{"PRIVATE KEY"}, "", ""},
		{"pem after openssl -text preamble", append([]byte("Certificate:\n    Data:\n        Version: 3\n"), pemOf(p.leaf)...),
			[]string{"leaf.example.test"}, "PEM", nil, "", ""},
		{"der single", p.leaf.Raw, []string{"leaf.example.test"}, "DER", nil, "", ""},
		{"der concatenated", append(append([]byte{}, p.leaf.Raw...), p.inter.Raw...),
			[]string{"leaf.example.test", "weeb test inter"}, "DER", nil, "", ""},
		// One cert Go rejects (a legacy root, say) is noted, not fatal.
		{"unreadable block among good ones", append(pemOf(p.leaf), bad...),
			[]string{"leaf.example.test"}, "PEM", nil, "PEM block 2: x509:", ""},
		{"only unreadable blocks", bad, nil, "", nil, "", "no readable certificate: PEM block 1"},
		{"key only", testKeyBlock(), nil, "", nil, "", "no CERTIFICATE block (found PRIVATE KEY)"},
		{"garbage", []byte("hello"), nil, "", nil, "", "expected PEM or DER"},
		{"empty", nil, nil, "", nil, "", "expected PEM or DER"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := parseCertBundle(c.data)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want %q", err, c.wantErr)
				}
				assertNoKeyMaterial(t, "error", err.Error())
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := certCNs(b.certs); !reflect.DeepEqual(got, c.wantCNs) {
				t.Errorf("certs = %v, want %v", got, c.wantCNs)
			}
			if b.format != c.wantFormat || !reflect.DeepEqual(b.skipped, c.wantSkipped) {
				t.Errorf("format, skipped = %q, %v; want %q, %v", b.format, b.skipped, c.wantFormat, c.wantSkipped)
			}
			if got := strings.Join(b.unreadable, "; "); (c.wantUnreadable == "") != (got == "") || !strings.Contains(got, c.wantUnreadable) {
				t.Errorf("unreadable = %q, want %q", got, c.wantUnreadable)
			}
		})
	}
}

func TestOrderChain(t *testing.T) {
	p := newTestPKI(t)
	const leaf, inter, root, other = "leaf.example.test", "weeb test inter", "weeb test root", "weeb other root"
	cases := []struct {
		name        string
		in          []*x509.Certificate
		chain, rest []string
	}{
		{"already ordered", []*x509.Certificate{p.leaf, p.inter, p.root}, []string{leaf, inter, root}, nil},
		{"root first", []*x509.Certificate{p.root, p.inter, p.leaf}, []string{leaf, inter, root}, nil},
		{"shuffled", []*x509.Certificate{p.inter, p.leaf, p.root}, []string{leaf, inter, root}, nil},
		{"missing intermediate", []*x509.Certificate{p.root, p.leaf}, []string{leaf}, []string{root}},
		{"unrelated cert", []*x509.Certificate{p.otherRoot, p.inter, p.leaf}, []string{leaf, inter}, []string{other}},
		{"duplicates dropped", []*x509.Certificate{p.leaf, p.inter, p.leaf}, []string{leaf, inter}, nil},
		{"no leaf", []*x509.Certificate{p.root, p.inter}, []string{inter, root}, nil},
		{"CA bundle", []*x509.Certificate{p.root, p.otherRoot}, []string{root}, []string{other}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			chain, rest := orderChain(c.in)
			if got := certCNs(chain); !reflect.DeepEqual(got, c.chain) {
				t.Errorf("chain = %v, want %v", got, c.chain)
			}
			if got := certCNs(rest); !reflect.DeepEqual(got, c.rest) {
				t.Errorf("others = %v, want %v", got, c.rest)
			}
		})
	}
}

// Trust for a file: the chain is verified against the roots (injected here;
// the system roots in production), with the file's other certs as
// intermediates. The exit code follows certExit exactly as for a live host.
func TestCertFileReportTrust(t *testing.T) {
	p := newTestPKI(t)
	roots := x509.NewCertPool()
	roots.AddCert(p.root)
	empty := x509.NewCertPool()
	cases := []struct {
		name         string
		data         []byte
		opts         certFileOptions
		wantVerified bool
		wantErr      string // substring of VerifyErr
		wantExit     int
	}{
		{"trusted, reversed order", pemOf(p.inter, p.leaf), certFileOptions{roots: roots}, true, "", 0},
		{"matching host", pemOf(p.leaf, p.inter), certFileOptions{roots: roots, host: "leaf.example.test"}, true, "", 0},
		{"host mismatch", pemOf(p.leaf, p.inter), certFileOptions{roots: roots, host: "other.example.test"}, false, "other.example.test", 1},
		{"unknown root", pemOf(p.leaf, p.inter), certFileOptions{roots: empty}, false, "unknown authority", 1},
		{"a root in the file doesn't trust itself", pemOf(p.leaf, p.inter, p.root), certFileOptions{roots: empty}, false, "unknown authority", 1},
		{"insecure skips trust", pemOf(p.leaf, p.inter), certFileOptions{roots: empty, insecure: true}, false, "", 0},
		{"client cert, no host: any usage", pemOf(p.clientLeaf, p.inter), certFileOptions{roots: roots}, true, "", 0},
		{"client cert checked as a server", pemOf(p.clientLeaf, p.inter), certFileOptions{roots: roots, host: "client.example.test"}, false, "key usage", 1},
		{"expired leaf", pemOf(p.expiredLeaf, p.inter), certFileOptions{roots: roots}, false, "expired", 1},
		{"expired leaf, insecure", pemOf(p.expiredLeaf, p.inter), certFileOptions{roots: roots, insecure: true}, false, "", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep, err := certFileReport("chain.pem", c.data, c.opts)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Verified != c.wantVerified || rep.Skipped != c.opts.insecure {
				t.Errorf("verified, skipped = %v, %v; want %v, %v (err %q)", rep.Verified, rep.Skipped, c.wantVerified, c.opts.insecure, rep.VerifyErr)
			}
			if c.wantErr != "" && !strings.Contains(rep.VerifyErr, c.wantErr) {
				t.Errorf("VerifyErr = %q, want it to mention %q", rep.VerifyErr, c.wantErr)
			}
			if got := certExit(rep, c.opts.insecure); got != c.wantExit {
				t.Errorf("certExit = %d, want %d", got, c.wantExit)
			}
			if rep.Chain[0].SubjectCN == "weeb test inter" {
				t.Errorf("chain not ordered leaf first: %+v", rep.Chain)
			}
		})
	}
}

func TestReadCertSource(t *testing.T) {
	p := newTestPKI(t)
	data, err := readCertSource("-", bytes.NewReader(pemOf(p.leaf)))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := certFileReport("-", data, certFileOptions{insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if line := checkCert(rep, 30, 14).line(); !strings.HasPrefix(line, "CERT WARNING - stdin expires in 20 days") {
		t.Errorf("stdin check line = %q", line)
	}

	// A path like /dev/zero must not be read forever.
	if _, err := readCertSource("-", io.LimitReader(zeroReader{}, certFileMax+1)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized input: err = %v, want the size cap", err)
	}
	if _, err := certFileReport("-", []byte("junk"), certFileOptions{}); err == nil || !strings.HasPrefix(err.Error(), "stdin: ") {
		t.Errorf("parse error should name the source: %v", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	clear(b)
	return len(b), nil
}

// A file report renders without the handshake rows (it has no handshake),
// shows where it came from, lists stray certs separately, and goes through
// the same TTY sanitizer as a live report: the path and cert fields are as
// untrusted as a peer's.
func TestRenderCertFileReport(t *testing.T) {
	const osc52 = "\x1b]52;c;ZXZpbA==\x07"
	p := newTestPKI(t)
	data := bytes.Join([][]byte{pemOf(p.otherRoot, p.leaf), testKeyBlock(), pemOf(p.inter)}, nil)
	rep, err := certFileReport(osc52+"evil.pem", data, certFileOptions{insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	fmt.Fprint(sanitizingWriter{w: &buf}, renderCertReport(rep, newStyles(), true, 100, true))
	colored := buf.String()
	plain := renderCertReport(rep, newStyles(), false, 100, true)

	for _, want := range []string{"📄 CERT", "📄 File", "PEM, 3 certificates", "1 PRIVATE KEY block (not shown)",
		"not checked (use --host NAME)", "2 from file, ordered leaf → root", "📦 Also in file", "weeb other root", "📜 Leaf"} {
		if !strings.Contains(plain, want) {
			t.Errorf("report missing %q:\n%s", want, plain)
		}
	}
	for _, absent := range []string{"Protocol", "Cipher", "OCSP", "SCTs", "🤝 Connection"} {
		if strings.Contains(plain, absent) {
			t.Errorf("file report shows network-only %q:\n%s", absent, plain)
		}
	}
	assertNoKeyMaterial(t, "report", plain)
	if strings.Contains(colored, "]52;") || !strings.Contains(colored, "evil.pem") {
		t.Errorf("file name not sanitized at the TTY boundary:\n%q", colored)
	}

	rep.Hostname, rep.Skipped, rep.Verified = "leaf.example.test", false, true
	if out := renderCertReport(rep, newStyles(), false, 100, true); !strings.Contains(out, "TRUSTED  chain & hostname") {
		t.Errorf("hostname-checked trust row:\n%s", out)
	}
	rep.Hostname = ""
	if out := renderCertReport(rep, newStyles(), false, 100, true); !strings.Contains(out, "TRUSTED  chain\n") {
		t.Errorf("chain-only trust row:\n%s", out)
	}
}

// The network report's JSON keeps every handshake field; a file report's
// leaves them out instead of reporting zero values it never observed.
func TestCertReportJSONShape(t *testing.T) {
	keys := func(rep *certReport) map[string]any {
		t.Helper()
		b, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	network := keys(&certReport{Host: "h", Port: "443", Chain: []certInfo{{}}})
	for _, k := range []string{"host", "port", "sni", "tls_version", "cipher", "ocsp_stapled", "sct_count", "verified", "chain"} {
		if _, ok := network[k]; !ok {
			t.Errorf("network JSON lost %q: %v", k, network)
		}
	}
	if _, ok := network["file"]; ok {
		t.Errorf("network JSON grew a file field: %v", network)
	}

	file := keys(&certReport{File: "c.pem", Format: "PEM", Chain: []certInfo{{}}})
	for _, k := range []string{"file", "format", "verified", "trust_check_skipped", "chain"} {
		if _, ok := file[k]; !ok {
			t.Errorf("file JSON missing %q: %v", k, file)
		}
	}
	for _, k := range []string{"host", "port", "sni", "tls_version", "cipher", "alpn", "ocsp_stapled", "sct_count"} {
		if _, ok := file[k]; ok {
			t.Errorf("file JSON has network-only %q: %v", k, file)
		}
	}
}

// swapErrW redirects the stderr boundary writer into a buffer for the test.
func swapErrW(t *testing.T) *strings.Builder {
	t.Helper()
	var buf strings.Builder
	old := errW
	errW = &buf
	t.Cleanup(func() { errW = old })
	return &buf
}

// runCert end to end on files. The chain's root is not in the system store,
// so without -k it is untrusted, exactly as a self-signed host would be.
func TestRunCertFile(t *testing.T) {
	p := newTestPKI(t)
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.pem")
	der := filepath.Join(dir, "leaf.der")
	junk := filepath.Join(dir, "junk.pem")
	mixed := filepath.Join(dir, "mixed.pem")
	for path, data := range map[string][]byte{
		bundle: bytes.Join([][]byte{pemOf(p.inter), testKeyBlock(), pemOf(p.leaf)}, nil),
		der:    p.leaf.Raw,
		junk:   []byte("not a certificate"),
		mixed:  append(pemOf(p.leaf), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")})...),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	missing := filepath.Join(dir, "missing.pem")
	// JSON escapes the path (Windows separators are backslashes).
	bundleJSON, _ := json.Marshal(bundle)

	cases := []struct {
		name     string
		args     []string
		wantCode int
		want     []string // substrings of stdout
		wantErr  string   // substring of errW
	}{
		{"report, untrusted", []string{bundle}, 1, []string{"📄 CERT  " + bundle, "✗ UNTRUSTED", "leaf.example.test", "1 PRIVATE KEY block"}, ""},
		{"report, -k", []string{bundle, "-k"}, 0, []string{"not checked (insecure)"}, ""},
		{"brief", []string{bundle, "-k", "--brief"}, 0, []string{"📜 Leaf"}, ""},
		{"der via -f", []string{"-f", der, "-k"}, 0, []string{"DER, 1 certificate"}, ""},
		{"json", []string{bundle, "-k", "--json"}, 0, []string{`"file": ` + string(bundleJSON), `"format": "PEM"`, `"skipped_pem_blocks"`}, ""},
		{"pem drops the key", []string{bundle, "-k", "--pem"}, 0, []string{"BEGIN CERTIFICATE"}, "skipped 1 PRIVATE KEY block"},
		{"check warns on expiry", []string{bundle, "-k", "--check"}, checkWarning, []string{"CERT WARNING - " + bundle + " expires in 20 days", "|days=20;30;14"}, ""},
		{"check json", []string{bundle, "-k", "--check", "--json", "-w", "10", "-c", "5"}, checkOK, []string{`"status":"OK"`}, ""},
		{"check untrusted is critical", []string{bundle, "--check"}, checkCritical, []string{"CERT CRITICAL - " + bundle + " untrusted"}, ""},
		{"host with -k", []string{bundle, "--host", "leaf.example.test", "-k"}, 0, []string{"Hostname     leaf.example.test"}, ""},
		{"sni names the host too", []string{bundle, "--sni", "leaf.example.test", "-k"}, 0, []string{"Hostname     leaf.example.test"}, ""},
		{"missing file", []string{"-f", missing}, 1, nil, "missing.pem"},
		{"missing file in check mode", []string{"-f", missing, "--check"}, checkUnknown, []string{"CERT UNKNOWN - "}, ""},
		{"not a certificate", []string{junk}, 1, nil, "expected PEM or DER"},
		{"unreadable block noted", []string{mixed, "-k"}, 0, []string{"Unreadable   PEM block 2: x509:"}, ""},
		{"pem notes unreadable block", []string{mixed, "-k", "--pem"}, 0, []string{"BEGIN CERTIFICATE"}, "skipped 1 unreadable CERTIFICATE block"},
		{"--host needs a file", []string{"--host", "x", "example.invalid"}, 2, nil, ""},
		{"handshake flag on a file", []string{bundle, "--starttls", "smtp"}, 2, nil, ""},
		{"file and host both", []string{"-f", bundle, "example.invalid"}, 2, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, errOut := swapOutW(t), swapErrW(t)
			if code := runCert(c.args); code != c.wantCode {
				t.Errorf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, c.wantCode, out, errOut)
			}
			for _, w := range c.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("stdout missing %q:\n%s", w, out)
				}
			}
			if c.wantErr != "" && !strings.Contains(errOut.String(), c.wantErr) {
				t.Errorf("stderr missing %q:\n%s", c.wantErr, errOut)
			}
			for _, s := range []string{"Cipher", "tls_version", "PRIVATE KEY-----"} {
				if strings.Contains(out.String(), s) {
					t.Errorf("stdout has %q:\n%s", s, out)
				}
			}
			assertNoKeyMaterial(t, "stdout", out.String())
			assertNoKeyMaterial(t, "stderr", errOut.String())
		})
	}
}
