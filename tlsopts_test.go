package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// clearRequestEnv keeps the developer's WEEB_* prefills out of a test.
func clearRequestEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"WEEB_BASE_URL", "WEEB_HEADERS", "WEEB_TOKEN", "WEEB_MAX_BODY"} {
		t.Setenv(k, "")
	}
}

// writeFile writes data under t's temp dir and returns the path.
func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// certPEMOf PEM-encodes a certificate.
func certPEMOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// newClientCert generates a self-signed client certificate — its own CA, so
// a server can trust it directly — and returns it with its PEM cert and key.
func newClientCert(t *testing.T, cn string) (*x509.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return cert, certPEMOf(cert), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// Each TLS option end to end against local TLS servers: -k, --cacert (which
// trusts only its own CAs), and mTLS with --cert/--key or a combined file.
func TestClientDoTLSOptions(t *testing.T) {
	clearRequestEnv(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	clientCert, clientPEM, keyPEM := newClientCert(t, "weeb-client")
	pool := x509.NewCertPool()
	pool.AddCert(clientCert)
	var gotCN string
	mtls := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCN = r.TLS.PeerCertificates[0].Subject.CommonName
	}))
	mtls.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	mtls.StartTLS()
	defer mtls.Close()

	srvCA := writeFile(t, "srv-ca.pem", certPEMOf(srv.Certificate()))
	mtlsCA := writeFile(t, "mtls-ca.pem", certPEMOf(mtls.Certificate()))
	otherCA := writeFile(t, "other-ca.pem", clientPEM)
	certFile := writeFile(t, "client.pem", clientPEM)
	keyFile := writeFile(t, "client.key", keyPEM)
	bundle := writeFile(t, "bundle.pem", append(append([]byte{}, clientPEM...), keyPEM...))

	cases := []struct {
		name   string
		url    string
		opts   TLSOptions
		wantOK bool
	}{
		{"self-signed fails verification by default", srv.URL, TLSOptions{}, false},
		{"-k skips verification", srv.URL, TLSOptions{Insecure: true}, true},
		{"--cacert trusts the server's CA", srv.URL, TLSOptions{CACert: srvCA}, true},
		{"--cacert with an unrelated CA fails", srv.URL, TLSOptions{CACert: otherCA}, false},
		{"mTLS without a client cert fails", mtls.URL, TLSOptions{CACert: mtlsCA}, false},
		{"mTLS with --cert and --key", mtls.URL, TLSOptions{CACert: mtlsCA, Cert: certFile, Key: keyFile}, true},
		{"mTLS with cert and key in one file", mtls.URL, TLSOptions{CACert: mtlsCA, Cert: bundle}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotCN = ""
			res := testClient().Do(RequestSpec{Method: "GET", URL: c.url, TLS: c.opts})
			if res.OK() != c.wantOK {
				t.Fatalf("OK = %v (status %d, err %v), want %v", res.OK(), res.Status, res.Err, c.wantOK)
			}
			if c.wantOK && c.opts.Cert != "" && gotCN != "weeb-client" {
				t.Errorf("server saw client cert CN %q, want weeb-client", gotCN)
			}
		})
	}
}

// --cacert replaces the system roots, as in curl, rather than adding to them.
func TestCACertReplacesSystemRoots(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	cfg, err := TLSOptions{CACert: writeFile(t, "ca.pem", certPEMOf(srv.Certificate()))}.config()
	if err != nil {
		t.Fatal(err)
	}
	want := x509.NewCertPool()
	want.AddCert(srv.Certificate())
	if !cfg.RootCAs.Equal(want) {
		t.Error("RootCAs should hold exactly the --cacert bundle")
	}
	if cfg.InsecureSkipVerify {
		t.Error("--cacert must not turn verification off")
	}
}

func TestTLSOptionsConfigErrors(t *testing.T) {
	_, certPEM, keyPEM := newClientCert(t, "a")
	_, _, otherKey := newClientCert(t, "b")
	cert := writeFile(t, "c.pem", certPEM)
	key := writeFile(t, "k.pem", keyPEM)
	wrongKey := writeFile(t, "wrong.pem", otherKey)
	notPEM := writeFile(t, "junk.pem", []byte("not a certificate"))

	cases := []struct {
		name string
		opts TLSOptions
		want string
	}{
		{"missing --cacert", TLSOptions{CACert: "/no/such/ca.pem"}, "--cacert"},
		{"--cacert without PEM", TLSOptions{CACert: notPEM}, "no PEM certificates"},
		{"--key without --cert", TLSOptions{Key: key}, "--key needs --cert"},
		{"missing --cert", TLSOptions{Cert: "/no/such/cert.pem", Key: key}, "load client cert"},
		{"--cert without its key", TLSOptions{Cert: cert}, "load client cert"},
		{"mismatched key", TLSOptions{Cert: cert, Key: wrongKey}, "load client cert"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.opts.config()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("config() err = %v, want it to mention %q", err, c.want)
			}
			// The same failure, reached through Do, is a bad request with
			// nothing sent.
			res := testClient().Do(RequestSpec{URL: "https://127.0.0.1:1", TLS: c.opts})
			if res.Err == nil || res.Status != 0 || !strings.Contains(res.DisplayErr, "doesn't look right") {
				t.Errorf("Do: err = %v, display = %q; want a bad-request failure", res.Err, res.DisplayErr)
			}
		})
	}
}

func TestParseCertArg(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "client.pem", want: "client.pem"},
		{in: "client.pem:", want: "client.pem"}, // empty password: ignored, as curl does
		{in: `odd\:name.pem`, want: "odd:name.pem"},
		{in: `back\\slash.pem`, want: `back\slash.pem`},
		{in: `keep\x`, want: `keep\x`},
		{in: `trailing\`, want: `trailing\`},
		{in: "client.pem:hunter2", wantErr: true},
		{in: "pkcs11:token=x", wantErr: true},
	}
	for _, c := range cases {
		got, err := parseCertArg(c.in)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("parseCertArg(%q) = %q, %v; want %q (error %v)", c.in, got, err, c.want, c.wantErr)
		}
	}
	// Export escapes so curl (and weeb) read the same path back.
	for _, p := range []string{"a.pem", "a:b.pem", `C:\certs\a.pem`, `x\:y`, `\`} {
		if got, err := parseCertArg(certArgEscape(p)); err != nil || got != p {
			t.Errorf("parseCertArg(certArgEscape(%q)) = %q, %v", p, got, err)
		}
	}
}

// TLS options get their own transport: a clone, never the shared default,
// cached per option set, keeping the proxy and (for streaming) the header
// timeout. Requests without options keep using the Client's own clients.
func TestClientTLSTransport(t *testing.T) {
	c := testClient()
	opts := TLSOptions{Insecure: true}

	tr, err := c.tlsTransport(opts, false)
	if err != nil {
		t.Fatal(err)
	}
	// (Go itself gives the default a TLSClientConfig when it sets up HTTP/2,
	// so the check is that ours never leaked into it.)
	def := http.DefaultTransport.(*http.Transport)
	if cfg := def.TLSClientConfig; tr == def || cfg != nil && (cfg.InsecureSkipVerify || cfg.RootCAs != nil || cfg.GetClientCertificate != nil) {
		t.Error("http.DefaultTransport must be cloned, never shared or mutated")
	}
	if tr.Proxy == nil {
		t.Error("the clone should keep proxy-from-environment")
	}
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("transport should carry the TLS options")
	}
	if again, _ := c.tlsTransport(opts, false); again != tr {
		t.Error("the same options should reuse the cached transport")
	}
	st, _ := c.tlsTransport(opts, true)
	if st == tr || st.ResponseHeaderTimeout != defaultTimeout {
		t.Errorf("streaming variant: same=%v, ResponseHeaderTimeout=%v", st == tr, st.ResponseHeaderTimeout)
	}

	if hc, _ := c.httpClientFor(RequestSpec{}, nil); hc != c.http {
		t.Error("a plain request should use the shared client")
	}
	hc, _ := c.httpClientFor(RequestSpec{TLS: opts}, nil)
	if hc == c.http || hc.Transport != tr || hc.CheckRedirect == nil || hc.Timeout != c.http.Timeout {
		t.Error("a TLS request should get a copy with its transport, the redirect policy and the timeout")
	}
}

// The per-request client must keep redirectPolicy: credentials still don't
// follow a cross-origin hop under -k.
func TestRedirectStripsCredentialsWithTLSOptions(t *testing.T) {
	clearRequestEnv(t)
	t.Setenv("WEEB_TOKEN", "tok")

	var gotAuth, gotCookie string
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotCookie = r.Header.Get("Authorization"), r.Header.Get("Cookie")
	}))
	defer target.Close()
	hopper := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer hopper.Close()

	res := testClient().Do(RequestSpec{
		Method:  "GET",
		URL:     hopper.URL,
		Headers: []Header{{Key: "Cookie", Value: "a=1"}},
		TLS:     TLSOptions{Insecure: true},
	})
	if !res.OK() {
		t.Fatalf("request failed: %v", res.Err)
	}
	if gotAuth != "" || gotCookie != "" {
		t.Errorf("credentials followed a cross-origin redirect: Authorization=%q Cookie=%q", gotAuth, gotCookie)
	}
}

// captureStderr runs fn with os.Stdout and os.Stderr pointed at temp files
// and returns what it wrote to stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	dir := t.TempDir()
	errF, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	outF, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	oldErr, oldOut := os.Stderr, os.Stdout
	os.Stderr, os.Stdout = errF, outF
	func() {
		defer func() { os.Stderr, os.Stdout = oldErr, oldOut }()
		fn()
	}()
	_ = errF.Close()
	_ = outF.Close()
	b, err := os.ReadFile(errF.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// -k is never silent headless: weeb's own flag and a pasted curl -k print the
// same warning, and a verified request prints none.
func TestInsecureWarning(t *testing.T) {
	clearRequestEnv(t)
	t.Setenv("WEEB_PERSONA", "")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	ca := writeFile(t, "ca.pem", certPEMOf(srv.Certificate()))

	cases := []struct {
		name     string
		run      func() int
		wantWarn bool
	}{
		{"weeb -k", func() int { return runCLI(cliArgs{method: "GET", url: srv.URL, tls: TLSOptions{Insecure: true}}) }, true},
		{"weeb curl -k", func() int { return runCurlImport([]string{"curl -sSk " + srv.URL}) }, true},
		{"weeb --cacert", func() int { return runCLI(cliArgs{method: "GET", url: srv.URL, tls: TLSOptions{CACert: ca}}) }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var code int
			stderr := captureStderr(t, func() { code = c.run() })
			if code != 0 {
				t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
			}
			if got := strings.Contains(stderr, insecureWarning); got != c.wantWarn {
				t.Errorf("warning printed = %v, want %v; stderr: %q", got, c.wantWarn, stderr)
			}
		})
	}
}

// Bad TLS material is a usage error (exit 2) before anything is sent.
func TestRunCLIPreflightTLS(t *testing.T) {
	clearRequestEnv(t)
	sent := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sent = true }))
	defer srv.Close()
	var code int
	stderr := captureStderr(t, func() {
		code = runCLI(cliArgs{method: "GET", url: srv.URL, tls: TLSOptions{CACert: "/no/such/ca.pem"}})
	})
	if code != 2 || sent || !strings.Contains(stderr, "--cacert") {
		t.Errorf("exit = %d, sent = %v, stderr = %q; want exit 2, nothing sent, a --cacert error", code, sent, stderr)
	}
}

func TestParseCLIRequestOptions(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		check func(t *testing.T, a cliArgs)
	}{
		{"-k", []string{"https://x", "-k"}, func(t *testing.T, a cliArgs) {
			if !a.tls.Insecure {
				t.Error("-k should set Insecure")
			}
		}},
		{"tls files", []string{"https://x", "--insecure", "--cacert", "ca.pem", "-E", `c\:1.pem`, "--key", "k.pem"}, func(t *testing.T, a cliArgs) {
			if want := (TLSOptions{Insecure: true, CACert: "ca.pem", Cert: "c:1.pem", Key: "k.pem"}); a.tls != want {
				t.Errorf("tls = %+v, want %+v", a.tls, want)
			}
		}},
		{"-F implies POST", []string{"https://x", "-F", "a=b", "--form", "f=@up.txt"}, func(t *testing.T, a cliArgs) {
			if a.method != "POST" || len(a.form) != 2 || a.form[1].Kind != formFile {
				t.Errorf("method %q form %+v", a.method, a.form)
			}
		}},
		{"-X wins over -F", []string{"PUT", "https://x", "-F", "a=b"}, func(t *testing.T, a cliArgs) {
			if a.method != "PUT" {
				t.Errorf("method = %q, want PUT", a.method)
			}
		}},
		{"-b data is a Cookie header", []string{"https://x", "-b", "a=1; b=2"}, func(t *testing.T, a cliArgs) {
			if len(a.headers) != 1 || a.headers[0] != (Header{Key: "Cookie", Value: "a=1; b=2"}) || a.cookieFile != "" {
				t.Errorf("headers %+v cookieFile %q", a.headers, a.cookieFile)
			}
		}},
		{"-b FILE and --cookie-jar", []string{"https://x", "-b", "jar.txt", "--cookie-jar", "out.txt"}, func(t *testing.T, a cliArgs) {
			if a.cookieFile != "jar.txt" || a.cookieJar != "out.txt" || len(a.headers) != 0 {
				t.Errorf("cookieFile %q cookieJar %q headers %+v", a.cookieFile, a.cookieJar, a.headers)
			}
		}},
		{"-c stays --crit", []string{"https://x", "--check", "-c", "2s"}, func(t *testing.T, a cliArgs) {
			if a.crit != 2*time.Second || a.cookieJar != "" {
				t.Errorf("crit %v cookieJar %q", a.crit, a.cookieJar)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := parseCLI(c.args)
			if err != nil {
				t.Fatal(err)
			}
			c.check(t, a)
		})
	}

	for _, args := range [][]string{
		{"https://x", "-E", "c.pem:secret"},
		{"https://x", "-F", "a=b", "-d", "c"},
		{"https://x", "-F", "nameonly"},
		{"https://x", "-b", "-"},
		{"https://x", "--cookie-jar", "-"},
		{"https://x", "--cacert"},
	} {
		if _, err := parseCLI(args); err == nil {
			t.Errorf("parseCLI(%q) should error", args)
		}
	}
}

func TestParseCurlRequestOptions(t *testing.T) {
	cases := []struct {
		cmd     string
		tls     TLSOptions
		file    string
		jar     string
		headers []Header
	}{
		{cmd: `curl -k https://x`, tls: TLSOptions{Insecure: true}},
		{cmd: `curl -sSLk https://x`, tls: TLSOptions{Insecure: true}},
		{cmd: `curl --cacert ca.pem -E c.pem --key k.pem https://x`, tls: TLSOptions{CACert: "ca.pem", Cert: "c.pem", Key: "k.pem"}},
		{cmd: `curl -Ec.pem --cert-type PEM https://x`, tls: TLSOptions{Cert: "c.pem"}},
		{cmd: `curl -b 'a=1; b=2' https://x`, headers: []Header{{Key: "Cookie", Value: "a=1; b=2"}}},
		{cmd: `curl -b jar.txt -c out.txt https://x`, file: "jar.txt", jar: "out.txt"},
		{cmd: `curl -cout.txt --cookie-jar out2.txt https://x`, jar: "out2.txt"},
	}
	for _, c := range cases {
		argv, err := tokenizeShell(c.cmd)
		if err != nil {
			t.Fatal(err)
		}
		s, err := parseCurl(argv)
		if err != nil {
			t.Errorf("%s: %v", c.cmd, err)
			continue
		}
		if s.URL != "https://x" || s.TLS != c.tls || s.CookieFile != c.file || s.CookieJar != c.jar || len(s.Headers) != len(c.headers) {
			t.Errorf("%s: got url %q tls %+v file %q jar %q headers %+v", c.cmd, s.URL, s.TLS, s.CookieFile, s.CookieJar, s.Headers)
		}
		for i := range c.headers {
			if s.Headers[i] != c.headers[i] {
				t.Errorf("%s: header %d = %+v, want %+v", c.cmd, i, s.Headers[i], c.headers[i])
			}
		}
	}

	for _, cmd := range []string{
		`curl --cert c.pem:secret https://x`,
		`curl --cert-type P12 --cert c.p12 https://x`,
		`curl -b - https://x`,
		`curl -c - https://x`,
	} {
		argv, _ := tokenizeShell(cmd)
		if _, err := parseCurl(argv); err == nil {
			t.Errorf("parseCurl(%s) should error", cmd)
		}
	}
}

// Every new option survives export and re-import, and the colored rendering
// is the same command.
func TestToCurlRequestOptionsRoundTrip(t *testing.T) {
	specs := []RequestSpec{
		{URL: "https://x", TLS: TLSOptions{Insecure: true}},
		{URL: "https://x", TLS: TLSOptions{CACert: "my ca.pem", Cert: `C:\certs\a:b.pem`, Key: "-k.pem"}},
		{URL: "https://x", CookieFile: "jar.txt", CookieJar: "out jar.txt"},
		{Method: "POST", URL: "https://x", TLS: TLSOptions{Insecure: true, Cert: "c.pem"}, CookieJar: "j",
			Headers: []Header{{Key: "Accept", Value: "*/*"}},
			Form:    []FormField{{Name: "a", Value: "b"}, {Name: "up", Kind: formFile, Value: "f.txt"}}},
	}
	for _, spec := range specs {
		for _, multiline := range []bool{false, true} {
			exported := toCurl(spec, multiline)
			argv, err := tokenizeShell(exported)
			if err != nil {
				t.Fatalf("%s: %v", exported, err)
			}
			back, err := parseCurl(argv)
			if err != nil {
				t.Fatalf("%s: %v", exported, err)
			}
			if d := specDiff(spec, back); d != "" {
				t.Errorf("round trip changed %s:\n%s", d, exported)
			}
			if plain := ansi.Strip(renderCurl(spec, newStyles(), true, multiline)); plain != exported {
				t.Errorf("colored renderCurl differs:\n got %q\nwant %q", plain, exported)
			}
		}
	}
	if got := toCurl(specs[0], false); got != "curl https://x -k" {
		t.Errorf("toCurl = %q, want curl https://x -k", got)
	}
}

// The TUI shows what it will send: a red badge for -k, the TLS and cookie
// files on one line, -F parts in place of the body, and all of it reaches
// the request and the ctrl+x export.
func TestTUIRequestOptions(t *testing.T) {
	clearRequestEnv(t)
	m := testModel()
	m.prefill(cliArgs{
		method:     "POST",
		url:        "https://x",
		tls:        TLSOptions{Insecure: true, CACert: "ca.pem"},
		form:       []FormField{{Name: "a", Value: "b"}},
		cookieFile: "jar.txt",
		cookieJar:  "out.txt",
	})
	mm := send(t, m, tea.WindowSizeMsg{Width: 120, Height: 40}).(model)
	view := ansi.Strip(mm.View().Content)
	for _, want := range []string{"INSECURE", "--cacert ca.pem", "-b jar.txt", "--cookie-jar out.txt", "-F a=b"} {
		if !strings.Contains(view, want) {
			t.Errorf("view missing %q:\n%s", want, view)
		}
	}

	spec := mm.specFromForm()
	if spec.TLS != mm.tlsOpts || len(spec.Form) != 1 || spec.Body != nil || spec.CookieFile != "jar.txt" || spec.CookieJar != "out.txt" {
		t.Errorf("specFromForm dropped options: %+v", spec)
	}
	mm = send(t, mm, kp("ctrl+x")).(model)
	if curl := ansi.Strip(mm.resp.View()); !strings.Contains(curl, "-k") || !strings.Contains(curl, "-F") {
		t.Errorf("ctrl+x export missing -k/-F:\n%s", curl)
	}

	plain := send(t, testModel(), tea.WindowSizeMsg{Width: 120, Height: 40}).(model)
	if strings.Contains(ansi.Strip(plain.View().Content), "INSECURE") {
		t.Error("the INSECURE badge should only show with -k")
	}
}
