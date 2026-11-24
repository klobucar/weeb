package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	stdlog "log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/log/v2"
)

func TestProbeTargetsFor(t *testing.T) {
	tests := []struct {
		in                       string
		host, addr, https, plain string
	}{
		{"example.com", "example.com", "example.com:443", "https://example.com/", "http://example.com/"},
		{"example.com:8443", "example.com", "example.com:8443", "https://example.com:8443/", "http://example.com/"},
		{"https://example.com/login?x=1", "example.com", "example.com:443", "https://example.com/login?x=1", "http://example.com/login?x=1"},
		{"http://example.com:8080/a", "example.com", "example.com:443", "https://example.com/a", "http://example.com:8080/a"},
		{"HTTPS://Example.com", "Example.com", "Example.com:443", "https://Example.com/", "http://Example.com/"},
		{"[::1]:8443", "::1", "[::1]:8443", "https://[::1]:8443/", "http://[::1]/"},
	}
	for _, tt := range tests {
		got, err := probeTargetsFor(tt.in)
		if err != nil {
			t.Errorf("%q: %v", tt.in, err)
			continue
		}
		want := probeTargets{tt.host, tt.addr, tt.https, tt.plain}
		if got != want {
			t.Errorf("%q = %+v, want %+v", tt.in, got, want)
		}
	}
	for _, bad := range []string{"", "ftp://example.com", "https://"} {
		if _, err := probeTargetsFor(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

func TestProbeRedirectFinding(t *testing.T) {
	const host = "example.com"
	hop := func(u string, status int, loc string) probeHop {
		return probeHop{URL: u, Status: status, Location: loc}
	}
	tests := []struct {
		name   string
		hops   []probeHop
		grade  auditGrade
		reason string
	}{
		{"301 same host", []probeHop{hop("http://example.com/", 301, "https://example.com/")}, gradePass, "301 to"},
		{"308 same host", []probeHop{hop("http://example.com/", 308, "https://example.com/")}, gradePass, "308 to"},
		{"302 temporary", []probeHop{hop("http://example.com/", 302, "https://example.com/")}, gradeWarn, "302 is temporary"},
		{"via www", []probeHop{
			hop("http://example.com/", 301, "http://www.example.com/"),
			hop("http://www.example.com/", 301, "https://www.example.com/"),
		}, gradeWarn, "not https on the same host"},
		{"other host https", []probeHop{hop("http://example.com/", 301, "https://cdn.example.net/")}, gradeWarn, "not https on the same host"},
		{"serves plain", []probeHop{hop("http://example.com/", 200, "")}, gradeFail, "serves 200 over plain http"},
		{"stays plain", []probeHop{
			hop("http://example.com/", 301, "http://example.com/home"),
			hop("http://example.com/home", 200, ""),
		}, gradeFail, "stay on plain http, ending at 200"},
		{"broken chain", []probeHop{
			hop("http://example.com/", 301, "http://www.example.com/"),
			{URL: "http://www.example.com/", Error: "connection refused"},
		}, gradeFail, "chain broke"},
		{"port 80 closed", []probeHop{{URL: "http://example.com/", Error: "connection refused"}}, gradePass, "doesn't answer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := probeRedirectFinding(tt.hops, host)
			if f.Grade != tt.grade || !strings.Contains(f.Reason, tt.reason) {
				t.Errorf("got %s %q, want %s containing %q", f.Grade, f.Reason, tt.grade, tt.reason)
			}
		})
	}

	loop := make([]probeHop, probeMaxHops)
	for i := range loop {
		loop[i] = hop("http://example.com/", 301, "http://example.com/")
	}
	if f := probeRedirectFinding(loop, host); f.Grade != gradeFail || !strings.Contains(f.Reason, "without reaching https") {
		t.Errorf("loop: %s %q", f.Grade, f.Reason)
	}
}

func TestProbeVersionFinding(t *testing.T) {
	with13 := map[uint16]bool{tls.VersionTLS13: true}
	tests := []struct {
		p       probeProtocol
		offered map[uint16]bool
		grade   auditGrade
	}{
		{probeProtocol{Version: "TLS 1.0", Offered: true}, nil, gradeFail},
		{probeProtocol{Version: "TLS 1.1"}, nil, gradePass},
		{probeProtocol{Version: "TLS 1.2", Offered: true}, nil, gradePass},
		{probeProtocol{Version: "TLS 1.2"}, with13, gradePass},
		{probeProtocol{Version: "TLS 1.2"}, nil, gradeFail},
		{probeProtocol{Version: "TLS 1.3"}, nil, gradeWarn},
		{probeProtocol{Version: "TLS 1.0", unsure: true, Error: "i/o timeout"}, nil, gradeWarn},
	}
	for _, tt := range tests {
		if f := probeVersionFinding(tt.p, tt.offered); f.Grade != tt.grade {
			t.Errorf("%+v: grade %s (%q), want %s", tt.p, f.Grade, f.Reason, tt.grade)
		}
	}
}

// probeServers starts a TLS server with tlsCfg and a plain-http server
// answering with plain, and returns probe targets aimed at the pair.
func probeServers(t *testing.T, tlsCfg *tls.Config, plain http.HandlerFunc) probeTargets {
	t.Helper()
	page := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = io.WriteString(w, "hi")
	})
	sec := httptest.NewUnstartedServer(page)
	sec.TLS = tlsCfg
	sec.EnableHTTP2 = tlsCfg.CipherSuites == nil        // HTTP/2 refuses the CBC-only legacy suites
	sec.Config.ErrorLog = stdlog.New(io.Discard, "", 0) // the probe's rejected handshakes are the point
	sec.StartTLS()
	t.Cleanup(sec.Close)
	if plain == nil {
		plain = func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, sec.URL+r.URL.Path, http.StatusMovedPermanently)
		}
	}
	ins := httptest.NewServer(plain)
	t.Cleanup(ins.Close)
	return probeTargets{
		host:     "127.0.0.1",
		addr:     sec.Listener.Addr().String(),
		httpsURL: sec.URL + "/",
		httpURL:  ins.URL + "/",
	}
}

func probeGrades(rep probeReport) map[string]auditGrade {
	out := map[string]auditGrade{}
	for _, f := range rep.findings() {
		out[f.ID] = f.Grade
	}
	return out
}

func testProbeClient() *Client {
	c := newClient(log.New(io.Discard), plainErrorChan{})
	c.SetTimeout(5 * time.Second)
	c.noHistory = true
	return c
}

// A server stuck in 2015: TLS 1.0-1.2, CBC and 3DES suites with static RSA.
func TestProbeLegacyServer(t *testing.T) {
	tg := probeServers(t, &tls.Config{
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}, nil)
	rep, err := probe(tg, probeOptions{timeout: 5 * time.Second, insecure: true}, testProbeClient())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]auditGrade{
		"tls1.0": gradeFail, "tls1.1": gradeFail, "tls1.2": gradePass, "tls1.3": gradeWarn,
		"weak_ciphers": gradeFail, "forward_secrecy": gradeWarn,
		"certificate":   gradeFail, // httptest's cert isn't in the system roots
		"http_redirect": gradePass,
		"hsts":          gradePass, "nosniff": gradePass,
	}
	got := probeGrades(rep)
	for id, g := range want {
		if got[id] != g {
			t.Errorf("%s = %s, want %s", id, got[id], g)
		}
	}
	if rep.Conn == nil || rep.Conn.Version != "TLS 1.2" {
		t.Errorf("default handshake = %+v, want TLS 1.2", rep.Conn)
	}
	if rep.Certificate == nil || rep.Status != 200 || len(rep.HTTP) != 1 {
		t.Errorf("cert %v, status %d, hops %+v", rep.Certificate, rep.Status, rep.HTTP)
	}
	if rep.Pass+rep.Warn+rep.Fail != len(rep.findings()) || rep.Fail == 0 {
		t.Errorf("tally %d/%d/%d of %d", rep.Pass, rep.Warn, rep.Fail, len(rep.findings()))
	}
}

// Go's defaults are a modern server: TLS 1.2+, ECDHE AEAD suites only.
func TestProbeModernServer(t *testing.T) {
	tg := probeServers(t, &tls.Config{}, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "plain hello") // no upgrade
	})
	rep, err := probe(tg, probeOptions{timeout: 5 * time.Second}, testProbeClient())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]auditGrade{
		"tls1.0": gradePass, "tls1.1": gradePass, "tls1.2": gradePass, "tls1.3": gradePass,
		"weak_ciphers": gradePass, "forward_secrecy": gradePass,
		"http_redirect": gradeFail,
		"headers":       gradeFail, // untrusted cert and no -k: headers not fetched
	}
	got := probeGrades(rep)
	for id, g := range want {
		if got[id] != g {
			t.Errorf("%s = %s, want %s", id, got[id], g)
		}
	}
	for _, f := range rep.findings() {
		if f.ID == "headers" && !strings.Contains(f.Reason, "-k grades the headers anyway") {
			t.Errorf("headers reason = %q", f.Reason)
		}
	}
	if rep.Conn == nil || rep.Conn.Version != "TLS 1.3" || rep.Conn.ALPN != "h2" {
		t.Errorf("default handshake = %+v, want TLS 1.3 + h2", rep.Conn)
	}

	out := renderProbe(rep, newStyles(), false, false)
	for _, s := range []string{"Probe  127.0.0.1", "TLS  " + tg.addr, "✔ PASS  TLS 1.0 ", "✘ FAIL  HTTPS redirect", "Plain HTTP  " + tg.httpURL} {
		if !strings.Contains(out, s) {
			t.Errorf("render missing %q:\n%s", s, out)
		}
	}

	v := checkProbe(rep)
	if v.Code != checkCritical || !strings.HasPrefix(v.line(), "PROBE CRITICAL - ") {
		t.Errorf("verdict = %q (code %d)", v.line(), v.Code)
	}
	if b, err := json.Marshal(rep); err != nil || !strings.Contains(string(b), `"sections"`) {
		t.Errorf("json: %v %s", err, b)
	}
}

func TestRunProbeErrors(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadHost := strings.TrimPrefix(dead.URL, "http://")
	dead.Close() // nothing listens there now; port 80 on 127.0.0.1 may, so aim http there too

	tests := []struct {
		name   string
		args   []string
		code   int
		prefix string
	}{
		{"no host", nil, 2, ""},
		{"unknown flag", []string{"example.com", "--bogus"}, 2, ""},
		{"two hosts", []string{"a.example", "b.example"}, 2, ""},
		{"bad scheme", []string{"ftp://example.com"}, 2, ""},
		{"bad header", []string{"example.com", "-H", "nocolon"}, 2, ""},
		{"bad timeout", []string{"example.com", "--timeout", "soon"}, 2, ""},
		{"bad persona", []string{"example.com", "--persona", "nope"}, 2, ""},
		{"unreachable check", []string{"http://" + deadHost, "--check", "--timeout", "2s"}, -1, "PROBE "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := swapOutW(t)
			code := runProbe(tt.args)
			if tt.code >= 0 && code != tt.code {
				t.Errorf("exit = %d, want %d", code, tt.code)
			}
			if !strings.HasPrefix(buf.String(), tt.prefix) || (tt.prefix == "" && buf.Len() != 0) {
				t.Errorf("stdout = %q, want prefix %q", buf.String(), tt.prefix)
			}
		})
	}
}

func TestCompletionProbeFlags(t *testing.T) {
	for name, script := range map[string]string{"zsh": zshCompletion(), "bash": bashCompletion(), "fish": fishCompletion()} {
		if !strings.Contains(script, "probe") {
			t.Errorf("%s script has no probe", name)
		}
		for _, f := range completionProbeFlags {
			if !strings.Contains(script, strings.TrimLeft(f, "-")) {
				t.Errorf("%s script missing probe flag %q", name, f)
			}
		}
	}
}

// Every non-passing check carries a fix; passing ones and "no answer" don't.
func TestProbeAndAuditFixes(t *testing.T) {
	for _, f := range auditHeaders(auditHdr(), true) {
		if (f.Grade == gradePass) != (f.Fix == "") {
			t.Errorf("%s: grade %s, fix %q", f.ID, f.Grade, f.Fix)
		}
	}
	if f := auditFindingByID(t, auditHdr("X-Content-Type-Options", "nosniff"), true, "nosniff"); f.Fix != "" {
		t.Errorf("passing nosniff has fix %q", f.Fix)
	}
	if f := probeVersionFinding(probeProtocol{Version: "TLS 1.0", Offered: true}, nil); !strings.Contains(f.Fix, "TLS 1.2 the minimum") {
		t.Errorf("tls1.0 fix = %q", f.Fix)
	}
	if f := probeVersionFinding(probeProtocol{Version: "TLS 1.0", unsure: true}, nil); f.Fix != "" {
		t.Errorf("unsure tls1.0 has fix %q", f.Fix)
	}
	hops := []probeHop{{URL: "http://example.com/", Status: 302, Location: "https://example.com/"}}
	if f := probeRedirectFinding(hops, "example.com"); !strings.Contains(f.Fix, "301") {
		t.Errorf("302 fix = %q", f.Fix)
	}

	rep := newAuditReport(Result{URL: "https://a.example/", Status: 200, Headers: auditHdr()})
	if out := renderAudit(rep, newStyles(), false, true); !strings.Contains(out, "fix: send Strict-Transport-Security: max-age=31536000") {
		t.Errorf("--fix render has no HSTS fix line:\n%s", out)
	}
	if out := renderAudit(rep, newStyles(), false, false); strings.Contains(out, "fix:") {
		t.Errorf("default render shows fixes:\n%s", out)
	}
}

// ctrl+l probes the URL in the form and shows the report in the response
// pane as foldable sections; ctrl+l again returns to the response.
func TestProbePane(t *testing.T) {
	var m tea.Model = testModel()
	m = send(t, m, tea.WindowSizeMsg{Width: 120, Height: 70})

	next, cmd := m.Update(kp("ctrl+l"))
	if !next.(model).inFlight || cmd == nil {
		t.Fatal("ctrl+l should start a probe")
	}

	rep := probeReport{
		Host: "example.com", Address: "example.com:443",
		Conn: &probeConn{Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", ALPN: "h2"},
		Sections: []probeSection{
			{Name: "TLS", Detail: "example.com:443", Findings: []auditFinding{
				probeVersionFinding(probeProtocol{Version: "TLS 1.0", Offered: true}, nil),
				probeVersionFinding(probeProtocol{Version: "TLS 1.3", Offered: true, Cipher: "TLS_AES_128_GCM_SHA256"}, nil),
			}},
			{Name: "Plain HTTP", Detail: "http://example.com/", Findings: []auditFinding{
				probeRedirectFinding([]probeHop{{URL: "http://example.com/", Status: 301, Location: "https://example.com/"}}, "example.com"),
			}},
		},
	}
	rep.tally()
	m = send(t, next, probeMsg{rep: rep})
	mm := m.(model)
	if mm.inFlight || mm.pane != paneProbe || len(mm.respSections) != 2 {
		t.Fatalf("inFlight=%v pane=%v sections=%d", mm.inFlight, mm.pane, len(mm.respSections))
	}
	out := m.View().Content
	for _, want := range []string{"Probe  example.com", "TLS 1.3 · TLS_AES_128_GCM_SHA256 · ALPN h2", "1 fail", "all pass", "FAIL", "f show fixes"} {
		if !strings.Contains(out, want) {
			t.Errorf("probe pane missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "TLS 1.2 the minimum") {
		t.Errorf("fixes should start hidden:\n%s", out)
	}

	// f in the focused probe pane shows the fixes, and again hides them.
	var fm tea.Model = focusResponse(m.(model))
	fm = send(t, fm, kp("f"))
	if out := probePaneText(fm); !strings.Contains(out, "TLS 1.2 the minimum") {
		t.Errorf("f should show fixes:\n%s", out)
	}
	fm = send(t, fm, kp("f"))
	if out := probePaneText(fm); strings.Contains(out, "TLS 1.2 the minimum") {
		t.Errorf("second f should hide fixes:\n%s", out)
	}

	m = send(t, m, kp("ctrl+l"))
	if m.(model).pane != paneResponse {
		t.Errorf("second ctrl+l should return to the response, pane = %v", m.(model).pane)
	}

	m = send(t, m, probeMsg{err: errProbeUnreachable})
	if out := m.View().Content; !strings.Contains(out, "Probe") || !strings.Contains(out, "unreachable") {
		t.Errorf("error pane:\n%s", out)
	}
}

// probePaneText is the response pane's content, fixes and all.
func probePaneText(m tea.Model) string {
	mm := m.(model)
	return mm.composeResponse()
}
