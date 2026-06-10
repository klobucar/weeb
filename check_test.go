package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCheckSafe(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain", "example.com ok", "example.com ok"},
		{"ansi stripped", "\x1b[31mred\x1b[0m CN", "red CN"},
		{"osc stripped", "\x1b]52;c;ZXZpbA==\x07cn", "cn"},
		{"newline flattened", "line1\nline2", "line1 line2"},
		{"pipe escaped", "a|b", "a/b"},
	}
	for _, c := range cases {
		if got := checkSafe(c.in); got != c.want {
			t.Errorf("%s: checkSafe(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestParseExpectStatus(t *testing.T) {
	cases := []struct {
		spec    string
		code    int
		want    bool
		wantErr bool
	}{
		{"200", 200, true, false},
		{"200", 201, false, false},
		{"2xx", 204, true, false},
		{"2xx", 301, false, false},
		{"200-204,301", 301, true, false},
		{"200-204,301", 302, false, false},
		{"200-204,301", 203, true, false},
		{"5xx", 503, true, false},
		{"6xx", 0, false, true},
		{"abc", 0, false, true},
		{"300-200", 0, false, true},
		{"", 0, false, true},
		{",,", 0, false, true},
	}
	for _, c := range cases {
		f, err := parseExpectStatus(c.spec)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseExpectStatus(%q) should error", c.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseExpectStatus(%q): %v", c.spec, err)
			continue
		}
		if got := f(c.code); got != c.want {
			t.Errorf("expect %q on %d = %v, want %v", c.spec, c.code, got, c.want)
		}
	}
}

func TestCheckCert(t *testing.T) {
	rep := func(days int, verified, skipped bool) *certReport {
		return &certReport{
			Host: "example.com", Port: "443",
			Verified: verified, Skipped: skipped,
			VerifyErr: "x509: untrusted",
			Chain: []certInfo{{
				DaysUntilExpiry: days,
				NotAfter:        time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC),
			}},
		}
	}
	cases := []struct {
		name     string
		rep      *certReport
		wantCode int
		wantSub  string
	}{
		{"ok", rep(87, true, false), checkOK, "CERT OK - example.com:443 expires in 87 days"},
		{"warn threshold", rep(21, true, false), checkWarning, "CERT WARNING"},
		{"warn boundary", rep(30, true, false), checkWarning, "CERT WARNING"},
		{"crit threshold", rep(14, true, false), checkCritical, "CERT CRITICAL"},
		{"expired", rep(-3, true, false), checkCritical, "expired 3 days ago"},
		{"untrusted", rep(87, false, false), checkCritical, "untrusted: x509: untrusted"},
		{"untrusted skipped (-k)", rep(87, false, true), checkOK, "CERT OK"},
		{"empty chain", &certReport{Host: "h", Port: "443"}, checkUnknown, "presented no certificates"},
	}
	for _, c := range cases {
		v := checkCert(c.rep, 30, 14)
		line := v.line()
		if v.Code != c.wantCode {
			t.Errorf("%s: code = %d, want %d (line %q)", c.name, v.Code, c.wantCode, line)
		}
		if !strings.Contains(line, c.wantSub) {
			t.Errorf("%s: line %q should contain %q", c.name, line, c.wantSub)
		}
		if strings.Contains(line, "\n") {
			t.Errorf("%s: plugin output must be one line: %q", c.name, line)
		}
	}

	// Perfdata carries the days and both thresholds.
	if line := checkCert(rep(87, true, false), 30, 14).line(); !strings.HasSuffix(line, "|days=87;30;14") {
		t.Errorf("perfdata missing or wrong: %q", line)
	}
	// A hostile CN/verify error can't smuggle escapes or break the line format.
	bad := rep(87, false, false)
	bad.VerifyErr = "x509: \x1b]52;c;x\x07evil\nline|pipe"
	if line := checkCert(bad, 30, 14).line(); strings.ContainsAny(line, "\x1b\n") {
		t.Errorf("hostile verify error leaked control bytes: %q", line)
	}
}

// The --json rendering carries the same verdict as the plugin line, as one
// JSON object with typed metrics, so script_exporter-style consumers don't
// have to parse perfdata.
func TestCheckVerdictJSON(t *testing.T) {
	rep := &certReport{
		Host: "example.com", Port: "443", Verified: true,
		Chain: []certInfo{{
			DaysUntilExpiry: 21,
			NotAfter:        time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		}},
	}
	out := checkCert(rep, 30, 14).json()
	if strings.Contains(out, "\n") {
		t.Errorf("JSON verdict must be one line: %q", out)
	}
	var v struct {
		Check   string         `json:"check"`
		Status  string         `json:"status"`
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Metrics map[string]any `json:"metrics"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("unmarshal %q: %v", out, err)
	}
	if v.Check != "cert" || v.Status != "WARNING" || v.Code != 1 {
		t.Errorf("verdict = %+v", v)
	}
	if !strings.Contains(v.Message, "expires in 21 days") {
		t.Errorf("message = %q", v.Message)
	}
	if v.Metrics["days_until_expiry"] != float64(21) || v.Metrics["warn_days"] != float64(30) {
		t.Errorf("metrics = %v", v.Metrics)
	}

	// HTTP side: status/time/size plus TLS leaf days.
	hres := Result{
		Status: 200, StatusText: "OK", Body: []byte("hello"),
		Timing: Timing{Total: 123 * time.Millisecond},
		TLS:    &connTLS{Leaf: &certInfo{DaysUntilExpiry: 87}},
	}
	hout := checkHTTP(hres, checkHTTPOpts{warn: 500 * time.Millisecond}).json()
	var hv struct {
		Check   string         `json:"check"`
		Status  string         `json:"status"`
		Metrics map[string]any `json:"metrics"`
	}
	if err := json.Unmarshal([]byte(hout), &hv); err != nil {
		t.Fatalf("unmarshal %q: %v", hout, err)
	}
	if hv.Check != "http" || hv.Status != "OK" {
		t.Errorf("verdict = %+v", hv)
	}
	for k, want := range map[string]float64{
		"http_status": 200, "time_ms": 123, "size_bytes": 5,
		"warn_ms": 500, "days_until_expiry": 87,
	} {
		if hv.Metrics[k] != want {
			t.Errorf("metrics[%s] = %v, want %v", k, hv.Metrics[k], want)
		}
	}
	if _, ok := hv.Metrics["crit_ms"]; ok {
		t.Error("unset crit threshold should be omitted from metrics")
	}
}

func TestCheckHTTP(t *testing.T) {
	res := func(status int, body string, total time.Duration) Result {
		return Result{
			Status: status, StatusText: http.StatusText(status),
			Body:   []byte(body),
			Timing: Timing{Total: total},
		}
	}
	expect2xx, _ := parseExpectStatus("2xx")
	cases := []struct {
		name     string
		res      Result
		opts     checkHTTPOpts
		wantCode int
		wantSub  string
	}{
		{"ok default", res(200, "hi", 120*time.Millisecond), checkHTTPOpts{},
			checkOK, "HTTP OK - 200 OK in 120 ms, 2 bytes"},
		{"3xx ok by default", res(302, "", time.Millisecond), checkHTTPOpts{},
			checkOK, "HTTP OK"},
		{"5xx critical by default", res(503, "", time.Millisecond), checkHTTPOpts{},
			checkCritical, "HTTP CRITICAL - 503 Service Unavailable (expected status < 400)"},
		{"custom expect fails on 302", res(302, "", time.Millisecond),
			checkHTTPOpts{expectSpec: "2xx", expect: expect2xx},
			checkCritical, "(expected 2xx)"},
		{"custom expect allows 5xx", res(503, "", time.Millisecond),
			checkHTTPOpts{expectSpec: "5xx", expect: mustExpect(t, "5xx")},
			checkOK, "HTTP OK - 503"},
		{"body match", res(200, `{"status":"ok"}`, time.Millisecond),
			checkHTTPOpts{bodyRe: mustOpts(t, cliArgs{check: true, expectBody: `"status":"ok"`}).bodyRe},
			checkOK, "HTTP OK"},
		{"body mismatch", res(200, `{"status":"down"}`, time.Millisecond),
			checkHTTPOpts{bodyRe: mustOpts(t, cliArgs{check: true, expectBody: `"status":"ok"`}).bodyRe},
			checkCritical, `body does not match`},
		{"warn time", res(200, "", 700*time.Millisecond),
			checkHTTPOpts{warn: 500 * time.Millisecond, crit: 2 * time.Second},
			checkWarning, "HTTP WARNING - 200 OK in 700 ms (warn at 500ms)"},
		{"crit time", res(200, "", 3*time.Second),
			checkHTTPOpts{warn: 500 * time.Millisecond, crit: 2 * time.Second},
			checkCritical, "(crit at 2s)"},
		{"transport error", Result{Err: errTest}, checkHTTPOpts{},
			checkCritical, "HTTP CRITICAL - dial tcp: connection refused"},
	}
	for _, c := range cases {
		v := checkHTTP(c.res, c.opts)
		line := v.line()
		if v.Code != c.wantCode {
			t.Errorf("%s: code = %d, want %d (line %q)", c.name, v.Code, c.wantCode, line)
		}
		if !strings.Contains(line, c.wantSub) {
			t.Errorf("%s: line %q should contain %q", c.name, line, c.wantSub)
		}
	}

	// An incomplete body (read error with a passing status) must not pretend
	// the assertions ran against real data.
	trunc := res(200, "partial", time.Millisecond)
	trunc.Err = errTest
	if v := checkHTTP(trunc, checkHTTPOpts{}); v.Code != checkCritical || !strings.Contains(v.line(), "body incomplete") {
		t.Errorf("incomplete body: got %d %q", v.Code, v.line())
	}

	// Perfdata: time with thresholds, size, and TLS leaf days when present.
	tlsRes := res(200, "hello", 123*time.Millisecond)
	tlsRes.TLS = &connTLS{Leaf: &certInfo{DaysUntilExpiry: 87}}
	line := checkHTTP(tlsRes, checkHTTPOpts{warn: 500 * time.Millisecond, crit: 2 * time.Second}).line()
	if !strings.Contains(line, "|time=0.123s;0.500;2.000 size=5B days_until_expiry=87") {
		t.Errorf("perfdata wrong: %q", line)
	}
}

// mustExpect compiles an --expect-status spec or fails the test.
func mustExpect(t *testing.T, spec string) func(int) bool {
	t.Helper()
	f, err := parseExpectStatus(spec)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// mustOpts compiles a cliArgs' check options or fails the test.
func mustOpts(t *testing.T, a cliArgs) checkHTTPOpts {
	t.Helper()
	o, err := a.checkOpts()
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestCheckOptsValidation(t *testing.T) {
	if _, err := (cliArgs{check: true, output: "f"}).checkOpts(); err == nil {
		t.Error("-o with --check should error")
	}
	if _, err := (cliArgs{check: true, warn: 2 * time.Second, crit: time.Second}).checkOpts(); err == nil {
		t.Error("--crit below --warn should error")
	}
	if _, err := (cliArgs{check: true, expectBody: "("}).checkOpts(); err == nil {
		t.Error("bad regexp should error")
	}
	if _, err := (cliArgs{check: true, expectStatus: "abc"}).checkOpts(); err == nil {
		t.Error("bad status spec should error")
	}
}

// swapOutW redirects the stdout boundary writer into a buffer for the test.
func swapOutW(t *testing.T) *strings.Builder {
	t.Helper()
	var buf strings.Builder
	old := outW
	outW = &buf
	t.Cleanup(func() { outW = old })
	return &buf
}

// runCLI in --check mode end to end: the only stdout output is the plugin
// line, the exit code is the verdict, and the body is buffered for the
// pattern check even though stdout is not a TTY (no streaming).
func TestRunCLICheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	buf := swapOutW(t)
	code := runCLI(cliArgs{method: "GET", url: srv.URL, check: true, expectBody: `"status":"ok"`})
	if code != checkOK {
		t.Fatalf("exit = %d, want 0 (output %q)", code, buf.String())
	}
	out := buf.String()
	if !strings.HasPrefix(out, "HTTP OK - 200 OK") {
		t.Errorf("plugin line = %q", out)
	}
	if strings.Contains(out, `{"status"`) {
		t.Errorf("body leaked into plugin output: %q", out)
	}

	// Usage errors are UNKNOWN on stdout, not weeb's stderr/2.
	buf2 := swapOutW(t)
	if code := runCLI(cliArgs{method: "GET", url: srv.URL, check: true, expectBody: "("}); code != checkUnknown {
		t.Errorf("bad pattern: exit = %d, want 3", code)
	}
	if !strings.HasPrefix(buf2.String(), "HTTP UNKNOWN - ") {
		t.Errorf("bad pattern output = %q", buf2.String())
	}

	// --json: the same verdict as one JSON object, same exit code.
	buf3 := swapOutW(t)
	if code := runCLI(cliArgs{method: "GET", url: srv.URL, check: true, checkJSON: true}); code != checkOK {
		t.Fatalf("json exit = %d, want 0 (output %q)", code, buf3.String())
	}
	var v struct {
		Check   string         `json:"check"`
		Status  string         `json:"status"`
		Metrics map[string]any `json:"metrics"`
	}
	if err := json.Unmarshal([]byte(buf3.String()), &v); err != nil {
		t.Fatalf("output is not JSON: %q (%v)", buf3.String(), err)
	}
	if v.Check != "http" || v.Status != "OK" || v.Metrics["http_status"] != float64(200) {
		t.Errorf("json verdict = %+v", v)
	}
}

// `weeb cert --check --json` renders even usage errors as a JSON UNKNOWN
// verdict (here: thresholds the wrong way round — no dial happens).
func TestRunCertCheckJSONUnknown(t *testing.T) {
	buf := swapOutW(t)
	if code := runCert([]string{"localhost:1", "--check", "--json", "-w", "5", "-c", "30"}); code != checkUnknown {
		t.Fatalf("exit = %d, want 3 (output %q)", code, buf.String())
	}
	var v struct {
		Check  string `json:"check"`
		Status string `json:"status"`
		Code   int    `json:"code"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &v); err != nil {
		t.Fatalf("output is not JSON: %q (%v)", buf.String(), err)
	}
	if v.Check != "cert" || v.Status != "UNKNOWN" || v.Code != 3 {
		t.Errorf("json verdict = %+v", v)
	}
}

// The assertion flags are meaningless without --check and must error loudly
// rather than silently not asserting.
func TestExpectFlagsRequireCheck(t *testing.T) {
	if code := runCLI(cliArgs{method: "GET", url: "http://x", expectBody: "ok"}); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if code := runCLI(cliArgs{method: "GET", url: "http://x", checkJSON: true}); code != 2 {
		t.Errorf("--json without --check: exit = %d, want 2", code)
	}
}

func TestParseCLICheckFlags(t *testing.T) {
	a, err := parseCLI([]string{"https://x", "--check",
		"--expect-status", "2xx", "--expect-body", "ok", "-w", "500ms", "-c", "2s"})
	if err != nil {
		t.Fatal(err)
	}
	if !a.check || a.expectStatus != "2xx" || a.expectBody != "ok" {
		t.Errorf("got %+v", a)
	}
	if a.warn != 500*time.Millisecond || a.crit != 2*time.Second {
		t.Errorf("thresholds = %v/%v", a.warn, a.crit)
	}
	if !a.headless() {
		t.Error("--check should imply headless")
	}
	if a2, _ := parseCLI([]string{"https://x", "--nagios"}); !a2.check {
		t.Error("--nagios should remain an alias for --check")
	}
	if _, err := parseCLI([]string{"https://x", "-w", "soon"}); err == nil {
		t.Error("bad -w duration should error")
	}
}
