package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
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

// TestCheckLineSinglePerfdataSeparator: a '|' in a user-supplied value echoed
// into the message (--expect-body 'ok|healthy') must not start the perfdata
// early — monitoring systems split the line at the first '|'.
func TestCheckLineSinglePerfdataSeparator(t *testing.T) {
	res := Result{Status: 200, StatusText: "OK", Body: []byte("degraded")}
	line := checkHTTP(res, mustOpts(t, cliArgs{check: true, expectBody: `ok|healthy`})).line()
	if n := strings.Count(line, "|"); n != 1 {
		t.Errorf("plugin line has %d '|', want 1 (the perfdata separator): %q", n, line)
	}
	if !strings.Contains(line, `body does not match "ok/healthy"`) {
		t.Errorf("message should show the pattern with '|' flattened to '/': %q", line)
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

func TestParseExpectJSON(t *testing.T) {
	cases := []struct {
		expr    string
		wantErr string // "" = must compile
	}{
		{`.status == "ok"`, ""},
		{`.items[0].id != null`, ""},
		{`.count > 0`, ""},
		{`.version =~ "^2\."`, ""},
		{`.data.items | length >= 1`, ""},
		{`.a.b`, ""},
		{`.`, ""},
		{`. | length > 0`, ""},
		{`.["key with spaces"] == "v"`, ""},
		{`.[0]`, ""},
		{`.a[-1]`, ""},
		{`.a.["b"][0]`, ""},
		{`.a[ 0 ]`, ""},
		{`.n <= 1.5e3`, ""},
		{`.o == {"a": [1, 2]}`, ""},
		{`.s >= "2026-01-01"`, ""},
		{`.a=="x"`, ""},
		{`  .x  ==  1  `, ""},
		{`.q =~ "say \"hi\""`, ""},

		{``, "empty expression"},
		{`status == "ok"`, `a path starts with "." (e.g. .status), got 's' at col 1`},
		{`.status = "ok"`, `"=" is not an operator; compare with == at col 9`},
		{`.status == ok`, `value ok is not JSON; strings need double quotes: "ok" at col 12`},
		{`.status == "ok" extra`, `invalid character 'e' after top-level value`},
		{`.status ==`, "missing a value after =="},
		{`.status ~ 1`, "expected an operator (==, !=, <, <=, >, >=, =~), got '~' at col 9"},
		{`.items[0`, `bad --expect-json '.items[0': unclosed "[" at col 7`},
		{`.items[0 1]`, `expected "]", got '1' at col 10`},
		{`.items[]`, "iterating with [] is not supported"},
		{`.items[1.5]`, "an index must be a whole number at col 8"},
		{`.items[99999999999999999999]`, "bad index"},
		{`.items[x]`, `expected an index or a "key" inside [], got 'x'`},
		{`.["a]`, "unterminated string at col 3"},
		{`.["a\q"]`, "bad key string"},
		{`.content-type == "x"`, `unexpected '-' (quote keys with other characters: .["my-key"]) at col 9`},
		{`.a..b`, `expected a key or "[" after ".", got '.'`},
		{`..a`, `recursive descent ".." is not supported`},
		{`.a.`, `expected a key or "[" after ".", got end of expression`},
		{`.0`, "an array index goes in brackets"},
		{`.a | keys`, `only "| length" may follow a path, got 'k' at col 6`},
		{`.a | length`, `"| length" needs a comparison`},
		{`.a | length == "3"`, `"| length" is a number; compare it with a number, not string`},
		{`.a | length =~ "3"`, `=~ matches strings, but "| length" is a number`},
		{`.a =~ ^2`, "=~ needs a double-quoted pattern"},
		{`.a =~ "("`, "bad pattern: error parsing regexp"},
		{`.a =~ "x" y`, `unexpected 'y' after the pattern`},
		{`.a =~ "abc`, "unterminated pattern string at col 7"},
		{`.a > true`, "> compares numbers or strings, not boolean"},
		{`.a < null`, "< compares numbers or strings, not null"},
	}
	for _, c := range cases {
		_, err := parseExpectJSON(c.expr)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("parseExpectJSON(%q): %v", c.expr, err)
		case c.wantErr != "" && err == nil:
			t.Errorf("parseExpectJSON(%q) should fail with %q", c.expr, c.wantErr)
		case c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr):
			t.Errorf("parseExpectJSON(%q) error = %q, want it to contain %q", c.expr, err, c.wantErr)
		}
	}
}

func TestExpectJSONEval(t *testing.T) {
	doc, err := decodeJSONBody([]byte(`{
		"status": "ok", "count": 3, "zero": 0, "neg": -2, "float": 1.5,
		"flag": false, "nothing": null, "version": "2.4.1", "str5": "5",
		"name": "héllo", "key with spaces": "v", "big": 12345678901234567891,
		"items": [{"id": 7}, {"id": null}], "data": {"items": [1, 2]},
		"obj": {"a": [1, 2]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		expr       string
		wantOK     bool
		wantMsg    string // the full failure message ("" when it passes)
		wantActual string // "-" = no actual (nothing was there)
	}{
		{`.status == "ok"`, true, "", `"ok"`},
		{`.status == "down"`, false, `json .status == "down": got "ok"`, `"ok"`},
		{`.status != "ok"`, false, `json .status != "ok": got "ok"`, `"ok"`},
		{`.count > 0`, true, "", "3"},
		{`.count >= 3`, true, "", "3"},
		{`.count < 3`, false, `json .count < 3: got 3`, "3"},
		{`.count == 3.0`, true, "", "3"},
		{`.float < 2`, true, "", "1.5"},
		{`.neg < -1`, true, "", "-2"},
		{`.big == 12345678901234567891`, true, "", "12345678901234567891"},
		{`.big == 12345678901234567890`, false, `json .big == 12345678901234567890: got 12345678901234567891`, "12345678901234567891"},
		{`.big > 12345678901234567890`, true, "", "12345678901234567891"},
		{`.version =~ "^2\."`, true, "", `"2.4.1"`},
		{`.version =~ "^3"`, false, `json .version =~ "^3": got "2.4.1"`, `"2.4.1"`},
		{`.version >= "2.0"`, true, "", `"2.4.1"`},
		{`.items[0].id != null`, true, "", "7"},
		{`.items[1].id != null`, false, `json .items[1].id != null: got null`, "null"},
		{`.items[-1].id == null`, true, "", "null"},
		{`.items[-2].id == 7`, true, "", "7"},
		{`.items[5].id`, false, `json .items[5].id: .items[5] is missing (.items has 2 items)`, "-"},
		{`.data.items | length >= 1`, true, "", "2"},
		{`.data.items | length > 2`, false, `json .data.items | length > 2: got 2`, "2"},
		{`.missing | length >= 1`, false, `json .missing | length >= 1: got 0 (.missing is missing)`, "0"},
		{`.name | length == 5`, true, "", "5"},
		{`. | length > 3`, true, "", "15"},
		{`.status`, true, "", `"ok"`},
		{`.zero`, true, "", "0"},
		{`.flag`, false, `json .flag: got false`, "false"},
		{`.nothing`, false, `json .nothing: got null`, "null"},
		{`.missing`, false, `json .missing: .missing is missing`, "-"},
		{`.missing == null`, true, "", "-"},
		{`.nothing.x`, false, `json .nothing.x: .nothing is null`, "-"},
		{`.["key with spaces"] == "v"`, true, "", `"v"`},
		{`.str5 > 0`, false, `json .str5 > 0: got "5", not a number`, `"5"`},
		{`.count =~ "3"`, false, `json .count =~ "3": got 3, not a string`, "3"},
		{`.items.id`, false, `json .items.id: .items is an array, cannot index it with "id"`, "-"},
		{`.data[0]`, false, `json .data[0]: .data is an object, cannot index it with [0]`, "-"},
		{`.status.x`, false, `json .status.x: .status is a string, cannot index it with "x"`, "-"},
		{`.flag | length > 0`, false, `json .flag | length > 0: .flag is a boolean, which has no length`, "-"},
		{`.obj == {"a": [1, 2.0]}`, true, "", `{"a":[1,2]}`},
		{`.obj == {"a": [1]}`, false, `json .obj == {"a": [1]}: got {"a":[1,2]}`, `{"a":[1,2]}`},
	}
	for _, c := range cases {
		e, err := parseExpectJSON(c.expr)
		if err != nil {
			t.Errorf("parseExpectJSON(%q): %v", c.expr, err)
			continue
		}
		a := e.eval(doc)
		if a.OK != c.wantOK || a.Message != c.wantMsg {
			t.Errorf("%s: ok=%v message=%q, want ok=%v message=%q", c.expr, a.OK, a.Message, c.wantOK, c.wantMsg)
		}
		switch {
		case c.wantActual == "-" && a.Actual != nil:
			t.Errorf("%s: actual = %q, want none", c.expr, *a.Actual)
		case c.wantActual != "-" && (a.Actual == nil || *a.Actual != c.wantActual):
			t.Errorf("%s: actual = %v, want %q", c.expr, a.Actual, c.wantActual)
		}
	}
}

func TestCompareNumbers(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1", "2", -1},
		{"10", "9", 1},
		{"-10", "-9", -1},
		{"-0", "0", 0},
		{"-1", "0", -1},
		{"9007199254740993", "9007199254740992", 1}, // equal as float64
		{"123456789012345678901234567890", "123456789012345678901234567890", 0},
		{"1", "1.0", 0},
		{"1e3", "1000", 0},
		{"2.5", "10", -1},
		{"1e999", "1", 1}, // overflows float64 to +Inf, still ordered
	}
	for _, c := range cases {
		if got := compareNumbers(c.a, c.b); got != c.want {
			t.Errorf("compareNumbers(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParseExpectHeader(t *testing.T) {
	cases := []struct {
		spec       string
		wantName   string
		wantAbsent bool
		wantRe     string
		wantErr    string
	}{
		{"Content-Type", "Content-Type", false, "", ""},
		{"content-type: ^application/json", "Content-Type", false, "^application/json", ""},
		{"  x-foo  :  bar baz  ", "X-Foo", false, "bar baz", ""},
		{"!X-Debug", "X-Debug", true, "", ""},
		{"! x-debug", "X-Debug", true, "", ""},
		{"", "", false, "", "missing header name"},
		{"!", "", false, "", "missing header name"},
		{": x", "", false, "", "missing header name"},
		{"Bad Name: x", "", false, "", `"Bad Name" is not a valid header name`},
		{"!X-Debug: 1", "", false, "", "'!X-Debug' asserts absence and takes no pattern"},
		{"X-Foo:", "", false, "", "empty pattern after ':'"},
		{"X-Foo: (", "", false, "", "bad --expect-header 'X-Foo: (': error parsing regexp"},
	}
	for _, c := range cases {
		h, err := parseExpectHeader(c.spec)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("parseExpectHeader(%q) error = %v, want %q", c.spec, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseExpectHeader(%q): %v", c.spec, err)
			continue
		}
		re := ""
		if h.re != nil {
			re = h.re.String()
		}
		if h.name != c.wantName || h.absent != c.wantAbsent || re != c.wantRe {
			t.Errorf("parseExpectHeader(%q) = %+v, want name %q absent %v re %q", c.spec, h, c.wantName, c.wantAbsent, c.wantRe)
		}
	}
}

func TestHeaderExpectEval(t *testing.T) {
	hdr := http.Header{
		"Content-Type": {"application/json; charset=utf-8"},
		"Set-Cookie":   {"a=1", "session=xyz"},
		"X-Empty":      {""},
	}
	cases := []struct {
		spec    string
		wantOK  bool
		wantMsg string
	}{
		{"Content-Type", true, ""},
		{"content-type: ^application/json", true, ""},
		{"Content-Type: ^text/", false, `header Content-Type "application/json; charset=utf-8" does not match "^text/"`},
		{"Set-Cookie: ^session=", true, ""}, // any one value may match
		{"X-Empty", true, ""},
		{"X-Empty: ^$", true, ""},
		{"X-Missing", false, "header X-Missing missing"},
		{"X-Missing: x", false, "header X-Missing missing"},
		{"!X-Missing", true, ""},
		{"!Set-Cookie", false, `header Set-Cookie present ("a=1, session=xyz"), expected absent`},
	}
	for _, c := range cases {
		h, err := parseExpectHeader(c.spec)
		if err != nil {
			t.Fatal(err)
		}
		a := h.eval(hdr)
		if a.OK != c.wantOK || a.Message != c.wantMsg {
			t.Errorf("%s: ok=%v message=%q, want ok=%v message=%q", c.spec, a.OK, a.Message, c.wantOK, c.wantMsg)
		}
	}
}

func TestCheckClip(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain", "hello", "hello"},
		{"ansi stripped", "\x1b[31mred\x1b[0m", "red"},
		{"controls flattened", "a\nb\tc\x7fd\u009be", "a b c d e"},
		{"invalid utf-8", "a\xffb", "a�b"},
		{"pipe kept (line() maps it)", "a|b", "a|b"},
		{"long cut", strings.Repeat("x", 200), strings.Repeat("x", checkActualMax-1) + "…"},
		{"exactly max", strings.Repeat("é", checkActualMax), strings.Repeat("é", checkActualMax)},
	}
	for _, c := range cases {
		if got := checkClip(c.in); got != c.want {
			t.Errorf("%s: checkClip(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
	// A huge body is clipped without being copied whole.
	if got := bodyExcerpt([]byte(strings.Repeat("y", 1<<20))); utf8.RuneCountInString(got) != checkActualMax || !strings.HasSuffix(got, "…") {
		t.Errorf("bodyExcerpt of 1 MiB = %d runes %q", utf8.RuneCountInString(got), got)
	}
	// So is a huge JSON value.
	big := make([]any, 100000)
	for i := range big {
		big[i] = map[string]any{"id": json.Number("1")}
	}
	if got := jsonPreview(big); utf8.RuneCountInString(got) != checkActualMax || !strings.HasPrefix(got, `[{"id":1},{"id":1}`) {
		t.Errorf("jsonPreview of a large array = %q", got)
	}
}

func TestCheckHTTPAssertions(t *testing.T) {
	res := func(status int, hdr http.Header, body string) Result {
		return Result{
			Status: status, StatusText: http.StatusText(status), Headers: hdr,
			Body: []byte(body), Timing: Timing{Total: time.Millisecond},
		}
	}
	jsonHdr := http.Header{"Content-Type": {"application/json"}, "X-Debug": {"1"}}
	okBody := `{"status":"ok","items":[1,2]}`
	cases := []struct {
		name     string
		res      Result
		args     cliArgs
		wantCode int
		wantMsg  string // the whole message
	}{
		{"all pass", res(200, jsonHdr, okBody),
			cliArgs{expectHeader: []string{"Content-Type: json"}, expectJSON: []string{`.status == "ok"`, `.items | length == 2`}},
			checkOK, "200 OK in 1 ms, 29 bytes"},
		{"one json failure, no count", res(200, jsonHdr, `{"status":"degraded"}`),
			cliArgs{expectJSON: []string{`.status == "ok"`}},
			checkCritical, `json .status == "ok": got "degraded"`},
		{"first failure leads, rest counted", res(200, jsonHdr, `{"status":"degraded"}`),
			cliArgs{expectHeader: []string{"Content-Type", "!X-Debug"}, expectJSON: []string{`.status == "ok"`, `.items | length > 0`}},
			checkCritical, `header X-Debug present ("1"), expected absent (+2 more failed)`},
		{"status failure leads", res(503, jsonHdr, `{"status":"down"}`),
			cliArgs{expectJSON: []string{`.status == "ok"`}},
			checkCritical, `503 Service Unavailable (expected status < 400) in 1 ms (+1 more failed)`},
		{"body pattern before headers", res(200, jsonHdr, okBody),
			cliArgs{expectBody: "nope", expectHeader: []string{"X-Missing"}},
			checkCritical, `body does not match "nope" (200 OK, 29 bytes) (+1 more failed)`},
		{"non-JSON body", res(200, nil, "<html>oops</html>"),
			cliArgs{expectJSON: []string{`.status == "ok"`}},
			checkCritical, `json .status == "ok": body is not JSON: invalid character '<' looking for beginning of value at offset 1`},
		{"non-JSON body fails every expression", res(200, nil, "<html>"),
			cliArgs{expectJSON: []string{`.a`, `.b`}},
			checkCritical, `json .a: body is not JSON: invalid character '<' looking for beginning of value at offset 1 (+1 more failed)`},
		{"empty body", res(200, nil, ""),
			cliArgs{expectJSON: []string{`.a`}},
			checkCritical, `json .a: body is empty, not JSON`},
		{"trailing data", res(200, nil, `{"a":1} {"b":2}`),
			cliArgs{expectJSON: []string{`.a`}},
			checkCritical, `json .a: body is not JSON: unexpected data after the value at offset 7`},
		{"truncated JSON", res(200, nil, `{"a":[1,2`),
			cliArgs{expectJSON: []string{`.a`}},
			checkCritical, `json .a: body is not JSON: it ends mid-value`},
		{"passing assertions still honor -w", res(200, jsonHdr, okBody),
			cliArgs{expectJSON: []string{`.status == "ok"`}, warn: time.Nanosecond},
			checkWarning, "200 OK in 1 ms (warn at 1ns)"},
	}
	for _, c := range cases {
		c.args.check = true
		v := checkHTTP(c.res, mustOpts(t, c.args))
		if v.Code != c.wantCode || v.Message != c.wantMsg {
			t.Errorf("%s: %d %q, want %d %q", c.name, v.Code, v.Message, c.wantCode, c.wantMsg)
		}
		if n := 1 + len(c.args.expectHeader) + len(c.args.expectJSON) + min(len(c.args.expectBody), 1); len(v.Assertions) != n {
			t.Errorf("%s: %d assertions listed, want %d", c.name, len(v.Assertions), n)
		}
	}

	// An incomplete body (read error or cap) is never parsed: the JSON
	// assertion is skipped, not counted, and the lead says why. Header
	// assertions don't need the body, so their failures still count.
	trunc := res(200, jsonHdr, `{"status":"o`)
	trunc.Err = errTest
	v := checkHTTP(trunc, mustOpts(t, cliArgs{check: true,
		expectHeader: []string{"X-Missing"}, expectJSON: []string{`.status == "ok"`}}))
	if want := "200 OK but body incomplete: dial tcp: connection refused (+1 more failed)"; v.Code != checkCritical || v.Message != want {
		t.Errorf("incomplete body: %d %q, want %q", v.Code, v.Message, want)
	}
	if last := v.Assertions[len(v.Assertions)-1]; last.OK || last.Actual != nil || !strings.Contains(last.Message, "not checked, body incomplete") {
		t.Errorf("incomplete body: json assertion = %+v", last)
	}
}

// Server-controlled header values and JSON strings reach the message: they
// must not break the one-line format, smuggle escapes, or run long.
func TestCheckAssertionsHostileValues(t *testing.T) {
	res := Result{
		Status: 200, StatusText: "OK",
		Headers: http.Header{"Server": {"\x1b]52;c;ZXZpbA==\x07evil|pipe\nnext " + strings.Repeat("A", 500)}},
		Body:    []byte(`{"s":"\u001b[2J|x\n` + strings.Repeat("B", 500) + `"}`),
	}
	v := checkHTTP(res, mustOpts(t, cliArgs{check: true,
		expectHeader: []string{"!Server"}, expectJSON: []string{`.s == "ok"`}}))
	line := v.line()
	if n := strings.Count(line, "|"); n != 1 || strings.ContainsAny(line, "\x1b\x07\n") {
		t.Errorf("hostile values broke the plugin line: %q", line)
	}
	if len(line) > 400 {
		t.Errorf("hostile values were not clipped (%d bytes): %q", len(line), line)
	}
	for _, a := range v.Assertions {
		if a.Actual != nil && (utf8.RuneCountInString(*a.Actual) > checkActualMax || strings.ContainsAny(*a.Actual, "\x1b\x07\n")) {
			t.Errorf("%s actual not clipped/sanitized: %q", a.Type, *a.Actual)
		}
	}
}

// The --json verdict lists every assertion in order with its outcome and the
// actual value; perfdata-derived metrics are unchanged.
func TestCheckHTTPAssertionsJSON(t *testing.T) {
	res := Result{
		Status: 200, StatusText: "OK", Body: []byte(`{"status":"down","n":3}`),
		Headers: http.Header{"Content-Type": {"application/json"}},
		Timing:  Timing{Total: 5 * time.Millisecond},
	}
	out := checkHTTP(res, mustOpts(t, cliArgs{check: true, expectStatus: "2xx",
		expectHeader: []string{"Content-Type: json", "X-Missing"},
		expectJSON:   []string{`.status == "ok"`, `.n > 1`}})).json()
	var v struct {
		Status     string         `json:"status"`
		Message    string         `json:"message"`
		Metrics    map[string]any `json:"metrics"`
		Assertions []struct {
			Type    string  `json:"type"`
			Expect  string  `json:"expect"`
			OK      bool    `json:"ok"`
			Actual  *string `json:"actual"`
			Message string  `json:"message"`
		} `json:"assertions"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("unmarshal %q: %v", out, err)
	}
	if v.Status != "CRITICAL" || v.Message != "header X-Missing missing (+1 more failed)" {
		t.Errorf("verdict = %s %q", v.Status, v.Message)
	}
	if len(v.Metrics) != 3 || v.Metrics["http_status"] != float64(200) {
		t.Errorf("metrics changed: %v", v.Metrics)
	}
	str := func(p *string) string {
		if p == nil {
			return "<none>"
		}
		return *p
	}
	want := []struct {
		typ, expect string
		ok          bool
		actual, msg string
	}{
		{"status", "2xx", true, "200", ""},
		{"header", "Content-Type: json", true, "application/json", ""},
		{"header", "X-Missing", false, "<none>", "header X-Missing missing"},
		{"json", `.status == "ok"`, false, `"down"`, `json .status == "ok": got "down"`},
		{"json", ".n > 1", true, "3", ""},
	}
	if len(v.Assertions) != len(want) {
		t.Fatalf("assertions = %+v", v.Assertions)
	}
	for i, w := range want {
		a := v.Assertions[i]
		if a.Type != w.typ || a.Expect != w.expect || a.OK != w.ok || str(a.Actual) != w.actual || a.Message != w.msg {
			t.Errorf("assertion %d = {%s %q %v %q %q}, want %+v", i, a.Type, a.Expect, a.OK, str(a.Actual), a.Message, w)
		}
	}
}

// End to end against a real server: the new assertions pass, fail as
// CRITICAL, treat a non-JSON body as CRITICAL, and reject a malformed
// expression as UNKNOWN before sending, always as exactly one line.
func TestRunCLICheckAssertions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>maintenance</html>"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Version", "2.4.1")
		_, _ = w.Write([]byte(`{"status":"ok","version":"2.4.1","data":{"items":[{"id":1}]}}`))
	}))
	defer srv.Close()

	cases := []struct {
		name     string
		path     string
		headers  []string
		exprs    []string
		wantCode int
		wantLine string // prefix
	}{
		{"pass", "/", []string{"Content-Type: ^application/json", "X-Version", "!X-Debug"},
			[]string{`.status == "ok"`, `.version =~ "^2\."`, `.data.items | length >= 1`, `.data.items[0].id != null`, `.data`},
			checkOK, "HTTP OK - 200 OK in "},
		{"json fails", "/", nil, []string{`.status == "down"`},
			checkCritical, `HTTP CRITICAL - json .status == "down": got "ok"|time=`},
		{"header fails", "/", []string{"X-Version: ^3"}, nil,
			checkCritical, `HTTP CRITICAL - header X-Version "2.4.1" does not match "^3"|time=`},
		{"non-JSON body", "/html", nil, []string{`.status == "ok"`},
			checkCritical, `HTTP CRITICAL - json .status == "ok": body is not JSON: invalid character '<'`},
		{"bad expression", "/", nil, []string{`.status = "ok"`},
			checkUnknown, `HTTP UNKNOWN - bad --expect-json '.status = "ok"': "=" is not an operator; compare with == at col 9`},
		{"bad header spec", "/", []string{"!X: y"}, nil,
			checkUnknown, `HTTP UNKNOWN - bad --expect-header '!X: y': '!X' asserts absence and takes no pattern`},
	}
	for _, c := range cases {
		buf := swapOutW(t)
		code := runCLI(cliArgs{method: "GET", url: srv.URL + c.path, check: true, expectHeader: c.headers, expectJSON: c.exprs})
		out := buf.String()
		if code != c.wantCode || !strings.HasPrefix(out, c.wantLine) {
			t.Errorf("%s: exit %d, output %q; want %d and prefix %q", c.name, code, out, c.wantCode, c.wantLine)
		}
		if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
			t.Errorf("%s: plugin output must be exactly one line: %q", c.name, out)
		}
	}

	// --json: every assertion is listed, with the same exit code.
	buf := swapOutW(t)
	code := runCLI(cliArgs{method: "GET", url: srv.URL, check: true, checkJSON: true,
		expectHeader: []string{"X-Version"}, expectJSON: []string{`.status == "ok"`, `.version == "3"`}})
	var v struct {
		Status     string `json:"status"`
		Assertions []struct {
			Type   string `json:"type"`
			OK     bool   `json:"ok"`
			Actual string `json:"actual"`
		} `json:"assertions"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &v); err != nil {
		t.Fatalf("output is not JSON: %q (%v)", buf.String(), err)
	}
	if code != checkCritical || v.Status != "CRITICAL" || len(v.Assertions) != 4 ||
		v.Assertions[1].Actual != "2.4.1" || v.Assertions[3].OK || v.Assertions[3].Actual != `"2.4.1"` {
		t.Errorf("json verdict (exit %d) = %+v", code, v)
	}
}

func TestParseCLIExpectAssertionFlags(t *testing.T) {
	a, err := parseCLI([]string{"https://x", "--check",
		"--expect-header", "Content-Type: json", "--expect-json", ".a == 1",
		"--expect-header", "!X-Debug", "--expect-json", ".b"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(a.expectHeader, ",") != "Content-Type: json,!X-Debug" || strings.Join(a.expectJSON, ",") != ".a == 1,.b" {
		t.Errorf("repeatable flags = %q / %q", a.expectHeader, a.expectJSON)
	}
	for _, flag := range []string{"--expect-header", "--expect-json"} {
		if _, err := parseCLI([]string{"https://x", "--check", flag}); err == nil {
			t.Errorf("%s without a value should error", flag)
		}
	}
	// Like the other assertion flags, they refuse to run without --check
	// rather than silently not asserting.
	if code := runCLI(cliArgs{method: "GET", url: "http://x", expectHeader: []string{"X"}}); code != 2 {
		t.Errorf("--expect-header without --check: exit = %d, want 2", code)
	}
	if code := runCLI(cliArgs{method: "GET", url: "http://x", expectJSON: []string{".a"}}); code != 2 {
		t.Errorf("--expect-json without --check: exit = %d, want 2", code)
	}
}
