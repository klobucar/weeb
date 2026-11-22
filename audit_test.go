package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hdr builds a header from key/value pairs; a repeated key adds a value.
func auditHdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

// auditFindingByID runs every check and returns the one with the given id.
func auditFindingByID(t *testing.T, h http.Header, https bool, id string) auditFinding {
	t.Helper()
	for _, f := range auditHeaders(h, https) {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("no finding %q", id)
	return auditFinding{}
}

func TestAuditChecks(t *testing.T) {
	const (
		strongHSTS = "max-age=63072000; includeSubDomains; preload"
		csp        = "Content-Security-Policy"
		cspRO      = "Content-Security-Policy-Report-Only"
		xfo        = "X-Frame-Options"
		acao       = "Access-Control-Allow-Origin"
		acac       = "Access-Control-Allow-Credentials"
	)
	tests := []struct {
		name   string
		id     string
		h      http.Header
		http   bool // served over plain http (default: https)
		grade  auditGrade
		reason string // substring of the reason
	}{
		// HSTS
		{"hsts strong", "hsts", auditHdr("Strict-Transport-Security", strongHSTS), false, gradePass, "2 years, includeSubDomains, preload"},
		{"hsts not preloaded", "hsts", auditHdr("Strict-Transport-Security", "max-age=31536000; includeSubDomains"), false, gradePass, "not preloaded"},
		{"hsts quoted lowercase", "hsts", auditHdr("Strict-Transport-Security", `max-age="31536000"; includesubdomains`), false, gradePass, "1 year"},
		{"hsts missing", "hsts", auditHdr(), false, gradeFail, "missing"},
		{"hsts over http", "hsts", auditHdr("Strict-Transport-Security", strongHSTS), true, gradeFail, "plain http"},
		{"hsts short max-age", "hsts", auditHdr("Strict-Transport-Security", "max-age=86400; includeSubDomains"), false, gradeWarn, "1 day is under 6 months"},
		{"hsts no subdomains", "hsts", auditHdr("Strict-Transport-Security", "max-age=31536000"), false, gradeWarn, "no includeSubDomains"},
		{"hsts max-age zero", "hsts", auditHdr("Strict-Transport-Security", "max-age=0"), false, gradeFail, "drop the policy"},
		{"hsts no max-age", "hsts", auditHdr("Strict-Transport-Security", "includeSubDomains"), false, gradeFail, "no valid max-age"},
		{"hsts preload ineligible", "hsts", auditHdr("Strict-Transport-Security", "max-age=15768000; includeSubDomains; preload"), false, gradeWarn, "preload set"},
		{"hsts first header wins", "hsts", auditHdr("Strict-Transport-Security", "max-age=60", "Strict-Transport-Security", strongHSTS), false, gradeWarn, "under 6 months"},

		// CSP
		{"csp missing", "csp", auditHdr(), false, gradeFail, "missing"},
		{"csp default-src self", "csp", auditHdr(csp, "default-src 'self'"), false, gradePass, "scripts restricted"},
		{"csp unsafe-inline", "csp", auditHdr(csp, "script-src 'self' 'unsafe-inline'"), false, gradeWarn, "'unsafe-inline'"},
		{"csp unsafe-inline with nonce", "csp", auditHdr(csp, "script-src 'self' 'unsafe-inline' 'nonce-abc'"), false, gradePass, "restricted"},
		{"csp unsafe-eval via default-src", "csp", auditHdr(csp, "default-src 'self' 'unsafe-eval'"), false, gradeWarn, "'unsafe-eval'"},
		{"csp wildcard", "csp", auditHdr(csp, "script-src *"), false, gradeWarn, "wildcard script source *"},
		{"csp scheme wildcard", "csp", auditHdr(csp, "default-src 'self' https:"), false, gradeWarn, "wildcard script source https:"},
		{"csp strict-dynamic", "csp", auditHdr(csp, "script-src 'strict-dynamic' 'nonce-x' https: 'unsafe-inline'"), false, gradePass, "restricted"},
		{"csp no script directive", "csp", auditHdr(csp, "img-src *"), false, gradeWarn, "unrestricted"},
		{"csp report-only", "csp", auditHdr(cspRO, "default-src 'self'"), false, gradeWarn, "report-only"},
		{"csp plus report-only", "csp", auditHdr(csp, "default-src 'self'", cspRO, "default-src 'none'"), false, gradePass, "plus a report-only"},
		{"csp strict second header", "csp", auditHdr(csp, "script-src 'unsafe-inline'", csp, "script-src 'self'"), false, gradePass, "restricted"},
		{"csp strict second policy", "csp", auditHdr(csp, "script-src *, script-src 'self'"), false, gradePass, "restricted"},
		{"csp all policies weak", "csp", auditHdr(csp, "script-src * 'unsafe-eval', default-src 'unsafe-eval'"), false, gradeWarn, "'unsafe-eval'"},
		{"csp empty", "csp", auditHdr(csp, " "), false, gradeFail, "empty policy"},

		// X-Content-Type-Options
		{"nosniff", "nosniff", auditHdr("X-Content-Type-Options", "nosniff"), false, gradePass, "nosniff"},
		{"nosniff any case", "nosniff", auditHdr("X-Content-Type-Options", "NoSniff"), false, gradePass, "nosniff"},
		{"nosniff missing", "nosniff", auditHdr(), false, gradeFail, "missing"},
		{"nosniff wrong value", "nosniff", auditHdr("X-Content-Type-Options", "sniff"), false, gradeFail, `"sniff"`},

		// Clickjacking
		{"frame-ancestors none", "clickjacking", auditHdr(csp, "frame-ancestors 'none'"), false, gradePass, "frame-ancestors 'none'"},
		{"frame-ancestors empty list", "clickjacking", auditHdr(csp, "default-src 'self'; frame-ancestors"), false, gradePass, "'none'"},
		{"frame-ancestors wildcard beats xfo", "clickjacking", auditHdr(csp, "frame-ancestors *", xfo, "DENY"), false, gradeFail, "any site"},
		{"frame-ancestors report-only ignored", "clickjacking", auditHdr(cspRO, "frame-ancestors 'none'"), false, gradeFail, "no CSP frame-ancestors"},
		{"xfo deny", "clickjacking", auditHdr(xfo, "DENY"), false, gradePass, "X-Frame-Options DENY"},
		{"xfo sameorigin", "clickjacking", auditHdr(xfo, "sameorigin"), false, gradePass, "SAMEORIGIN"},
		{"xfo allow-from", "clickjacking", auditHdr(xfo, "ALLOW-FROM https://a.example"), false, gradeWarn, "obsolete"},
		{"xfo conflicting", "clickjacking", auditHdr(xfo, "DENY, SAMEORIGIN"), false, gradeWarn, "conflicting"},
		{"xfo bogus", "clickjacking", auditHdr(xfo, "maybe"), false, gradeFail, "unrecognized"},
		{"framing unprotected", "clickjacking", auditHdr(), false, gradeFail, "any site can frame"},

		// Referrer-Policy
		{"referrer missing", "referrer_policy", auditHdr(), false, gradeWarn, "missing"},
		{"referrer strict", "referrer_policy", auditHdr("Referrer-Policy", "strict-origin-when-cross-origin"), false, gradePass, "strict-origin-when-cross-origin"},
		{"referrer unsafe-url", "referrer_policy", auditHdr("Referrer-Policy", "unsafe-url"), false, gradeFail, "full URLs"},
		{"referrer downgrade", "referrer_policy", auditHdr("Referrer-Policy", "no-referrer-when-downgrade"), false, gradeWarn, "other https sites"},
		{"referrer last token wins", "referrer_policy", auditHdr("Referrer-Policy", "unsafe-url, no-referrer"), false, gradePass, "no-referrer"},
		{"referrer unknown", "referrer_policy", auditHdr("Referrer-Policy", "whatever"), false, gradeWarn, "no recognized policy"},

		// Permissions-Policy
		{"permissions set", "permissions_policy", auditHdr("Permissions-Policy", "camera=(), geolocation=()"), false, gradePass, "2 features"},
		{"permissions missing", "permissions_policy", auditHdr(), false, gradeWarn, "missing"},
		{"permissions legacy only", "permissions_policy", auditHdr("Feature-Policy", "camera 'none'"), false, gradeWarn, "deprecated Feature-Policy"},

		// COOP / CORP
		{"coop same-origin", "coop", auditHdr("Cross-Origin-Opener-Policy", `same-origin; report-to="coop"`), false, gradePass, "same-origin"},
		{"coop missing", "coop", auditHdr(), false, gradeWarn, "missing"},
		{"coop unsafe-none", "coop", auditHdr("Cross-Origin-Opener-Policy", "unsafe-none"), false, gradeWarn, "unsafe-none"},
		{"corp same-site", "corp", auditHdr("Cross-Origin-Resource-Policy", "same-site"), false, gradePass, "same-site"},
		{"corp cross-origin", "corp", auditHdr("Cross-Origin-Resource-Policy", "cross-origin"), false, gradeWarn, "any site"},
		{"corp missing", "corp", auditHdr(), false, gradeWarn, "missing"},

		// Set-Cookie
		{"no cookies", "cookies", auditHdr(), false, gradePass, "no cookies"},
		{"cookie hardened", "cookies", auditHdr("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax"), false, gradePass, "1 cookie, all Secure"},
		{"cookie not secure", "cookies", auditHdr("Set-Cookie", "sid=1; HttpOnly; SameSite=Lax"), false, gradeFail, `"sid" lacks Secure`},
		{"cookie not httponly", "cookies", auditHdr("Set-Cookie", "sid=1; Secure; SameSite=Strict"), false, gradeWarn, "lacks HttpOnly"},
		{"cookie no samesite", "cookies", auditHdr("Set-Cookie", "sid=1; Secure; HttpOnly"), false, gradeWarn, "lacks SameSite"},
		{"cookie bare samesite", "cookies", auditHdr("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite"), false, gradeWarn, "lacks SameSite"},
		{"cookie list capped", "cookies", auditHdr("Set-Cookie", "a=1", "Set-Cookie", "b=1", "Set-Cookie", "c=1", "Set-Cookie", "d=1", "Set-Cookie", "e=1"), false, gradeFail, "2 more"},

		// CORS
		{"cors none", "cors", auditHdr(), false, gradePass, "no Access-Control-Allow-Origin"},
		{"cors public", "cors", auditHdr(acao, "*"), false, gradePass, "public"},
		{"cors star with credentials", "cors", auditHdr(acao, "*", acac, "true"), false, gradeFail, "* with Allow-Credentials"},
		{"cors null", "cors", auditHdr(acao, "null"), false, gradeWarn, "null"},
		{"cors null with credentials", "cors", auditHdr(acao, "null", acac, "true"), false, gradeFail, "null with credentials"},
		{"cors specific origin", "cors", auditHdr(acao, "https://app.example", acac, "true"), false, gradePass, "with credentials"},

		// Info leaks
		{"banner none", "info_leak", auditHdr(), false, gradePass, "no Server"},
		{"server no version", "info_leak", auditHdr("Server", "nginx"), false, gradePass, "has no version"},
		{"server version", "info_leak", auditHdr("Server", "Apache/2.4.58 (Ubuntu)"), false, gradeWarn, "reveals a version"},
		{"powered-by", "info_leak", auditHdr("Server", "nginx", "X-Powered-By", "Express"), false, gradeWarn, `X-Powered-By "Express"`},
		{"aspnet version", "info_leak", auditHdr("X-AspNet-Version", "4.0.30319"), false, gradeWarn, "X-AspNet-Version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := auditFindingByID(t, tt.h, !tt.http, tt.id)
			if f.Grade != tt.grade {
				t.Errorf("grade = %s, want %s (reason %q)", f.Grade, tt.grade, f.Reason)
			}
			if !strings.Contains(f.Reason, tt.reason) {
				t.Errorf("reason = %q, want it to contain %q", f.Reason, tt.reason)
			}
		})
	}
}

// Set-Cookie values are session credentials: the finding's value (which
// --json prints) carries cookie names only.
func TestAuditCookieValueNotLeaked(t *testing.T) {
	f := auditFindingByID(t, auditHdr("Set-Cookie", "sid=s3cr3t-token; Secure; HttpOnly; SameSite=Lax"), true, "cookies")
	if strings.Contains(f.Value, "s3cr3t") || strings.Contains(f.Reason, "s3cr3t") {
		t.Errorf("cookie value leaked: value %q, reason %q", f.Value, f.Reason)
	}
	if f.Value != "sid" {
		t.Errorf("value = %q, want the cookie name", f.Value)
	}
}

func TestAuditShow(t *testing.T) {
	tests := []struct{ in, want string }{
		{"nginx/1.25", `"nginx/1.25"`},
		{"\x1b[31mred\x1b[0m", `"red"`},
		{"a\x07b\nc", `"a\ab\nc"`},
		{"\x1b]52;c;ZXZpbA==\x07evil", `"evil"`},
		{strings.Repeat("x", 100), `"` + strings.Repeat("x", 59) + `…"`},
	}
	for _, tt := range tests {
		if got := auditShow(tt.in); got != tt.want {
			t.Errorf("auditShow(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

// Header values are server-controlled. A hostile one must neither act on the
// terminal (the table goes through the TTY sanitizer) nor break the
// one-line plugin output (newlines, a second '|').
func TestAuditHostileHeaderValues(t *testing.T) {
	const osc52 = "\x1b]52;c;ZXZpbA==\x07"
	res := Result{
		URL: "https://victim.test/", Status: 200,
		Headers: auditHdr(
			"Server", osc52+"nginx/1.0|evil\x9b2J",
			"X-Powered-By", "PHP/8\r\nInjected: yes",
			"Set-Cookie", "ses|sion=1; HttpOnly",
			"X-Frame-Options", osc52+"bogus",
		),
	}
	rep := newAuditReport(res)

	var tty strings.Builder
	fmt.Fprint(sanitizingWriter{w: &tty}, renderAudit(rep, newStyles(), true))
	if strings.Contains(tty.String(), "]52;") || strings.Contains(tty.String(), "\x9b") {
		t.Errorf("control sequence reached the terminal:\n%q", tty.String())
	}
	if !strings.Contains(tty.String(), "nginx/1.0") {
		t.Errorf("banner text should survive sanitization:\n%q", tty.String())
	}

	line := checkAudit(rep).line()
	if strings.ContainsAny(line, "\r\n\x1b\x07") {
		t.Errorf("plugin line not flat: %q", line)
	}
	if strings.Count(line, "|") != 1 {
		t.Errorf("plugin line must have exactly one '|': %q", line)
	}
}

func TestCheckAudit(t *testing.T) {
	tests := []struct {
		name     string
		findings []auditFinding
		code     int
		msg      string
	}{
		{"all pass", []auditFinding{{Name: "A", Grade: gradePass}, {Name: "B", Grade: gradePass}}, checkOK, "all 2 checks pass"},
		{"warn", []auditFinding{{Name: "A", Grade: gradePass}, {Name: "B", Grade: gradeWarn, Reason: "meh"}}, checkWarning, "0 fail, 1 warn: B (meh)"},
		{"fail listed first", []auditFinding{{Name: "W", Grade: gradeWarn, Reason: "meh"}, {Name: "F", Grade: gradeFail, Reason: "bad"}}, checkCritical, "1 fail, 1 warn: F (bad); W (meh)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := auditReport{Status: 200, Findings: tt.findings}
			for _, f := range tt.findings {
				switch f.Grade {
				case gradePass:
					rep.Pass++
				case gradeWarn:
					rep.Warn++
				case gradeFail:
					rep.Fail++
				}
			}
			v := checkAudit(rep)
			if v.Code != tt.code || v.Message != tt.msg {
				t.Errorf("verdict = %d %q, want %d %q", v.Code, v.Message, tt.code, tt.msg)
			}
			wantPerf := fmt.Sprintf("|pass=%d warn=%d fail=%d", rep.Pass, rep.Warn, rep.Fail)
			if !strings.HasSuffix(v.line(), wantPerf) {
				t.Errorf("line = %q, want perfdata %q", v.line(), wantPerf)
			}
		})
	}
}

func TestRenderAuditPlain(t *testing.T) {
	rep := newAuditReport(Result{
		URL: "https://a.example/", Status: 200,
		Redirects: []string{"http://a.example/", "https://a.example/"},
		Headers:   auditHdr("X-Content-Type-Options", "nosniff"),
	})
	out := renderAudit(rep, newStyles(), false)
	if strings.Contains(out, "\x1b") {
		t.Errorf("plain render has ANSI:\n%q", out)
	}
	for _, want := range []string{
		"Security headers  https://a.example/  200 OK",
		"↪ 1 redirect: http://a.example/ → https://a.example/",
		"✔ PASS  X-Content-Type-Options        nosniff",
		"✘ FAIL  Strict-Transport-Security     missing",
		fmt.Sprintf("%d pass · %d warn · %d fail", rep.Pass, rep.Warn, rep.Fail),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
}

// runAudit end to end against a local server: redirects are followed, the
// final response is graded, and --json / --check render the same report.
func TestRunAudit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Server", "weebtest/1.2")
		_, _ = w.Write([]byte("<html>hi</html>"))
	}))
	defer srv.Close()

	t.Run("json", func(t *testing.T) {
		buf := swapOutW(t)
		if code := runAudit([]string{srv.URL + "/start", "--json"}); code != 0 {
			t.Fatalf("exit = %d, want 0 (output %q)", code, buf.String())
		}
		var rep struct {
			URL       string   `json:"url"`
			Status    int      `json:"status"`
			Redirects []string `json:"redirects"`
			Findings  []struct {
				ID    string `json:"id"`
				Grade string `json:"grade"`
			} `json:"findings"`
			Fail int `json:"fail"`
		}
		if err := json.Unmarshal([]byte(buf.String()), &rep); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, buf.String())
		}
		if rep.URL != srv.URL+"/final" || rep.Status != 200 || len(rep.Redirects) != 2 {
			t.Errorf("url/status/redirects = %q %d %v", rep.URL, rep.Status, rep.Redirects)
		}
		grades := map[string]string{}
		for _, f := range rep.Findings {
			grades[f.ID] = f.Grade
		}
		want := map[string]string{"hsts": "fail", "nosniff": "pass", "clickjacking": "pass", "info_leak": "warn"}
		for id, g := range want {
			if grades[id] != g {
				t.Errorf("%s = %q, want %q", id, grades[id], g)
			}
		}
		if len(rep.Findings) != 11 || rep.Fail == 0 {
			t.Errorf("findings = %d, fail = %d", len(rep.Findings), rep.Fail)
		}
	})

	t.Run("check", func(t *testing.T) {
		buf := swapOutW(t)
		if code := runAudit([]string{srv.URL, "--check"}); code != checkCritical {
			t.Fatalf("exit = %d, want %d (output %q)", code, checkCritical, buf.String())
		}
		if !strings.HasPrefix(buf.String(), "AUDIT CRITICAL - ") || strings.Count(buf.String(), "\n") != 1 {
			t.Errorf("plugin output = %q", buf.String())
		}
	})

	t.Run("check json", func(t *testing.T) {
		buf := swapOutW(t)
		code := runAudit([]string{srv.URL, "--check", "--json"})
		var v struct {
			Check   string         `json:"check"`
			Code    int            `json:"code"`
			Metrics map[string]any `json:"metrics"`
		}
		if err := json.Unmarshal([]byte(buf.String()), &v); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, buf.String())
		}
		if v.Check != "audit" || v.Code != code || v.Metrics["http_status"] != float64(200) {
			t.Errorf("verdict = %+v (exit %d)", v, code)
		}
	})

	t.Run("table", func(t *testing.T) {
		buf := swapOutW(t)
		if code := runAudit([]string{srv.URL}); code != 0 {
			t.Fatalf("exit = %d", code)
		}
		if !strings.Contains(buf.String(), "✘ FAIL  Strict-Transport-Security") {
			t.Errorf("table output:\n%s", buf.String())
		}
	})
}

func TestRunAuditErrors(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close() // nothing listens there now

	tests := []struct {
		name   string
		args   []string
		code   int
		prefix string // expected stdout prefix, if any
	}{
		{"no url", nil, 2, ""},
		{"unknown flag", []string{"https://x", "--bogus"}, 2, ""},
		{"two urls", []string{"https://x", "https://y"}, 2, ""},
		{"bad header", []string{"https://x", "-H", "nocolon"}, 2, ""},
		{"bad timeout", []string{"https://x", "--timeout", "soon"}, 2, ""},
		{"bad persona", []string{"https://x", "--persona", "nope"}, 2, ""},
		{"unreachable", []string{deadURL}, 1, ""},
		{"unreachable check", []string{deadURL, "--check"}, checkUnknown, "AUDIT UNKNOWN - "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := swapOutW(t)
			if code := runAudit(tt.args); code != tt.code {
				t.Errorf("exit = %d, want %d", code, tt.code)
			}
			if !strings.HasPrefix(buf.String(), tt.prefix) || (tt.prefix == "" && buf.Len() != 0) {
				t.Errorf("stdout = %q, want prefix %q", buf.String(), tt.prefix)
			}
		})
	}
}
