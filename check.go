package main

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"
)

// Monitoring-plugin mode (--check). The output contract is the Nagios plugin
// API, which Icinga, Sensu, Zabbix agents and friends all consume: exactly one
// line on stdout — "SERVICE STATUS - message|perfdata" — and the verdict in
// the exit code. With --json the same verdict renders as one JSON object
// (script_exporter-style consumers) under the same exit-code contract. weeb's
// normal output matrix (body to stdout, stats to stderr, 0/1/2 exits) is
// suspended entirely in this mode; the line and the code ARE the result.

// Plugin exit codes. These deliberately do not match weeb's normal CLI codes
// (where 2 means "bad usage"): in plugin-land 2 is CRITICAL and usage errors
// are UNKNOWN.
const (
	checkOK       = 0
	checkWarning  = 1
	checkCritical = 2
	checkUnknown  = 3
)

var checkStatusNames = [...]string{"OK", "WARNING", "CRITICAL", "UNKNOWN"}

// checkVerdict is one evaluated check: severity, the human message, and the
// measurements behind it. It renders as the classic plugin line or — with
// --json — as a JSON object carrying the same fields plus typed metrics.
type checkVerdict struct {
	Check   string         `json:"check"`  // "cert" or "http"
	Status  string         `json:"status"` // OK | WARNING | CRITICAL | UNKNOWN
	Code    int            `json:"code"`   // 0..3; also the process exit code
	Message string         `json:"message"`
	Metrics map[string]any `json:"metrics,omitempty"`

	perf string // plugin perfdata (sans '|'); JSON consumers get Metrics instead
}

func newCheckVerdict(check string, code int, msg, perf string, metrics map[string]any) checkVerdict {
	return checkVerdict{
		Check: check, Status: checkStatusNames[code], Code: code,
		Message: msg, Metrics: metrics, perf: perf,
	}
}

// line renders the one-line plugin format: "CERT OK - message|perfdata".
func (v checkVerdict) line() string {
	s := strings.ToUpper(v.Check) + " " + v.Status + " - " + v.Message
	if v.perf != "" {
		s += "|" + v.perf
	}
	return s
}

// json renders the same verdict as a single-line JSON object.
func (v checkVerdict) json() string {
	b, _ := json.Marshal(v) // the struct holds only marshalable fields
	return string(b)
}

// printCheck emits a verdict in the chosen rendering and returns its exit code.
func printCheck(w io.Writer, v checkVerdict, asJSON bool) int {
	if asJSON {
		fmt.Fprintln(w, v.json())
	} else {
		fmt.Fprintln(w, v.line())
	}
	return v.Code
}

// checkSafe flattens peer-controlled text (cert CNs, verify/transport error
// strings) for embedding in the one-line plugin format: ANSI escapes are
// stripped, control characters become spaces (the line must stay a line), and
// '|' becomes '/' because it would start the perfdata section early.
func checkSafe(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r < 0x20 || r == 0x7f:
			return ' '
		case r == '|':
			return '/'
		}
		return r
	}, ansi.Strip(s))
}

// ---- weeb cert --check ------------------------------------------------------

// checkCert turns a TLS inspection into a plugin verdict. The leaf drives the
// expiry thresholds (intermediates routinely outlive it; if one doesn't, the
// chain fails verification and that path fires instead). Trust is CRITICAL
// unless -k skipped the check, mirroring the normal exit-code rule.
func checkCert(rep *certReport, warnDays, critDays int) checkVerdict {
	target := checkSafe(rep.Host + ":" + rep.Port)
	if len(rep.Chain) == 0 {
		return newCheckVerdict("cert", checkUnknown, target+" presented no certificates", "", nil)
	}
	leaf := rep.Chain[0]
	days := leaf.DaysUntilExpiry
	until := leaf.NotAfter.Format("2006-01-02")
	perf := fmt.Sprintf("days=%d;%d;%d", days, warnDays, critDays)
	metrics := map[string]any{
		"days_until_expiry": days,
		"warn_days":         warnDays,
		"crit_days":         critDays,
	}

	code := checkOK
	msg := fmt.Sprintf("%s expires in %d days (%s)", target, days, until)
	switch {
	case !rep.Verified && !rep.Skipped:
		code = checkCritical
		msg = fmt.Sprintf("%s untrusted: %s", target, checkSafe(rep.VerifyErr))
	case days < 0:
		code = checkCritical
		msg = fmt.Sprintf("%s expired %d days ago (%s)", target, -days, until)
	case days <= critDays:
		code = checkCritical
	case days <= warnDays:
		code = checkWarning
	}
	return newCheckVerdict("cert", code, msg, perf, metrics)
}

// ---- weeb URL --check -------------------------------------------------------

// checkHTTPOpts are the assertions for an HTTP check, pre-compiled by
// cliArgs.checkOpts so a bad pattern is a usage error (UNKNOWN), not a
// per-request failure.
type checkHTTPOpts struct {
	expectSpec string         // raw --expect-status, for the failure message
	expect     func(int) bool // nil = the default rule: any status < 400 is OK
	bodyRe     *regexp.Regexp // nil = no body assertion
	warn, crit time.Duration  // zero = no response-time threshold
}

// checkOpts validates and compiles the --check flag set. Errors here are
// usage errors: the caller reports them as UNKNOWN.
func (a cliArgs) checkOpts() (checkHTTPOpts, error) {
	var o checkHTTPOpts
	if a.output != "" {
		return o, fmt.Errorf("-o cannot be combined with --check (the body is checked, not saved)")
	}
	if a.warn > 0 && a.crit > 0 && a.crit < a.warn {
		return o, fmt.Errorf("--crit %s is below --warn %s", a.crit, a.warn)
	}
	if a.expectStatus != "" {
		f, err := parseExpectStatus(a.expectStatus)
		if err != nil {
			return o, err
		}
		o.expect, o.expectSpec = f, a.expectStatus
	}
	if a.expectBody != "" {
		re, err := regexp.Compile(a.expectBody)
		if err != nil {
			return o, fmt.Errorf("bad --expect-body pattern: %w", err)
		}
		o.bodyRe = re
	}
	o.warn, o.crit = a.warn, a.crit
	return o, nil
}

// parseExpectStatus compiles an --expect-status spec: comma-separated codes
// ("204"), ranges ("200-299"), or class wildcards ("2xx"), e.g. "200-204,301".
func parseExpectStatus(spec string) (func(int) bool, error) {
	type span struct{ lo, hi int }
	var spans []span
	for _, part := range strings.Split(spec, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		switch {
		case part == "":
			continue
		case len(part) == 3 && strings.HasSuffix(part, "xx"):
			d := int(part[0] - '0')
			if d < 1 || d > 5 {
				return nil, fmt.Errorf("bad status class %q (want 1xx–5xx)", part)
			}
			spans = append(spans, span{d * 100, d*100 + 99})
		case strings.Contains(part, "-"):
			los, his, _ := strings.Cut(part, "-")
			lo, err1 := strconv.Atoi(strings.TrimSpace(los))
			hi, err2 := strconv.Atoi(strings.TrimSpace(his))
			if err1 != nil || err2 != nil || lo > hi {
				return nil, fmt.Errorf("bad status range %q", part)
			}
			spans = append(spans, span{lo, hi})
		default:
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("bad status %q", part)
			}
			spans = append(spans, span{n, n})
		}
	}
	if len(spans) == 0 {
		return nil, fmt.Errorf("empty --expect-status")
	}
	return func(code int) bool {
		for _, s := range spans {
			if code >= s.lo && code <= s.hi {
				return true
			}
		}
		return false
	}, nil
}

// checkHTTP turns a finished request into a plugin verdict. Severity order:
// no response at all is CRITICAL, then the status assertion, an incomplete
// body, the body pattern, and finally the response-time thresholds.
func checkHTTP(res Result, o checkHTTPOpts) checkVerdict {
	if res.Status == 0 { // never got a response
		msg := "no response"
		if res.Err != nil {
			msg = res.Err.Error()
		}
		return newCheckVerdict("http", checkCritical, checkSafe(msg), "", nil)
	}

	perf := checkHTTPPerf(res, o)
	metrics := checkHTTPMetrics(res, o)
	verdict := func(code int, msg string) checkVerdict {
		return newCheckVerdict("http", code, msg, perf, metrics)
	}
	statusTxt := fmt.Sprintf("%d %s", res.Status, res.StatusText)
	ms := res.Timing.Total.Milliseconds()

	ok, want := res.Status < 400, "status < 400"
	if o.expect != nil {
		ok, want = o.expect(res.Status), o.expectSpec
	}
	if !ok {
		return verdict(checkCritical, fmt.Sprintf("%s (expected %s) in %d ms", statusTxt, want, ms))
	}
	// A passing status with res.Err set means the body read failed or was
	// truncated at the cap — the data below would lie, so say that instead.
	// (A non-passing status already reported above; its Err is the status
	// error itself.)
	if res.Err != nil && res.Status < 400 {
		return verdict(checkCritical, fmt.Sprintf("%s but body incomplete: %s", statusTxt, checkSafe(res.Err.Error())))
	}
	if o.bodyRe != nil && !o.bodyRe.Match(res.Body) {
		return verdict(checkCritical, fmt.Sprintf("body does not match %q (%s, %d bytes)",
			o.bodyRe.String(), statusTxt, res.bodySize()))
	}
	if o.crit > 0 && res.Timing.Total > o.crit {
		return verdict(checkCritical, fmt.Sprintf("%s in %d ms (crit at %s)", statusTxt, ms, o.crit))
	}
	if o.warn > 0 && res.Timing.Total > o.warn {
		return verdict(checkWarning, fmt.Sprintf("%s in %d ms (warn at %s)", statusTxt, ms, o.warn))
	}
	return verdict(checkOK, fmt.Sprintf("%s in %d ms, %d bytes", statusTxt, ms, res.bodySize()))
}

// checkHTTPPerf renders the perfdata section: response time against its
// thresholds, body size, and — when the connection was TLS — the leaf's days
// to expiry, so one HTTP check can also feed cert-expiry graphs/alerts.
func checkHTTPPerf(res Result, o checkHTTPOpts) string {
	var b strings.Builder
	fmt.Fprintf(&b, "time=%.3fs;%s;%s", res.Timing.Total.Seconds(), perfSeconds(o.warn), perfSeconds(o.crit))
	fmt.Fprintf(&b, " size=%dB", res.bodySize())
	if res.TLS != nil && res.TLS.Leaf != nil {
		fmt.Fprintf(&b, " days_until_expiry=%d", res.TLS.Leaf.DaysUntilExpiry)
	}
	return b.String()
}

// checkHTTPMetrics is the perfdata's typed twin for the --json rendering.
func checkHTTPMetrics(res Result, o checkHTTPOpts) map[string]any {
	m := map[string]any{
		"http_status": res.Status,
		"time_ms":     res.Timing.Total.Milliseconds(),
		"size_bytes":  res.bodySize(),
	}
	if o.warn > 0 {
		m["warn_ms"] = o.warn.Milliseconds()
	}
	if o.crit > 0 {
		m["crit_ms"] = o.crit.Milliseconds()
	}
	if res.TLS != nil && res.TLS.Leaf != nil {
		m["days_until_expiry"] = res.TLS.Leaf.DaysUntilExpiry
	}
	return m
}

// perfSeconds renders a threshold for a perfdata field, empty when unset (the
// plugin format leaves absent thresholds blank: "time=0.1s;;").
func perfSeconds(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return fmt.Sprintf("%.3f", d.Seconds())
}
