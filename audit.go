package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// `weeb audit URL` fetches a page the way a browser lands on it (GET,
// redirects followed) and grades the security headers of the final response.
// Every check yields one finding, pass/warn/fail with a one-line reason,
// rendered as a table, as JSON (--json), or as a monitoring-plugin verdict
// (--check: any fail is CRITICAL, any warn is WARNING).
//
// Header values are server-controlled. Reasons only ever quote them through
// auditShow (ANSI stripped, quoted, length-capped), the table goes out
// through outW (sanitized at a TTY), and the plugin line through checkSafe.

type auditGrade int

const (
	gradePass auditGrade = iota
	gradeWarn
	gradeFail
)

var auditGradeNames = [...]string{"pass", "warn", "fail"}

func (g auditGrade) String() string { return auditGradeNames[g] }

// MarshalText makes a grade a plain "pass"/"warn"/"fail" string in JSON.
func (g auditGrade) MarshalText() ([]byte, error) { return []byte(g.String()), nil }

// auditFinding is one graded check.
type auditFinding struct {
	ID     string     `json:"id"`
	Name   string     `json:"name"`
	Grade  auditGrade `json:"grade"`
	Reason string     `json:"reason"`
	Value  string     `json:"value,omitempty"` // the header value(s) behind the grade
}

// auditReport is the whole audit of one final response.
type auditReport struct {
	URL       string         `json:"url"`
	Status    int            `json:"status"`
	Redirects []string       `json:"redirects,omitempty"`
	Findings  []auditFinding `json:"findings"`
	Pass      int            `json:"pass"`
	Warn      int            `json:"warn"`
	Fail      int            `json:"fail"`
}

// newAuditReport grades the headers of a finished request.
func newAuditReport(res Result) auditReport {
	https := false
	if u, err := url.Parse(res.URL); err == nil {
		https = strings.EqualFold(u.Scheme, "https")
	}
	rep := auditReport{
		URL: res.URL, Status: res.Status, Redirects: res.Redirects,
		Findings: auditHeaders(res.Headers, https),
	}
	for _, f := range rep.Findings {
		switch f.Grade {
		case gradePass:
			rep.Pass++
		case gradeWarn:
			rep.Warn++
		case gradeFail:
			rep.Fail++
		}
	}
	return rep
}

// auditHeaders runs every check against one response's headers. https is
// whether that response arrived over TLS.
func auditHeaders(h http.Header, https bool) []auditFinding {
	enforced := parseCSP(h.Values("Content-Security-Policy"))
	return []auditFinding{
		auditHSTS(h, https),
		auditCSP(h, enforced),
		auditNosniff(h),
		auditFraming(h, enforced),
		auditReferrer(h),
		auditPermissions(h),
		auditCOOP(h),
		auditCORP(h),
		auditCookies(h),
		auditCORS(h),
		auditBanner(h),
	}
}

// auditNotes accumulates one check's problems: the grade is the worst one
// flagged and the reason lists them all, so a row never hides a second
// problem behind the first.
type auditNotes struct {
	grade  auditGrade
	issues []string
}

func (n *auditNotes) flag(g auditGrade, issue string) {
	n.grade = max(n.grade, g)
	n.issues = append(n.issues, issue)
}

// finding builds the row; ok is the reason when nothing was flagged.
func (n auditNotes) finding(id, name, value, ok string) auditFinding {
	reason := ok
	if len(n.issues) > 0 {
		reason = strings.Join(n.issues, "; ")
	}
	return auditFinding{ID: id, Name: name, Grade: n.grade, Reason: reason, Value: value}
}

// auditShow renders a server-controlled value inside a reason: ANSI
// stripped, cut to 60 runes (a hostile header can be kilobytes long), then
// Go-quoted, so any control character left becomes a visible escape instead
// of acting on the terminal or breaking the one-line plugin output.
func auditShow(s string) string {
	s = strings.ToValidUTF8(ansi.Strip(s), "�")
	if r := []rune(s); len(r) > 60 {
		s = string(r[:59]) + "…"
	}
	return strconv.Quote(s)
}

// auditTokens splits every value of a header on commas, trimmed and
// lowercased, dropping empties: the list form most of these headers use.
func auditTokens(h http.Header, key string) []string {
	var out []string
	for _, v := range h.Values(key) {
		for _, t := range strings.Split(v, ",") {
			if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
				out = append(out, t)
			}
		}
	}
	return out
}

func auditPlural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// ---- Strict-Transport-Security ----------------------------------------------

const (
	hstsMinAge     = 15768000 // six months, the usual audit bar (Mozilla Observatory)
	hstsPreloadAge = 31536000 // one year, the hstspreload.org minimum
)

func auditHSTS(h http.Header, https bool) auditFinding {
	const id, name = "hsts", "Strict-Transport-Security"
	vals := h.Values(name)
	var n auditNotes
	if !https {
		// Browsers ignore HSTS received over plain http (anyone on the path
		// could forge or strip it), so a plain-http page can't be protected.
		n.flag(gradeFail, "served over plain http, where browsers ignore HSTS")
		return n.finding(id, name, strings.Join(vals, ", "), "")
	}
	if len(vals) == 0 {
		n.flag(gradeFail, "missing")
		return n.finding(id, name, "", "")
	}
	raw := vals[0] // RFC 6797 §8.1: only the first header is processed
	maxAge, sub, preload := int64(-1), false, false
	for _, d := range strings.Split(raw, ";") {
		k, v, _ := strings.Cut(d, "=")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "max-age":
			if s, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(v), `"`), 10, 64); err == nil && s >= 0 {
				maxAge = s
			}
		case "includesubdomains":
			sub = true
		case "preload":
			preload = true
		}
	}
	switch {
	case maxAge < 0:
		n.flag(gradeFail, "no valid max-age")
	case maxAge == 0:
		n.flag(gradeFail, "max-age=0 tells browsers to drop the policy")
	case maxAge < hstsMinAge:
		n.flag(gradeWarn, "max-age "+hstsAge(maxAge)+" is under 6 months")
	}
	if !sub {
		n.flag(gradeWarn, "no includeSubDomains")
	}
	if preload && (maxAge < hstsPreloadAge || !sub) {
		n.flag(gradeWarn, "preload set, but the preload list needs max-age of 1 year+ and includeSubDomains")
	}
	ok := "max-age " + hstsAge(maxAge) + ", includeSubDomains"
	if preload {
		ok += ", preload"
	} else {
		// Preloading is an opt-in commitment that's slow to undo, so its
		// absence is noted rather than graded.
		ok += ", not preloaded"
	}
	return n.finding(id, name, raw, ok)
}

// hstsAge renders an HSTS max-age in years or days.
func hstsAge(sec int64) string {
	const day, year = 86400, 365 * 86400
	switch {
	case sec >= year && sec%year == 0:
		return auditPlural(int(sec/year), "year", "years")
	case sec >= day:
		return auditPlural(int(sec/day), "day", "days")
	default:
		return fmt.Sprintf("%ds", sec)
	}
}

// ---- Content-Security-Policy ------------------------------------------------

// cspPolicy maps lowercased directive names to their lowercased sources.
type cspPolicy map[string][]string

// parseCSP splits CSP header values into policies. The header may repeat and
// one value may carry several comma-separated policies; browsers enforce
// every one of them. Within a policy the first occurrence of a directive
// wins, as in the spec.
func parseCSP(values []string) []cspPolicy {
	var out []cspPolicy
	for _, v := range values {
		for _, pol := range strings.Split(v, ",") {
			p := cspPolicy{}
			for _, d := range strings.Split(pol, ";") {
				fields := strings.Fields(strings.ToLower(d))
				if len(fields) == 0 {
					continue
				}
				if _, dup := p[fields[0]]; !dup {
					p[fields[0]] = fields[1:]
				}
			}
			if len(p) > 0 {
				out = append(out, p)
			}
		}
	}
	return out
}

// cspBroad reports whether a source is a wildcard that matches any host.
func cspBroad(src string) bool {
	return src == "*" || src == "http:" || src == "https:" || src == "data:"
}

// cspScriptIssues lists what would let injected script run under one policy.
func cspScriptIssues(p cspPolicy) []string {
	srcs, ok := p["script-src"]
	if !ok {
		srcs, ok = p["default-src"] // the fallback browsers use
	}
	if !ok {
		return []string{"no script-src or default-src, so scripts are unrestricted"}
	}
	var inline, eval, nonceOrHash, strictDynamic bool
	var broad []string
	for _, s := range srcs {
		switch {
		case s == "'unsafe-inline'":
			inline = true
		case s == "'unsafe-eval'":
			eval = true
		case s == "'strict-dynamic'":
			strictDynamic = true
		case strings.HasPrefix(s, "'nonce-"), strings.HasPrefix(s, "'sha256-"),
			strings.HasPrefix(s, "'sha384-"), strings.HasPrefix(s, "'sha512-"):
			nonceOrHash = true
		case cspBroad(s):
			broad = append(broad, s)
		}
	}
	var out []string
	// CSP2+ browsers ignore 'unsafe-inline' once a nonce or hash is present;
	// it is then only a fallback for old browsers.
	if inline && !nonceOrHash {
		out = append(out, "allows 'unsafe-inline' scripts")
	}
	if eval {
		out = append(out, "allows 'unsafe-eval'")
	}
	// 'strict-dynamic' makes CSP3 browsers ignore host and scheme sources.
	if !strictDynamic {
		for _, s := range broad {
			out = append(out, "wildcard script source "+s)
		}
	}
	return out
}

// cspCommonIssues keeps only the issues every policy shares: browsers
// enforce all policies, so one strict policy is enough to block a source.
func cspCommonIssues(policies []cspPolicy) []string {
	if len(policies) == 0 {
		return nil
	}
	count := map[string]int{}
	for _, p := range policies {
		for _, issue := range cspScriptIssues(p) {
			count[issue]++
		}
	}
	var out []string
	for _, issue := range cspScriptIssues(policies[0]) {
		if count[issue] == len(policies) {
			out = append(out, issue)
		}
	}
	return out
}

func auditCSP(h http.Header, enforced []cspPolicy) auditFinding {
	const id, name = "csp", "Content-Security-Policy"
	vals := h.Values(name)
	reportOnly := h.Values("Content-Security-Policy-Report-Only")
	var n auditNotes
	switch {
	case len(enforced) > 0:
	case len(vals) > 0:
		n.flag(gradeFail, "empty policy")
		return n.finding(id, name, strings.Join(vals, ", "), "")
	case len(reportOnly) > 0:
		n.flag(gradeWarn, "report-only: violations are reported, not blocked")
		return n.finding(id, name, strings.Join(reportOnly, ", "), "")
	default:
		n.flag(gradeFail, "missing")
		return n.finding(id, name, "", "")
	}
	for _, issue := range cspCommonIssues(enforced) {
		n.flag(gradeWarn, issue)
	}
	ok := "scripts restricted"
	if len(reportOnly) > 0 {
		ok += ", plus a report-only policy"
	}
	return n.finding(id, name, strings.Join(vals, ", "), ok)
}

// ---- X-Content-Type-Options -------------------------------------------------

func auditNosniff(h http.Header) auditFinding {
	const id, name = "nosniff", "X-Content-Type-Options"
	vals := h.Values(name)
	var n auditNotes
	switch {
	case len(vals) == 0:
		n.flag(gradeFail, "missing, so browsers may sniff a response into script or HTML")
	case !strings.EqualFold(strings.TrimSpace(vals[0]), "nosniff"):
		n.flag(gradeFail, "value "+auditShow(vals[0])+" is not nosniff")
	}
	return n.finding(id, name, strings.Join(vals, ", "), "nosniff")
}

// ---- Clickjacking -----------------------------------------------------------

func auditFraming(h http.Header, enforced []cspPolicy) auditFinding {
	const id, name = "clickjacking", "Clickjacking"
	var n auditNotes

	// CSP frame-ancestors overrides X-Frame-Options wherever it appears, and
	// every policy is enforced, so one restrictive frame-ancestors suffices.
	seen := false
	for _, p := range enforced {
		fa, ok := p["frame-ancestors"]
		if !ok {
			continue
		}
		seen = true
		if !slices.ContainsFunc(fa, cspBroad) {
			srcs := strings.Join(fa, " ")
			if srcs == "" {
				srcs = "'none'" // an empty source list matches nothing
			}
			return n.finding(id, name, "frame-ancestors "+srcs, "CSP frame-ancestors "+srcs)
		}
	}
	if seen {
		n.flag(gradeFail, "CSP frame-ancestors lets any site frame the page")
		return n.finding(id, name, "", "")
	}

	opts := auditTokens(h, "X-Frame-Options")
	value := strings.Join(h.Values("X-Frame-Options"), ", ")
	distinct := map[string]bool{}
	for _, o := range opts {
		distinct[o] = true
	}
	switch {
	case len(opts) == 0:
		n.flag(gradeFail, "no CSP frame-ancestors or X-Frame-Options, so any site can frame the page")
	case len(distinct) > 1:
		n.flag(gradeWarn, "conflicting X-Frame-Options values")
	case opts[0] == "deny" || opts[0] == "sameorigin":
		return n.finding(id, name, value, "X-Frame-Options "+strings.ToUpper(opts[0]))
	case strings.HasPrefix(opts[0], "allow-from"):
		n.flag(gradeWarn, "X-Frame-Options ALLOW-FROM is obsolete and ignored by modern browsers")
	default:
		n.flag(gradeFail, "unrecognized X-Frame-Options "+auditShow(value))
	}
	return n.finding(id, name, value, "")
}

// ---- Referrer-Policy --------------------------------------------------------

var referrerPolicies = map[string]struct {
	grade  auditGrade
	reason string
}{
	"no-referrer":                     {gradePass, "no-referrer"},
	"same-origin":                     {gradePass, "same-origin"},
	"strict-origin":                   {gradePass, "strict-origin"},
	"strict-origin-when-cross-origin": {gradePass, "strict-origin-when-cross-origin"},
	"origin":                          {gradeWarn, "origin: sends the origin everywhere, even to plain http"},
	"origin-when-cross-origin":        {gradeWarn, "origin-when-cross-origin: sends the origin even to plain http"},
	"no-referrer-when-downgrade":      {gradeWarn, "no-referrer-when-downgrade: sends full URLs to other https sites"},
	"unsafe-url":                      {gradeFail, "unsafe-url: sends full URLs, query included, to every site"},
}

func auditReferrer(h http.Header) auditFinding {
	const id, name = "referrer_policy", "Referrer-Policy"
	value := strings.Join(h.Values(name), ", ")
	// The last recognized token wins: senders list fallbacks for old
	// browsers first.
	policy := ""
	for _, t := range auditTokens(h, name) {
		if _, ok := referrerPolicies[t]; ok {
			policy = t
		}
	}
	var n auditNotes
	switch {
	case value == "":
		n.flag(gradeWarn, "missing, so browsers fall back to strict-origin-when-cross-origin")
	case policy == "":
		n.flag(gradeWarn, "no recognized policy in "+auditShow(value))
	default:
		if p := referrerPolicies[policy]; p.grade != gradePass {
			n.flag(p.grade, p.reason)
		}
	}
	return n.finding(id, name, value, policy)
}

// ---- Permissions-Policy -----------------------------------------------------

func auditPermissions(h http.Header) auditFinding {
	const id, name = "permissions_policy", "Permissions-Policy"
	var n auditNotes
	features := auditTokens(h, name)
	switch {
	case len(features) > 0:
	case h.Get("Feature-Policy") != "":
		n.flag(gradeWarn, "only the deprecated Feature-Policy")
		return n.finding(id, name, h.Get("Feature-Policy"), "")
	default:
		n.flag(gradeWarn, "missing, so camera, microphone, geolocation etc. keep browser defaults")
	}
	return n.finding(id, name, strings.Join(h.Values(name), ", "),
		"sets "+auditPlural(len(features), "feature", "features"))
}

// ---- Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy ---------------

// auditFirstToken is a structured header's bare value: the first item, minus any
// ;params (COOP may carry report-to).
func auditFirstToken(h http.Header, key string) string {
	v, _, _ := strings.Cut(h.Get(key), ";")
	v, _, _ = strings.Cut(v, ",")
	return strings.ToLower(strings.Trim(strings.TrimSpace(v), `"`))
}

func auditCOOP(h http.Header) auditFinding {
	const id, name = "coop", "Cross-Origin-Opener-Policy"
	v := auditFirstToken(h, name)
	var n auditNotes
	switch v {
	case "same-origin", "same-origin-allow-popups", "noopener-allow-popups":
	case "":
		n.flag(gradeWarn, "missing, so cross-origin windows can keep a handle to this one")
	case "unsafe-none":
		n.flag(gradeWarn, "unsafe-none lets cross-origin windows keep a handle to this one")
	default:
		n.flag(gradeWarn, "unrecognized value "+auditShow(v))
	}
	return n.finding(id, name, h.Get(name), v)
}

func auditCORP(h http.Header) auditFinding {
	const id, name = "corp", "Cross-Origin-Resource-Policy"
	v := auditFirstToken(h, name)
	var n auditNotes
	switch v {
	case "same-origin", "same-site":
	case "":
		n.flag(gradeWarn, "missing, so any site can embed this response")
	case "cross-origin":
		n.flag(gradeWarn, "cross-origin lets any site embed this response")
	default:
		n.flag(gradeWarn, "unrecognized value "+auditShow(v))
	}
	return n.finding(id, name, h.Get(name), v)
}

// ---- Set-Cookie -------------------------------------------------------------

// auditCookieList caps how many offending cookies a reason names.
const auditCookieList = 3

func auditCookies(h http.Header) auditFinding {
	const id, name = "cookies", "Set-Cookie"
	raw := h.Values("Set-Cookie")
	var n auditNotes
	if len(raw) == 0 {
		return n.finding(id, name, "", "no cookies set")
	}
	cookies := (&http.Response{Header: h}).Cookies()
	// The value lists cookie NAMES only: Set-Cookie values are session
	// credentials, and --json output ends up in logs and pipelines.
	names := make([]string, 0, len(cookies))
	bad := 0
	for _, c := range cookies {
		names = append(names, c.Name)
		var missing []string
		g := gradePass
		if !c.Secure {
			missing, g = append(missing, "Secure"), gradeFail // readable on the wire
		}
		if !c.HttpOnly {
			// A warning, not a failure: some cookies (CSRF double-submit
			// tokens) must be readable from script by design.
			missing, g = append(missing, "HttpOnly"), max(g, gradeWarn)
		}
		if c.SameSite == 0 || c.SameSite == http.SameSiteDefaultMode {
			missing, g = append(missing, "SameSite"), max(g, gradeWarn)
		}
		if len(missing) == 0 {
			continue
		}
		bad++
		n.grade = max(n.grade, g)
		if bad <= auditCookieList {
			n.issues = append(n.issues, auditShow(c.Name)+" lacks "+strings.Join(missing, ", "))
		}
	}
	if bad > auditCookieList {
		n.issues = append(n.issues, fmt.Sprintf("%d more", bad-auditCookieList))
	}
	if unparsed := len(raw) - len(cookies); unparsed > 0 {
		n.flag(gradeWarn, auditPlural(unparsed, "Set-Cookie header", "Set-Cookie headers")+" could not be parsed")
	}
	return n.finding(id, name, strings.Join(names, ", "),
		auditPlural(len(cookies), "cookie", "cookies")+", all Secure, HttpOnly and SameSite")
}

// ---- CORS -------------------------------------------------------------------

func auditCORS(h http.Header) auditFinding {
	const id, name = "cors", "CORS"
	origin := strings.TrimSpace(h.Get("Access-Control-Allow-Origin"))
	creds := strings.EqualFold(strings.TrimSpace(h.Get("Access-Control-Allow-Credentials")), "true")
	value := ""
	if origin != "" {
		value = "Access-Control-Allow-Origin: " + origin
		if creds {
			value += ", Access-Control-Allow-Credentials: true"
		}
	}
	var n auditNotes
	switch {
	case origin == "":
		return n.finding(id, name, "", "no Access-Control-Allow-Origin")
	case origin == "*" && creds:
		n.flag(gradeFail, "Allow-Origin * with Allow-Credentials: true")
	case origin == "null" && creds:
		n.flag(gradeFail, "Allow-Origin null with credentials, which any sandboxed frame matches")
	case origin == "null":
		n.flag(gradeWarn, "Allow-Origin null, which any sandboxed frame matches")
	case origin == "*":
		return n.finding(id, name, value, "public (*), without credentials")
	}
	ok := "Allow-Origin " + auditShow(origin)
	if creds {
		ok += " with credentials"
	}
	return n.finding(id, name, value, ok)
}

// ---- Info leaks -------------------------------------------------------------

// auditVersionRe spots a version in a banner: "nginx/1.25.3", "PHP/8",
// "Apache/2.4.58 (Ubuntu)".
var auditVersionRe = regexp.MustCompile(`\d+\.\d+|/v?\d`)

func auditBanner(h http.Header) auditFinding {
	const id, name = "info_leak", "Info leaks"
	var n auditNotes
	var shown []string
	server := h.Get("Server")
	if server != "" {
		shown = append(shown, "Server: "+server)
		if auditVersionRe.MatchString(server) {
			n.flag(gradeWarn, "Server "+auditShow(server)+" reveals a version")
		}
	}
	// X-Powered-By and friends exist only to advertise the stack, so their
	// presence is flagged even without a version number.
	for _, k := range []string{"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"} {
		if v := h.Get(k); v != "" {
			shown = append(shown, k+": "+v)
			n.flag(gradeWarn, k+" "+auditShow(v)+" reveals the stack")
		}
	}
	ok := "no Server or X-Powered-By banner"
	if server != "" {
		ok = "Server " + auditShow(server) + " has no version"
	}
	return n.finding(id, name, strings.Join(shown, ", "), ok)
}

// ---- rendering --------------------------------------------------------------

// renderAudit draws the report as a table: a grade badge, the check name and
// its reason per row, then the tally. color=false gives the same layout as
// plain text, for pipes and NO_COLOR.
func renderAudit(rep auditReport, st styles, color bool) string {
	paint := auditPainter(color)
	var b strings.Builder
	head := fmt.Sprintf("%d %s", rep.Status, http.StatusText(rep.Status))
	fmt.Fprintf(&b, "%s  %s  %s\n", paint(st.paneTitle, "Security headers"), rep.URL,
		paint(lipgloss.NewStyle().Foreground(statusColor(rep.Status)), head))
	if len(rep.Redirects) > 0 {
		hops := len(rep.Redirects) - 1
		fmt.Fprintln(&b, paint(st.meta, fmt.Sprintf("↪ %s: %s",
			auditPlural(hops, "redirect", "redirects"), strings.Join(rep.Redirects, " → "))))
	}
	b.WriteString("\n")
	writeAuditRows(&b, rep.Findings, auditNameWidth(rep.Findings), st, paint)
	b.WriteString("\n")
	writeAuditTally(&b, rep.Pass, rep.Warn, rep.Fail, st, paint)
	return b.String()
}

// auditPainter styles text when color is on and passes it through otherwise.
func auditPainter(color bool) func(lipgloss.Style, string) string {
	return func(s lipgloss.Style, text string) string {
		if !color {
			return text
		}
		return s.Render(text)
	}
}

// auditBadges is each grade's label and color in a report table.
var auditBadges = [...]struct {
	label string
	col   lipgloss.Style
}{
	gradePass: {"✔ PASS", lipgloss.NewStyle().Bold(true).Foreground(cGreen)},
	gradeWarn: {"! WARN", lipgloss.NewStyle().Bold(true).Foreground(cOrange)},
	gradeFail: {"✘ FAIL", lipgloss.NewStyle().Bold(true).Foreground(cRed)},
}

// auditNameWidth is the widest check name in runes, so rows align.
func auditNameWidth(findings []auditFinding) int {
	width := 0
	for _, f := range findings {
		width = max(width, len([]rune(f.Name)))
	}
	return width
}

// writeAuditRows writes one "badge  name  reason" row per finding, the name
// padded to width runes.
func writeAuditRows(b *strings.Builder, findings []auditFinding, width int, st styles, paint func(lipgloss.Style, string) string) {
	for _, f := range findings {
		bd := auditBadges[f.Grade]
		name := f.Name + strings.Repeat(" ", max(0, width-len([]rune(f.Name))))
		fmt.Fprintf(b, "  %s  %s  %s\n", paint(bd.col, bd.label), paint(st.headerKey, name), f.Reason)
	}
}

// writeAuditTally writes the "N pass · N warn · N fail" footer line.
func writeAuditTally(b *strings.Builder, pass, warn, fail int, st styles, paint func(lipgloss.Style, string) string) {
	b.WriteString("  ")
	b.WriteString(strings.Join([]string{
		paint(auditBadges[gradePass].col, fmt.Sprintf("%d pass", pass)),
		paint(auditBadges[gradeWarn].col, fmt.Sprintf("%d warn", warn)),
		paint(auditBadges[gradeFail].col, fmt.Sprintf("%d fail", fail)),
	}, paint(st.meta, " · ")))
	b.WriteString("\n")
}

// checkAudit turns a report into a plugin verdict (see checkFindings).
func checkAudit(rep auditReport) checkVerdict {
	return checkFindings("audit", rep.Findings, map[string]any{"http_status": rep.Status})
}

// checkFindings grades findings as a plugin verdict for check: any fail is
// CRITICAL, any warn WARNING. The message names the failing checks first,
// then the warning ones, each with its reason; line() runs it through
// checkSafe. metrics gains the pass/warn/fail counts, which are also the
// perfdata.
func checkFindings(check string, findings []auditFinding, metrics map[string]any) checkVerdict {
	var count [len(auditGradeNames)]int
	for _, f := range findings {
		count[f.Grade]++
	}
	pass, warn, fail := count[gradePass], count[gradeWarn], count[gradeFail]
	perf := fmt.Sprintf("pass=%d warn=%d fail=%d", pass, warn, fail)
	if metrics == nil {
		metrics = map[string]any{}
	}
	metrics["pass"], metrics["warn"], metrics["fail"] = pass, warn, fail
	code := checkOK
	switch {
	case fail > 0:
		code = checkCritical
	case warn > 0:
		code = checkWarning
	}
	msg := fmt.Sprintf("all %d checks pass", len(findings))
	if code != checkOK {
		var parts []string
		for _, g := range []auditGrade{gradeFail, gradeWarn} {
			for _, f := range findings {
				if f.Grade == g {
					parts = append(parts, f.Name+" ("+f.Reason+")")
				}
			}
		}
		msg = fmt.Sprintf("%d fail, %d warn: %s", fail, warn, strings.Join(parts, "; "))
	}
	return newCheckVerdict(check, code, msg, perf, metrics)
}

// ---- command ----------------------------------------------------------------

// runAudit handles `weeb audit URL [-H "K: V"]... [--timeout DUR] [--json]
// [--check] [--persona MODE]`. It exits 0 once the audit ran, whatever the
// grades (--check is the graded mode), 1 when the page couldn't be fetched,
// and 2 on bad usage.
func runAudit(args []string) int {
	var target, persona string
	var headers []Header
	var asJSON, checkMode bool
	timeout := defaultTimeout

	usage := func(err error) int {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 2
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--json":
			asJSON = true
		case arg == "--check" || arg == "--nagios":
			checkMode = true
		case arg == "-H" || arg == "--header":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return usage(err)
			}
			k, v, ok := strings.Cut(val, ":")
			if !ok {
				return usage(fmt.Errorf("bad header %q (want \"Key: Value\")", val))
			}
			headers = append(headers, Header{Key: strings.TrimSpace(k), Value: strings.TrimSpace(v)})
		case arg == "--timeout":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return usage(err)
			}
			d, err := time.ParseDuration(val)
			if err != nil || d <= 0 {
				return usage(fmt.Errorf("bad --timeout %q", val))
			}
			timeout = d
		case arg == "--persona":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return usage(err)
			}
			persona = val
		case strings.HasPrefix(arg, "-") && arg != "-":
			return usage(fmt.Errorf("unknown flag %q", arg))
		default:
			if target != "" {
				return usage(fmt.Errorf("unexpected argument %q", arg))
			}
			target = arg
		}
	}
	if target == "" {
		return usage(fmt.Errorf("audit needs a URL, e.g. 'weeb audit https://example.com'"))
	}
	personaMode, err := resolvePersona(persona)
	if err != nil {
		return usage(err)
	}

	// Like weeb cert, a bare host means https: the plain-http listener's
	// answer is always "no HSTS", which is rarely the question.
	if t := strings.TrimSpace(target); !hasScheme(t) && !strings.HasPrefix(t, "/") {
		target = "https://" + t
	}

	logger, _, cleanup := newLogger(modeCLI)
	defer cleanup()
	client := newClient(logger, errorChanFor(personaMode))
	// Only the headers matter, so the body is discarded through a sink; an
	// explicit timeout keeps Do bounding that sink's transfer too.
	client.SetTimeout(timeout)
	res := client.Do(RequestSpec{Method: "GET", URL: target, Headers: headers, BodySink: io.Discard})

	if res.Status == 0 {
		if checkMode {
			// The headers were never observed: UNKNOWN, as for an
			// unreachable `weeb cert --check`.
			msg := "no response"
			if res.Err != nil {
				msg = res.Err.Error()
			}
			return printCheck(outW, newCheckVerdict("audit", checkUnknown, checkSafe(msg), "", nil), asJSON)
		}
		fmt.Fprintln(errW, res.DisplayErr)
		return 1
	}

	rep := newAuditReport(res)
	switch {
	case checkMode:
		return printCheck(outW, checkAudit(rep), asJSON)
	case asJSON:
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Fprintln(outW, string(out))
	default:
		color := stdoutIsTTY() && os.Getenv("NO_COLOR") == ""
		fmt.Fprint(outW, renderAudit(rep, newStyles(), color))
	}
	return 0
}
