package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// `weeb probe HOST` is a one-shot transport-security report for a site. It
// asks the server, one handshake per question, which TLS versions it accepts,
// whether it still takes RC4/3DES or static-RSA cipher suites, and what
// certificate it presents; it walks the plain-http entry point to see whether
// it upgrades to https; and it grades the https page's security headers the
// way `weeb audit` does. Every check is an auditFinding, so the table, --json
// and --check outputs follow audit's.
//
// Handshakes skip verification so a broken certificate still yields a full
// protocol report; the Certificate row grades trust separately. Every server
// value quoted in a reason goes through auditShow or checkSafe, as in audit.

// probeDefaultTimeout bounds each handshake and each request. It's shorter
// than a request's 30s because a probe makes a dozen of them, and a filtered
// port 80 would otherwise hold the whole report for half a minute.
const probeDefaultTimeout = 10 * time.Second

// probeMaxHops caps the plain-http redirect walk, like the stdlib's 10.
const probeMaxHops = 10

// Certificate expiry thresholds, the `weeb cert --check` defaults.
const (
	probeCertWarnDays = 30
	probeCertCritDays = 14
)

// probeTargets is where each part of the probe goes. runProbe derives it from
// the argument; tests point it at httptest servers.
type probeTargets struct {
	host     string // server name: SNI and the certificate hostname check
	addr     string // host:port the TLS handshakes dial
	httpsURL string // page whose security headers are graded
	httpURL  string // plain-http entry point the redirect walk starts from
}

// probeTargetsFor reads `weeb probe` input: a bare host, host:port, or URL. A
// port belongs to the URL's scheme (https when none is given), and the other
// scheme keeps its default port; a path is kept for both URLs.
func probeTargetsFor(arg string) (probeTargets, error) {
	raw := strings.TrimSpace(arg)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return probeTargets{}, fmt.Errorf("no host in %q", arg)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return probeTargets{}, fmt.Errorf("probe takes an http(s) URL or a host, not %q", u.Scheme+"://")
	}
	host := u.Hostname()
	httpsPort, httpPort := "443", "80"
	if p := u.Port(); p != "" {
		if scheme == "https" {
			httpsPort = p
		} else {
			httpPort = p
		}
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return probeTargets{
		host:     host,
		addr:     net.JoinHostPort(host, httpsPort),
		httpsURL: probeURL("https", host, httpsPort, "443", path),
		httpURL:  probeURL("http", host, httpPort, "80", path),
	}, nil
}

// probeURL builds scheme://host[:port]path, leaving out the default port.
func probeURL(scheme, host, port, defPort, path string) string {
	hp := host
	if strings.Contains(host, ":") {
		hp = "[" + host + "]" // IPv6 literal
	}
	if port != defPort {
		hp = net.JoinHostPort(host, port)
	}
	return scheme + "://" + hp + path
}

// probeOptions are runProbe's flags.
type probeOptions struct {
	timeout  time.Duration
	headers  []Header // -H, sent only on the https header fetch
	insecure bool     // -k: fetch headers even when the certificate is untrusted
}

// ---- report -----------------------------------------------------------------

// probeProtocol is whether the server completed a handshake pinned to one
// TLS version.
type probeProtocol struct {
	Version string `json:"version"`
	Offered bool   `json:"offered"`
	Cipher  string `json:"cipher,omitempty"` // suite chosen when offered
	Error   string `json:"error,omitempty"`  // why the handshake failed
	unsure  bool   // timed out or the connection dropped: no answer either way
}

// probeConn summarizes the handshake made with default client settings, the
// one a modern browser would get.
type probeConn struct {
	Version     string `json:"version"`
	Cipher      string `json:"cipher"`
	ALPN        string `json:"alpn,omitempty"`
	OCSPStapled bool   `json:"ocsp_stapled"`
}

// probeHop is one response on the plain-http redirect walk.
type probeHop struct {
	URL      string `json:"url"`
	Status   int    `json:"status,omitempty"`
	Location string `json:"location,omitempty"` // resolved redirect target
	Error    string `json:"error,omitempty"`    // no response
}

// probeSection groups findings under a heading; Detail is what was probed.
type probeSection struct {
	Name     string         `json:"name"`
	Detail   string         `json:"detail,omitempty"`
	Findings []auditFinding `json:"findings"`
}

// probeReport is the whole probe of one host.
type probeReport struct {
	Host        string          `json:"host"`
	Address     string          `json:"address"`
	Conn        *probeConn      `json:"tls,omitempty"`
	Protocols   []probeProtocol `json:"protocols,omitempty"`
	Certificate *certInfo       `json:"certificate,omitempty"` // the leaf
	HTTP        []probeHop      `json:"http_redirects"`
	URL         string          `json:"url"`              // final https page whose headers were graded
	Status      int             `json:"status,omitempty"` // its status; 0 when the fetch failed
	Redirects   []string        `json:"redirects,omitempty"`
	Sections    []probeSection  `json:"sections"`
	Pass        int             `json:"pass"`
	Warn        int             `json:"warn"`
	Fail        int             `json:"fail"`
}

// findings is every section's findings in order.
func (r probeReport) findings() []auditFinding {
	var out []auditFinding
	for _, s := range r.Sections {
		out = append(out, s.Findings...)
	}
	return out
}

func (r *probeReport) tally() {
	r.Pass, r.Warn, r.Fail = 0, 0, 0
	for _, f := range r.findings() {
		switch f.Grade {
		case gradePass:
			r.Pass++
		case gradeWarn:
			r.Warn++
		case gradeFail:
			r.Fail++
		}
	}
}

// errProbeUnreachable means neither https nor plain http answered, so there
// is nothing to report on.
var errProbeUnreachable = errors.New("unreachable")

// ---- TLS --------------------------------------------------------------------

// probeAttempt is one handshake's outcome. dialed separates "the server
// refused this handshake" from "nothing answered".
type probeAttempt struct {
	state  tls.ConnectionState
	dialed bool
	err    error
}

func (a probeAttempt) ok() bool { return a.dialed && a.err == nil }

// probeHandshake dials addr and runs a single TLS handshake with cfg.
func probeHandshake(addr string, cfg *tls.Config, timeout time.Duration) probeAttempt {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return probeAttempt{err: err}
	}
	defer conn.Close()
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return probeAttempt{dialed: true, err: err}
	}
	return probeAttempt{state: tc.ConnectionState(), dialed: true}
}

// probeUnsure reports whether a failed handshake says nothing about the
// server's settings: it timed out or the connection dropped mid-handshake.
// Servers that reject a version usually send an alert, which is a definite no.
func probeUnsure(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// probeSuites lists the TLS 1.0–1.2 suites Go can offer, insecure ones
// included, whose names pass keep.
func probeSuites(keep func(name string) bool) []uint16 {
	var ids []uint16
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if keep(s.Name) {
			ids = append(ids, s.ID)
		}
	}
	return ids
}

func probeWeakSuite(name string) bool {
	return strings.Contains(name, "_RC4_") || strings.Contains(name, "_3DES_")
}

func probeStaticRSASuite(name string) bool { return strings.HasPrefix(name, "TLS_RSA_") }

var probeVersions = []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}

// probeTLSRun is the raw outcome of every handshake a probe makes.
type probeTLSRun struct {
	main      probeAttempt   // default client settings, ALPN h2 + http/1.1
	versions  []probeAttempt // one per probeVersions entry
	weak      probeAttempt   // only RC4 and 3DES suites offered
	staticRSA probeAttempt   // only static-RSA key exchange offered
}

// runProbeTLS makes every handshake concurrently.
func runProbeTLS(t probeTargets, timeout time.Duration) probeTLSRun {
	base := func() *tls.Config {
		return &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // probing what the server accepts; trust is graded on its own
			ServerName:         t.host,
		}
	}
	legacy := func(suites []uint16) *tls.Config {
		c := base()
		c.MinVersion, c.MaxVersion = tls.VersionTLS10, tls.VersionTLS12
		c.CipherSuites = suites
		return c
	}
	all := probeSuites(func(string) bool { return true })

	run := probeTLSRun{versions: make([]probeAttempt, len(probeVersions))}
	var wg sync.WaitGroup
	wg.Go(func() {
		c := base()
		c.NextProtos = []string{"h2", "http/1.1"}
		run.main = probeHandshake(t.addr, c, timeout)
	})
	for i, v := range probeVersions {
		wg.Go(func() {
			c := base()
			// An explicit MinVersion is what lets Go offer TLS 1.0 and 1.1 at
			// all, and an explicit suite list what lets it offer the suites
			// left out by default, the ones old servers tend to need.
			c.MinVersion, c.MaxVersion, c.CipherSuites = v, v, all
			run.versions[i] = probeHandshake(t.addr, c, timeout)
		})
	}
	wg.Go(func() { run.weak = probeHandshake(t.addr, legacy(probeSuites(probeWeakSuite)), timeout) })
	wg.Go(func() { run.staticRSA = probeHandshake(t.addr, legacy(probeSuites(probeStaticRSASuite)), timeout) })
	wg.Wait()
	return run
}

// reachable reports whether any handshake got as far as a TCP connection.
func (r probeTLSRun) reachable() bool {
	if r.main.dialed || r.weak.dialed || r.staticRSA.dialed {
		return true
	}
	for _, v := range r.versions {
		if v.dialed {
			return true
		}
	}
	return false
}

// probeClean makes a peer-influenced error string safe for one line of a
// report: ANSI and control characters gone, capped in length.
func probeClean(s string) string {
	s = strings.TrimSpace(checkSafe(s))
	if r := []rune(s); len(r) > 120 {
		s = string(r[:119]) + "…"
	}
	return s
}

// tlsSection grades the handshakes and fills in the report's TLS fields.
func (r *probeReport) tlsSection(run probeTLSRun, host string) probeSection {
	sec := probeSection{Name: "TLS", Detail: r.Address}
	if !run.reachable() {
		err := run.main.err
		sec.Findings = []auditFinding{{
			ID: "tls", Name: "TLS", Grade: gradeFail,
			Reason: "can't connect to " + r.Address + ": " + probeClean(errString(err)),
		}}
		return sec
	}

	if run.main.ok() {
		s := run.main.state
		r.Conn = &probeConn{
			Version: tls.VersionName(s.Version), Cipher: tls.CipherSuiteName(s.CipherSuite),
			ALPN: s.NegotiatedProtocol, OCSPStapled: len(s.OCSPResponse) > 0,
		}
	}

	offered := map[uint16]bool{}
	var chain []*x509.Certificate // the highest offered version's, if main failed
	if run.main.ok() {
		chain = run.main.state.PeerCertificates
	}
	for i, v := range probeVersions {
		a := run.versions[i]
		p := probeProtocol{Version: tls.VersionName(v), Offered: a.ok()}
		if a.ok() {
			offered[v] = true
			p.Cipher = tls.CipherSuiteName(a.state.CipherSuite)
			if !run.main.ok() {
				chain = a.state.PeerCertificates
			}
		} else {
			p.Error = probeClean(errString(a.err))
			p.unsure = !a.dialed || probeUnsure(a.err)
		}
		r.Protocols = append(r.Protocols, p)
	}
	for _, p := range r.Protocols {
		sec.Findings = append(sec.Findings, probeVersionFinding(p, offered))
	}
	sec.Findings = append(sec.Findings,
		probeSuiteFinding("weak_ciphers", "Weak ciphers", run.weak, gradeFail,
			"accepts %s, a broken cipher", "rejects RC4 and 3DES"),
		probeSuiteFinding("forward_secrecy", "Forward secrecy", run.staticRSA, gradeWarn,
			"accepts %s: static RSA key exchange, so a stolen key decrypts recorded traffic",
			"rejects static RSA key exchange"),
	)
	cert, leaf := probeCertFinding(chain, host)
	r.Certificate = leaf
	sec.Findings = append(sec.Findings, cert)
	return sec
}

// probeVersionFinding grades one protocol version. TLS 1.0 and 1.1 are
// deprecated (RFC 8996); TLS 1.2 may be absent only when 1.3 is offered.
func probeVersionFinding(p probeProtocol, offered map[uint16]bool) auditFinding {
	id := "tls" + strings.TrimPrefix(p.Version, "TLS ")
	f := auditFinding{ID: id, Name: p.Version, Value: p.Cipher}
	switch {
	case p.unsure:
		f.Grade, f.Reason = gradeWarn, "no answer: "+p.Error
	case p.Version == "TLS 1.0" || p.Version == "TLS 1.1":
		if p.Offered {
			f.Grade, f.Reason = gradeFail, "offered, but deprecated since 2021 (RFC 8996)"
		} else {
			f.Reason = "not offered"
		}
	case p.Offered:
		f.Reason = "offered, " + p.Cipher
	case p.Version == "TLS 1.2" && offered[tls.VersionTLS13]:
		f.Reason = "not offered; TLS 1.3 only"
	case p.Version == "TLS 1.2":
		f.Grade, f.Reason = gradeFail, "not offered, and neither is TLS 1.3"
	default: // TLS 1.3
		f.Grade, f.Reason = gradeWarn, "not offered"
	}
	return f
}

// probeSuiteFinding grades a handshake that offered only suites the server
// should refuse: completing it earns bad, with badFmt naming the suite.
func probeSuiteFinding(id, name string, a probeAttempt, bad auditGrade, badFmt, ok string) auditFinding {
	f := auditFinding{ID: id, Name: name}
	switch {
	case a.ok():
		suite := tls.CipherSuiteName(a.state.CipherSuite)
		f.Grade, f.Reason, f.Value = bad, fmt.Sprintf(badFmt, suite), suite
	case !a.dialed || probeUnsure(a.err):
		f.Grade, f.Reason = gradeWarn, "no answer: "+probeClean(errString(a.err))
	default:
		f.Reason = ok
	}
	return f
}

// probeCertFinding grades the presented chain: trust and hostname against
// the system roots, then the leaf's expiry.
func probeCertFinding(chain []*x509.Certificate, host string) (auditFinding, *certInfo) {
	f := auditFinding{ID: "certificate", Name: "Certificate"}
	if len(chain) == 0 {
		f.Grade, f.Reason = gradeFail, "no handshake completed, so no certificate to check"
		return f, nil
	}
	leaf := describeCert(chain[0])
	f.Value = leaf.name()
	trusted, verr := verifyChain(host, chain)
	days := leaf.DaysUntilExpiry
	switch {
	case days < 0:
		f.Grade, f.Reason = gradeFail, "expired "+auditPlural(-days, "day", "days")+" ago"
	case !trusted:
		f.Grade, f.Reason = gradeFail, "untrusted: "+probeClean(verr)
	case days < probeCertCritDays:
		f.Grade, f.Reason = gradeFail, "expires in "+auditPlural(days, "day", "days")
	case days < probeCertWarnDays:
		f.Grade, f.Reason = gradeWarn, "expires in "+auditPlural(days, "day", "days")
	default:
		f.Reason = "trusted, expires in " + auditPlural(days, "day", "days")
		if leaf.IssuerCN != "" {
			f.Reason += ", issued by " + auditShow(leaf.IssuerCN)
		}
	}
	return f, &leaf
}

func errString(err error) string {
	if err == nil {
		return "no response"
	}
	return err.Error()
}

// ---- plain http -------------------------------------------------------------

// probeRedirects walks the plain-http entry point one hop at a time until a
// redirect points at https, a response isn't a redirect, or probeMaxHops.
// Nothing ambient is sent: plain http is readable on the wire, so neither -H
// nor WEEB_TOKEN/WEEB_HEADERS go along.
func probeRedirects(client *Client, start string) []probeHop {
	var hops []probeHop
	cur := start
	for range probeMaxHops {
		res := client.Do(RequestSpec{
			Method: "GET", URL: cur, NoFollow: true, HeadersResolved: true, BodySink: io.Discard,
		})
		hop := probeHop{URL: cur, Status: res.Status}
		if res.Status == 0 {
			hop.Error = probeClean(errString(res.Err))
			return append(hops, hop)
		}
		loc := res.Headers.Get("Location")
		if res.Status < 300 || res.Status > 399 || loc == "" {
			return append(hops, hop)
		}
		base, _ := url.Parse(cur)
		next, err := base.Parse(loc)
		if err != nil {
			hop.Error = "bad Location " + auditShow(loc)
			return append(hops, hop)
		}
		hop.Location = next.String()
		hops = append(hops, hop)
		if !strings.EqualFold(next.Scheme, "http") {
			return hops // reached https (or left the web): the walk is over
		}
		cur = next.String()
	}
	return hops
}

// probeRedirectFinding grades the walk. The first hop should be a permanent
// redirect to https on the same host: a browser only applies HSTS to a host
// after visiting it over https, so an upgrade by way of another host (or a
// temporary redirect the browser won't remember) leaves the first plain-http
// visit exposed every time.
func probeRedirectFinding(hops []probeHop, host string) auditFinding {
	f := auditFinding{ID: "http_redirect", Name: "HTTPS redirect", Value: probeHopChain(hops)}
	if len(hops) == 0 {
		f.Grade, f.Reason = gradeFail, "no response"
		return f
	}
	first, last := hops[0], hops[len(hops)-1]
	if first.Status == 0 {
		f.Reason = "plain http doesn't answer, so nothing is served over it (" + first.Error + ")"
		return f
	}
	lastURL, _ := url.Parse(last.Location)
	if last.Location == "" || lastURL == nil || !strings.EqualFold(lastURL.Scheme, "https") {
		f.Grade = gradeFail
		switch {
		case len(hops) == 1 && first.Location == "" && first.Error == "":
			f.Reason = fmt.Sprintf("serves %d over plain http instead of redirecting to https", first.Status)
		case last.Error != "":
			f.Reason = "redirect chain broke: " + last.Error
		case len(hops) >= probeMaxHops && last.Location != "":
			f.Reason = fmt.Sprintf("%d redirects without reaching https", probeMaxHops)
		default:
			f.Reason = fmt.Sprintf("redirects stay on plain http, ending at %d", last.Status)
		}
		return f
	}
	firstURL, _ := url.Parse(first.Location)
	sameHost := firstURL != nil && strings.EqualFold(firstURL.Scheme, "https") &&
		strings.EqualFold(firstURL.Hostname(), host)
	switch {
	case !sameHost:
		f.Grade = gradeWarn
		f.Reason = "first redirect goes to " + auditShow(first.Location) +
			", not https on the same host, so browsers can't pick up HSTS for it"
	case first.Status == http.StatusMovedPermanently || first.Status == http.StatusPermanentRedirect:
		f.Reason = fmt.Sprintf("%d to %s", first.Status, auditShow(first.Location))
	default:
		f.Grade = gradeWarn
		f.Reason = fmt.Sprintf("%d is temporary; 301 or 308 lets browsers remember the upgrade", first.Status)
	}
	return f
}

// probeHopChain renders the walk as "URL 301 → URL 200".
func probeHopChain(hops []probeHop) string {
	var parts []string
	for i, h := range hops {
		s := h.URL
		if h.Status != 0 {
			s += fmt.Sprintf(" %d", h.Status)
		}
		parts = append(parts, s)
		if i == len(hops)-1 && h.Location != "" {
			parts = append(parts, h.Location)
		}
	}
	return strings.Join(parts, " → ")
}

// ---- headers ----------------------------------------------------------------

// headerSection fetches the https page (redirects followed) and grades its
// security headers with audit's checks.
func (r *probeReport) headerSection(res Result, insecure bool) probeSection {
	sec := probeSection{Name: "Security headers", Detail: r.URL}
	if res.Status == 0 {
		reason := "couldn't fetch the page: " + probeClean(errString(res.Err))
		var verr *tls.CertificateVerificationError
		if !insecure && errors.As(res.Err, &verr) {
			reason += "; -k grades the headers anyway"
		}
		sec.Findings = []auditFinding{{ID: "headers", Name: "Security headers", Grade: gradeFail, Reason: reason}}
		return sec
	}
	r.URL, r.Status, r.Redirects = res.URL, res.Status, res.Redirects
	sec.Detail = fmt.Sprintf("%s  %d %s", res.URL, res.Status, http.StatusText(res.Status))
	https := false
	if u, err := url.Parse(res.URL); err == nil {
		https = strings.EqualFold(u.Scheme, "https")
	}
	sec.Findings = auditHeaders(res.Headers, https)
	return sec
}

// ---- probe ------------------------------------------------------------------

// probe runs every check against t. The TLS handshakes, the redirect walk
// and the header fetch run concurrently, so the probe takes about as long as
// its slowest connection.
func probe(t probeTargets, o probeOptions, client *Client) (probeReport, error) {
	rep := probeReport{Host: t.host, Address: t.addr, URL: t.httpsURL}
	var (
		run  probeTLSRun
		hops []probeHop
		page Result
		wg   sync.WaitGroup
	)
	wg.Go(func() { run = runProbeTLS(t, o.timeout) })
	wg.Go(func() { hops = probeRedirects(client, t.httpURL) })
	wg.Go(func() {
		// Only the -H the user typed go along (HeadersResolved), not the
		// ambient WEEB_TOKEN/WEEB_HEADERS: a probe aims at arbitrary hosts.
		page = client.Do(RequestSpec{
			Method: "GET", URL: t.httpsURL, Headers: o.headers, HeadersResolved: true,
			BodySink: io.Discard, TLS: TLSOptions{Insecure: o.insecure},
		})
	})
	wg.Wait()

	if !run.reachable() && len(hops) > 0 && hops[0].Status == 0 {
		return rep, fmt.Errorf("%w: %s and %s: %s", errProbeUnreachable, t.addr, t.httpURL, errString(run.main.err))
	}
	rep.HTTP = hops
	rep.Sections = []probeSection{
		rep.tlsSection(run, t.host),
		{Name: "Plain HTTP", Detail: t.httpURL, Findings: []auditFinding{probeRedirectFinding(hops, t.host)}},
		rep.headerSection(page, o.insecure),
	}
	rep.tally()
	return rep, nil
}

// ---- rendering --------------------------------------------------------------

// renderProbe draws the report: a summary of the default handshake, then
// each section's rows under its heading, then the tally.
func renderProbe(rep probeReport, st styles, color bool) string {
	paint := auditPainter(color)
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s\n", paint(st.paneTitle, "Probe"), rep.Host)
	if c := rep.Conn; c != nil {
		parts := []string{c.Version, c.Cipher}
		if c.ALPN != "" {
			parts = append(parts, "ALPN "+c.ALPN)
		}
		if c.OCSPStapled {
			parts = append(parts, "OCSP stapled")
		}
		if l := rep.Certificate; l != nil {
			parts = append(parts, checkSafe(l.name()))
		}
		fmt.Fprintln(&b, paint(st.meta, strings.Join(parts, " · ")))
	}
	width := auditNameWidth(rep.findings())
	for _, s := range rep.Sections {
		fmt.Fprintf(&b, "\n%s  %s\n", paint(st.headerKey, s.Name), paint(st.meta, s.Detail))
		writeAuditRows(&b, s.Findings, width, st, paint)
	}
	b.WriteString("\n")
	writeAuditTally(&b, rep.Pass, rep.Warn, rep.Fail, st, paint)
	return b.String()
}

// checkProbe turns a report into a plugin verdict (see checkFindings).
func checkProbe(rep probeReport) checkVerdict {
	metrics := map[string]any{}
	if rep.Status != 0 {
		metrics["http_status"] = rep.Status
	}
	if rep.Certificate != nil {
		metrics["days_until_expiry"] = rep.Certificate.DaysUntilExpiry
	}
	return checkFindings("probe", rep.findings(), metrics)
}

// ---- command ----------------------------------------------------------------

// runProbe handles `weeb probe HOST|URL [-H "K: V"]... [-k] [--timeout DUR]
// [--json] [--check] [--persona MODE]`. Like audit it exits 0 once the
// report is out, whatever the grades (--check is the graded mode), 1 when the
// host is unreachable, and 2 on bad usage.
func runProbe(args []string) int {
	var target, persona string
	var asJSON, checkMode bool
	o := probeOptions{timeout: probeDefaultTimeout}

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
		case arg == "-k" || arg == "--insecure":
			o.insecure = true
		case arg == "-H" || arg == "--header":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return usage(err)
			}
			k, v, ok := strings.Cut(val, ":")
			if !ok {
				return usage(fmt.Errorf("bad header %q (want \"Key: Value\")", val))
			}
			o.headers = append(o.headers, Header{Key: strings.TrimSpace(k), Value: strings.TrimSpace(v)})
		case arg == "--timeout":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return usage(err)
			}
			d, err := time.ParseDuration(val)
			if err != nil || d <= 0 {
				return usage(fmt.Errorf("bad --timeout %q", val))
			}
			o.timeout = d
		case arg == "--persona":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return usage(err)
			}
			persona = val
		case strings.HasPrefix(arg, "-"):
			return usage(fmt.Errorf("unknown flag %q", arg))
		default:
			if target != "" {
				return usage(fmt.Errorf("unexpected argument %q", arg))
			}
			target = arg
		}
	}
	if target == "" {
		return usage(fmt.Errorf("probe needs a host, e.g. 'weeb probe example.com'"))
	}
	t, err := probeTargetsFor(target)
	if err != nil {
		return usage(err)
	}
	personaMode, err := resolvePersona(persona)
	if err != nil {
		return usage(err)
	}
	if o.insecure {
		fmt.Fprintln(os.Stderr, "weeb: warning: -k/--insecure: the header fetch skips certificate verification (the Certificate check still grades trust)")
	}

	logger, _, cleanup := newLogger(modeCLI)
	defer cleanup()
	voice := errorChanFor(personaMode)
	client := newClient(logger, voice)
	client.SetTimeout(o.timeout)
	client.noHistory = true // a dozen probe requests would crowd out real history
	logger.Info("probe", "host", t.host, "addr", t.addr)

	rep, err := probe(t, o, client)
	if err != nil {
		logger.Error("probe failed", "kind", KindTransport.String(), "err", err)
		if checkMode {
			// Nothing was observed: UNKNOWN, as for an unreachable cert check.
			return printCheck(outW, newCheckVerdict("probe", checkUnknown, checkSafe(err.Error()), "", nil), asJSON)
		}
		fmt.Fprintln(errW, voice.Render(KindTransport, 0, err))
		return 1
	}

	switch {
	case checkMode:
		return printCheck(outW, checkProbe(rep), asJSON)
	case asJSON:
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Fprintln(outW, string(out))
	default:
		color := stdoutIsTTY() && os.Getenv("NO_COLOR") == ""
		fmt.Fprint(outW, renderProbe(rep, newStyles(), color))
	}
	return 0
}
