package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	log "charm.land/log/v2"
)

const defaultTimeout = 30 * time.Second

// maxBodyBytes caps how much of a response body is buffered. Everything weeb
// does with a body (pretty-print, tree views, TUI render) needs it in memory,
// so an unbounded read would let a hostile or runaway server stream gigabytes
// within the timeout window and OOM the process. A var so tests can lower it
// and applyMaxBody can override it (--max-body / WEEB_MAX_BODY). Bodies
// streamed to a BodySink are never capped.
var maxBodyBytes int64 = 64 << 20 // 64 MiB

// applyMaxBody sets the buffered-body cap: the --max-body flag value wins,
// then WEEB_MAX_BODY, then the 64 MiB default stands. A value of 0 disables
// the cap entirely.
func applyMaxBody(flag string) error {
	src := flag
	if src == "" {
		src = os.Getenv("WEEB_MAX_BODY")
	}
	if src == "" {
		return nil
	}
	n, err := parseSize(src)
	if err != nil {
		return fmt.Errorf("bad body size limit %q (bytes, or k/m/g suffix, e.g. 256m; 0 = no cap)", src)
	}
	if n == 0 {
		n = 1 << 62 // effectively uncapped, without overflowing the +1 probe read
	}
	maxBodyBytes = n
	return nil
}

// parseSize parses a human byte size: a plain integer is bytes; k/m/g
// suffixes are binary multiples, case-insensitive, with b/ib tolerated
// ("64m", "1G", "512KiB", "1048576").
func parseSize(s string) (int64, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	num, mult := t, int64(1)
	switch {
	case strings.HasSuffix(t, "kib"):
		num, mult = t[:len(t)-3], 1<<10
	case strings.HasSuffix(t, "mib"):
		num, mult = t[:len(t)-3], 1<<20
	case strings.HasSuffix(t, "gib"):
		num, mult = t[:len(t)-3], 1<<30
	case strings.HasSuffix(t, "kb"):
		num, mult = t[:len(t)-2], 1<<10
	case strings.HasSuffix(t, "mb"):
		num, mult = t[:len(t)-2], 1<<20
	case strings.HasSuffix(t, "gb"):
		num, mult = t[:len(t)-2], 1<<30
	case strings.HasSuffix(t, "k"):
		num, mult = t[:len(t)-1], 1<<10
	case strings.HasSuffix(t, "m"):
		num, mult = t[:len(t)-1], 1<<20
	case strings.HasSuffix(t, "g"):
		num, mult = t[:len(t)-1], 1<<30
	case strings.HasSuffix(t, "b"):
		num = t[:len(t)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(num), 10, 64)
	if err != nil || n < 0 || n > (1<<62)/mult {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return n * mult, nil
}

// Header is a single request header row.
type Header struct {
	Key   string
	Value string
}

// RequestSpec describes one HTTP request as entered by the user, before env
// prefills are resolved.
type RequestSpec struct {
	Method  string
	URL     string
	Headers []Header
	Body    []byte

	// HeadersResolved marks Headers as the user's final say: env header
	// prefills (WEEB_HEADERS/WEEB_TOKEN) were already surfaced to the user,
	// who may have deliberately removed them, so resolveSpec must not add
	// them back. The TUI form sets this; one-shot CLI specs leave it false.
	HeadersResolved bool

	// BodySink, when non-nil, receives the response body as it arrives
	// instead of it being buffered into Result.Body. Streaming bypasses
	// maxBodyBytes — the caller owns the destination (a pipe, a file), so
	// memory stays constant no matter the size, like curl.
	BodySink io.Writer
}

// Result is the outcome of handling one request. Body always holds the raw
// response bytes (even for 4xx/5xx) — except when the spec carried a BodySink,
// which received them instead; BodySize counts the bytes either way.
// DisplayErr, when non-empty, is the human-facing weeb error string produced
// by the ErrorChan seam. Err is the underlying Go error used for CLI exit
// codes; it is nil on a 2xx/3xx success.
type Result struct {
	Method      string
	URL         string
	Status      int
	StatusText  string
	Proto       string
	Headers     http.Header
	Body        []byte
	BodySize    int64
	ContentType string
	Timing      Timing
	TLS         *connTLS
	DisplayErr  string
	Err         error
}

// OK reports whether the request fully succeeded (sent, received, status < 400).
func (r Result) OK() bool { return r.Err == nil }

// bodySize is the response size in bytes, valid both for buffered bodies and
// for ones streamed to a BodySink (where Body itself stays empty). The len
// fallback keeps hand-built Results (tests, TUI fixtures) honest.
func (r Result) bodySize() int64 {
	if r.BodySize != 0 {
		return r.BodySize
	}
	return int64(len(r.Body))
}

// Client is the single component that executes requests and handles their
// results. Construct it once per process with the chosen logger and ErrorChan.
type Client struct {
	http  *http.Client
	log   *log.Logger
	voice ErrorChan
}

func newClient(logger *log.Logger, voice ErrorChan) *Client {
	return &Client{
		http:  &http.Client{Timeout: defaultTimeout, CheckRedirect: redirectPolicy},
		log:   logger,
		voice: voice,
	}
}

// redirectPolicy follows up to 10 redirects (the stdlib limit) but strips
// credential headers when a redirect leaves the original origin. Go's default
// policy only drops Authorization/Cookie on cross-DOMAIN hops — subdomains
// are allowed, the scheme is ignored, and custom headers are never touched —
// so the ambient env credentials weeb injects (WEEB_HEADERS, WEEB_TOKEN)
// would otherwise follow a redirect to an attacker origin, and a bearer token
// would survive a same-host https→http downgrade in cleartext.
func redirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	if keepsCredentials(via[0].URL, req.URL) {
		return nil
	}
	req.Header.Del("Authorization")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Cookie")
	for _, h := range parseHeaderList(os.Getenv("WEEB_HEADERS")) {
		req.Header.Del(h.Key)
	}
	return nil
}

// keepsCredentials reports whether a redirect from orig to next stays within
// the original origin closely enough to keep sending credentials: the same
// host, no TLS downgrade, and the same effective port — compared regardless
// of scheme, so http://host:8080 → https://host:8443 can't reach a different
// service on the host with credentials attached. The one allowed port change
// is the default-port http(80) → https(443) upgrade.
func keepsCredentials(orig, next *url.URL) bool {
	if !strings.EqualFold(orig.Hostname(), next.Hostname()) {
		return false
	}
	if orig.Scheme == "https" && next.Scheme == "http" {
		return false // TLS downgrade: never send credentials in cleartext
	}
	op, np := effectivePort(orig), effectivePort(next)
	if op == np {
		return true
	}
	// Another port is a different service — except the standard TLS upgrade.
	return orig.Scheme == "http" && next.Scheme == "https" && op == "80" && np == "443"
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// Do is THE chokepoint. It resolves env prefills, builds and executes the
// request, and is the ONLY place that drives both seams: charm/log records the
// structured diagnostic line, and on failure the ErrorChan produces the human
// display string. No other code logs request-lifecycle events or formats a
// failure for display.
func (c *Client) Do(spec RequestSpec) Result {
	spec = resolveSpec(spec)
	res := Result{Method: strings.ToUpper(strings.TrimSpace(spec.Method)), URL: spec.URL}

	req, err := buildRequest(spec)
	if err != nil {
		c.log.Error("request failed", "kind", KindBadRequest.String(), "err", err)
		res.Err = err
		res.DisplayErr = c.voice.Render(KindBadRequest, 0, err)
		return res
	}
	res.Method = req.Method
	res.URL = req.URL.String()

	rlog := c.log.With("method", req.Method, "url", res.URL)
	rlog.Info("request")

	// History is recorded after the fact: deferred here — past the build
	// errors, so only requests that were actually attempted leave an entry —
	// and the closure sees the final res (status, duration) on every return
	// path below. Best-effort by construction; recordHistory never fails Do.
	defer func() { c.recordHistory(spec, res) }()

	tr := &reqTrace{}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), tr.clientTrace()))

	start := time.Now()
	tr.start = start
	resp, err := c.http.Do(req)
	if err != nil {
		dur := time.Since(start)
		res.Timing.Total = dur // no trace events fired; record the wall time at least
		rlog.Error("request failed",
			"kind", KindTransport.String(), "duration_ms", dur.Milliseconds(), "err", err)
		res.Err = err
		res.DisplayErr = c.voice.Render(KindTransport, 0, err)
		return res
	}
	defer resp.Body.Close()

	var body []byte
	var bodySize int64
	var readErr error
	if spec.BodySink != nil {
		// Streaming: bytes go to the sink as they arrive, uncapped — the
		// caller owns the destination, memory stays constant.
		bodySize, readErr = io.Copy(spec.BodySink, resp.Body)
	} else {
		body, readErr = io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
		if readErr == nil && int64(len(body)) > maxBodyBytes {
			body = body[:maxBodyBytes]
			capStr := humanSize(int(maxBodyBytes))
			readErr = fmt.Errorf("response body exceeds %s; keeping the first %s", capStr, capStr)
		}
		bodySize = int64(len(body))
	}
	done := time.Now()
	dur := done.Sub(start)

	res.Timing = tr.timing(done)
	res.TLS = tlsSummary(resp.TLS)
	res.Status = resp.StatusCode
	res.StatusText = http.StatusText(resp.StatusCode)
	res.Proto = resp.Proto
	res.Headers = resp.Header
	res.ContentType = resp.Header.Get("Content-Type")
	res.Body = body
	res.BodySize = bodySize

	if readErr != nil {
		rlog.Error("request failed",
			"kind", KindBadBody.String(), "status", resp.StatusCode,
			"duration_ms", dur.Milliseconds(), "err", readErr)
		res.Err = readErr
		res.DisplayErr = c.voice.Render(KindBadBody, resp.StatusCode, readErr)
		return res
	}

	rlog.Info("response",
		"status", resp.StatusCode, "duration_ms", dur.Milliseconds(), "bytes", bodySize,
		"dns_ms", res.Timing.DNS.Milliseconds(), "tcp_ms", res.Timing.TCP.Milliseconds(),
		"tls_ms", res.Timing.TLS.Milliseconds(), "send_ms", res.Timing.Send.Milliseconds(),
		"server_ms", res.Timing.Server.Milliseconds(),
		"transfer_ms", res.Timing.Transfer.Milliseconds(), "reused", res.Timing.Reused)

	if resp.StatusCode >= 400 {
		statusErr := fmt.Errorf("server returned %d %s", resp.StatusCode, res.StatusText)
		rlog.Error("request failed",
			"kind", KindHTTPStatus.String(), "status", resp.StatusCode,
			"duration_ms", dur.Milliseconds())
		res.Err = statusErr
		res.DisplayErr = c.voice.Render(KindHTTPStatus, resp.StatusCode, statusErr)
	}
	return res
}

// resolveSpec applies the env prefills. None of them override a value the user
// already supplied, so it is safe to call even on a form that already shows the
// defaults (it stays idempotent).
//
//	WEEB_BASE_URL : relative URLs ("/me") resolve against it
//	WEEB_HEADERS  : default headers ("K:V;K2:V2"), added only if absent
//	WEEB_TOKEN    : "Authorization: Bearer $WEEB_TOKEN" unless an Authorization
//	                header is already present
//
// Header prefills are skipped when spec.HeadersResolved is set — the user has
// already seen (and possibly deleted) them in the form, and a deleted auth
// header must stay deleted. URL resolution always applies.
func resolveSpec(spec RequestSpec) RequestSpec {
	if base := envOr("WEEB_BASE_URL", ""); base != "" {
		if u := strings.TrimSpace(spec.URL); u != "" && !hasScheme(u) {
			spec.URL = joinURL(base, u)
		}
	}

	// A schemeless host defaults to http (port 80) — type "example.com:8080" and
	// it just works. (TLS cert inspection keeps its own https/443 default.) The
	// leading-slash guard leaves a bare relative path alone for WEEB_BASE_URL.
	if u := strings.TrimSpace(spec.URL); u != "" && !hasScheme(u) && !strings.HasPrefix(u, "/") {
		spec.URL = "http://" + u
	}

	if spec.HeadersResolved {
		return spec
	}

	have := map[string]bool{}
	for _, h := range spec.Headers {
		if k := strings.TrimSpace(h.Key); k != "" {
			have[strings.ToLower(k)] = true
		}
	}
	for _, h := range parseHeaderList(os.Getenv("WEEB_HEADERS")) {
		lk := strings.ToLower(h.Key)
		if !have[lk] {
			spec.Headers = append(spec.Headers, h)
			have[lk] = true
		}
	}
	if tok := os.Getenv("WEEB_TOKEN"); tok != "" && !have["authorization"] {
		spec.Headers = append(spec.Headers, Header{Key: "Authorization", Value: "Bearer " + tok})
	}
	return spec
}

func buildRequest(spec RequestSpec) (*http.Request, error) {
	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method == "" {
		method = http.MethodGet
	}
	if strings.TrimSpace(spec.URL) == "" {
		return nil, fmt.Errorf("no URL provided")
	}

	var body io.Reader
	if len(spec.Body) > 0 && methodAllowsBody(method) {
		body = bytes.NewReader(spec.Body)
	}

	req, err := http.NewRequest(method, spec.URL, body)
	if err != nil {
		return nil, err
	}
	for _, h := range spec.Headers {
		if strings.TrimSpace(h.Key) == "" {
			continue
		}
		req.Header.Add(h.Key, h.Value)
	}
	return req, nil
}

// methodAllowsBody reports whether a request body is meaningful for a method.
// Used both to attach the body and to grey out the TUI body field.
func methodAllowsBody(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func hasScheme(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}

func joinURL(base, rel string) string {
	b, err := url.Parse(base)
	if err != nil {
		return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(rel, "/")
	}
	r, err := url.Parse(rel)
	if err != nil {
		return base
	}
	return b.ResolveReference(r).String()
}

// parseHeaderList parses a "K:V;K2:V2" string into headers, tolerating spaces
// and empty segments.
func parseHeaderList(s string) []Header {
	var out []Header
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		out = append(out, Header{Key: strings.TrimSpace(k), Value: strings.TrimSpace(v)})
	}
	return out
}

// prettyBody pretty-prints the body when it looks like JSON, otherwise returns
// it unchanged. This is for DISPLAY only — CLI stdout always emits the raw bytes
// so downstream tools (jq, etc.) see exactly what the server sent.
func prettyBody(body []byte, contentType string) string {
	if isJSON(contentType) {
		var buf bytes.Buffer
		if err := json.Indent(&buf, body, "", "  "); err == nil {
			return buf.String()
		}
	}
	return string(body)
}

func isJSON(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "application/json") || strings.Contains(ct, "+json")
}

func sortedHeaderKeys(h http.Header) []string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
