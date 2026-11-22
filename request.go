package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
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

	// NoFollow stops redirect following: the 3xx response itself comes back
	// (status, Location header, body) instead of whatever it points at.
	NoFollow bool

	// TLS carries -k, --cacert and --cert/--key; the zero value verifies
	// against the system roots, as before.
	TLS TLSOptions

	// Form, when set, is a multipart/form-data body (-F) that takes the place
	// of Body. Upload files are read when the request is sent.
	Form []FormField

	// CookieFile (-b FILE) seeds a cookie jar from a Netscape cookie file and
	// CookieJar (--cookie-jar FILE, curl's -c) receives the jar's cookies
	// afterwards. Either one turns the jar on for the request, every
	// redirect hop included.
	CookieFile string
	CookieJar  string
	// OnStream, when non-nil, takes event streams live: if the response is
	// text/event-stream or JSON lines (see streamFormatOf), Do hands it the
	// response metadata as soon as the headers arrive, then each event as it
	// completes, instead of buffering the body until the server closes it.
	// Any other response is handled as if OnStream were nil. BodySink wins
	// when both are set.
	OnStream StreamSink

	// envHeaderKeys holds the lowercased names of the headers that came from
	// the environment (WEEB_HEADERS, WEEB_TOKEN) — injected by resolveSpec,
	// or, for the TUI form, rows still holding their env prefill — so
	// redirectPolicy can strip exactly those on a cross-origin hop without
	// touching same-named headers the user typed themselves.
	envHeaderKeys []string
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

	// Redirects is the URL chain when redirects were followed: the original
	// URL first, then every hop taken, ending at the final URL (which is also
	// what URL above holds). Empty when the request wasn't redirected.
	Redirects []string

	// Stream is set when the body was an event stream delivered live through
	// RequestSpec.OnStream (Body stays empty); Events counts its events.
	// Stopped records that the caller ended the request (DoContext's ctx).
	Stream  streamFormat
	Events  int
	Stopped bool
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
	http   *http.Client // its Timeout is the timeout in force: the default or --timeout
	stream *http.Client // the live path (BodySink / OnStream): no Timeout, liveTimer instead
	log    *log.Logger
	voice  ErrorChan

	// explicitTimeout records that the user passed --timeout. An explicit
	// value is a total cap, so Do keeps it on streamed transfers too — except
	// on an event stream, where it becomes an idle timeout. Only the DEFAULT
	// timeout steps aside for a BodySink or an event stream.
	explicitTimeout bool

	// transports caches one transport per TLSOptions (see tlsTransport); the
	// TUI sends from a goroutine, hence the lock.
	trMu       sync.Mutex
	transports map[tlsTransportKey]*http.Transport
}

func newClient(logger *log.Logger, voice ErrorChan) *Client {
	// http.Client.Timeout covers reading the entire body, which would kill a
	// streamed download (-o / piped) at 30s mid-transfer — and streaming
	// exists precisely for arbitrarily large bodies — or a live event stream
	// that runs for minutes. The stream client has no Timeout: Do's liveTimer
	// bounds those requests instead and, once the headers say what the body
	// is, decides whether the body is capped at all. The default transport
	// still carries its 30s dial timeout.
	return &Client{
		http:   &http.Client{Timeout: defaultTimeout, CheckRedirect: redirectPolicy},
		stream: &http.Client{CheckRedirect: redirectPolicy},
		log:    logger,
		voice:  voice,
	}
}

// SetTimeout applies a user-supplied --timeout. Explicit means "cap the whole
// request", so unlike the default it also bounds streamed (BodySink)
// transfers; on an event stream it caps the silence between bytes instead.
func (c *Client) SetTimeout(d time.Duration) {
	c.http.Timeout = d
	c.explicitTimeout = true
}

// noFollowKey and redirectChainKey are unexported request-context keys. The
// http.Client (and so its CheckRedirect) is shared across requests, so Do
// passes per-request redirect signals to redirectPolicy on the request
// context instead: noFollowKey carries a bool, redirectChainKey a *[]string
// that collects the URL of every hop followed.
type (
	noFollowKey      struct{}
	redirectChainKey struct{}
)

// envHeaderKeysCtx carries spec.envHeaderKeys on the request context so
// redirectPolicy can see which headers were env-injected — CheckRedirect
// requests inherit the original request's context.
type envHeaderKeysCtx struct{}

// redirectPolicy follows up to 10 redirects (the stdlib limit) but strips
// credential headers when a redirect leaves the original origin. Go's default
// policy only drops Authorization/Cookie on cross-DOMAIN hops — subdomains
// are allowed, the scheme is ignored, and custom headers are never touched —
// so the ambient env credentials weeb injects (WEEB_HEADERS, WEEB_TOKEN)
// would otherwise follow a redirect to an attacker origin, and a bearer token
// would survive a same-host https→http downgrade in cleartext. Only headers
// that actually came from the env (spec.envHeaderKeys, recorded on the
// context at build time, not re-read from the env) are stripped: a user-typed
// header that merely shares a name with a WEEB_HEADERS key is the user's own
// and follows redirects like any custom header, matching curl. An auto-added
// Referer is dropped on every hop, as curl -L never sends one.
func redirectPolicy(req *http.Request, via []*http.Request) error {
	// A NoFollow spec wants the 3xx itself: ErrUseLastResponse hands back the
	// redirect response, body and all, with no error.
	if nf, _ := req.Context().Value(noFollowKey{}).(bool); nf {
		return http.ErrUseLastResponse
	}
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	// Record the hop for Result.Redirects (req is the upcoming request).
	if chain, ok := req.Context().Value(redirectChainKey{}).(*[]string); ok {
		*chain = append(*chain, req.URL.String())
	}
	// net/http has already set Referer to the previous URL, query string
	// included, so a ?api_key= would reach the next origin. A Referer the user
	// set on the original request is theirs to keep, like any custom header.
	if via[0].Header.Get("Referer") == "" {
		req.Header.Del("Referer")
	}
	if keepsCredentials(via[0].URL, req.URL) {
		return nil
	}
	req.Header.Del("Authorization")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Cookie")
	if keys, ok := req.Context().Value(envHeaderKeysCtx{}).([]string); ok {
		for _, k := range keys {
			req.Header.Del(k)
		}
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
	return c.DoContext(context.Background(), spec)
}

// DoContext is Do under the caller's ctx: canceling it stops the request
// (the TUI's stop key). A live event stream stopped that way ends cleanly —
// the events that arrived stand, Result.Stopped is set and Err stays nil —
// while any other request stopped early fails as stopped.
//
// res is named so the deferred cookie-jar write can still report a failure.
func (c *Client) DoContext(ctx context.Context, spec RequestSpec) (res Result) {
	spec = resolveSpec(spec)
	res = Result{Method: strings.ToUpper(strings.TrimSpace(spec.Method)), URL: spec.URL}

	// -F parts become the body here, before the request is built, so history
	// records the bytes actually sent.
	spec, err := materializeForm(spec)
	if err != nil {
		return c.badRequest(res, err)
	}

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

	// Redirect signals travel on the request context — see redirectPolicy.
	var hops []string
	rctx := context.WithValue(req.Context(), redirectChainKey{}, &hops)
	if spec.NoFollow {
		rctx = context.WithValue(rctx, noFollowKey{}, true)
	}

	// A cookie jar (-b FILE / --cookie-jar) and TLS options each need their
	// own http.Client; both are settled before anything counts as sent.
	var jar *cookieSession
	if spec.CookieFile != "" || spec.CookieJar != "" {
		if jar, err = newCookieSession(spec.CookieFile); err != nil {
			return c.badRequest(res, err)
		}
	}
	// A body that goes somewhere as it arrives (a BodySink, or a live stream
	// for OnStream) can't run under http.Client.Timeout, which would cap the
	// body too: it takes the live client, and liveTimer applies the timeout.
	live := spec.BodySink != nil || spec.OnStream != nil
	httpc, err := c.httpClientFor(spec, jar, live)
	if err != nil {
		return c.badRequest(res, err)
	}

	// Each way weeb ends a request early — the caller's stop, a liveTimer
	// timeout — cancels with a cause naming why, which explainCancel puts in
	// the error in place of a bare "context canceled".
	rctx, cancel := context.WithCancelCause(rctx)
	defer cancel(nil)
	defer context.AfterFunc(ctx, func() { cancel(errStopped) })()
	// History is recorded after the fact: deferred here — past the build
	// errors, so only requests that were actually attempted leave an entry —
	// and the closure sees the final res (status, duration) on every return
	// path below. Best-effort by construction; recordHistory never fails Do.
	defer func() { c.recordHistory(spec, res) }()
	// The jar is written whatever happened (curl writes it even on failure:
	// a redirect hop may have set cookies), and a failed write fails the run.
	if jar != nil && spec.CookieJar != "" {
		defer func() {
			if err := jar.save(spec.CookieJar); err != nil {
				err = fmt.Errorf("writing cookie jar: %w", err)
				c.log.Error("cookie jar write failed", "err", err)
				if res.Err == nil {
					res.Err = err
				}
				if res.DisplayErr != "" {
					res.DisplayErr += "\n"
				}
				res.DisplayErr += c.voice.Render(KindBadRequest, 0, err)
			}
		}()
	}

	tr := &reqTrace{}
	req = req.WithContext(httptrace.WithClientTrace(rctx, tr.clientTrace()))

	var lt *liveTimer
	if live {
		lt = startLiveTimer(c.http.Timeout, cancel)
		defer lt.stop()
	}

	start := time.Now()
	tr.start = start
	resp, err := httpc.Do(req)
	if err != nil {
		err = explainCancel(rctx, err)
		res.Stopped = errors.Is(err, errStopped)
		dur := time.Since(start)
		res.Timing.Total = dur // no trace events fired; record the wall time at least
		rlog.Error("request failed",
			"kind", KindTransport.String(), "duration_ms", dur.Milliseconds(), "err", err)
		res.Err = err
		res.DisplayErr = c.voice.Render(KindTransport, 0, err)
		return res
	}
	defer resp.Body.Close()

	// Redirects followed: prefix the original URL so the chain reads
	// start → … → final, and point URL at where the request ended up.
	if len(hops) > 0 {
		res.Redirects = append([]string{res.URL}, hops...)
		res.URL = resp.Request.URL.String()
	}

	// The metadata is all known before the body, so a live stream can show
	// it straight away.
	res.TLS = tlsSummary(resp.TLS)
	res.Status = resp.StatusCode
	res.StatusText = http.StatusText(resp.StatusCode)
	res.Proto = resp.Proto
	res.Headers = resp.Header
	res.ContentType = resp.Header.Get("Content-Type")
	stream := streamFormatOf(res.ContentType)

	// With the body's kind known, settle the live path's timeout. An event
	// stream runs as long as the server keeps it open, so the default timeout
	// never caps one and an explicit --timeout caps only silence; the default
	// never caps a piped download either (#28). Anything else keeps the total
	// cap, as on the buffered path.
	var src io.Reader = resp.Body
	if lt != nil {
		lt.headers()
		switch {
		case stream != streamNone && c.explicitTimeout:
			src = lt.idle(resp.Body)
		case stream != streamNone, spec.BodySink != nil && !c.explicitTimeout:
			lt.stop()
		}
	}

	var body []byte
	var bodySize int64
	var readErr error
	switch {
	case spec.BodySink != nil:
		// Streaming: bytes go to the sink as they arrive, uncapped — the
		// caller owns the destination, memory stays constant.
		bodySize, readErr = io.Copy(spec.BodySink, src)
	case stream != streamNone && spec.OnStream != nil:
		// A live event stream: parsed as it arrives and handed over event by
		// event, so memory holds one event at a time (see eventCap).
		res.Stream = stream
		res.Timing = tr.timing(time.Now())
		spec.OnStream.StreamStart(res)
		p := newEventParser(stream, spec.OnStream.StreamEvent)
		bodySize, readErr = io.Copy(p, src)
		_ = p.Close()
		res.Events = p.seq
	default:
		body, readErr = io.ReadAll(io.LimitReader(src, maxBodyBytes+1))
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
	res.Body = body
	res.BodySize = bodySize

	if readErr != nil {
		readErr = explainCancel(rctx, readErr)
		if errors.Is(readErr, errStopped) {
			res.Stopped = true
			if res.Stream != streamNone {
				readErr = nil // stopping is how a live stream normally ends
			}
		}
	}
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

// badRequest fails res as a request that couldn't be built — before anything
// was sent — through both seams.
func (c *Client) badRequest(res Result, err error) Result {
	c.log.Error("request failed", "kind", KindBadRequest.String(), "err", err)
	res.Err = err
	res.DisplayErr = c.voice.Render(KindBadRequest, 0, err)
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
// header must stay deleted. Such a spec carries the form's own envHeaderKeys,
// which pass through untouched. URL resolution always applies.
//
// Each header actually injected here is recorded in spec.envHeaderKeys so
// redirectPolicy strips exactly those on a cross-origin hop — a user-supplied
// header that happens to share a name with a WEEB_HEADERS key is never
// injected, and so never stripped.
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
			spec.envHeaderKeys = append(spec.envHeaderKeys, lk)
			have[lk] = true
		}
	}
	if tok := os.Getenv("WEEB_TOKEN"); tok != "" && !have["authorization"] {
		spec.Headers = append(spec.Headers, Header{Key: "Authorization", Value: "Bearer " + tok})
		spec.envHeaderKeys = append(spec.envHeaderKeys, "authorization")
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
	if len(spec.envHeaderKeys) > 0 {
		req = req.WithContext(context.WithValue(req.Context(), envHeaderKeysCtx{}, spec.envHeaderKeys))
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
// and empty segments. A backslash escapes the separator, so "\;" yields a
// literal semicolon inside a value and "\\" a literal backslash.
func parseHeaderList(s string) []Header {
	var out []Header
	for _, part := range splitHeaderSegments(s) {
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

// splitHeaderSegments splits s on unescaped ';', unescaping "\;" and "\\"
// within each segment. Any other backslash passes through unchanged.
func splitHeaderSegments(s string) []string {
	var segs []string
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s) && (s[i+1] == ';' || s[i+1] == '\\'):
			b.WriteByte(s[i+1])
			i++
		case c == ';':
			segs = append(segs, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	return append(segs, b.String())
}

// prettyBody pretty-prints the body when it looks like JSON, otherwise returns
// it unchanged. This is for DISPLAY only — CLI stdout always emits the raw bytes
// so downstream tools (jq, etc.) see exactly what the server sent. A body whose
// indented form would outgrow prettyCap is also returned unchanged.
func prettyBody(body []byte, contentType string) string {
	if isJSON(contentType) && jsonIndentFits(body, prettyCap(len(body))) {
		var buf bytes.Buffer
		if err := json.Indent(&buf, body, "", "  "); err == nil {
			return buf.String()
		}
	}
	return string(body)
}

// jsonIndentFits reports whether json.Indent(body, "", "  ") would produce at
// most limit bytes, without producing it: json.Indent writes into a
// bytes.Buffer and can't be stopped partway. It adds what Indent adds (a
// newline plus the new depth's indentation after '{', '[', ',' and before '}',
// ']'; a space after ':') to the body's length, so it never undercounts; it
// overcounts empty containers and the source's own whitespace. It stops as
// soon as the limit is passed.
func jsonIndentFits(body []byte, limit int) bool {
	n, depth := len(body), 0
	inStr, esc := false, false
	for _, c := range body {
		if n > limit {
			return false
		}
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{', '[':
			depth++
			n += 1 + 2*depth
		case ',':
			n += 1 + 2*depth
		case '}', ']':
			depth = max(depth-1, 0)
			n += 1 + 2*depth
		case ':':
			n++
		}
	}
	return n <= limit
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
