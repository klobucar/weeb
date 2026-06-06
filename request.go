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
	"strings"
	"time"

	log "charm.land/log/v2"
)

const defaultTimeout = 30 * time.Second

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
}

// Result is the outcome of handling one request. Body always holds the raw
// response bytes (even for 4xx/5xx). DisplayErr, when non-empty, is the
// human-facing weeb error string produced by the ErrorChan seam. Err is the
// underlying Go error used for CLI exit codes; it is nil on a 2xx/3xx success.
type Result struct {
	Method      string
	URL         string
	Status      int
	StatusText  string
	Proto       string
	Headers     http.Header
	Body        []byte
	ContentType string
	Duration    time.Duration
	Timing      Timing
	TLS         *connTLS
	DisplayErr  string
	Err         error
}

// OK reports whether the request fully succeeded (sent, received, status < 400).
func (r Result) OK() bool { return r.Err == nil }

// Client is the single component that executes requests and handles their
// results. Construct it once per process with the chosen logger and ErrorChan.
type Client struct {
	http  *http.Client
	log   *log.Logger
	voice ErrorChan
}

func newClient(logger *log.Logger, voice ErrorChan) *Client {
	return &Client{
		// The zero-value CheckRedirect follows up to 10 redirects, which is the
		// behaviour we want.
		http:  &http.Client{Timeout: defaultTimeout},
		log:   logger,
		voice: voice,
	}
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

	tr := &reqTrace{}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), tr.clientTrace()))

	start := time.Now()
	tr.start = start
	resp, err := c.http.Do(req)
	if err != nil {
		dur := time.Since(start)
		res.Duration = dur
		rlog.Error("request failed",
			"kind", KindTransport.String(), "duration_ms", dur.Milliseconds(), "err", err)
		res.Err = err
		res.DisplayErr = c.voice.Render(KindTransport, 0, err)
		return res
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	done := time.Now()
	dur := done.Sub(start)

	res.Duration = dur
	res.Timing = tr.timing(done)
	res.TLS = tlsSummary(resp.TLS)
	res.Status = resp.StatusCode
	res.StatusText = http.StatusText(resp.StatusCode)
	res.Proto = resp.Proto
	res.Headers = resp.Header
	res.ContentType = resp.Header.Get("Content-Type")
	res.Body = body

	if readErr != nil {
		rlog.Error("request failed",
			"kind", KindBadBody.String(), "status", resp.StatusCode,
			"duration_ms", dur.Milliseconds(), "err", readErr)
		res.Err = readErr
		res.DisplayErr = c.voice.Render(KindBadBody, resp.StatusCode, readErr)
		return res
	}

	rlog.Info("response",
		"status", resp.StatusCode, "duration_ms", dur.Milliseconds(), "bytes", len(body),
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
