package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"charm.land/lipgloss/v2"
	log "charm.land/log/v2"
	"github.com/charmbracelet/x/term"
)

// --repeat N is a latency mini-benchmark: the request goes out N times (C at
// once with --concurrency) and the output is a summary instead of a body,
// built from the same httptrace timing a single request shows: per-phase
// percentiles, a status histogram and an error count.
//
// Connection reuse decides what gets measured, so it is the one knob:
//
//   - default (keep-alive): connections are pooled like a real client's, so
//     the numbers are steady-state latency, and dns/connect/tls only show up
//     for the few connections actually opened.
//   - --fresh: keep-alive off, so every request pays a DNS lookup, a TCP
//     connect and a full TLS handshake: what a first-time visitor (or a
//     client without pooling) sees, and the way to isolate handshake cost.

// checkRepeatFlags rejects the benchmark flags without --repeat, and the
// flags --repeat can't honour with it.
func (a cliArgs) checkRepeatFlags() error {
	if a.repeat == 0 {
		if a.concurrency > 0 || a.fresh {
			return fmt.Errorf("--concurrency and --fresh only apply with --repeat")
		}
		return nil
	}
	switch {
	case a.check:
		return fmt.Errorf("--repeat can't be combined with --check")
	case a.output != "":
		return fmt.Errorf("--repeat discards response bodies; it can't be combined with -o")
	case a.include:
		return fmt.Errorf("--repeat prints a summary; it can't be combined with -i")
	case a.toCurl:
		return fmt.Errorf("--repeat can't be combined with --to-curl")
	case a.expectStatus != "" || a.expectBody != "" || a.warn > 0 || a.crit > 0:
		return fmt.Errorf("--expect-status/--expect-body/-w/-c only apply with --check")
	}
	return nil
}

// runRepeat is runCLI's --repeat branch. It exits 0 when every request got
// a status below 400, 1 when any failed (or none finished), 2 on bad usage.
func runRepeat(a cliArgs, spec RequestSpec) int {
	persona, err := resolvePersona(a.persona)
	if err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 2
	}

	logger, _, cleanup := newLogger(modeCLI)
	defer cleanup()
	// Do logs a "request failed" line per failure; hundreds of them would
	// bury the summary, which counts them anyway. WEEB_LOG still opts in.
	if os.Getenv("WEEB_LOG") == "" {
		logger.SetLevel(log.FatalLevel)
	}
	voice := errorChanFor(persona)
	client := newRepeatClient(logger, voice, a)

	// A request that can't even be built fails identically N times; say so
	// once, the way a single request would.
	if _, err := buildRequest(resolveSpec(spec)); err != nil {
		fmt.Fprintln(errW, voice.Render(KindBadRequest, 0, err))
		return 1
	}

	// ctrl+c cancels the run: in-flight requests abort and the summary of
	// what finished still prints. The handler is released as soon as it
	// fires, so a second ctrl+c kills weeb the usual way.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	context.AfterFunc(ctx, stop)

	if term.IsTerminal(os.Stderr.Fd()) {
		fmt.Fprintf(errW, "sending %d requests (ctrl+c stops early and prints the summary so far)…\n", a.repeat)
	}
	sum := repeatRun(ctx, client, spec, a.repeat, cmp.Or(a.concurrency, 1))
	sum.Fresh = a.fresh

	if a.checkJSON {
		out, _ := json.MarshalIndent(sum, "", "  ")
		fmt.Fprintln(outW, string(out))
	} else {
		color := stdoutIsTTY() && os.Getenv("NO_COLOR") == ""
		fmt.Fprint(outW, renderRepeat(sum, newStyles(), color))
	}
	return sum.exitCode()
}

// newRepeatClient builds the benchmark's client: a pool sized to the
// concurrency, keep-alive per --fresh, every request bounded end to end, and
// no history.
func newRepeatClient(logger *log.Logger, voice ErrorChan, a cliArgs) *Client {
	c := newClient(logger, voice)
	// Bodies stream to io.Discard, and only an explicit timeout bounds a
	// sink's transfer (see Do), so make the default one explicit.
	c.SetTimeout(cmp.Or(a.timeout, defaultTimeout))
	conc := cmp.Or(a.concurrency, 1)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// The stock pool keeps 2 idle connections per host: at --concurrency 8
	// most requests would quietly dial anew, mixing handshakes into what is
	// meant to be a keep-alive run.
	tr.MaxIdleConnsPerHost = conc
	tr.MaxIdleConns = max(tr.MaxIdleConns, conc)
	tr.DisableKeepAlives = a.fresh
	c.http.Transport = tr
	// BodySink requests (repeat discards bodies through one) go through the
	// stream client, so it needs the same pool, or --fresh and the pool size
	// would silently not apply.
	c.stream.Transport = tr
	c.noHistory = true
	return c
}

// repeatSample is what one finished request contributes to the summary.
type repeatSample struct {
	timing Timing
	status int    // 0 when no response arrived
	errKey string // non-empty when the request failed (see repeatErrorKey)
}

// repeatSampleOf classifies a result. A status >= 400 is a response like any
// other here (the histogram shows it); a failure is no response at all, or a
// body cut short. (Do reports a >= 400 status in place of a body error, so a
// truncated error page counts by its status.)
func repeatSampleOf(res Result) repeatSample {
	s := repeatSample{timing: res.Timing, status: res.Status}
	if res.Err != nil && res.Status < 400 {
		s.errKey = repeatErrorKey(res.Err)
	}
	return s
}

// repeatErrorKey reduces an error to its cause so failures group: the URL
// and socket addresses in the full text (a fresh ephemeral port on every
// connection) would otherwise give each failed request a line of its own.
func repeatErrorKey(err error) string {
	var msg string
	var opErr *net.OpError
	var urlErr *url.Error
	switch {
	case errors.As(err, &opErr) && opErr.Err != nil:
		msg = opErr.Op + ": " + opErr.Err.Error()
	case errors.As(err, &urlErr) && urlErr.Err != nil:
		msg = urlErr.Err.Error()
	default:
		msg = err.Error()
	}
	return strings.Join(strings.Fields(msg), " ") // one line, whatever the error held
}

// repeatRun sends spec n times from conc workers, until done or ctx is
// cancelled, and summarizes what finished. Requests cut off by the
// cancellation are dropped, not counted as errors: the user stopped them,
// the server didn't fail them.
func repeatRun(ctx context.Context, c *Client, spec RequestSpec, n, conc int) repeatSummary {
	// Do's resolveSpec appends env headers to spec.Headers. Workers share
	// this spec, so without the clip those appends could write into one
	// shared backing array concurrently.
	spec.Headers = slices.Clip(spec.Headers)
	spec.BodySink = io.Discard

	var next atomic.Int64
	results := make(chan repeatSample)
	var wg sync.WaitGroup
	start := time.Now()
	for range min(conc, n) {
		wg.Go(func() {
			for ctx.Err() == nil && next.Add(1) <= int64(n) {
				res := c.DoContext(ctx, spec) // ctx cancels in-flight requests (ctrl+c)
				if res.Err != nil && ctx.Err() != nil {
					return
				}
				results <- repeatSampleOf(res)
			}
		})
	}
	go func() { wg.Wait(); close(results) }()

	var samples []repeatSample
	for s := range results {
		samples = append(samples, s)
	}
	sum := summarizeRepeat(samples, time.Since(start))
	resolved := resolveSpec(spec)
	sum.Method = strings.ToUpper(cmp.Or(strings.TrimSpace(resolved.Method), http.MethodGet))
	sum.URL = resolved.URL
	sum.Requested = n
	sum.Concurrency = min(conc, n)
	sum.Interrupted = len(samples) < n
	return sum
}

// repeatPhase is one phase's latency distribution, in milliseconds.
type repeatPhase struct {
	N   int     `json:"n"`
	Min float64 `json:"min_ms"`
	P50 float64 `json:"p50_ms"`
	P90 float64 `json:"p90_ms"`
	P99 float64 `json:"p99_ms"`
	Max float64 `json:"max_ms"`
}

// newRepeatPhase computes nearest-rank percentiles (each one is a real
// sample, never an interpolation). It is nil when no request went through
// the phase: no TLS over http, no DNS for an IP, no dial on a reused
// connection.
func newRepeatPhase(ds []time.Duration) *repeatPhase {
	if len(ds) == 0 {
		return nil
	}
	slices.Sort(ds)
	rank := func(p float64) float64 {
		i := int(math.Ceil(p/100*float64(len(ds)))) - 1
		return repeatMS(ds[max(i, 0)])
	}
	return &repeatPhase{
		N:   len(ds),
		Min: repeatMS(ds[0]),
		P50: rank(50), P90: rank(90), P99: rank(99),
		Max: repeatMS(ds[len(ds)-1]),
	}
}

// repeatMS is a duration in milliseconds, kept to the microsecond.
func repeatMS(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// repeatPhases are the phases the summary reports. dns, connect and tls
// count only requests that opened a connection.
type repeatPhases struct {
	DNS     *repeatPhase `json:"dns,omitempty"`
	Connect *repeatPhase `json:"connect,omitempty"`
	TLS     *repeatPhase `json:"tls,omitempty"`
	Wait    *repeatPhase `json:"wait,omitempty"` // request sent -> first byte (TTFB)
	Total   *repeatPhase `json:"total,omitempty"`
}

// repeatCause is one distinct failure and how often it happened.
type repeatCause struct {
	Error string `json:"error"`
	Count int    `json:"count"`
}

// repeatSummary is the benchmark's output, as text or --json.
type repeatSummary struct {
	Method      string        `json:"method"`
	URL         string        `json:"url"`
	Requested   int           `json:"requested"`
	Completed   int           `json:"completed"` // finished, with a response or an error
	Interrupted bool          `json:"interrupted"`
	Concurrency int           `json:"concurrency"`
	Fresh       bool          `json:"fresh"`
	ElapsedMS   float64       `json:"elapsed_ms"`
	RPS         float64       `json:"requests_per_sec"`
	NewConns    int           `json:"new_conns"`
	ReusedConns int           `json:"reused_conns"`
	Status      map[int]int   `json:"status"` // status code -> count
	Errors      int           `json:"errors"`
	Causes      []repeatCause `json:"error_causes,omitempty"`
	Phases      repeatPhases  `json:"phases"`
}

// summarizeRepeat aggregates finished samples. Only responses feed the
// latency phases: a failed request's timing stops wherever it broke.
func summarizeRepeat(samples []repeatSample, elapsed time.Duration) repeatSummary {
	s := repeatSummary{Completed: len(samples), Status: map[int]int{}, ElapsedMS: repeatMS(elapsed)}
	if elapsed > 0 {
		s.RPS = math.Round(float64(len(samples))/elapsed.Seconds()*10) / 10
	}
	var dns, connect, tlsHS, wait, total []time.Duration
	causes := map[string]int{}
	for _, x := range samples {
		if x.errKey != "" {
			s.Errors++
			causes[x.errKey]++
			continue
		}
		s.Status[x.status]++
		t := x.timing
		if t.Reused {
			s.ReusedConns++
		} else {
			s.NewConns++
		}
		// By whether the phase ran, not duration > 0: a loopback connect can
		// measure 0 on a coarse clock (Windows) and still be a new connection.
		if t.DidDNS {
			dns = append(dns, t.DNS)
		}
		if t.DidConnect {
			connect = append(connect, t.TCP)
		}
		if t.DidTLS {
			tlsHS = append(tlsHS, t.TLS)
		}
		wait = append(wait, t.Server)
		total = append(total, t.Total)
	}
	s.Phases = repeatPhases{
		DNS: newRepeatPhase(dns), Connect: newRepeatPhase(connect), TLS: newRepeatPhase(tlsHS),
		Wait: newRepeatPhase(wait), Total: newRepeatPhase(total),
	}
	for msg, n := range causes {
		s.Causes = append(s.Causes, repeatCause{Error: msg, Count: n})
	}
	slices.SortFunc(s.Causes, func(a, b repeatCause) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Error, b.Error))
	})
	return s
}

// exitCode follows a single request's rule across the run: 1 if any request
// failed or got a status >= 400, or if none finished at all.
func (s repeatSummary) exitCode() int {
	if s.Completed == 0 || s.Errors > 0 {
		return 1
	}
	for code := range s.Status {
		if code >= 400 {
			return 1
		}
	}
	return 0
}

// repeatCauseList caps how many distinct failures the text summary lists.
const repeatCauseList = 5

// renderRepeat draws the summary: what ran, throughput and connections, a
// percentile table per phase, the status histogram, then the top failures.
// color=false gives the same layout as plain text, for pipes and NO_COLOR.
func renderRepeat(s repeatSummary, st styles, color bool) string {
	paint := func(style lipgloss.Style, text string) string {
		if !color {
			return text
		}
		return style.Render(text)
	}
	sep := paint(st.meta, " · ")
	var b strings.Builder

	fmt.Fprintf(&b, "%s %s\n", paint(lipgloss.NewStyle().Bold(true).Foreground(methodColor(s.Method)), s.Method), s.URL)
	mode := "keep-alive"
	if s.Fresh {
		mode = "fresh connections"
	}
	ran := fmt.Sprintf("%d requests", s.Requested)
	if s.Interrupted {
		ran = fmt.Sprintf("interrupted after %d of %d requests", s.Completed, s.Requested)
	}
	fmt.Fprintln(&b, strings.Join([]string{
		paint(st.meta, ran), paint(st.meta, fmt.Sprintf("concurrency %d", s.Concurrency)), paint(st.meta, mode),
	}, sep))
	errText := repeatCount(s.Errors, "error", "errors")
	if s.Errors > 0 {
		errText = paint(st.errText, errText)
	}
	fmt.Fprintln(&b, strings.Join([]string{
		repeatDur(s.ElapsedMS) + " elapsed",
		fmt.Sprintf("%.1f req/s", s.RPS),
		repeatCount(s.NewConns, "new connection", "new connections") + fmt.Sprintf(", %d reused", s.ReusedConns),
		errText,
	}, sep))

	rows := []struct {
		name string
		p    *repeatPhase
		col  lipgloss.Style
	}{
		{"dns", s.Phases.DNS, lipgloss.NewStyle().Foreground(cBlue)},
		{"connect", s.Phases.Connect, lipgloss.NewStyle().Foreground(cCyan)},
		{"tls", s.Phases.TLS, lipgloss.NewStyle().Foreground(cViolet)},
		{"wait", s.Phases.Wait, lipgloss.NewStyle().Foreground(cOrange)},
		{"total", s.Phases.Total, lipgloss.NewStyle().Bold(true)},
	}
	if s.Phases.Total != nil {
		fmt.Fprintf(&b, "\n%s\n", paint(st.meta, fmt.Sprintf("%-8s %6s %9s %9s %9s %9s %9s", "", "n", "min", "p50", "p90", "p99", "max")))
		for _, r := range rows {
			if r.p == nil {
				continue
			}
			fmt.Fprintf(&b, "%s %6d %9s %9s %9s %9s %9s\n", paint(r.col, fmt.Sprintf("%-8s", r.name)), r.p.N,
				repeatDur(r.p.Min), repeatDur(r.p.P50), repeatDur(r.p.P90), repeatDur(r.p.P99), repeatDur(r.p.Max))
		}
	}

	if len(s.Status) > 0 {
		codes := make([]int, 0, len(s.Status))
		most, responses := 0, 0
		for code, n := range s.Status {
			codes = append(codes, code)
			most = max(most, n)
			responses += n
		}
		slices.Sort(codes)
		const barMax = 30
		b.WriteString("\n")
		for _, code := range codes {
			n := s.Status[code]
			cells := max(1, n*barMax/most)
			col := lipgloss.NewStyle().Foreground(statusColor(code))
			fmt.Fprintf(&b, "%s  %s %s%d (%.0f%%)\n", paint(col, fmt.Sprintf("%-8d", code)),
				paint(col, strings.Repeat("█", cells)), strings.Repeat(" ", barMax-cells),
				n, float64(n)*100/float64(responses))
		}
	}

	if len(s.Causes) > 0 {
		b.WriteString("\n" + paint(st.errText, "errors") + "\n")
		for i, c := range s.Causes {
			if i == repeatCauseList {
				fmt.Fprintf(&b, "  … %d more kinds\n", len(s.Causes)-repeatCauseList)
				break
			}
			fmt.Fprintf(&b, "  %d× %s\n", c.Count, c.Error)
		}
	}
	return b.String()
}

// repeatCount renders "1 error" / "3 errors".
func repeatCount(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// repeatDur formats milliseconds for the table: two decimals under 10 ms,
// one under a second, seconds beyond.
func repeatDur(ms float64) string {
	switch {
	case ms >= 1000:
		return fmt.Sprintf("%.2fs", ms/1000)
	case ms >= 10:
		return fmt.Sprintf("%.1fms", ms)
	default:
		return fmt.Sprintf("%.2fms", ms)
	}
}
