package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "charm.land/log/v2"
)

func TestNewRepeatPhase(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	var hundred []time.Duration
	for i := 100; i >= 1; i-- { // unsorted on purpose
		hundred = append(hundred, ms(i))
	}
	tests := []struct {
		name string
		in   []time.Duration
		want *repeatPhase
	}{
		{"empty", nil, nil},
		{"one", []time.Duration{ms(7)}, &repeatPhase{N: 1, Min: 7, P50: 7, P90: 7, P99: 7, Max: 7}},
		{"hundred", hundred, &repeatPhase{N: 100, Min: 1, P50: 50, P90: 90, P99: 99, Max: 100}},
		{"ten", []time.Duration{ms(10), ms(1), ms(9), ms(2), ms(8), ms(3), ms(7), ms(4), ms(6), ms(5)},
			&repeatPhase{N: 10, Min: 1, P50: 5, P90: 9, P99: 10, Max: 10}},
		{"sub-millisecond", []time.Duration{1500 * time.Microsecond}, &repeatPhase{N: 1, Min: 1.5, P50: 1.5, P90: 1.5, P99: 1.5, Max: 1.5}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newRepeatPhase(tt.in)
			if (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
				t.Errorf("newRepeatPhase = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSummarizeRepeat(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	fresh := Timing{DNS: ms(1), TCP: ms(2), TLS: ms(3), DidDNS: true, DidConnect: true, DidTLS: true, Server: ms(10), Total: ms(20)}
	reused := Timing{Server: ms(5), Total: ms(6), Reused: true}
	samples := []repeatSample{
		{timing: fresh, status: 200},
		{timing: reused, status: 200},
		{timing: reused, status: 200},
		{timing: reused, status: 503},
		{status: 0, errKey: "dial: connection refused"},
		{status: 0, errKey: "dial: connection refused"},
		{status: 200, errKey: "unexpected EOF"}, // body cut short
	}
	s := summarizeRepeat(samples, 2*time.Second)

	if s.Completed != 7 || s.Errors != 3 || s.NewConns != 1 || s.ReusedConns != 3 {
		t.Errorf("completed/errors/new/reused = %d/%d/%d/%d, want 7/3/1/3", s.Completed, s.Errors, s.NewConns, s.ReusedConns)
	}
	if s.Status[200] != 3 || s.Status[503] != 1 || len(s.Status) != 2 {
		t.Errorf("status histogram = %v", s.Status)
	}
	if s.RPS != 3.5 {
		t.Errorf("rps = %v, want 3.5", s.RPS)
	}
	// Handshake phases count only the request that opened a connection.
	if s.Phases.DNS == nil || s.Phases.DNS.N != 1 || s.Phases.TLS.N != 1 || s.Phases.Connect.Max != 2 {
		t.Errorf("handshake phases = dns %+v connect %+v tls %+v", s.Phases.DNS, s.Phases.Connect, s.Phases.TLS)
	}
	if s.Phases.Total.N != 4 || s.Phases.Total.Max != 20 || s.Phases.Wait.Min != 5 {
		t.Errorf("total %+v wait %+v", s.Phases.Total, s.Phases.Wait)
	}
	want := []repeatCause{{"dial: connection refused", 2}, {"unexpected EOF", 1}}
	if fmt.Sprint(s.Causes) != fmt.Sprint(want) {
		t.Errorf("causes = %v, want %v", s.Causes, want)
	}
	if s.exitCode() != 1 {
		t.Errorf("exit = %d, want 1", s.exitCode())
	}
}

func TestRepeatExitCode(t *testing.T) {
	tests := []struct {
		name string
		s    repeatSummary
		want int
	}{
		{"all ok", repeatSummary{Completed: 2, Status: map[int]int{200: 1, 304: 1}}, 0},
		{"a 404", repeatSummary{Completed: 2, Status: map[int]int{200: 1, 404: 1}}, 1},
		{"an error", repeatSummary{Completed: 2, Errors: 1, Status: map[int]int{200: 1}}, 1},
		{"nothing finished", repeatSummary{Status: map[int]int{}}, 1},
	}
	for _, tt := range tests {
		if got := tt.s.exitCode(); got != tt.want {
			t.Errorf("%s: exit = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestRepeatErrorKey(t *testing.T) {
	refused := &url.Error{Op: "Get", URL: "http://127.0.0.1:1/x", Err: &net.OpError{
		Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		Err: errors.New("connect: connection refused"),
	}}
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"op error drops addresses", refused, "dial: connect: connection refused"},
		{"url error drops the URL", &url.Error{Op: "Get", URL: "http://x/", Err: context.DeadlineExceeded}, "context deadline exceeded"},
		{"plain", errors.New("unexpected EOF"), "unexpected EOF"},
		{"flattened", errors.New("bad\nthing\r\n  here"), "bad thing here"},
	}
	for _, tt := range tests {
		if got := repeatErrorKey(tt.err); got != tt.want {
			t.Errorf("%s: key = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestParseCLIRepeatFlags(t *testing.T) {
	a, err := parseCLI([]string{"https://x", "--repeat", "50", "--concurrency", "4", "--fresh", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if a.repeat != 50 || a.concurrency != 4 || !a.fresh || !a.checkJSON {
		t.Errorf("got %+v", a)
	}
	if !a.headless() {
		t.Error("--repeat should imply headless")
	}

	bad := []struct {
		name string
		args []string
	}{
		{"zero", []string{"https://x", "--repeat", "0"}},
		{"not a number", []string{"https://x", "--repeat", "lots"}},
		{"bad concurrency", []string{"https://x", "--repeat", "5", "--concurrency", "-1"}},
		{"concurrency alone", []string{"https://x", "--concurrency", "4"}},
		{"fresh alone", []string{"https://x", "--fresh"}},
		{"with check", []string{"https://x", "--repeat", "5", "--check"}},
		{"with output", []string{"https://x", "--repeat", "5", "-o", "f"}},
		{"with include", []string{"https://x", "--repeat", "5", "-i"}},
		{"with to-curl", []string{"https://x", "--repeat", "5", "--to-curl"}},
		{"with cookie-jar", []string{"https://x", "--repeat", "5", "--cookie-jar", "jar.txt"}},
		{"with thresholds", []string{"https://x", "--repeat", "5", "-w", "1s"}},
		{"missing value", []string{"https://x", "--repeat"}},
	}
	for _, tt := range bad {
		if _, err := parseCLI(tt.args); err == nil {
			t.Errorf("%s: parseCLI(%v) should fail", tt.name, tt.args)
		}
	}
}

// testRepeatClient is newRepeatClient with silent logging.
func testRepeatClient(a cliArgs) *Client {
	return newRepeatClient(log.New(io.Discard), plainErrorChan{}, a)
}

// repeatCountConns starts a server that counts the TCP connections it accepts.
func repeatCountConns(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var conns atomic.Int64
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &conns
}

// Keep-alive reuses pooled connections; --fresh dials one per request. The
// summary's connection counts must match what the server saw.
func TestRepeatRunConnectionReuse(t *testing.T) {
	const n = 40
	tests := []struct {
		name  string
		fresh bool
	}{
		{"keep-alive", false},
		{"fresh", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, conns := repeatCountConns(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, strings.Repeat("x", 4096))
			})
			a := cliArgs{repeat: n, concurrency: 4, fresh: tt.fresh}
			s := repeatRun(context.Background(), testRepeatClient(a), RequestSpec{Method: "GET", URL: srv.URL}, n, 4)

			if s.Completed != n || s.Errors != 0 || s.Status[200] != n || s.Interrupted {
				t.Fatalf("summary = %+v", s)
			}
			if s.NewConns+s.ReusedConns != n || int64(s.NewConns) > conns.Load() {
				t.Errorf("new %d + reused %d vs %d server conns", s.NewConns, s.ReusedConns, conns.Load())
			}
			if tt.fresh {
				if s.NewConns != n || conns.Load() != n || s.Phases.Connect == nil || s.Phases.Connect.N != n {
					t.Errorf("fresh: new %d, server conns %d, connect %+v; want %d each", s.NewConns, conns.Load(), s.Phases.Connect, n)
				}
			} else if s.ReusedConns == 0 || conns.Load() >= n {
				t.Errorf("keep-alive: reused %d, server conns %d", s.ReusedConns, conns.Load())
			}
			if s.Phases.TLS != nil || s.Phases.DNS != nil {
				t.Errorf("plain http to an IP has no tls/dns phase: %+v", s.Phases)
			}
			if s.Phases.Total == nil || s.Phases.Total.N != n || s.Phases.Wait.N != n {
				t.Errorf("total/wait = %+v / %+v", s.Phases.Total, s.Phases.Wait)
			}
		})
	}
}

// ctrl+c (a cancelled context): in-flight requests abort promptly, what
// finished is summarized, and the aborted request is not an error.
func TestRepeatRunInterrupt(t *testing.T) {
	var hits atomic.Int64
	stalled := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= 3 {
			return
		}
		once.Do(func() { close(stalled) })
		<-r.Context().Done() // hang until the client gives up
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan repeatSummary)
	go func() {
		done <- repeatRun(ctx, testRepeatClient(cliArgs{repeat: 10}), RequestSpec{Method: "GET", URL: srv.URL}, 10, 1)
	}()
	<-stalled
	cancel()

	select {
	case s := <-done:
		if !s.Interrupted || s.Completed != 3 || s.Errors != 0 || s.Status[200] != 3 {
			t.Errorf("summary = %+v", s)
		}
		if out := renderRepeat(s, newStyles(), false); !strings.Contains(out, "interrupted after 3 of 10 requests") {
			t.Errorf("render:\n%s", out)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("repeatRun did not stop after cancel")
	}
}

// The real ctrl+c path: a SIGINT while a request hangs stops the run, the
// process survives it, and the summary of what finished still prints.
func TestRunCLIRepeatSIGINT(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a process can't send itself SIGINT on windows")
	}
	t.Setenv("WEEB_LOG", "off")
	var hits atomic.Int64
	stalled := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= 3 {
			return
		}
		once.Do(func() { close(stalled) })
		<-r.Context().Done()
	}))
	defer srv.Close()

	buf := swapOutW(t)
	done := make(chan int)
	go func() { done <- runCLI(cliArgs{method: "GET", url: srv.URL, repeat: 10, checkJSON: true}) }()
	<-stalled // requests only go out once the interrupt handler is installed
	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := self.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}

	select {
	case code := <-done:
		var s struct {
			Interrupted bool `json:"interrupted"`
			Completed   int  `json:"completed"`
			Errors      int  `json:"errors"`
		}
		if err := json.Unmarshal([]byte(buf.String()), &s); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, buf.String())
		}
		if code != 0 || !s.Interrupted || s.Completed != 3 || s.Errors != 0 {
			t.Errorf("exit %d, summary %+v", code, s)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SIGINT did not stop the run")
	}
}

// Workers share one spec. Do appends WEEB_HEADERS to spec.Headers, so a
// header slice with spare capacity would be written concurrently (the race
// detector flags it) unless repeatRun clips it.
func TestRepeatRunSharedHeadersNoRace(t *testing.T) {
	t.Setenv("WEEB_HEADERS", "X-Env: 1")
	var missing atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Env") != "1" || r.Header.Get("X-User") != "u" {
			missing.Add(1)
		}
	}))
	defer srv.Close()

	headers := make([]Header, 1, 8) // spare capacity on purpose
	headers[0] = Header{Key: "X-User", Value: "u"}
	s := repeatRun(context.Background(), testRepeatClient(cliArgs{repeat: 32, concurrency: 8}),
		RequestSpec{Method: "GET", URL: srv.URL, Headers: headers}, 32, 8)
	if s.Status[200] != 32 || missing.Load() != 0 {
		t.Errorf("200s = %d, requests missing a header = %d", s.Status[200], missing.Load())
	}
}

// runCLI --repeat end to end: the summary (not the body) is the stdout
// output, --json is machine-readable, the exit code follows the statuses,
// and none of the N requests is written to history.
func TestRunCLIRepeat(t *testing.T) {
	path := useHistoryFile(t)
	t.Setenv("WEEB_LOG", "off")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/down" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = io.WriteString(w, "BODY-MARKER")
	}))
	defer srv.Close()

	t.Run("json", func(t *testing.T) {
		buf := swapOutW(t)
		code := runCLI(cliArgs{method: "GET", url: srv.URL, repeat: 6, concurrency: 2, checkJSON: true})
		if code != 0 {
			t.Fatalf("exit = %d, want 0\n%s", code, buf.String())
		}
		var s struct {
			Method      string         `json:"method"`
			URL         string         `json:"url"`
			Requested   int            `json:"requested"`
			Completed   int            `json:"completed"`
			Concurrency int            `json:"concurrency"`
			Status      map[string]int `json:"status"`
			Errors      int            `json:"errors"`
			Phases      map[string]struct {
				N   int     `json:"n"`
				P99 float64 `json:"p99_ms"`
			} `json:"phases"`
		}
		if err := json.Unmarshal([]byte(buf.String()), &s); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, buf.String())
		}
		if s.Method != "GET" || s.URL != srv.URL || s.Requested != 6 || s.Completed != 6 || s.Concurrency != 2 ||
			s.Status["200"] != 6 || s.Errors != 0 || s.Phases["total"].N != 6 {
			t.Errorf("summary = %+v", s)
		}
		if strings.Contains(buf.String(), "BODY-MARKER") {
			t.Error("response body leaked into the summary")
		}
	})

	t.Run("text with 5xx", func(t *testing.T) {
		buf := swapOutW(t)
		if code := runCLI(cliArgs{method: "GET", url: srv.URL + "/down", repeat: 3}); code != 1 {
			t.Errorf("exit = %d, want 1 for 503s", code)
		}
		out := buf.String()
		for _, want := range []string{"GET " + srv.URL + "/down", "3 requests", "p50", "total", "503"} {
			if !strings.Contains(out, want) {
				t.Errorf("summary missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("unbuildable request", func(t *testing.T) {
		buf := swapOutW(t)
		if code := runCLI(cliArgs{method: "GET", url: "http://[::1", repeat: 3}); code != 1 {
			t.Errorf("exit = %d, want 1", code)
		}
		if buf.Len() != 0 {
			t.Errorf("stdout = %q, want nothing", buf.String())
		}
	})

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("--repeat wrote history (stat err %v)", err)
	}
}

func TestRenderRepeat(t *testing.T) {
	s := summarizeRepeat([]repeatSample{
		{timing: Timing{TCP: time.Millisecond, DidConnect: true, Server: 2 * time.Millisecond, Total: 3 * time.Millisecond}, status: 200},
		{timing: Timing{Server: 1500 * time.Millisecond, Total: 1600 * time.Millisecond, Reused: true}, status: 404},
		{errKey: "dial: connection refused"},
	}, time.Second)
	s.Method, s.URL, s.Requested, s.Concurrency, s.Fresh = "GET", "http://a.example/", 3, 1, true

	out := renderRepeat(s, newStyles(), false)
	if strings.Contains(out, "\x1b") {
		t.Errorf("plain render has ANSI:\n%q", out)
	}
	for _, want := range []string{
		"GET http://a.example/",
		"3 requests · concurrency 1 · fresh connections",
		"1 new connection, 1 reused · 1 error",
		"connect       1    1.00ms",
		"total         2    3.00ms",
		"1.60s",
		"200       ██████████████████████████████ 1 (50%)",
		"404       ██████████████████████████████ 1 (50%)",
		"1× dial: connection refused",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "tls ") || strings.Contains(out, "dns ") {
		t.Errorf("phases with no samples should be omitted:\n%s", out)
	}
}

// --repeat gets the same pre-send file check as a single request (and the
// -k warning): a bad --cacert is one usage error, not N failed requests.
func TestRunCLIRepeatPreflight(t *testing.T) {
	a, err := parseCLI([]string{"https://127.0.0.1:1/", "--repeat", "3", "--cacert", filepath.Join(t.TempDir(), "missing.pem")})
	if err != nil {
		t.Fatal(err)
	}
	if code := runCLI(a); code != 2 {
		t.Errorf("exit = %d, want 2 (usage error before anything is sent)", code)
	}
}
