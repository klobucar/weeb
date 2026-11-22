package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
)

// parseAll runs input through an eventParser in chunks of the given size (0 =
// one write), so a test can check that no split point changes the result.
func parseAll(f streamFormat, input string, chunk int) []streamEvent {
	var evs []streamEvent
	p := newEventParser(f, func(ev streamEvent) { evs = append(evs, ev) })
	if chunk <= 0 {
		chunk = len(input)
	}
	for b := []byte(input); len(b) > 0; {
		n := min(chunk, len(b))
		_, _ = p.Write(b[:n])
		b = b[n:]
	}
	_ = p.Close()
	return evs
}

func TestEventParserSSE(t *testing.T) {
	input := "\xef\xbb\xbf: keepalive\n\n" + // BOM, then a comment-only block: no event
		"event: delta\nid: 7\nretry: 3000\ndata: {\"a\":1}\n\n" +
		"data: line one\r\ndata:line two\r\n\r\n" + // CRLF; no space after the colon
		"retry: 10\n\n" + // no data: not an event
		"data\rid: x\r\r" + // a bare field name is an empty value; CR line ends
		"event: tail\ndata: unterminated" // no blank line before EOF: still shown
	want := []streamEvent{
		{Seq: 1, Event: "delta", ID: "7", Retry: "3000", Data: `{"a":1}`,
			Raw: "event: delta\nid: 7\nretry: 3000\ndata: {\"a\":1}"},
		{Seq: 2, Data: "line one\nline two", Raw: "data: line one\ndata:line two"},
		{Seq: 3, ID: "x", Data: "", Raw: "data\nid: x"},
		{Seq: 4, Event: "tail", Data: "unterminated", Raw: "event: tail\ndata: unterminated"},
	}
	for _, chunk := range []int{0, 1, 2, 3, 7} {
		if got := parseAll(streamSSE, input, chunk); !reflect.DeepEqual(got, want) {
			t.Errorf("chunk %d:\n got %+v\nwant %+v", chunk, got, want)
		}
	}
}

func TestEventParserJSONLines(t *testing.T) {
	input := "{\"n\":1}\r\n\n  \n{\"n\":2}\n" + // CRLF and blank lines between records
		"\x1e{\"n\":3}\n\x1e{\"n\":4}\x1e{\"n\":5}\n" + // json-seq record separators
		"{\"n\":6}" // no trailing newline
	for _, chunk := range []int{0, 1, 5} {
		got := parseAll(streamNDJSON, input, chunk)
		if len(got) != 6 {
			t.Fatalf("chunk %d: got %d events, want 6: %+v", chunk, len(got), got)
		}
		for i, ev := range got {
			want := `{"n":` + string(rune('1'+i)) + `}`
			if ev.Data != want || ev.Raw != want || ev.Seq != i+1 {
				t.Errorf("chunk %d: event %d = %+v, want data %s", chunk, i, ev, want)
			}
		}
	}
}

// A line that never ends can't grow without bound: past eventCap the rest is
// dropped, the event is marked, and parsing carries on after it.
func TestEventParserCapsEvents(t *testing.T) {
	old := maxEventBytes
	maxEventBytes = 16
	t.Cleanup(func() { maxEventBytes = old })

	long := strings.Repeat("x", 1000)
	got := parseAll(streamNDJSON, long+"\n{\"ok\":1}\n", 7)
	if len(got) != 2 || len(got[0].Data) != 16 || !got[0].Truncated || got[1].Data != `{"ok":1}` || got[1].Truncated {
		t.Errorf("ndjson: %+v", got)
	}

	got = parseAll(streamSSE, "data: "+long+"\ndata: more\n\ndata: next\n\n", 7)
	if len(got) != 2 || len(got[0].Data) > 16 || !got[0].Truncated || got[1].Data != "next" {
		t.Errorf("sse: %+v", got)
	}
}

// However the network splits a body, the parser must see the same events,
// and no event may outgrow the cap.
func FuzzEventParser(f *testing.F) {
	f.Add("event: a\r\ndata: {\"x\":1}\r\n\r\ndata: b\rdata: c\r\r: c\n\n", 3)
	f.Add("\xef\xbb\xbf{\"n\":1}\r\n\x1e{\"n\":2}\n\n{", 1)
	f.Add("data: "+strings.Repeat("y", 300)+"\ndata\n\n", 7)
	f.Fuzz(func(t *testing.T, input string, chunk int) {
		old := maxEventBytes
		maxEventBytes = 64
		defer func() { maxEventBytes = old }()
		chunk = 1 + abs(chunk)%17
		for _, fm := range []streamFormat{streamSSE, streamNDJSON} {
			whole := parseAll(fm, input, 0)
			if split := parseAll(fm, input, chunk); !reflect.DeepEqual(whole, split) {
				t.Fatalf("format %v, chunk %d:\nwhole %+v\nsplit %+v", fm, chunk, whole, split)
			}
			for _, ev := range whole {
				if len(ev.Data) > 64 || len(ev.Raw) > 64 {
					t.Fatalf("event outgrew the cap: %d data / %d raw bytes", len(ev.Data), len(ev.Raw))
				}
			}
		}
	})
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func TestStreamFormatOf(t *testing.T) {
	cases := map[string]streamFormat{
		"text/event-stream":                 streamSSE,
		"Text/Event-Stream; charset=utf-8":  streamSSE,
		"application/x-ndjson":              streamNDJSON,
		"application/jsonl":                 streamNDJSON,
		"application/json-seq":              streamNDJSON,
		"application/json":                  streamNone,
		"text/plain":                        streamNone,
		"":                                  streamNone,
		"text/event-stream; bad param":      streamSSE, // unparsable params still name the type
		"application/vnd.api+json; charset": streamNone,
	}
	for ct, want := range cases {
		if got := streamFormatOf(ct); got != want {
			t.Errorf("streamFormatOf(%q) = %v, want %v", ct, got, want)
		}
	}
}

// ---- Do ------------------------------------------------------------------------

// streamServer serves contentType, writing and flushing each chunk in turn and
// calling after(i) once chunk i is out (to pause, or to wait for the test).
// With hold it then keeps the stream open until the client hangs up.
func streamServer(t *testing.T, contentType string, chunks []string, after func(ctx context.Context, i int), hold bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		fl := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		fl.Flush()
		for i, c := range chunks {
			if _, err := w.Write([]byte(c)); err != nil {
				return
			}
			fl.Flush()
			if after != nil {
				after(r.Context(), i)
			}
		}
		if hold {
			<-r.Context().Done()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func pause(d time.Duration) func(context.Context, int) {
	return func(context.Context, int) { time.Sleep(d) }
}

// recSink records what Do hands a StreamSink; onEvent, if set, runs on Do's
// goroutine after each event is recorded.
type recSink struct {
	mu      sync.Mutex
	heads   []Result
	events  []streamEvent
	onEvent func(streamEvent)
}

func (s *recSink) StreamStart(head Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.heads = append(s.heads, head)
}

func (s *recSink) StreamEvent(ev streamEvent) {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
	if s.onEvent != nil {
		s.onEvent(ev)
	}
}

// Events reach the sink as they arrive, not when the body ends: the server
// won't send event 2 until the sink has seen event 1.
func TestDoStreamDeliversEventsLive(t *testing.T) {
	sawFirst := make(chan struct{})
	srv := streamServer(t, "text/event-stream", []string{
		"event: delta\ndata: {\"text\":\"hi\"}\n\n",
		"data: [DONE]\n\n",
	}, func(ctx context.Context, i int) {
		if i == 0 {
			select {
			case <-sawFirst:
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
				t.Error("event 1 never reached the sink while the stream was open")
			}
		}
	}, false)

	sink := &recSink{}
	sink.onEvent = func(ev streamEvent) {
		if ev.Seq == 1 {
			close(sawFirst)
		}
	}
	res := testClient().Do(RequestSpec{Method: "GET", URL: srv.URL, OnStream: sink})

	if !res.OK() {
		t.Fatalf("stream failed: %v", res.Err)
	}
	if res.Stream != streamSSE || res.Events != 2 || len(res.Body) != 0 || res.BodySize == 0 {
		t.Errorf("result: stream=%v events=%d body=%d size=%d", res.Stream, res.Events, len(res.Body), res.BodySize)
	}
	if len(sink.heads) != 1 || sink.heads[0].Status != 200 || sink.heads[0].Stream != streamSSE {
		t.Errorf("StreamStart: %+v", sink.heads)
	}
	if len(sink.events) != 2 || sink.events[0].Event != "delta" || sink.events[1].Data != "[DONE]" {
		t.Errorf("events: %+v", sink.events)
	}
}

// The default timeout never caps a stream: a pause longer than it is fine.
func TestDoStreamDefaultTimeoutDoesNotCap(t *testing.T) {
	srv := streamServer(t, "application/x-ndjson", []string{"{\"n\":1}\n", "{\"n\":2}\n"},
		func(_ context.Context, i int) {
			if i == 0 {
				time.Sleep(80 * time.Millisecond)
			}
		}, false)

	c := testClient()
	c.http.Timeout = 40 * time.Millisecond // a tiny default, not an explicit --timeout
	res := c.Do(RequestSpec{Method: "GET", URL: srv.URL, OnStream: &recSink{}})
	if !res.OK() || res.Events != 2 {
		t.Fatalf("the default timeout cut the stream: events=%d err=%v", res.Events, res.Err)
	}
}

// An explicit --timeout is an idle timeout on a stream: the stream outlives
// it while events keep coming, then ends once it falls silent.
func TestDoStreamExplicitTimeoutIsIdle(t *testing.T) {
	chunks := make([]string, 8)
	for i := range chunks {
		chunks[i] = "data: tick\n\n"
	}
	srv := streamServer(t, "text/event-stream", chunks, pause(8*time.Millisecond), true)

	c := testClient()
	c.SetTimeout(40 * time.Millisecond) // shorter than the ~64ms the events take
	res := c.Do(RequestSpec{Method: "GET", URL: srv.URL, OnStream: &recSink{}})

	if res.Events != 8 {
		t.Errorf("events = %d, want all 8 (an idle timeout must not cap the stream)", res.Events)
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "stream idle") || res.DisplayErr == "" {
		t.Errorf("want an idle-timeout error once the stream went quiet, got %v", res.Err)
	}
	if !errors.Is(res.Err, context.DeadlineExceeded) {
		t.Errorf("idle timeout should read as a deadline: %v", res.Err)
	}
}

// Canceling the context ends a stream cleanly: what arrived stands, no error.
func TestDoStreamStop(t *testing.T) {
	srv := streamServer(t, "text/event-stream", []string{"data: one\n\n"}, nil, true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink := &recSink{onEvent: func(streamEvent) { cancel() }}
	res := testClient().DoContext(ctx, RequestSpec{Method: "GET", URL: srv.URL, OnStream: sink})

	if res.Err != nil || res.DisplayErr != "" {
		t.Errorf("a stopped stream is not an error: %v", res.Err)
	}
	if !res.Stopped || res.Events != 1 || res.Status != 200 {
		t.Errorf("stopped=%v events=%d status=%d", res.Stopped, res.Events, res.Status)
	}
}

// Stopped before the response arrives, the request fails — as stopped.
func TestDoStopBeforeHeaders(t *testing.T) {
	got := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(got)
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-got; cancel() }()
	res := testClient().DoContext(ctx, RequestSpec{Method: "GET", URL: srv.URL, OnStream: &recSink{}})

	if !errors.Is(res.Err, errStopped) || !res.Stopped || res.DisplayErr == "" {
		t.Errorf("want a stopped error, got err=%v stopped=%v", res.Err, res.Stopped)
	}
}

// On the live path the timeout still bounds the wait for headers.
func TestDoLiveTimeoutBeforeHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	c := testClient()
	c.http.Timeout = 20 * time.Millisecond
	res := c.Do(RequestSpec{Method: "GET", URL: srv.URL, OnStream: &recSink{}})
	if res.Err == nil || !strings.Contains(res.Err.Error(), "no response headers") {
		t.Errorf("want a header timeout, got %v", res.Err)
	}
}

// OnStream leaves an ordinary response as it was: buffered into Body, and the
// timeout still caps the whole request.
func TestDoOnStreamLeavesOrdinaryResponses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	sink := &recSink{}
	res := testClient().Do(RequestSpec{Method: "GET", URL: srv.URL, OnStream: sink})
	if !res.OK() || string(res.Body) != `{"ok":true}` || res.Stream != streamNone || res.Events != 0 {
		t.Errorf("ordinary response changed: %+v", res)
	}
	if len(sink.heads)+len(sink.events) != 0 {
		t.Error("the sink should never hear about an ordinary response")
	}

	c := testClient()
	c.SetTimeout(50 * time.Millisecond)
	res = c.Do(RequestSpec{Method: "GET", URL: dripServer(t, 8, 30*time.Millisecond).URL, OnStream: sink})
	if res.Err == nil || !strings.Contains(res.Err.Error(), "response not complete") {
		t.Errorf("the timeout should still cap a slow ordinary body, got %v", res.Err)
	}
}

// Piped or -o, a stream is the exact bytes as received, and an explicit
// --timeout is an idle timeout there too.
func TestDoPipedStreamExactBytes(t *testing.T) {
	chunks := []string{": hi\r\n", "event: a\r\ndata: {\"x\":1}\r\n\r\n", "\x1edata: raw\n\n"}
	for range 5 {
		chunks = append(chunks, "data: tick\n\n")
	}
	srv := streamServer(t, "text/event-stream", chunks, pause(8*time.Millisecond), false)

	c := testClient()
	c.SetTimeout(40 * time.Millisecond)
	var sink bytes.Buffer
	res := c.Do(RequestSpec{Method: "GET", URL: srv.URL, BodySink: &sink, OnStream: &recSink{}})
	if !res.OK() {
		t.Fatalf("piped stream failed: %v", res.Err)
	}
	if got, want := sink.String(), strings.Join(chunks, ""); got != want {
		t.Errorf("piped bytes = %q, want %q", got, want)
	}
	if res.Stream != streamNone {
		t.Error("a piped stream is a BodySink transfer, not a live one")
	}
}

// ---- rendering & CLI -----------------------------------------------------------

func TestRenderEvent(t *testing.T) {
	st := newStyles()
	ev := streamEvent{Seq: 3, Event: "delta", ID: "7", Data: `{"text":"hi","n":[1,2]}`, Raw: "event: delta\nid: 7\ndata: {...}"}

	plain := ansi.Strip(renderEvent(ev, st, true, true))
	for _, want := range []string{"#3", "event: delta", "id: 7", "{\n  \"text\": \"hi\",\n  \"n\": ["} {
		if !strings.Contains(plain, want) {
			t.Errorf("pretty render missing %q:\n%s", want, plain)
		}
	}
	if colored := renderEvent(ev, st, true, true); colored == plain {
		t.Error("JSON data should be colored")
	}
	if got := renderEvent(ev, st, true, false); got != ev.Raw {
		t.Errorf("raw render = %q, want the raw lines", got)
	}
	if got := renderEvent(streamEvent{Seq: 1, Data: "[DONE]"}, st, false, true); got != "#1\n[DONE]" {
		t.Errorf("non-JSON data should pass through: %q", got)
	}
}

// swapOutputs points outW/errW at buffers for the test.
func swapOutputs(t *testing.T) (out, errOut *bytes.Buffer) {
	t.Helper()
	out, errOut = new(bytes.Buffer), new(bytes.Buffer)
	oldOut, oldErr := outW, errW
	outW, errW = out, errOut
	t.Cleanup(func() { outW, errW = oldOut, oldErr })
	return out, errOut
}

// At a terminal each event prints the moment it arrives, formatted like the
// TUI; the status goes to stderr first and the closing stats once it ends.
func TestCLIStreamPrintsEachEvent(t *testing.T) {
	out, errOut := swapOutputs(t)
	cs := newCLIStream(true, false, false, true, false)

	head := Result{Status: 200, StatusText: "OK", Proto: "HTTP/1.1", ContentType: "text/event-stream", Stream: streamSSE}
	cs.StreamStart(head)
	if !strings.Contains(ansi.Strip(errOut.String()), "200 OK") || out.Len() != 0 {
		t.Fatalf("start: stderr=%q stdout=%q", errOut, out)
	}
	cs.StreamEvent(streamEvent{Seq: 1, Event: "delta", Data: `{"a":1}`})
	if got := ansi.Strip(out.String()); got != "#1  event: delta\n{\n  \"a\": 1\n}\n" {
		t.Errorf("first event printed as %q", got)
	}
	cs.StreamEvent(streamEvent{Seq: 2, Data: "[DONE]"})
	if got := ansi.Strip(out.String()); !strings.HasSuffix(got, "}\n\n#2\n[DONE]\n") {
		t.Errorf("second event should follow a blank line: %q", got)
	}

	errOut.Reset()
	printed := out.Len()
	res := head
	res.Events, res.BodySize = 2, 42
	if code := emitResult(res, true, false, true, false); code != 0 {
		t.Errorf("exit = %d", code)
	}
	if out.Len() != printed {
		t.Error("emitResult must not print a live stream's body again")
	}
	if !strings.Contains(errOut.String(), "stream ended") || !strings.Contains(errOut.String(), "2 events") {
		t.Errorf("closing line: %q", errOut)
	}
}

// -i at a terminal: the status line and headers lead stdout, as with a body.
func TestCLIStreamInclude(t *testing.T) {
	out, _ := swapOutputs(t)
	cs := newCLIStream(true, false, true, true, true)
	cs.StreamStart(Result{Status: 200, StatusText: "OK", Proto: "HTTP/1.1", Stream: streamSSE,
		Headers: http.Header{"Content-Type": {"text/event-stream"}}})
	if got := out.String(); got != "HTTP/1.1 200 OK\nContent-Type: text/event-stream\n\n" {
		t.Errorf("include head = %q", got)
	}
}

// NO_COLOR at a terminal: the raw lines, as emitResult shows a raw body.
func TestCLIStreamNoColorIsRaw(t *testing.T) {
	out, _ := swapOutputs(t)
	cs := newCLIStream(false, false, true, true, false)
	cs.StreamStart(Result{Status: 200, Stream: streamNDJSON})
	cs.StreamEvent(streamEvent{Seq: 1, Data: `{"a":1}`, Raw: `{"a":1}`})
	cs.StreamEvent(streamEvent{Seq: 2, Data: `{"a":2}`, Raw: `{"a":2}`})
	if got := out.String(); got != "{\"a\":1}\n{\"a\":2}\n" {
		t.Errorf("raw NDJSON = %q", got)
	}
}

// -o FILE gets a stream's exact bytes.
func TestRunCLIOutputFileStream(t *testing.T) {
	t.Setenv("WEEB_BASE_URL", "")
	t.Setenv("WEEB_HEADERS", "")
	t.Setenv("WEEB_TOKEN", "")
	t.Setenv("WEEB_MAX_BODY", "")
	t.Setenv("WEEB_HISTORY", "0")

	chunks := []string{"data: {\"a\":1}\r\n\r\n", ": ping\n\n", "data: [DONE]\n\n"}
	srv := streamServer(t, "text/event-stream", chunks, nil, false)
	path := filepath.Join(t.TempDir(), "events.txt")
	if code := runCLI(cliArgs{method: "GET", url: srv.URL, output: path, quiet: true}); code != 0 {
		t.Fatalf("runCLI exit = %d", code)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != strings.Join(chunks, "") {
		t.Errorf("file = %q", got)
	}
}
