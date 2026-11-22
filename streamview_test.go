package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// teaLoop is a minimal Bubble Tea runtime for tests: commands run on their
// own goroutines, as in the real program, and every message they produce goes
// through Update on the test goroutine. So these tests drive the real stream
// plumbing, and -race checks that nothing touches the model off the loop.
type teaLoop struct {
	t    *testing.T
	m    tea.Model
	msgs chan tea.Msg
	done chan struct{}
}

func newTeaLoop(t *testing.T, m tea.Model) *teaLoop {
	l := &teaLoop{t: t, m: m, msgs: make(chan tea.Msg), done: make(chan struct{})}
	t.Cleanup(func() { close(l.done) })
	return l
}

func (l *teaLoop) run(cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	go func() {
		switch msg := cmd().(type) {
		case nil:
		case tea.BatchMsg:
			for _, c := range msg {
				l.run(c)
			}
		default:
			select {
			case l.msgs <- msg:
			case <-l.done:
			}
		}
	}()
}

// send puts msg through Update now, as a key press would, and returns the
// command Update produced (already started).
func (l *teaLoop) send(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	l.m, cmd = l.m.Update(msg)
	l.run(cmd)
	return cmd
}

// until feeds command messages through Update until cond holds.
func (l *teaLoop) until(what string, cond func(model) bool) model {
	l.t.Helper()
	timeout := time.After(5 * time.Second)
	for !cond(l.m.(model)) {
		select {
		case msg := <-l.msgs:
			l.send(msg)
		case <-timeout:
			l.t.Fatalf("timed out waiting for %s", what)
		}
	}
	return l.m.(model)
}

func screen(m model) string { return ansi.Strip(m.View().Content) }

func quietEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"WEEB_BASE_URL", "WEEB_HEADERS", "WEEB_TOKEN", "WEEB_MAX_BODY"} {
		t.Setenv(k, "")
	}
	t.Setenv("WEEB_HISTORY", "0")
}

// ctrl+s on an SSE endpoint: each event shows up while the stream is still
// open (the server holds event 2 until the screen shows event 1), with the
// live counter, and the finished stream says how it ended.
func TestTUIStreamRendersLive(t *testing.T) {
	quietEnv(t)
	release := make(chan struct{})
	srv := streamServer(t, "text/event-stream", []string{
		"event: delta\ndata: {\"text\":\"hi\"}\n\n",
		"event: done\ndata: [DONE]\n\n",
	}, func(ctx context.Context, i int) {
		if i == 0 {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	}, false)

	m := testModel()
	m.url.SetValue(srv.URL)
	l := newTeaLoop(t, m)
	l.send(tea.WindowSizeMsg{Width: 100, Height: 60})
	l.send(kp("ctrl+s"))

	m = l.until("the first event", func(m model) bool { return m.stream != nil && m.stream.total == 1 })
	view := screen(m)
	for _, want := range []string{"● streaming… 1 event", "#1  event: delta", `"text": "hi"`, "esc stop"} {
		if !strings.Contains(view, want) {
			t.Errorf("live view missing %q:\n%s", want, view)
		}
	}

	close(release)
	m = l.until("the stream to end", func(m model) bool { return !m.inFlight })
	view = screen(m)
	for _, want := range []string{"#2  event: done", "[DONE]", "stream ended", "2 events"} {
		if !strings.Contains(view, want) {
			t.Errorf("finished view missing %q:\n%s", want, view)
		}
	}
	if m.live != nil || m.lastResult == nil || m.lastResult.Events != 2 || !m.lastResult.OK() {
		t.Errorf("final state: live=%v result=%+v", m.live, m.lastResult)
	}
}

// The stop key ends the stream — connection closed, events kept — and the
// app keeps running.
func TestTUIStopKeyEndsStream(t *testing.T) {
	quietEnv(t)
	srv := streamServer(t, "application/x-ndjson", []string{"{\"n\":1}\n"}, nil, true)

	m := testModel()
	m.url.SetValue(srv.URL)
	l := newTeaLoop(t, m)
	l.send(tea.WindowSizeMsg{Width: 100, Height: 60})
	l.send(kp("ctrl+s"))
	l.until("the first event", func(m model) bool { return m.stream != nil && m.stream.total == 1 })

	if cmd := l.send(tea.KeyPressMsg{Code: tea.KeyEscape}); cmd != nil {
		t.Errorf("stop returned a command (%T); it must not quit", cmd())
	}
	m = l.until("the stopped stream", func(m model) bool { return !m.inFlight })

	if r := m.lastResult; r == nil || !r.Stopped || r.Err != nil || r.Events != 1 {
		t.Fatalf("stopped result: %+v", m.lastResult)
	}
	view := screen(m)
	if !strings.Contains(view, "stopped") || !strings.Contains(view, `"n": 1`) {
		t.Errorf("stopped view:\n%s", view)
	}
}

// An ordinary response sent with ctrl+s lands exactly as before: a buffered
// body with its fold tree, no stream state left behind.
func TestTUIOrdinaryResponseThroughLive(t *testing.T) {
	quietEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"items":[1,2]}`))
	}))
	defer srv.Close()

	m := testModel()
	m.url.SetValue(srv.URL)
	l := newTeaLoop(t, m)
	l.send(tea.WindowSizeMsg{Width: 100, Height: 60})
	l.send(kp("ctrl+s"))
	m = l.until("the response", func(m model) bool { return !m.inFlight })

	if m.lastResult == nil || string(m.lastResult.Body) != `{"ok":true,"items":[1,2]}` || m.lastResult.Stream != streamNone {
		t.Fatalf("result: %+v", m.lastResult)
	}
	if bodyTree(m) == nil || m.stream != nil || m.live != nil {
		t.Errorf("tree=%v stream=%v live=%v", bodyTree(m) != nil, m.stream, m.live)
	}
}

// liveModel is a sized model with a live request in flight, for tests that
// feed liveMsgs straight into Update.
func liveModel(t *testing.T, height int) (model, *liveReq) {
	t.Helper()
	m := send(t, testModel(), tea.WindowSizeMsg{Width: 80, Height: height}).(model)
	lv := newLiveReq()
	m.live, m.inFlight = lv, true
	head := Result{Status: 200, StatusText: "OK", Proto: "HTTP/1.1",
		Headers:     http.Header{"Content-Type": {"text/event-stream"}},
		ContentType: "text/event-stream", Stream: streamSSE}
	return send(t, m, liveMsg{req: lv, head: &head}).(model), lv
}

func sseEvents(from, n int) []streamEvent {
	evs := make([]streamEvent, n)
	for i := range evs {
		data := fmt.Sprintf(`{"n":%d}`, from+i)
		evs[i] = streamEvent{Seq: from + i, Data: data, Raw: "data: " + data}
	}
	return evs
}

// The pane follows the newest event; scrolling up pauses that, and scrolling
// back to the bottom resumes it.
func TestTUIStreamAutoScroll(t *testing.T) {
	m, lv := liveModel(t, 30)
	m = send(t, m, liveMsg{req: lv, events: sseEvents(1, 40)}).(model)
	if !m.resp.AtBottom() {
		t.Fatal("a live stream should follow its newest event")
	}

	m = send(t, focusResponse(m), kp("up")).(model)
	off := m.resp.YOffset()
	if m.stream.follow {
		t.Fatal("scrolling up should pause auto-scroll")
	}
	m = send(t, m, liveMsg{req: lv, events: sseEvents(41, 10)}).(model)
	if m.resp.YOffset() != off || m.resp.AtBottom() {
		t.Errorf("paused pane moved: offset %d -> %d", off, m.resp.YOffset())
	}

	for i := 0; i < 1000 && !m.resp.AtBottom(); i++ {
		m = send(t, m, kp("down")).(model)
	}
	m = send(t, m, liveMsg{req: lv, events: sseEvents(51, 10)}).(model)
	if !m.stream.follow || !m.resp.AtBottom() {
		t.Error("back at the bottom, the pane should follow again")
	}
}

// The pane keeps only the newest events and says how many it dropped.
func TestTUIStreamDropsOldest(t *testing.T) {
	oldN, oldB := maxStreamEvents, maxStreamBytes
	maxStreamEvents = 5
	t.Cleanup(func() { maxStreamEvents, maxStreamBytes = oldN, oldB })

	m, lv := liveModel(t, 80)
	m = send(t, m, liveMsg{req: lv, events: sseEvents(1, 12)}).(model)
	if len(m.stream.events) != 5 || m.stream.dropped != 7 || m.stream.total != 12 {
		t.Fatalf("kept %d, dropped %d, total %d", len(m.stream.events), m.stream.dropped, m.stream.total)
	}
	view := screen(m)
	if !strings.Contains(view, "7 earlier events dropped") || !strings.Contains(view, "#12") || strings.Contains(view, "#7") {
		t.Errorf("view:\n%s", view)
	}

	// The byte cap evicts too.
	maxStreamEvents, maxStreamBytes = 1000, 100
	m = send(t, m, liveMsg{req: lv, events: sseEvents(13, 20)}).(model)
	if m.stream.kept > 100 || len(m.stream.events) == 0 {
		t.Errorf("kept %d bytes in %d events, cap 100", m.stream.kept, len(m.stream.events))
	}
}

// ctrl+p flips a stream between pretty blocks and the raw lines.
func TestTUIStreamRawToggle(t *testing.T) {
	m, lv := liveModel(t, 60)
	m = send(t, m, liveMsg{req: lv, events: sseEvents(1, 2)}).(model)
	if view := screen(m); !strings.Contains(view, `"n": 1`) {
		t.Fatalf("pretty view:\n%s", view)
	}
	m = send(t, m, kp("ctrl+p")).(model)
	view := screen(m)
	if !strings.Contains(view, `data: {"n":1}`) || strings.Contains(view, "#1") {
		t.Errorf("raw view:\n%s", view)
	}

	// A message from some other request changes nothing.
	before := m.stream.total
	m = send(t, m, liveMsg{req: newLiveReq(), events: sseEvents(9, 1)}).(model)
	if m.stream.total != before {
		t.Error("a stale liveMsg was applied")
	}
}
