package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"charm.land/lipgloss/v2"
)

// streamFormat is the wire shape of a response weeb renders live, event by
// event, instead of once the body ends.
type streamFormat int

const (
	streamNone   streamFormat = iota
	streamSSE                 // text/event-stream: field lines, events end at a blank line
	streamNDJSON              // one JSON text per line: NDJSON, JSON Lines, json-seq
)

// streamFormatOf maps a response Content-Type to its stream format. Only an
// explicit streaming media type counts: sniffing the body would turn an
// ordinary slow response into a stream, and lift its timeout, on a guess.
func streamFormatOf(contentType string) streamFormat {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt, _, _ = strings.Cut(strings.ToLower(contentType), ";")
		mt = strings.TrimSpace(mt)
	}
	switch mt {
	case "text/event-stream":
		return streamSSE
	case "application/x-ndjson", "application/ndjson",
		"application/jsonl", "application/x-jsonl",
		"application/jsonlines", "application/x-jsonlines",
		"application/json-seq":
		return streamNDJSON
	}
	return streamNone
}

// streamEvent is one event of a live stream: an SSE event, or one JSON-lines
// record (Data and Raw only).
type streamEvent struct {
	Seq       int    // 1-based position in the stream
	Event     string // SSE "event:"; "" means the default type, "message"
	ID        string // SSE "id:"
	Retry     string // SSE "retry:"
	Data      string // SSE "data:" lines joined with "\n", or the JSON-lines record
	Raw       string // the event's lines as they arrived, for the raw view
	Truncated bool   // the event outgrew eventCap and the rest was dropped
}

// size is what the event costs to keep, for the TUI's stream budget.
func (ev streamEvent) size() int { return len(ev.Data) + len(ev.Raw) }

// StreamSink receives a live event stream from Do (RequestSpec.OnStream).
// Both methods run on Do's goroutine, in order: StreamStart once the headers
// arrive, then StreamEvent as each event completes.
type StreamSink interface {
	StreamStart(head Result)
	StreamEvent(ev streamEvent)
}

// maxEventBytes caps a single event (a line, or an SSE event's data): an
// event is held whole until it completes, so a server that never sends a
// newline would otherwise grow it without bound. Past the cap the rest of the
// event is dropped and it is marked Truncated. A var so tests can lower it.
var maxEventBytes = 1 << 20

// eventCap is the per-event cap in force: --max-body lowers it too, since an
// event is a body weeb buffers to render.
func eventCap() int { return int(min(int64(maxEventBytes), maxBodyBytes)) }

// eventParser splits a streamed body into events as the bytes arrive. It is
// an io.Writer, so Do can io.Copy the body into it; emit runs synchronously
// for each event as soon as its terminator arrives. SSE follows the WHATWG
// event-stream rules (CR, LF or CRLF line ends; ":" comments; an event is
// dispatched at a blank line, and only when it has data). JSON lines split on
// LF, with CRLF tolerated and the json-seq record separator (RS) treated as a
// separator too.
type eventParser struct {
	format streamFormat
	emit   func(streamEvent)
	limit  int
	seq    int // events emitted so far

	line    []byte // the line being received
	lineCut bool   // line passed limit; the rest of it is being dropped
	afterCR bool   // SSE: the last byte was CR, so a leading LF belongs to it
	started bool   // a first line was seen (an SSE stream may open with a BOM)

	// The SSE event being assembled.
	cur     streamEvent
	data    []byte
	hasData bool
	raw     []byte
	cut     bool
}

func newEventParser(f streamFormat, emit func(streamEvent)) *eventParser {
	return &eventParser{format: f, emit: emit, limit: eventCap()}
}

func (p *eventParser) Write(b []byte) (int, error) {
	n := len(b)
	for len(b) > 0 {
		if p.afterCR {
			p.afterCR = false
			if b[0] == '\n' {
				b = b[1:]
				continue
			}
		}
		eol := "\n\x1e"
		if p.format == streamSSE {
			eol = "\r\n"
		}
		i := bytes.IndexAny(b, eol)
		if i < 0 {
			p.appendLine(b)
			break
		}
		p.appendLine(b[:i])
		p.afterCR = b[i] == '\r'
		b = b[i+1:]
		p.endLine()
	}
	return n, nil
}

// Close flushes what the stream ended on: a last line without a newline,
// and for SSE an event the server never terminated with a blank line. The
// spec would drop that event; a debugging client shouldn't hide bytes.
func (p *eventParser) Close() error {
	if len(p.line) > 0 || p.lineCut {
		p.endLine()
	}
	if p.format == streamSSE {
		p.dispatch()
	}
	return nil
}

func (p *eventParser) appendLine(b []byte) {
	if room := p.limit - len(p.line); len(b) > room {
		p.line = append(p.line, b[:max(room, 0)]...)
		p.lineCut = true
		return
	}
	p.line = append(p.line, b...)
}

func (p *eventParser) endLine() {
	line, cut := p.line, p.lineCut
	p.line, p.lineCut = p.line[:0], false // the backing array is reused: copy out of line
	if !p.started {
		p.started = true
		line = bytes.TrimPrefix(line, []byte("\xef\xbb\xbf"))
	}
	if p.format != streamSSE {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if !cut && len(bytes.TrimSpace(line)) == 0 {
			return // blank lines between records aren't records
		}
		s := string(line)
		p.send(streamEvent{Data: s, Raw: s, Truncated: cut})
		return
	}

	if len(line) == 0 {
		if !cut {
			p.dispatch()
		}
		return
	}
	if len(p.raw) > 0 {
		p.raw = appendCapped(p.raw, []byte("\n"), p.limit, &p.cut)
	}
	p.raw = appendCapped(p.raw, line, p.limit, &p.cut)
	if line[0] == ':' {
		return // a comment, usually a keepalive
	}
	field, value, _ := bytes.Cut(line, []byte(":"))
	value = bytes.TrimPrefix(value, []byte(" "))
	switch string(field) {
	case "event":
		p.cur.Event = string(value)
	case "data":
		if p.hasData {
			p.data = appendCapped(p.data, []byte("\n"), p.limit, &p.cut)
		}
		p.data = appendCapped(p.data, value, p.limit, &p.cut)
		p.hasData = true
		p.cut = p.cut || cut
	case "id":
		if !bytes.ContainsRune(value, 0) {
			p.cur.ID = string(value)
		}
	case "retry":
		if len(value) > 0 && len(bytes.Trim(value, "0123456789")) == 0 {
			p.cur.Retry = string(value)
		}
	}
}

// dispatch ends the SSE event being assembled. Per the spec, a block with no
// data line (a keepalive, a lone retry:) is not an event.
func (p *eventParser) dispatch() {
	if p.hasData {
		ev := p.cur
		ev.Data = string(p.data)
		ev.Raw = string(p.raw)
		ev.Truncated = p.cut
		p.send(ev)
	}
	p.cur = streamEvent{}
	p.data, p.raw = p.data[:0], p.raw[:0]
	p.hasData, p.cut = false, false
}

func (p *eventParser) send(ev streamEvent) {
	p.seq++
	ev.Seq = p.seq
	p.emit(ev)
}

// appendCapped appends b to dst without letting dst pass limit, setting
// *cut when anything had to be dropped.
func appendCapped(dst, b []byte, limit int, cut *bool) []byte {
	if room := limit - len(dst); len(b) > room {
		*cut = true
		return append(dst, b[:max(room, 0)]...)
	}
	return append(dst, b...)
}

// ---- timeouts on the live path ---------------------------------------------

// errStopped is the cancel cause when the caller stops a request (the TUI's
// stop key), so the result can tell a deliberate stop from a failure.
var errStopped = errors.New("request stopped")

// timeoutError is the cancel cause when liveTimer fires. It unwraps to
// context.DeadlineExceeded and reports Timeout(), like the stdlib's own
// timeout errors.
type timeoutError struct{ msg string }

func (e *timeoutError) Error() string { return e.msg }
func (e *timeoutError) Timeout() bool { return true }
func (e *timeoutError) Unwrap() error { return context.DeadlineExceeded }

// liveTimer applies the timeout on Do's live path (a BodySink or an
// OnStream request), where http.Client.Timeout can't be used: it also caps
// reading the body, which would kill a stream. It starts as a cap on the
// whole request; once the headers show what the body is, Do leaves it
// running (an ordinary body: the same total cap as before), swaps it for an
// idle timeout (an event stream under an explicit --timeout), or stops it.
type liveTimer struct {
	d       time.Duration
	cancel  context.CancelCauseFunc
	gotHead atomic.Bool
	total   *time.Timer
	idleT   *time.Timer
}

func startLiveTimer(d time.Duration, cancel context.CancelCauseFunc) *liveTimer {
	lt := &liveTimer{d: d, cancel: cancel}
	if d > 0 {
		lt.total = time.AfterFunc(d, func() {
			what := "no response headers"
			if lt.gotHead.Load() {
				what = "response not complete"
			}
			cancel(&timeoutError{fmt.Sprintf("timeout: %s within %s", what, d)})
		})
	}
	return lt
}

// headers records that the response headers arrived, for the timeout message.
func (lt *liveTimer) headers() { lt.gotHead.Store(true) }

// idle switches to an idle timeout: r's reads re-arm it, so the stream lives
// as long as data keeps coming and ends once d passes in silence.
func (lt *liveTimer) idle(r io.Reader) io.Reader {
	lt.stop()
	if lt.d <= 0 {
		return r
	}
	lt.idleT = time.AfterFunc(lt.d, func() {
		lt.cancel(&timeoutError{fmt.Sprintf("stream idle: no data for %s", lt.d)})
	})
	return &idleReader{r: r, t: lt.idleT, d: lt.d}
}

func (lt *liveTimer) stop() {
	if lt.total != nil {
		lt.total.Stop()
	}
	if lt.idleT != nil {
		lt.idleT.Stop()
	}
}

// idleReader re-arms an idle timer whenever a read brings data.
type idleReader struct {
	r io.Reader
	t *time.Timer
	d time.Duration
}

func (ir *idleReader) Read(p []byte) (int, error) {
	n, err := ir.r.Read(p)
	if n > 0 {
		ir.t.Reset(ir.d)
	}
	return n, err
}

// explainCancel replaces the error of a request weeb canceled itself (a
// stop, a liveTimer timeout) with the reason, keeping the url.Error framing
// (`Get "…": …`) when there is one; a bare "context canceled" says nothing.
// Errors with any other cause pass through unchanged.
func explainCancel(ctx context.Context, err error) error {
	cause := context.Cause(ctx)
	var te *timeoutError
	if !errors.Is(cause, errStopped) && !errors.As(cause, &te) {
		return err
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return &url.Error{Op: ue.Op, URL: ue.URL, Err: cause}
	}
	return cause
}

// ---- rendering ---------------------------------------------------------------

// renderEvent formats one event for display. Pretty: a one-line caption (the
// event's position, then the SSE event/id/retry it set), then its data —
// indented and, with color, syntax-colored when it is JSON. Raw: the event's
// lines exactly as they arrived. The TUI and the CLI share it so a stream
// reads the same in both.
func renderEvent(ev streamEvent, st styles, color, pretty bool) string {
	if !pretty {
		return ev.Raw
	}
	paint := func(s lipgloss.Style, text string) string {
		if color {
			return s.Render(text)
		}
		return text
	}
	parts := []string{paint(st.meta, fmt.Sprintf("#%d", ev.Seq))}
	for _, f := range [...][2]string{{"event", ev.Event}, {"id", ev.ID}, {"retry", ev.Retry}} {
		if f[1] != "" {
			parts = append(parts, paint(st.headerKey, f[0]+":")+" "+paint(st.headerVal, f[1]))
		}
	}
	out := strings.Join(parts, "  ")
	if ev.Data != "" {
		out += "\n" + eventData(ev.Data, st, color)
	}
	if ev.Truncated {
		out += "\n" + paint(st.meta, "… event cut at "+humanSize(eventCap()))
	}
	return out
}

// eventData pretty-prints an event's data when it is JSON (bounded like any
// pretty body, see prettyBody) and leaves anything else — "[DONE]", plain
// text — as it came.
func eventData(data string, st styles, color bool) string {
	b := []byte(data)
	if !json.Valid(b) {
		return data
	}
	out := prettyBody(b, "application/json")
	if color {
		return colorizeJSON(out, st)
	}
	return out
}

// eventSep goes between two rendered events: a blank line, except in the raw
// view of JSON lines, whose records sit one per line on the wire too.
func eventSep(f streamFormat, pretty bool) string {
	if !pretty && f == streamNDJSON {
		return "\n"
	}
	return "\n\n"
}

// plural renders "1 event" / "2 events".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// statusChip is the colored "200 OK" badge that heads a response.
func statusChip(r Result) string {
	return lipgloss.NewStyle().Bold(true).Foreground(cInk).Background(statusColor(r.Status)).
		Padding(0, 1).Render(fmt.Sprintf("%d %s", r.Status, r.StatusText))
}

// streamEnd describes how a finished stream went, for the closing line.
func streamEnd(r Result) string {
	how := "stream ended"
	if r.Stopped {
		how = "stopped"
	}
	return fmt.Sprintf("%s  ·  %s  ·  %s", how, plural(r.Events, "event"), humanSize(int(r.bodySize())))
}

// ---- CLI ---------------------------------------------------------------------

// cliStream is the CLI's StreamSink at a terminal: the status block goes to
// stderr when the stream starts, each event to stdout as it arrives (with
// renderEvent's formatting), and emitStreamEnd closes with the timing once
// Do returns. Each event is a single write, so outW's sanitizer never sees an
// escape sequence split across two.
type cliStream struct {
	st                            styles
	color, pretty, stats, include bool
	format                        streamFormat
	printed                       int
}

// ttyStream returns the CLI's live printer for event streams, or nil when
// stdout isn't a terminal: a pipe or file gets the raw bytes through BodySink
// instead. The flags mirror emitResult's, which closes the stream.
func ttyStream(wantStats, quiet, pretty, include bool) StreamSink {
	if !stdoutIsTTY() {
		return nil
	}
	return newCLIStream(os.Getenv("NO_COLOR") == "", wantStats, quiet, pretty, include)
}

func newCLIStream(color, wantStats, quiet, pretty, include bool) *cliStream {
	return &cliStream{
		st:    newStyles(),
		color: color,
		// Without color emitResult shows a body raw, so a stream is raw too.
		pretty:  pretty && color,
		stats:   !quiet && (color || wantStats),
		include: include,
	}
}

func (c *cliStream) StreamStart(head Result) {
	c.format = head.Stream
	if c.stats && head.Status != 0 {
		fmt.Fprintln(errW, statusChip(head)+c.st.meta.Render(fmt.Sprintf("  %s  ·  streaming %s…",
			head.Proto, shortContentType(head.ContentType))))
		if head.TLS != nil {
			fmt.Fprintln(errW, renderConnTLS(head.TLS, c.st))
		}
		if len(head.Redirects) > 0 {
			fmt.Fprintln(errW, renderRedirects(head.Redirects, c.st))
		}
	}
	// -i: the status line and headers come first on stdout, like emitResult.
	if c.include && head.Status != 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "%s %d %s\n", head.Proto, head.Status, head.StatusText)
		for _, k := range sortedHeaderKeys(head.Headers) {
			for _, v := range head.Headers[k] {
				fmt.Fprintf(&b, "%s: %s\n", k, v)
			}
		}
		fmt.Fprintln(outW, b.String())
	}
}

func (c *cliStream) StreamEvent(ev streamEvent) {
	out := renderEvent(ev, c.st, c.color, c.pretty)
	if c.printed > 0 {
		out = strings.TrimSuffix(eventSep(c.format, c.pretty), "\n") + out
	}
	c.printed++
	fmt.Fprintln(outW, out)
}

// emitStreamEnd finishes a stream cliStream already printed: the timing and
// the closing line go to stderr (like emitResult's stats block), then any
// error; the exit code follows emitResult's.
func emitStreamEnd(res Result, wantStats, quiet bool) int {
	color := stdoutIsTTY() && os.Getenv("NO_COLOR") == ""
	if !quiet && (color || wantStats) && res.Status != 0 {
		st := newStyles()
		fmt.Fprintln(errW, renderTiming(res.Timing, st, 50))
		fmt.Fprintln(errW, st.meta.Render(streamEnd(res)))
	}
	if res.DisplayErr != "" {
		fmt.Fprintln(errW, res.DisplayErr)
	}
	if !res.OK() {
		return 1
	}
	return 0
}
