package main

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
)

// liveBatch bounds how many events one liveMsg carries, and how many wait
// queued between Do and the event loop: a fast stream re-renders the pane
// once per batch rather than once per event, and a UI that falls behind
// holds the stream back instead of buffering it without bound.
const liveBatch = 256

// liveReq is a request sent from the form (ctrl+s). Do runs on a command
// goroutine and reports only through ch — an event stream's head, each event,
// then the final result, in that order — and the event loop drains ch via
// wait, so the model is only ever touched by Update. cancel backs the stop
// key.
type liveReq struct {
	ctx    context.Context
	cancel context.CancelFunc
	ch     chan liveMsg
}

func newLiveReq() *liveReq {
	ctx, cancel := context.WithCancel(context.Background())
	return &liveReq{ctx: ctx, cancel: cancel, ch: make(chan liveMsg, liveBatch)}
}

// liveMsg is what a liveReq delivered since the last one. A merged message
// keeps arrival order: the head comes before any event, the final result
// after all of them.
type liveMsg struct {
	req    *liveReq
	head   *Result       // response metadata, when an event stream starts
	events []streamEvent // events, oldest first
	final  *Result       // the finished request; nothing follows it
}

func (a liveMsg) merge(b liveMsg) liveMsg {
	if a.head == nil {
		a.head = b.head
	}
	a.events = append(a.events, b.events...)
	a.final = b.final
	return a
}

// StreamStart and StreamEvent make liveReq Do's StreamSink. They run on Do's
// goroutine and only send; a full channel blocks the stream until Update
// catches up.
func (lv *liveReq) StreamStart(head Result) { lv.ch <- liveMsg{req: lv, head: &head} }
func (lv *liveReq) StreamEvent(ev streamEvent) {
	lv.ch <- liveMsg{req: lv, events: []streamEvent{ev}}
}

// finish delivers the final result; it is the last thing sent on ch.
func (lv *liveReq) finish(res Result) {
	lv.ch <- liveMsg{req: lv, final: &res}
	close(lv.ch)
}

// wait is the command that waits for the next liveMsg, merging whatever else
// is already queued (up to liveBatch events) into it. Update re-issues it
// until the final result arrives.
func (lv *liveReq) wait() tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-lv.ch
		if !ok {
			return nil
		}
		for msg.final == nil && len(msg.events) < liveBatch {
			select {
			case next, ok := <-lv.ch:
				if !ok {
					return msg
				}
				msg = msg.merge(next)
			default:
				return msg
			}
		}
		return msg
	}
}

// maxStreamEvents and maxStreamBytes cap what the response pane keeps of a
// stream. The pane is rebuilt as events arrive and a stream may never end,
// so it holds the newest events only and counts the rest as dropped. Vars so
// tests can lower them; a lower --max-body lowers the byte cap too.
var (
	maxStreamEvents = 2000
	maxStreamBytes  = 4 << 20
)

// streamView is the TUI's record of the event stream in the response pane,
// live or finished.
type streamView struct {
	format  streamFormat
	events  []streamEvent
	renders []string // renders[i] caches events[i] rendered for the pane
	pretty  bool     // the pretty setting the renders were made with
	total   int      // events received, the dropped ones included
	dropped int      // oldest events evicted to stay under the caps
	kept    int      // bytes held in events
	live    bool     // still receiving
	follow  bool     // keep the newest event in view; scrolling up pauses it
}

// add appends newly arrived events, evicting the oldest past the caps (the
// newest one always stays, however big: eventCap already bounds it).
func (sv *streamView) add(evs []streamEvent) {
	for _, ev := range evs {
		sv.events = append(sv.events, ev)
		sv.renders = append(sv.renders, "")
		sv.kept += ev.size()
	}
	sv.total += len(evs)
	budget := int(min(int64(maxStreamBytes), maxBodyBytes))
	n := 0
	for len(sv.events)-n > maxStreamEvents || (sv.kept > budget && len(sv.events)-n > 1) {
		sv.kept -= sv.events[n].size()
		n++
	}
	if n > 0 {
		clear(sv.events[:n]) // let the evicted strings go now, not at the next realloc
		clear(sv.renders[:n])
		sv.events, sv.renders = sv.events[n:], sv.renders[n:]
		sv.dropped += n
	}
}

// content is the Body section of a stream: a note about dropped events, then
// the kept events, each rendered once and cached until pretty flips.
func (sv *streamView) content(st styles, pretty bool) string {
	if pretty != sv.pretty {
		clear(sv.renders)
		sv.pretty = pretty
	}
	var b strings.Builder
	if sv.dropped > 0 {
		b.WriteString(st.meta.Render(fmt.Sprintf("⋯ %s dropped to bound memory; showing the newest %d",
			plural(sv.dropped, "earlier event"), len(sv.events))))
		b.WriteString("\n\n")
	}
	if len(sv.events) == 0 {
		msg := "no events"
		if sv.live {
			msg = "waiting for events…"
		}
		b.WriteString(st.meta.Render(msg))
	}
	sep := eventSep(sv.format, pretty)
	for i := range sv.events {
		if sv.renders[i] == "" {
			sv.renders[i] = renderEvent(sv.events[i], st, true, pretty)
		}
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(sv.renders[i])
	}
	return b.String()
}

// summary is the Body section heading's note: events, size once known, type.
func (sv *streamView) summary(r Result) string {
	s := plural(sv.total, "event")
	if !sv.live {
		s += " · " + humanSize(int(r.bodySize()))
	}
	if tag := shortContentType(r.ContentType); tag != "" {
		s += " · " + tag
	}
	return s
}

// badge is the status line atop a stream: the status chip, then the live
// event count while streaming, or how it ended.
func (sv *streamView) badge(r Result, st styles) string {
	meta := fmt.Sprintf("  %s  ·  ● streaming… %s", r.Proto, plural(sv.total, "event"))
	if !sv.live {
		meta = fmt.Sprintf("  %s  ·  %d ms  ·  %s", r.Proto, r.Timing.Total.Milliseconds(), streamEnd(r))
	}
	return statusChip(r) + st.meta.Render(meta)
}

// ---- model -------------------------------------------------------------------

// onLive applies a liveMsg. An ordinary response arrives only as a final
// result and takes the resultMsg path unchanged; an event stream starts
// with its head, grows with each batch, and ends with its final result.
func (m model) onLive(msg liveMsg) (tea.Model, tea.Cmd) {
	if m.live == nil || msg.req != m.live {
		return m, nil // left over from a request that has already finished
	}
	if msg.head != nil {
		head := *msg.head
		m.stream = &streamView{format: head.Stream, live: true, follow: true}
		m.lastResult = &head
		m.layout()
		m.renderResult(head)
	}
	if m.stream != nil && m.stream.live {
		m.stream.add(msg.events)
		if len(msg.events) > 0 && m.pane == paneResponse {
			m.renderResult(*m.lastResult)
		}
		if m.live.ctx.Err() == nil { // keep "stopping…" once the stop key was pressed
			m.flightLabel = fmt.Sprintf("streaming… %s  ·  esc stop", plural(m.stream.total, "event"))
		}
	}
	if msg.final == nil {
		return m, m.live.wait()
	}

	m.live = nil
	res := *msg.final
	if res.Stream == streamNone {
		m.stream = nil
		return m.Update(resultMsg(res))
	}
	m.inFlight = false
	m.stream.live = false
	m.lastResult = &res
	m.renderResult(res)
	return m, nil
}

// stopLive is the stop key: cancel the request in flight without quitting.
// A stream ends with everything that arrived kept on screen; a request still
// waiting for its response fails as stopped.
func (m *model) stopLive() {
	m.live.cancel()
	m.flightLabel = "stopping…"
}
