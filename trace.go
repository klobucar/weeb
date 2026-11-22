package main

import (
	"crypto/tls"
	"net/http/httptrace"
	"sync"
	"time"
)

// Timing is the per-phase breakdown of a single request, captured via
// net/http/httptrace. Phases are zero when they don't apply (e.g. DNS/TCP/TLS
// are zero on a reused keep-alive connection).
type Timing struct {
	DNS      time.Duration // name resolution
	TCP      time.Duration // TCP connect
	TLS      time.Duration // TLS handshake
	Send     time.Duration // connection ready -> request fully written
	Server   time.Duration // request written -> first response byte (server think time)
	Transfer time.Duration // first byte -> body fully read
	Total    time.Duration // everything
	Reused   bool          // connection came from the keep-alive pool

	// Which connection-setup phases ran for this request. A phase can measure
	// 0 on a coarse clock (Windows, loopback) and still have happened, so
	// counting phases by duration > 0 undercounts.
	DidDNS, DidConnect, DidTLS bool
}

// connTLS summarizes the negotiated TLS parameters of a request's connection.
type connTLS struct {
	Version string
	Cipher  string
	ALPN    string
	Leaf    *certInfo
}

// reqTrace records phase timestamps as a request progresses. Its callbacks
// can run on transport goroutines concurrently with timing(): the transport
// may start a dial for a request, hand it a pooled connection instead, and
// finish the abandoned dial (firing ConnectDone/TLS callbacks on this trace)
// after Do has read the timing. mu guards every field.
type reqTrace struct {
	mu                  sync.Mutex
	start               time.Time
	dnsStart, dnsDone   time.Time
	connStart, connDone time.Time
	tlsStart, tlsDone   time.Time
	gotConn, wroteReq   time.Time
	firstByte           time.Time
	reused              bool
}

func (t *reqTrace) clientTrace() *httptrace.ClientTrace {
	at := func(f func(now time.Time)) {
		now := time.Now()
		t.mu.Lock()
		f(now)
		t.mu.Unlock()
	}
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { at(func(n time.Time) { t.dnsStart = n }) },
		DNSDone:  func(httptrace.DNSDoneInfo) { at(func(n time.Time) { t.dnsDone = n }) },
		ConnectStart: func(_, _ string) {
			at(func(n time.Time) {
				if t.connStart.IsZero() {
					t.connStart = n
				}
			})
		},
		ConnectDone:       func(_, _ string, _ error) { at(func(n time.Time) { t.connDone = n }) },
		TLSHandshakeStart: func() { at(func(n time.Time) { t.tlsStart = n }) },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { at(func(n time.Time) { t.tlsDone = n }) },
		GotConn: func(gi httptrace.GotConnInfo) {
			at(func(n time.Time) { t.gotConn, t.reused = n, gi.Reused })
		},
		WroteRequest:         func(httptrace.WroteRequestInfo) { at(func(n time.Time) { t.wroteReq = n }) },
		GotFirstResponseByte: func() { at(func(n time.Time) { t.firstByte = n }) },
	}
}

// timing computes the phase breakdown given when the body finished reading.
func (t *reqTrace) timing(done time.Time) Timing {
	t.mu.Lock()
	defer t.mu.Unlock()
	tm := Timing{Reused: t.reused, Total: done.Sub(t.start)}
	// A pooled connection paid no setup. Dial/TLS events on its trace belong
	// to an abandoned background dial, so they are ignored rather than
	// reported as this request's setup time.
	if !t.reused {
		if tm.DidDNS = !t.dnsStart.IsZero() && !t.dnsDone.IsZero(); tm.DidDNS {
			tm.DNS = t.dnsDone.Sub(t.dnsStart)
		}
		if tm.DidConnect = !t.connStart.IsZero() && !t.connDone.IsZero(); tm.DidConnect {
			tm.TCP = t.connDone.Sub(t.connStart)
		}
		if tm.DidTLS = !t.tlsStart.IsZero() && !t.tlsDone.IsZero(); tm.DidTLS {
			tm.TLS = t.tlsDone.Sub(t.tlsStart)
		}
	}
	// Whenever the connection became usable (post-handshake / from the pool).
	afterConn := t.gotConn
	setupDone := []time.Time{t.connDone, t.tlsDone}
	if t.reused {
		setupDone = nil
	}
	for _, ts := range setupDone {
		if ts.After(afterConn) {
			afterConn = ts
		}
	}
	// Send = connection ready -> request fully written.
	if !t.wroteReq.IsZero() && !afterConn.IsZero() {
		tm.Send = t.wroteReq.Sub(afterConn)
	}
	// Server wait = request written (or connection ready) -> first response byte.
	waitFrom := t.wroteReq
	if waitFrom.IsZero() {
		waitFrom = afterConn
	}
	if !t.firstByte.IsZero() && !waitFrom.IsZero() {
		tm.Server = t.firstByte.Sub(waitFrom)
	}
	if !t.firstByte.IsZero() {
		tm.Transfer = done.Sub(t.firstByte)
	}
	return tm
}

// tlsSummary builds a connTLS from an http.Response's TLS state (nil for plain HTTP).
func tlsSummary(state *tls.ConnectionState) *connTLS {
	if state == nil {
		return nil
	}
	c := &connTLS{
		Version: tls.VersionName(state.Version),
		Cipher:  tls.CipherSuiteName(state.CipherSuite),
		ALPN:    state.NegotiatedProtocol,
	}
	if len(state.PeerCertificates) > 0 {
		info := describeCert(state.PeerCertificates[0])
		c.Leaf = &info
	}
	return c
}
