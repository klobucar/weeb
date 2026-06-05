package main

import (
	"crypto/tls"
	"net/http/httptrace"
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
}

// connTLS summarizes the negotiated TLS parameters of a request's connection.
type connTLS struct {
	Version string
	Cipher  string
	ALPN    string
	Leaf    *certInfo
}

// reqTrace records phase timestamps as a request progresses.
type reqTrace struct {
	start               time.Time
	dnsStart, dnsDone   time.Time
	connStart, connDone time.Time
	tlsStart, tlsDone   time.Time
	gotConn, wroteReq   time.Time
	firstByte           time.Time
	reused              bool
}

func (t *reqTrace) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { t.dnsStart = time.Now() },
		DNSDone:  func(httptrace.DNSDoneInfo) { t.dnsDone = time.Now() },
		ConnectStart: func(_, _ string) {
			if t.connStart.IsZero() {
				t.connStart = time.Now()
			}
		},
		ConnectDone:          func(_, _ string, _ error) { t.connDone = time.Now() },
		TLSHandshakeStart:    func() { t.tlsStart = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { t.tlsDone = time.Now() },
		GotConn:              func(gi httptrace.GotConnInfo) { t.gotConn = time.Now(); t.reused = gi.Reused },
		WroteRequest:         func(httptrace.WroteRequestInfo) { t.wroteReq = time.Now() },
		GotFirstResponseByte: func() { t.firstByte = time.Now() },
	}
}

// timing computes the phase breakdown given when the body finished reading.
func (t *reqTrace) timing(done time.Time) Timing {
	tm := Timing{Reused: t.reused, Total: done.Sub(t.start)}
	if !t.dnsStart.IsZero() && !t.dnsDone.IsZero() {
		tm.DNS = t.dnsDone.Sub(t.dnsStart)
	}
	if !t.connStart.IsZero() && !t.connDone.IsZero() {
		tm.TCP = t.connDone.Sub(t.connStart)
	}
	if !t.tlsStart.IsZero() && !t.tlsDone.IsZero() {
		tm.TLS = t.tlsDone.Sub(t.tlsStart)
	}
	// Whenever the connection became usable (post-handshake / from the pool).
	afterConn := t.gotConn
	for _, ts := range []time.Time{t.connDone, t.tlsDone} {
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
		Version: tlsVersionName(state.Version),
		Cipher:  tls.CipherSuiteName(state.CipherSuite),
		ALPN:    state.NegotiatedProtocol,
	}
	if len(state.PeerCertificates) > 0 {
		info := describeCert(state.PeerCertificates[0])
		c.Leaf = &info
	}
	return c
}
