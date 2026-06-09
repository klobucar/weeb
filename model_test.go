package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	log "charm.land/log/v2"
)

func testModel() model {
	logger := log.New(io.Discard)
	client := newClient(logger, newErrorChan())
	return newModel(client, logger, &safeBuffer{})
}

// kp builds a v2 tea.KeyPressMsg from a key spec like "tab", "shift+tab",
// "ctrl+o", "enter", or a single rune ("-"). It mirrors what the terminal
// decoder produces so key.Matches (which compares String()) behaves as in a
// real session.
func kp(s string) tea.KeyPressMsg {
	switch s {
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	case "shift+tab":
		return tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "left":
		return tea.KeyPressMsg{Code: tea.KeyLeft}
	case "right":
		return tea.KeyPressMsg{Code: tea.KeyRight}
	case "up":
		return tea.KeyPressMsg{Code: tea.KeyUp}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	}
	if strings.HasPrefix(s, "ctrl+") && len(s) == len("ctrl+")+1 {
		return tea.KeyPressMsg{Code: rune(s[len("ctrl+")]), Mod: tea.ModCtrl}
	}
	r := []rune(s)[0]
	return tea.KeyPressMsg{Code: r, Text: s}
}

func send(t *testing.T, m tea.Model, msgs ...tea.Msg) tea.Model {
	t.Helper()
	for _, msg := range msgs {
		m, _ = m.Update(msg)
	}
	return m
}

// TestModelLifecycle drives the model through resize, focus cycling, header
// add/remove, method changes, a result, and the debug toggle, calling View at
// each step to catch panics in layout/render.
func TestModelLifecycle(t *testing.T) {
	var m tea.Model = testModel()

	m = send(t, m, tea.WindowSizeMsg{Width: 80, Height: 30})
	_ = m.View()

	// Cycle focus all the way around twice.
	for i := 0; i < 24; i++ {
		m = send(t, m, kp("tab"))
		_ = m.View()
	}
	m = send(t, m, kp("shift+tab"))
	_ = m.View()

	// Add several headers, then remove one while focused on it.
	m = send(t, m, kp("ctrl+o"), kp("ctrl+o"), kp("ctrl+o"))
	m = send(t, m, kp("ctrl+r"))
	_ = m.View()

	// Change the method (should disable the body field for GET-like methods).
	m = send(t, m, kp("tab")) // ensure we can move
	mm := m.(model)
	mm.focusIdx = 0 // method
	var tm tea.Model = mm
	tm = send(t, tm, kp("right"), kp("right"))
	_ = tm.View()

	// Toggle the debug pane.
	tm = send(t, tm, kp("ctrl+g"))
	_ = tm.View()
	tm = send(t, tm, kp("ctrl+g"))
	_ = tm.View()

	// Deliver a result and render it.
	tm = send(t, tm, resultMsg(Result{
		Status:      200,
		StatusText:  "OK",
		Proto:       "HTTP/2.0",
		Headers:     http.Header{"Content-Type": []string{"application/json"}},
		Body:        []byte(`{"ok":true}`),
		ContentType: "application/json",
	}))
	out := tm.View().Content
	if !strings.Contains(out, "200") {
		t.Fatalf("expected status 200 in view, got:\n%s", out)
	}
}

// A custom -X method must survive into the TUI: prefill used to leave
// methodIdx at 0 when the method wasn't in the fixed list, so `weeb -X PURGE
// url` at a TTY silently sent GET.
func TestPrefillCustomMethod(t *testing.T) {
	m := testModel()
	m.prefill(cliArgs{method: "purge", url: "http://x"})
	if got := m.currentMethod(); got != "PURGE" {
		t.Errorf("currentMethod = %q, want PURGE", got)
	}

	// Known methods still select the existing entry instead of duplicating it.
	m = testModel()
	m.prefill(cliArgs{method: "post", url: "http://x"})
	if got := m.currentMethod(); got != "POST" {
		t.Errorf("currentMethod = %q, want POST", got)
	}
	if len(m.methods) != 7 {
		t.Errorf("methods grew to %v, want the original 7", m.methods)
	}
}

func TestResolveSpecPrefills(t *testing.T) {
	t.Setenv("WEEB_BASE_URL", "https://api.example.com")
	t.Setenv("WEEB_HEADERS", "X-A:1;X-B:2")
	t.Setenv("WEEB_TOKEN", "tok")

	got := resolveSpec(RequestSpec{
		Method:  "GET",
		URL:     "/me",
		Headers: []Header{{Key: "X-A", Value: "override"}},
	})

	if got.URL != "https://api.example.com/me" {
		t.Errorf("base URL not resolved: %q", got.URL)
	}
	// X-A is user-set, so the env default must NOT override it.
	var xa, auth string
	for _, h := range got.Headers {
		switch strings.ToLower(h.Key) {
		case "x-a":
			xa = h.Value
		case "authorization":
			auth = h.Value
		}
	}
	if xa != "override" {
		t.Errorf("user header overridden by env: %q", xa)
	}
	if auth != "Bearer tok" {
		t.Errorf("token not applied: %q", auth)
	}
}

func TestPrefill(t *testing.T) {
	m := testModel()
	m.prefill(cliArgs{
		method:  "POST",
		url:     "https://api.example.com/u",
		headers: []Header{{Key: "X-A", Value: "1"}},
		body:    []byte(`{"a":1}`),
	})

	if m.url.Value() != "https://api.example.com/u" {
		t.Errorf("url = %q", m.url.Value())
	}
	if m.currentMethod() != "POST" {
		t.Errorf("method = %q, want POST", m.currentMethod())
	}
	if m.body.Value() != `{"a":1}` {
		t.Errorf("body = %q", m.body.Value())
	}
	found := false
	for _, h := range m.headers {
		if h.key.Value() == "X-A" && h.val.Value() == "1" {
			found = true
		}
	}
	if !found {
		t.Errorf("prefilled header missing: %+v", m.headers)
	}
}

func TestArrowFieldNav(t *testing.T) {
	var m tea.Model = testModel()
	m = send(t, m, tea.WindowSizeMsg{Width: 80, Height: 30})
	mm := m.(model)
	mm.focusIdx = 0 // method
	mm.applyFocus()

	// down: method -> URL
	var tm tea.Model = mm
	tm = send(t, tm, kp("down"))
	fm := tm.(model)
	if got := fm.currentFocus().kind; got != focURL {
		t.Fatalf("down from method should focus URL, got %v", got)
	}
	// up: URL -> method
	tm = send(t, tm, kp("up"))
	fm = tm.(model)
	if got := fm.currentFocus().kind; got != focMethod {
		t.Fatalf("up should return to method, got %v", got)
	}

	// In the response pane, ↑/↓ scroll (they must not change focus).
	fm.focusIdx = len(fm.focusList()) - 1 // response
	fm.applyFocus()
	tm = send(t, tea.Model(fm), kp("up"), kp("down"))
	fm = tm.(model)
	if got := fm.currentFocus().kind; got != focResponse {
		t.Fatalf("↑/↓ in the response pane must not change focus, got %v", got)
	}
}

func TestMethodAllowsBody(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "PATCH"} {
		if !methodAllowsBody(m) {
			t.Errorf("%s should allow a body", m)
		}
	}
	for _, m := range []string{"GET", "HEAD", "DELETE", "OPTIONS"} {
		if methodAllowsBody(m) {
			t.Errorf("%s should not allow a body", m)
		}
	}
}

func TestCertMsgRendering(t *testing.T) {
	var m tea.Model = testModel()
	m = send(t, m, tea.WindowSizeMsg{Width: 90, Height: 70})

	// Success: a fake report (leaf + intermediate) should render into the pane.
	rep := &certReport{
		Host: "example.com", Port: "443",
		TLSVersion: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", Verified: true,
		Chain: []certInfo{
			{
				SubjectCN: "example.com", Issuer: "CN=R3", IssuerCN: "R3",
				NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<33, 0),
				DaysUntilExpiry: 90, DNSNames: []string{"example.com"},
				Serial: "AB:CD", KeyType: "RSA 2048", SigAlg: "SHA256-RSA",
			},
			{
				SubjectCN: "R3", Issuer: "CN=Root", IssuerCN: "Root",
				NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<33, 0),
				DaysUntilExpiry: 900, Serial: "EF", KeyType: "RSA 4096", SigAlg: "SHA256-RSA",
			},
		},
	}
	m = send(t, m, certMsg{rep: rep})
	out := m.View().Content
	if !strings.Contains(out, "TLS  example.com:443") {
		t.Fatalf("cert pane heading missing:\n%s", out)
	}
	if !strings.Contains(out, "Leaf") || !strings.Contains(out, "Intermediate") {
		t.Fatalf("chain section headings missing:\n%s", out)
	}
	// The leaf detail shows on load; the CA cert above it starts folded.
	if !strings.Contains(out, "RSA 2048") {
		t.Fatalf("leaf detail should show on load:\n%s", out)
	}
	if strings.Contains(out, "RSA 4096") {
		t.Fatalf("intermediate detail should start folded:\n%s", out)
	}

	// Focus the response pane and unfold all — the intermediate detail appears.
	mm := focusResponse(m.(model))
	var tm tea.Model = mm
	tm = send(t, tm, kp("+"))
	final := tm.(model)
	if out := final.composeResponse(); !strings.Contains(out, "RSA 4096") {
		t.Fatalf("intermediate detail missing after unfold:\n%s", out)
	}

	// Failure: a dial error should route through the persona voice into the pane.
	m = send(t, m, certMsg{err: errTest})
	if out := m.View().Content; !strings.Contains(out, "TLS") {
		t.Fatalf("cert error heading missing:\n%s", out)
	}
}

var errTest = fmt.Errorf("dial tcp: connection refused")

// focusResponse moves focus to the response pane so fold keys are live.
func focusResponse(m model) model {
	m.focusIdx = len(m.focusList()) - 1
	m.applyFocus()
	return m
}

func sampleResult() Result {
	return Result{
		Status:      200,
		StatusText:  "OK",
		Proto:       "HTTP/2.0",
		Headers:     http.Header{"Content-Type": []string{"application/json"}, "Server": []string{"nginx"}},
		Body:        []byte(`{"ok":true,"items":[1,2,3]}`),
		ContentType: "application/json",
		Timing:      Timing{Total: 120 * time.Millisecond},
	}
}

func bodyTree(m model) *bnode {
	for i := range m.respSections {
		if m.respSections[i].title == "Body" {
			return m.respSections[i].tree
		}
	}
	return nil
}

func nodeByKey(root *bnode, key string) *bnode {
	for _, c := range root.children {
		if c.key == key {
			return c
		}
	}
	return nil
}

func TestStructuralFolding(t *testing.T) {
	var m tea.Model = testModel()
	m = send(t, m, tea.WindowSizeMsg{Width: 90, Height: 40})
	r := sampleResult()
	r.Body = []byte(`{"a":1,"nested":{"x":1,"y":2},"list":[1,2]}`)
	m = send(t, m, resultMsg(r))
	mm := focusResponse(m.(model))

	tr := bodyTree(mm)
	if tr == nil {
		t.Fatal("expected a JSON body tree")
	}

	// Cursor targets: 3 section headings, then the two foldable JSON nodes.
	ts := mm.foldTargets()
	if len(ts) != 5 {
		t.Fatalf("got %d fold targets, want 5", len(ts))
	}
	n3, ok := ts[3].node.(*bnode)
	if !ok || n3.key != "nested" {
		t.Fatalf("target 3 should be the \"nested\" node, got %+v", ts[3].node)
	}

	// Navigate Connection->Headers->Body->nested and fold it.
	var tm tea.Model = mm
	tm = send(t, tm, kp("right"), kp("right"), kp("right"), kp("enter"))
	mm = tm.(model)

	if n := nodeByKey(bodyTree(mm), "nested"); n == nil || !n.folded {
		t.Fatal("\"nested\" should be folded after enter")
	}
	out := mm.composeResponse()
	if !strings.Contains(out, "2 keys") {
		t.Fatalf("folded summary \"2 keys\" missing:\n%s", out)
	}
	if strings.Contains(out, `"x"`) {
		t.Fatalf("folded node's children should be hidden:\n%s", out)
	}
	// The sibling array is untouched and still expanded.
	if n := nodeByKey(bodyTree(mm), "list"); n == nil || n.folded {
		t.Fatal("\"list\" should remain expanded")
	}

	// Unfold all brings the children back.
	tm = send(t, tm, kp("+"))
	mm = tm.(model)
	if strings.Contains(mm.composeResponse(), "2 keys") {
		t.Fatal("unfold-all should expand the nested node")
	}
	if nodeByKey(bodyTree(mm), "nested").folded {
		t.Fatal("nested should be expanded after unfold-all")
	}
}

func bodyXTree(m model) *xnode {
	for i := range m.respSections {
		if m.respSections[i].title == "Body" {
			return m.respSections[i].xtree
		}
	}
	return nil
}

func TestXMLFolding(t *testing.T) {
	var m tea.Model = testModel()
	m = send(t, m, tea.WindowSizeMsg{Width: 90, Height: 40})
	r := sampleResult()
	r.ContentType = "application/xml"
	r.Headers = http.Header{"Content-Type": []string{"application/xml"}}
	r.Body = []byte(`<?xml version="1.0"?><slideshow title="Demo"><slide type="all"><title>Wake up</title></slide><slide><title>Overview</title></slide></slideshow>`)
	m = send(t, m, resultMsg(r))
	mm := focusResponse(m.(model))

	xt := bodyXTree(mm)
	if xt == nil {
		t.Fatal("expected an XML body tree")
	}
	// JSON parse must not have claimed it.
	if bodyTree(mm) != nil {
		t.Fatal("XML body should not produce a JSON tree")
	}

	// Targets: Connection, Headers, Body, slideshow, slide, slide.
	ts := mm.foldTargets()
	if len(ts) != 6 {
		t.Fatalf("got %d fold targets, want 6", len(ts))
	}
	slideshow, ok := ts[3].node.(*xnode)
	if !ok || slideshow.name != "slideshow" {
		t.Fatalf("target 3 should be <slideshow>, got %+v", ts[3].node)
	}

	// Fold <slideshow> (cursor at index 3).
	var tm tea.Model = mm
	tm = send(t, tm, kp("right"), kp("right"), kp("right"), kp("enter"))
	mm = tm.(model)

	if !bodyXTree(mm).children[1].folded {
		t.Fatal("<slideshow> should be folded after enter")
	}
	out := mm.composeResponse()
	if !strings.Contains(out, "2 children") {
		t.Fatalf("folded summary \"2 children\" missing:\n%s", out)
	}
	if strings.Contains(out, "Overview") {
		t.Fatalf("folded element's descendants should be hidden:\n%s", out)
	}

	// Unfold all brings them back.
	tm = send(t, tm, kp("+"))
	mm = tm.(model)
	if !strings.Contains(mm.composeResponse(), "Overview") {
		t.Fatal("unfold-all should reveal the slide contents")
	}
}

func bodyYTree(m model) *ynode {
	for i := range m.respSections {
		if m.respSections[i].title == "Body" {
			return m.respSections[i].ytree
		}
	}
	return nil
}

func TestYAMLFolding(t *testing.T) {
	var m tea.Model = testModel()
	m = send(t, m, tea.WindowSizeMsg{Width: 90, Height: 40})
	r := sampleResult()
	r.ContentType = "application/yaml"
	r.Headers = http.Header{"Content-Type": []string{"application/yaml"}}
	r.Body = []byte("name: weeb\ntags:\n  - a\n  - b\nmeta:\n  version: 1\n  nested:\n    deep: true\n")
	m = send(t, m, resultMsg(r))
	mm := focusResponse(m.(model))

	if bodyYTree(mm) == nil {
		t.Fatal("expected a YAML body tree")
	}
	if bodyTree(mm) != nil {
		t.Fatal("YAML must not be parsed as a JSON tree")
	}

	// Targets: Connection, Headers, Body, then tags / meta / nested.
	ts := mm.foldTargets()
	if len(ts) != 6 {
		t.Fatalf("got %d fold targets, want 6", len(ts))
	}
	n3, ok := ts[3].node.(*ynode)
	if !ok || n3.key != "tags" {
		t.Fatalf("target 3 should be the \"tags\" node, got %+v", ts[3].node)
	}

	// Navigate to "meta" (index 4) and fold it.
	var tm tea.Model = mm
	tm = send(t, tm, kp("right"), kp("right"), kp("right"), kp("right"), kp("enter"))
	mm = tm.(model)

	out := mm.composeResponse()
	if !strings.Contains(out, "2 keys") {
		t.Fatalf("folded \"meta\" summary missing:\n%s", out)
	}
	if strings.Contains(out, "deep") {
		t.Fatalf("folding meta should hide its nested contents:\n%s", out)
	}
}

func TestHTMLFolding(t *testing.T) {
	var m tea.Model = testModel()
	m = send(t, m, tea.WindowSizeMsg{Width: 90, Height: 40})
	r := sampleResult()
	r.ContentType = "text/html"
	r.Headers = http.Header{"Content-Type": []string{"text/html"}}
	// Real-world HTML the lenient XML tokenizer chokes on: doctype, a <script>
	// with a bare '<', and an unquoted attribute.
	r.Body = []byte(`<!DOCTYPE html><html><head><title>weeb</title>` +
		`<script>if (a < b) { go() }</script></head>` +
		`<body class=main><h1>Hi</h1><p>ok</p></body></html>`)
	m = send(t, m, resultMsg(r))
	mm := focusResponse(m.(model))

	if bodyXTree(mm) == nil {
		t.Fatal("real-world HTML should parse into a fold tree (via x/net/html)")
	}

	// Targets: Connection, Headers, Body, then <html>, <head>, <body>.
	ts := mm.foldTargets()
	if len(ts) != 6 {
		t.Fatalf("got %d fold targets, want 6: %+v", len(ts), ts)
	}
	n3, ok := ts[3].node.(*xnode)
	if !ok || n3.name != "html" {
		t.Fatalf("target 3 should be <html>, got %+v", ts[3].node)
	}

	// Fold <html> and confirm its descendants vanish.
	var tm tea.Model = mm
	tm = send(t, tm, kp("right"), kp("right"), kp("right"), kp("enter"))
	mm = tm.(model)
	if out := mm.composeResponse(); strings.Contains(out, "Hi") {
		t.Fatalf("folding <html> should hide its contents:\n%s", out)
	}
}

func TestSectionFolding(t *testing.T) {
	var m tea.Model = testModel()
	m = send(t, m, tea.WindowSizeMsg{Width: 90, Height: 40})
	m = send(t, m, resultMsg(sampleResult()))

	mm := focusResponse(m.(model))

	want := []string{"Connection", "Headers", "Body"}
	if len(mm.respSections) != len(want) {
		t.Fatalf("got %d sections, want %d", len(mm.respSections), len(want))
	}
	for i, w := range want {
		if mm.respSections[i].title != w {
			t.Fatalf("section %d = %q, want %q", i, mm.respSections[i].title, w)
		}
	}

	// Fold the section under the cursor (Connection).
	var tm tea.Model = mm
	tm = send(t, tm, kp("enter"))
	mm = tm.(model)
	if !mm.respSections[0].folded {
		t.Fatalf("Connection should be folded after enter")
	}
	if !mm.foldState["Connection"] {
		t.Fatalf("fold state not recorded for Connection")
	}
	if !strings.Contains(mm.composeResponse(), "▸ Connection") {
		t.Fatalf("folded marker missing:\n%s", mm.composeResponse())
	}

	// Move cursor right and fold Headers too.
	tm = send(t, tm, kp("right"), kp("enter"))
	mm = tm.(model)
	if !mm.respSections[1].folded {
		t.Fatalf("Headers should be folded")
	}

	// Fold all, then unfold all.
	tm = send(t, tm, kp("-"))
	mm = tm.(model)
	for _, s := range mm.respSections {
		if !s.folded {
			t.Fatalf("section %q not folded after fold-all", s.title)
		}
	}
	tm = send(t, tm, kp("+"))
	mm = tm.(model)
	for _, s := range mm.respSections {
		if s.folded {
			t.Fatalf("section %q still folded after unfold-all", s.title)
		}
	}

	// Fold state is sticky: fold all, then deliver a fresh result; sections
	// should come back folded.
	tm = send(t, tm, kp("-"))
	tm = send(t, tm, resultMsg(sampleResult()))
	mm = tm.(model)
	for _, s := range mm.respSections {
		if !s.folded {
			t.Fatalf("section %q lost sticky fold across re-render", s.title)
		}
	}
}
