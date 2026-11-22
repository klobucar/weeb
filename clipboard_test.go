package main

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
)

// clipboardWrite runs cmd, expanding batches, and returns the text of the
// first OSC 52 write it produces. Commands run concurrently and the wait is
// bounded: a batch can also hold the status-clear or cursor-blink timers,
// which would otherwise hold a test for seconds, while a clipboard write
// returns at once. A negative result therefore costs the full wait.
func clipboardWrite(cmd tea.Cmd, wait time.Duration) (string, bool) {
	if cmd == nil {
		return "", false
	}
	clip := reflect.TypeOf(tea.SetClipboard("x")())
	results := make(chan tea.Msg, 16)
	run := func(c tea.Cmd) { go func() { results <- c() }() }
	run(cmd)
	timeout := time.After(wait)
	for {
		select {
		case msg := <-results:
			if b, ok := msg.(tea.BatchMsg); ok {
				for _, c := range b {
					if c != nil {
						run(c)
					}
				}
				continue
			}
			if reflect.TypeOf(msg) == clip {
				return reflect.ValueOf(msg).String(), true
			}
		case <-timeout:
			return "", false
		}
	}
}

const (
	expectCopy   = 5 * time.Second        // generous: a write returns at once
	expectNoCopy = 150 * time.Millisecond // a write would have arrived by now
)

// nodeAt follows child positions from root, the way indexPath reports them.
func nodeAt(t *testing.T, root foldNode, idx []int) foldNode {
	t.Helper()
	n := root
	for _, i := range idx {
		kids := n.kids()
		if i >= len(kids) {
			t.Fatalf("index path %v runs off the tree", idx)
		}
		n = kids[i]
	}
	return n
}

func TestJQPath(t *testing.T) {
	k := func(s string) pathSeg { return pathSeg{key: s} }
	i := func(n int) pathSeg { return pathSeg{index: n, isIdx: true} }
	tests := []struct {
		name string
		segs []pathSeg
		want string
	}{
		{"root", nil, "."},
		{"key", []pathSeg{k("items")}, ".items"},
		{"nested", []pathSeg{k("items"), i(3), k("id")}, ".items[3].id"},
		{"root index", []pathSeg{i(0)}, ".[0]"},
		{"index chain", []pathSeg{i(0), i(1), k("id")}, ".[0][1].id"},
		{"weird key at root", []pathSeg{k("weird key")}, `.["weird key"]`},
		{"weird key nested", []pathSeg{k("a"), k("b.c"), i(2)}, `.a["b.c"][2]`},
		{"empty key", []pathSeg{k("")}, `.[""]`},
		{"leading digit", []pathSeg{k("1st")}, `.["1st"]`},
		{"identifier chars", []pathSeg{k("_id"), k("x9"), k("A_b")}, "._id.x9.A_b"},
		{"jq keywords quoted", []pathSeg{k("if"), k("end")}, `.["if"]["end"]`},
		{"quote, backslash, no interpolation", []pathSeg{k(`a"b\(c)`)}, `.["a\"b\\(c)"]`},
		{"C0 escaped", []pathSeg{k("a\x1b[31mb\n")}, `.["a\u001b[31mb\n"]`},
		{"DEL and C1 escaped", []pathSeg{k("a\x7fb\u009bc")}, `.["a\u007fb\u009bc"]`},
		{"non-ASCII quoted, not escaped", []pathSeg{k("naïve")}, `.["naïve"]`},
		{"no HTML escaping", []pathSeg{k("<a&b>")}, `.["<a&b>"]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := jqPath(tt.segs); got != tt.want {
				t.Errorf("jqPath = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestJSONNodePathAndValue(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		idx       []int
		wantPath  string
		wantValue string
	}{
		{"root", `{"a": [1, 2]}`, nil, ".", `{"a":[1,2]}`},
		{"array member", `{"items": [{"id": 1}, {"id": 2}]}`, []int{0}, ".items", `[{"id":1},{"id":2}]`},
		{"array element", `{"items": [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4, "tags": ["a"]}]}`,
			[]int{0, 3}, ".items[3]", `{"id":4,"tags":["a"]}`},
		{"nested leaf", `{"items": [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}]}`, []int{0, 3, 0}, ".items[3].id", "4"},
		{"weird key", `{"ok": 1, "weird key": {"x": [1, 2.50, null]}}`, []int{1}, `.["weird key"]`, `{"x":[1,2.50,null]}`},
		{"root array", `[[1], [2, [3, "s"]]]`, []int{1, 1}, ".[1][1]", `[3,"s"]`},
		{"duplicate keys and order kept", `{"b": {"z": 1, "a": 2, "z": 3}}`, []int{0}, ".b", `{"z":1,"a":2,"z":3}`},
		{"escapes kept, no HTML escaping", `{"h": {"s": "<b>&\u001b\"\n"}}`, []int{0}, ".h", `{"s":"<b>&\u001b\"\n"}`},
		{"keyword key", `{"if": {"then": true}}`, []int{0}, `.["if"]`, `{"then":true}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := parseJSONTree([]byte(tt.body), "application/json", "", true)
			if root == nil {
				t.Fatal("body did not parse")
			}
			target := nodeAt(t, root, tt.idx)
			if got, ok := nodePath(root, target, nil); !ok || got != tt.wantPath {
				t.Errorf("path = %q (ok=%v), want %q", got, ok, tt.wantPath)
			}
			if got, ok := nodeValue(root, target, nil, false); !ok || got != tt.wantValue {
				t.Errorf("value = %s (ok=%v), want %s", got, ok, tt.wantValue)
			}
		})
	}
}

func TestYAMLNodePathAndValue(t *testing.T) {
	body := `# top
items:
  - id: 1
  - id: 2
    tags: [a, b]
"weird key":
  x: 1 # note
"":
  empty: yes
quoted:
  'it''s': {k: v}
anchors:
  base: &b
    k: v
  ref: *b
text:
  block: |
    line1
    line2
`
	tests := []struct {
		name      string
		idx       []int
		wantPath  string
		wantValue string
	}{
		{"sequence", []int{0}, ".items", "- id: 1\n- id: 2\n  tags: [a, b]"},
		{"sequence item", []int{0, 1}, ".items[1]", "id: 2\ntags: [a, b]"},
		{"flow sequence", []int{0, 1, 1}, ".items[1].tags", "[a, b]"},
		{"quoted key, comment kept", []int{1}, `.["weird key"]`, "x: 1 # note"},
		{"empty key", []int{2}, `.[""]`, "empty: yes"},
		{"raw key, not display form", []int{3, 0}, `.quoted["it's"]`, "{k: v}"},
		{"anchor and alias kept", []int{4}, ".anchors", "base: &b\n  k: v\nref: *b"},
		{"block scalar style kept", []int{5}, ".text", "block: |\n  line1\n  line2"},
	}
	root := parseYAMLTree([]byte(body), "application/yaml", "", true)
	if root == nil {
		t.Fatal("body did not parse")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := nodeAt(t, root, tt.idx)
			if got, ok := nodePath(root, target, []byte(body)); !ok || got != tt.wantPath {
				t.Errorf("path = %q (ok=%v), want %q", got, ok, tt.wantPath)
			}
			if got, ok := nodeValue(root, target, []byte(body), false); !ok || got != tt.wantValue {
				t.Errorf("value = %q (ok=%v), want %q", got, ok, tt.wantValue)
			}
		})
	}
}

func TestXMLNodePathAndValue(t *testing.T) {
	const doc = `<?xml version="1.0"?>
<root xmlns:x="urn:x">
  <item n="1"/>
  <item n="2"><name>a</name></item>
  <item n="3">
    <name>b &amp; c</name>
    <x:note>m</x:note>
  </item>
  <!-- c -->
</root>`
	const page = `<!DOCTYPE html><html><head><title>t</title></head>` +
		`<body class=main><div>1</div><div id=two><p>Hi &amp; bye</p></div></body></html>`
	tests := []struct {
		name      string
		body      string
		html      bool
		idx       []int
		wantPath  string
		wantValue string // "" when the node has no copyable value
	}{
		{"document element", doc, false, []int{1}, "/root", doc[strings.Index(doc, "<root"):]},
		{"positioned sibling", doc, false, []int{1, 2}, "/root/item[3]",
			"<item n=\"3\">\n    <name>b &amp; c</name>\n    <x:note>m</x:note>\n  </item>"},
		{"self-closing", doc, false, []int{1, 0}, "/root/item[1]", `<item n="1"/>`},
		{"unique name has no position", doc, false, []int{1, 2, 0}, "/root/item[3]/name", "<name>b &amp; c</name>"},
		{"local name, source keeps prefix", doc, false, []int{1, 2, 1}, "/root/item[3]/note", "<x:note>m</x:note>"},
		{"comment", doc, false, []int{1, 3}, "/root/comment()", ""},
		{"text", doc, false, []int{1, 1, 0, 0}, "/root/item[2]/name/text()", ""},
		{"after an auto-closed void element", `<root><br><div><p>x</p></div></root>`, false,
			[]int{0, 1}, "/root/div", "<div><p>x</p></div>"},
		{"html element", page, true, []int{1, 1, 1}, "/html/body/div[2]", `<div id="two"><p>Hi &amp; bye</p></div>`},
		{"html body", page, true, []int{1, 1}, "/html/body",
			`<body class="main"><div>1</div><div id="two"><p>Hi &amp; bye</p></div></body>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var root *xnode
			if tt.html {
				root = parseHTMLTree([]byte(tt.body), "text/html", "", true)
			} else {
				root = parseXMLTree([]byte(tt.body), "application/xml", "", true)
			}
			if root == nil {
				t.Fatal("body did not parse")
			}
			target := nodeAt(t, root, tt.idx)
			if got, ok := nodePath(root, target, []byte(tt.body)); !ok || got != tt.wantPath {
				t.Errorf("path = %q (ok=%v), want %q", got, ok, tt.wantPath)
			}
			got, ok := nodeValue(root, target, []byte(tt.body), tt.html)
			if ok != (tt.wantValue != "") || got != tt.wantValue {
				t.Errorf("value = %q (ok=%v), want %q", got, ok, tt.wantValue)
			}
		})
	}
}

func TestClipboardText(t *testing.T) {
	long := "a" + strings.Repeat("é", maxClipboardText) // the cap falls mid-rune
	tests := []struct {
		name      string
		in        string
		want      string
		wantLen   int // checked instead of want when non-zero
		truncated bool
	}{
		{name: "plain", in: "abc", want: "abc"},
		{name: "empty", in: "", want: ""},
		{name: "SGR styling", in: "\x1b[1;31mred\x1b[0m text", want: "red text"},
		{name: "OSC 52 injection", in: "a\x1b]52;c;ZXZpbA==\x07b", want: "ab"},
		{name: "C0, DEL, C1 dropped", in: "a\rb\x00c\x7fd\u009be\x07f", want: "abcdef"},
		{name: "newline and tab kept", in: "a\n\tb", want: "a\n\tb"},
		{name: "invalid UTF-8 never survives", in: "a\xffb\xc3(c", want: "ab\ufffd(c"},
		{name: "capped on a rune boundary", in: long, wantLen: maxClipboardText - 1, truncated: true},
		{name: "huge input", in: strings.Repeat("x", 1<<20), wantLen: maxClipboardText, truncated: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, truncated := clipboardText(tt.in)
			if truncated != tt.truncated {
				t.Errorf("truncated = %v, want %v", truncated, tt.truncated)
			}
			if !utf8.ValidString(got) {
				t.Errorf("result is not valid UTF-8")
			}
			if tt.wantLen != 0 {
				if len(got) != tt.wantLen {
					t.Errorf("len = %d, want %d", len(got), tt.wantLen)
				}
				return
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// copyModel is a sized model holding r, focused on the response pane with the
// fold cursor at target index cursor.
func copyModel(t *testing.T, r Result, cursor int) model {
	t.Helper()
	var m tea.Model = testModel()
	m = send(t, m, tea.WindowSizeMsg{Width: 100, Height: 40}, resultMsg(r))
	mm := focusResponse(m.(model))
	if n := len(mm.foldTargets()); cursor >= n {
		t.Fatalf("cursor %d out of %d fold targets", cursor, n)
	}
	mm.respCursor = cursor
	return mm
}

func press(m model, k tea.KeyPressMsg) (model, tea.Cmd) {
	tm, cmd := m.Update(k)
	return tm.(model), cmd
}

// The copy keys are plain letters, so in a text field they must type, not copy.
func TestCopyKeysTypeInTextFields(t *testing.T) {
	m := copyModel(t, sampleResult(), 3)
	for _, f := range []struct {
		name  string
		focus int
	}{{"method", 0}, {"url", 1}, {"header key", 2}} {
		t.Run(f.name, func(t *testing.T) {
			mm := m
			mm.focusIdx = f.focus
			mm.applyFocus()
			for _, k := range []tea.KeyPressMsg{kp("y"), kp("Y")} {
				var cmd tea.Cmd
				mm, cmd = press(mm, k)
				if s, ok := clipboardWrite(cmd, expectNoCopy); ok {
					t.Errorf("%q copied %q outside the response pane", k.String(), s)
				}
			}
			if mm.status != "" {
				t.Errorf("status = %q, want none", mm.status)
			}
		})
	}
	mm := m
	mm.focusIdx = 1
	mm.applyFocus()
	mm, _ = press(mm, kp("y"))
	mm, _ = press(mm, kp("Y"))
	if got := mm.url.Value(); got != "yY" {
		t.Errorf("url = %q, want the typed \"yY\"", got)
	}
}

// In the response pane, y/Y copy whatever the fold cursor is on: sections and
// body nodes alike, or explain that there's nothing to copy.
func TestCopyKeysInResponsePane(t *testing.T) {
	r := sampleResult() // {"ok":true,"items":[1,2,3]}
	tests := []struct {
		name       string
		cursor     int
		key        tea.KeyPressMsg
		want       string // clipboard text; "" means no write
		wantStatus string
	}{
		{"section has no path", 0, kp("y"), "", "nothing to copy: Connection has no path"},
		{"headers value", 1, kp("Y"), "Content-Type: application/json\nServer: nginx", "copied Headers to clipboard"},
		{"body path is the root", 2, kp("y"), ".", "copied path . to clipboard"},
		{"body value is the raw body", 2, kp("Y"), string(r.Body), "copied body to clipboard"},
		{"node path", 3, kp("y"), ".items", "copied path .items to clipboard"},
		{"node value", 3, kp("Y"), "[1,2,3]", "copied value to clipboard"},
		{"shift+y without text", 3, tea.KeyPressMsg{Code: 'y', Mod: tea.ModShift}, "[1,2,3]", "copied value to clipboard"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, cmd := press(copyModel(t, r, tt.cursor), tt.key)
			wait := expectCopy
			if tt.want == "" {
				wait = expectNoCopy
			}
			got, ok := clipboardWrite(cmd, wait)
			if ok != (tt.want != "") || got != tt.want {
				t.Errorf("clipboard = %q (written=%v), want %q", got, ok, tt.want)
			}
			if m.status != tt.wantStatus {
				t.Errorf("status = %q, want %q", m.status, tt.wantStatus)
			}
			if !strings.Contains(m.View().Content, tt.wantStatus) {
				t.Errorf("status %q not shown in the view", tt.wantStatus)
			}
		})
	}
}

// Each body format routes to its own path and value builder through the model.
func TestCopyKeysByBodyFormat(t *testing.T) {
	tests := []struct {
		ct, body            string
		wantPath, wantValue string
	}{
		{"application/json", `{"a": {"b": 1}}`, ".a", `{"b":1}`},
		{"application/yaml", "a:\n  'b c': 1\n", ".a", "'b c': 1"},
		{"application/xml", `<r><i><n>x</n></i></r>`, "/r", `<r><i><n>x</n></i></r>`},
		{"text/html", `<html><body><p>x</p></body></html>`, "/html", `<html><head></head><body><p>x</p></body></html>`},
	}
	for _, tt := range tests {
		t.Run(tt.ct, func(t *testing.T) {
			r := sampleResult()
			r.ContentType = tt.ct
			r.Headers = http.Header{"Content-Type": []string{tt.ct}}
			r.Body = []byte(tt.body)
			for key, want := range map[string]string{"y": tt.wantPath, "Y": tt.wantValue} {
				_, cmd := press(copyModel(t, r, 3), kp(key))
				if got, ok := clipboardWrite(cmd, expectCopy); !ok || got != want {
					t.Errorf("%s copied %q (written=%v), want %q", key, got, ok, want)
				}
			}
		})
	}
}

func TestCopyNothingYet(t *testing.T) {
	var tm tea.Model = testModel()
	tm = send(t, tm, tea.WindowSizeMsg{Width: 100, Height: 40})
	m, cmd := press(focusResponse(tm.(model)), kp("Y"))
	if s, ok := clipboardWrite(cmd, expectNoCopy); ok {
		t.Errorf("copied %q with no response", s)
	}
	if m.status != "nothing to copy yet" {
		t.Errorf("status = %q", m.status)
	}
}

func TestCopyLargeValueIsTruncated(t *testing.T) {
	r := sampleResult()
	r.Body = []byte(`{"big": "` + strings.Repeat("x", 2*maxClipboardText) + `"}`)
	m, cmd := press(copyModel(t, r, 2), kp("Y"))
	got, ok := clipboardWrite(cmd, expectCopy)
	if !ok || len(got) != maxClipboardText {
		t.Errorf("copied %d bytes (written=%v), want the %d-byte cap", len(got), ok, maxClipboardText)
	}
	if !strings.Contains(m.status, "truncated to 73.2 KB of 146.5 KB") {
		t.Errorf("status = %q, want a truncation note", m.status)
	}
}

// ctrl+x shows the curl and copies it as plain text; toggling back doesn't.
func TestExportCurlCopies(t *testing.T) {
	var tm tea.Model = testModel()
	tm = send(t, tm, tea.WindowSizeMsg{Width: 100, Height: 40})
	m := tm.(model)
	m.url.SetValue("https://api.example.com/x?q=a b")
	m.headers[0].key.SetValue("Accept")
	m.headers[0].val.SetValue("application/json")

	m, cmd := press(m, kp("ctrl+x"))
	want := toCurl(resolveSpec(m.specFromForm()), true)
	got, ok := clipboardWrite(cmd, expectCopy)
	if !ok || got != want {
		t.Fatalf("clipboard = %q (written=%v), want %q", got, ok, want)
	}
	if strings.Contains(got, "\x1b") {
		t.Errorf("copied curl carries styling: %q", got)
	}
	if !strings.Contains(m.View().Content, "copied curl to clipboard") {
		t.Error("no status message after ctrl+x")
	}

	m, cmd = press(m, kp("ctrl+x"))
	if s, ok := clipboardWrite(cmd, expectNoCopy); ok {
		t.Errorf("toggling back copied %q", s)
	}
	if m.pane != paneResponse {
		t.Errorf("second ctrl+x should return to the response pane")
	}
}

// A status clears on its own timer, but an older timer must not wipe a newer
// message.
func TestStatusClears(t *testing.T) {
	m := testModel()
	_ = m.flash("first")
	stale := m.statusSeq
	_ = m.flash("second")

	tm, _ := m.Update(statusClearMsg{seq: stale})
	if got := tm.(model).status; got != "second" {
		t.Fatalf("stale timer cleared the newer status: %q", got)
	}
	tm, _ = tm.Update(statusClearMsg{seq: m.statusSeq})
	if got := tm.(model).status; got != "" {
		t.Fatalf("status = %q after its own timer, want cleared", got)
	}
}

// Status text can carry server names (keys, element names), and the form isn't
// sanitized by setResp, so flash strips it.
func TestFlashStripsServerText(t *testing.T) {
	m := testModel()
	_ = m.flash("copied path .[\"\x1b]52;c;ZXZpbA==\x07k\"]\n to clipboard")
	if strings.ContainsAny(m.status, "\x1b\x07\n") {
		t.Errorf("status kept control characters: %q", m.status)
	}
}

func TestSpecHasCredentials(t *testing.T) {
	for _, c := range []struct {
		hs   []Header
		want bool
	}{
		{nil, false},
		{[]Header{{Key: "Accept", Value: "application/json"}}, false},
		{[]Header{{Key: "Authorization", Value: "Bearer x"}}, true},
		{[]Header{{Key: "X-Api-Key", Value: "k"}}, true},
		{[]Header{{Key: "Cookie", Value: ""}}, false},
	} {
		if got := specHasCredentials(RequestSpec{Headers: c.hs}); got != c.want {
			t.Errorf("specHasCredentials(%v) = %v, want %v", c.hs, got, c.want)
		}
	}
}
