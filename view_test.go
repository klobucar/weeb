package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestParseViewArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    viewArgs
		wantErr string
	}{
		{"no args reads stdin", nil, viewArgs{}, ""},
		{"file", []string{"data.json"}, viewArgs{file: "data.json"}, ""},
		{"dash is stdin", []string{"-"}, viewArgs{file: "-"}, ""},
		{"flags around the file", []string{"--raw", "x", "--type", "YAML", "--max-body", "1k"},
			viewArgs{file: "x", typ: "yaml", raw: true, maxBody: "1k"}, ""},
		{"type by extension spelling", []string{"--type", "yml"}, viewArgs{typ: "yaml"}, ""},
		{"type markdown alias", []string{"--type", "markdown"}, viewArgs{typ: "md"}, ""},
		{"help", []string{"--help"}, viewArgs{help: true}, ""},
		{"unknown type", []string{"--type", "toml"}, viewArgs{}, "bad --type"},
		{"type needs a value", []string{"--type"}, viewArgs{}, "needs a value"},
		{"unknown flag", []string{"--nope"}, viewArgs{}, "unknown flag"},
		{"two files", []string{"a.json", "b.json"}, viewArgs{}, "unexpected argument"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseViewArgs(tt.args)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestViewFormatDetection(t *testing.T) {
	tests := []struct {
		name, file, typ, body string
		want                  bodyFormat
	}{
		{"json extension", "data.json", "", `{"a":1}`, fmtJSON},
		{"extension case-insensitive", "CONF.YML", "", "a: 1", fmtYAML},
		{"markdown extension, no markdown syntax", "notes.md", "", "plain words", fmtMarkdown},
		{"htm extension", "page.htm", "", "<p>x</p>", fmtHTML},
		{"svg is xml", "icon.svg", "", "<svg/>", fmtXML},
		{"unknown extension sniffs json", "dump.txt", "", `[1,2]`, fmtJSON},
		{"no extension sniffs xml", "feed", "", `<?xml version="1.0"?><a/>`, fmtXML},
		{"yaml is never sniffed", "conf", "", "a: 1\nb: 2", fmtText},
		{"--type beats the extension", "data.json", "yaml", "a: 1", fmtYAML},
		{"--type on stdin", "-", "md", "words", fmtMarkdown},
		{"stdin sniffs", "", "", `{"a":1}`, fmtJSON},
		{"dotted directory, no extension", filepath.Join("v1.json", "README"), "", "plain", fmtText},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newViewDoc(tt.file, tt.typ, []byte(tt.body)).format; got != tt.want {
				t.Errorf("format = %s, want %s", formatName(got), formatName(tt.want))
			}
		})
	}
}

func TestLoadViewDoc(t *testing.T) {
	// The OS wording for a missing file differs ("no such file or directory" on
	// Unix, "The system cannot find the file specified." on Windows).
	_, openErr := os.Open(filepath.Join(t.TempDir(), "missing"))
	notFound := errors.Unwrap(openErr).Error()

	old := maxBodyBytes
	maxBodyBytes = 16
	t.Cleanup(func() { maxBodyBytes = old })

	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	fits := write("fits.json", `{"a":[1,2,3,4]}`) // 15 bytes
	atCap := write("at-cap.txt", strings.Repeat("x", 16))
	tooBig := write("big.json", strings.Repeat("x", 17))

	tests := []struct {
		name     string
		file     string
		stdin    string
		wantName string
		wantBody string
		wantErr  string
	}{
		{"file", fits, "", "fits.json", `{"a":[1,2,3,4]}`, ""},
		{"exactly at the cap", atCap, "", "at-cap.txt", strings.Repeat("x", 16), ""},
		{"dash reads stdin", "-", "piped", "stdin", "piped", ""},
		{"no file reads stdin", "", "piped", "stdin", "piped", ""},
		{"over the cap", tooBig, "", "", "", "--max-body"},
		{"stdin over the cap", "", strings.Repeat("y", 17), "", "", "--max-body"},
		{"missing file", filepath.Join(dir, "nope.json"), "", "", "", notFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := loadViewDoc(viewArgs{file: tt.file}, strings.NewReader(tt.stdin))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if d.name != tt.wantName || string(d.body) != tt.wantBody {
				t.Errorf("got name %q body %q, want %q %q", d.name, d.body, tt.wantName, tt.wantBody)
			}
		})
	}
}

func TestWriteView(t *testing.T) {
	hostile := "text\x1b]52;c;ZXZpbA==\x07"
	tests := []struct {
		name, file, body string
		raw              bool
		want             string
	}{
		{"json reindented", "d.json", `{"a":[1,2]}`, false, "{\n  \"a\": [\n    1,\n    2\n  ]\n}\n"},
		{"json keeps one final newline", "d.json", "{\"a\":1}\n", false, "{\n  \"a\": 1\n}\n"},
		{"xml reindented", "d.xml", `<a><b>t</b></a>`, false, "<a>\n  <b>t</b>\n</a>\n"},
		{"invalid json as-is", "d.json", `{"a":`, false, "{\"a\":\n"},
		{"yaml as source", "d.yaml", "a:  1", false, "a:  1\n"},
		{"raw is byte-exact", "d.json", `{"a":[1,2]}`, true, `{"a":[1,2]}`},
		{"raw keeps hostile bytes for the pipe", "d.txt", hostile, true, hostile},
		{"empty prints nothing", "d.json", "", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			if err := writeView(&out, newViewDoc(tt.file, "", []byte(tt.body)), tt.raw); err != nil {
				t.Fatal(err)
			}
			if out.String() != tt.want {
				t.Errorf("got %q, want %q", out.String(), tt.want)
			}
		})
	}

	// Piped pretty output is for files and other tools: no color, ever.
	var out strings.Builder
	for f, body := range map[string]string{
		"d.json": `{"k":["v",1,null]}`, "d.xml": `<a x="1"><b>t</b></a>`, "d.html": `<p class="c">hi</p>`,
		"d.yaml": "a: [1, 2]", "d.md": "# Title\n\n- a\n- **b**\n",
	} {
		if err := writeView(&out, newViewDoc(f, "", []byte(body)), false); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Errorf("piped pretty output carries ANSI color: %q", out.String())
	}
}

func TestRunViewExitCodes(t *testing.T) {
	old := maxBodyBytes
	t.Cleanup(func() { maxBodyBytes = old })
	t.Setenv("WEEB_MAX_BODY", "")

	big := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(big, []byte(`{"a":"0123456789"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"unknown flag", []string{"--nope"}, 2},
		{"bad type", []string{"x.json", "--type", "toml"}, 2},
		{"bad max-body", []string{big, "--max-body", "lots"}, 2},
		{"missing file", []string{filepath.Join(t.TempDir(), "nope.json")}, 1},
		{"over the cap", []string{big, "--max-body", "8"}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runView(tt.args); got != tt.want {
				t.Errorf("runView(%q) = %d, want %d", tt.args, got, tt.want)
			}
		})
	}
}

// viewerAt builds the viewer TUI for doc and gives it a window, which is when
// the document renders.
func viewerAt(t *testing.T, d viewDoc, raw bool) tea.Model {
	t.Helper()
	var m tea.Model = newViewerModel(d, raw)
	return send(t, m, tea.WindowSizeMsg{Width: 90, Height: 30})
}

func TestViewerModel(t *testing.T) {
	body := `{"a":1,"nested":{"x":1,"y":2},"list":[1,2]}`
	m := viewerAt(t, newViewDoc("data.json", "", []byte(body)), false)

	out := m.View().Content
	for _, form := range []string{"METHOD", "HEADERS", "ctrl+s"} {
		if strings.Contains(out, form) {
			t.Errorf("viewer shows request-form element %q", form)
		}
	}
	if want := fmt.Sprintf("data.json · %d B · json", len(body)); !strings.Contains(out, want) {
		t.Errorf("Body summary %q missing:\n%s", want, out)
	}
	if strings.Contains(out, "compose a request") {
		t.Error("viewer shows the request builder's empty state")
	}

	// The response-pane keys fold the document: → selects "nested", enter folds it.
	m = send(t, m, kp("right"), kp("enter"))
	if n := nodeByKey(bodyTree(m.(model)), "nested"); n == nil || !n.folded {
		t.Fatal(`"nested" should be folded after → enter`)
	}
	m = send(t, m, kp("-"))
	if !m.(model).respSections[0].folded {
		t.Error("- should fold the whole document")
	}
	m = send(t, m, kp("+"))
	if m.(model).respSections[0].folded || nodeByKey(bodyTree(m.(model)), "nested").folded {
		t.Error("+ should unfold everything")
	}

	// ctrl+p drops to the raw bytes and back.
	m = send(t, m, kp("ctrl+p"))
	if m.(model).pretty || bodyTree(m.(model)) != nil {
		t.Error("ctrl+p should switch to the raw view (no fold tree)")
	}
	if !strings.Contains(m.View().Content, body) {
		t.Error("raw view should show the bytes as-is")
	}
	m = send(t, m, kp("ctrl+p"))
	if bodyTree(m.(model)) == nil {
		t.Error("second ctrl+p should restore the pretty fold tree")
	}

	// Request-form actions do nothing and focus never leaves the pane.
	for _, k := range []string{"ctrl+s", "ctrl+t", "ctrl+l", "ctrl+x", "ctrl+o", "tab", "shift+tab", "up", "down"} {
		next, cmd := m.Update(kp(k))
		mm := next.(model)
		if mm.inFlight || mm.pane != paneResponse || mm.currentFocus().kind != focResponse {
			t.Errorf("%s changed viewer state: inFlight=%v pane=%v focus=%v", k, mm.inFlight, mm.pane, mm.currentFocus().kind)
		}
		if k != "up" && k != "down" && cmd != nil {
			t.Errorf("%s returned a command", k)
		}
		m = next
	}

	for _, k := range []string{"q", "ctrl+c"} {
		_, cmd := m.Update(kp(k))
		if cmd == nil {
			t.Fatalf("%s should quit", k)
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Errorf("%s should quit, got %T", k, cmd())
		}
	}
}

func TestViewerStartsRaw(t *testing.T) {
	m := viewerAt(t, newViewDoc("data.json", "", []byte(`{"a":{"b":1}}`)), true)
	if m.(model).pretty || bodyTree(m.(model)) != nil {
		t.Error("--raw should open the viewer in the raw view")
	}
}

// A resize re-wraps the document without rebuilding it, so folds survive.
func TestViewerResizeKeepsFolds(t *testing.T) {
	m := viewerAt(t, newViewDoc("data.json", "", []byte(`{"nested":{"x":1},"z":2}`)), false)
	m = send(t, m, kp("right"), kp("enter"), tea.WindowSizeMsg{Width: 60, Height: 20})
	if n := nodeByKey(bodyTree(m.(model)), "nested"); n == nil || !n.folded {
		t.Error("fold lost on resize")
	}
	if w := m.(model).resp.Width(); w != 60-4 {
		t.Errorf("viewport width = %d after resize, want %d", w, 60-4)
	}
}

// File contents and names are as untrusted as response bodies: neither may
// put a live control sequence on the terminal.
func TestViewerSanitizes(t *testing.T) {
	tests := []struct {
		name, file, body, wantText string
	}{
		{"OSC 52 in a text body", "notes.txt", "BODYMARK\x1b]52;c;ZXZpbA==\x07", "BODYMARK"},
		{"OSC in a JSON string", "d.json", `{"k":"\u001b]52;c;ZXZpbA==\u0007"}`, `"k"`},
		{"title-setting file name", "evil\x1b]0;pwned\x07.txt", "fine", `evil\x1b]0;pwned\a.txt`},
		{"newline and bidi in file name", "a\nb\u202e.txt", "fine", `"a\nb\u202e.txt"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := viewerAt(t, newViewDoc(tt.file, "", []byte(tt.body)), false).View().Content
			for _, bad := range []string{"\x1b]52", "\x1b]0;", "\x07", "\u202e"} {
				if strings.Contains(out, bad) {
					t.Errorf("%q reached the screen:\n%q", bad, out)
				}
			}
			if !strings.Contains(out, tt.wantText) {
				t.Errorf("want %q on screen:\n%s", tt.wantText, out)
			}
		})
	}
}

func TestCompletionView(t *testing.T) {
	for shell, gen := range map[string]func() string{"zsh": zshCompletion, "bash": bashCompletion} {
		out := gen()
		for _, want := range []string{" view ", "view)", "--type", "yaml md"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s completion missing %q", shell, want)
			}
		}
	}
}
