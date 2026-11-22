package main

import (
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFormArg(t *testing.T) {
	cases := []struct {
		arg     string
		literal bool
		want    FormField
	}{
		{arg: "a=b", want: FormField{Name: "a", Value: "b"}},
		{arg: "a=", want: FormField{Name: "a"}},
		{arg: "a= b ", want: FormField{Name: "a", Value: "b"}},
		{arg: `a=" b;c "`, want: FormField{Name: "a", Value: " b;c "}},
		{arg: `a="q\"uo\\te\n"`, want: FormField{Name: "a", Value: `q"uo\te\n`}},
		{arg: `a="unterminated`, want: FormField{Name: "a", Value: `"unterminated`}},
		{arg: "a=b;type=text/x-a", want: FormField{Name: "a", Value: "b", Type: "text/x-a"}},
		{arg: "a=b;;", want: FormField{Name: "a", Value: "b"}},
		{arg: "f=@up.txt", want: FormField{Name: "f", Value: "up.txt", Kind: formFile}},
		{arg: "f=@up.txt;type=image/png;filename=pic.png", want: FormField{Name: "f", Value: "up.txt", Kind: formFile, Type: "image/png", Filename: "pic.png"}},
		{arg: "f=@up.txt; filename=x;TYPE=text/plain; charset=utf-8", want: FormField{Name: "f", Value: "up.txt", Kind: formFile, Type: "text/plain;charset=utf-8", Filename: "x"}},
		{arg: `f=@"a,b;c.txt";filename="n;m"`, want: FormField{Name: "f", Value: "a,b;c.txt", Kind: formFile, Filename: "n;m"}},
		{arg: "n=<note.txt", want: FormField{Name: "n", Value: "note.txt", Kind: formFileText}},
		{arg: "a=@x;b", literal: true, want: FormField{Name: "a", Value: "@x;b"}},
	}
	for _, c := range cases {
		got, err := parseFormArg(c.arg, c.literal)
		if err != nil || got != c.want {
			t.Errorf("parseFormArg(%q, %v) = %+v, %v; want %+v", c.arg, c.literal, got, err, c.want)
		}
	}

	for _, arg := range []string{
		"nameonly",                // no '='
		"=value",                  // no name
		"f=@",                     // no file
		"f=@-",                    // stdin
		"f=<-",                    // stdin
		"f=@a.txt,b.txt",          // several files in one field
		"a=b;bogus=1",             // unknown parameter
		"a=b;headers=X-A: 1",      // unsupported parameter
		"a=b;type=plain",          // not a MIME type
		"a=b;type=a/b\nX-Evil: 1", // a header break in the type
	} {
		if _, err := parseFormArg(arg, false); err == nil {
			t.Errorf("parseFormArg(%q) should error", arg)
		}
	}
}

// -F parts reach the server as a real multipart/form-data body: text fields,
// <file text, file uploads with curl's type guess, and filename/type
// overrides. Names are escaped so a quote can't break the part header.
func TestClientDoMultipart(t *testing.T) {
	clearRequestEnv(t)
	dir := t.TempDir()
	up := filepath.Join(dir, "up.txt")
	blob := filepath.Join(dir, "blob.dat")
	note := filepath.Join(dir, "note.md")
	for p, data := range map[string]string{up: "file body", blob: "\x00\x01", note: "from a file"} {
		writeAt(t, p, data)
	}

	type part struct{ name, filename, ctype, data string }
	var method string
	var parts []part
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		_, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			b, _ := io.ReadAll(p)
			parts = append(parts, part{p.FormName(), p.FileName(), p.Header.Get("Content-Type"), string(b)})
		}
	}))
	defer srv.Close()

	a, err := parseCLI([]string{srv.URL,
		"-F", "a=b",
		"-F", "up=@" + up,
		"-F", "bin=@" + blob,
		"-F", "renamed=@" + up + ";filename=pic.png",
		"-F", "typed=@" + blob + ";type=application/x-thing",
		"-F", "note=<" + note,
		"-F", `q"x=1`,
		"--form-string", "lit=@not-a-file",
	})
	if err != nil {
		t.Fatal(err)
	}
	res := testClient().Do(RequestSpec{Method: a.method, URL: a.url, Headers: a.headers, Form: a.form})
	if !res.OK() {
		t.Fatalf("request failed: %v", res.Err)
	}
	if method != "POST" {
		t.Errorf("method = %s, want POST (-F implies it)", method)
	}
	want := []part{
		{"a", "", "", "b"},
		{"up", "up.txt", "text/plain", "file body"},
		{"bin", "blob.dat", "application/octet-stream", "\x00\x01"},
		{"renamed", "pic.png", "image/png", "file body"},
		{"typed", "blob.dat", "application/x-thing", "\x00\x01"},
		{"note", "", "", "from a file"},
		{"q%22x", "", "", "1"},
		{"lit", "", "", "@not-a-file"},
	}
	if len(parts) != len(want) {
		t.Fatalf("got %d parts %+v, want %d", len(parts), parts, len(want))
	}
	for i := range want {
		if parts[i] != want[i] {
			t.Errorf("part %d = %+v, want %+v", i, parts[i], want[i])
		}
	}
}

func writeAt(t *testing.T, path, data string) {
	t.Helper()
	if err := writePrivateFile(path, []byte(data)); err != nil {
		t.Fatal(err)
	}
}

// A user Content-Type is kept, as curl keeps it: the boundary is appended,
// or, when the header already names one, the body uses that boundary.
func TestMaterializeFormContentType(t *testing.T) {
	form := []FormField{{Name: "a", Value: "b"}}
	cases := []struct {
		name    string
		headers []Header
		prefix  string // of the resulting Content-Type
		bound   string // "" = generated
	}{
		{"default", nil, "multipart/form-data; boundary=", ""},
		{"user type", []Header{{Key: "content-type", Value: "multipart/mixed"}}, "multipart/mixed; boundary=", ""},
		{"user boundary", []Header{{Key: "Content-Type", Value: "multipart/form-data; boundary=xyz"}}, "multipart/form-data; boundary=xyz", "xyz"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, err := materializeForm(RequestSpec{Method: "POST", Headers: c.headers, Form: form})
			if err != nil {
				t.Fatal(err)
			}
			var cts []string
			for _, h := range spec.Headers {
				if strings.EqualFold(h.Key, "Content-Type") {
					cts = append(cts, h.Value)
				}
			}
			if len(cts) != 1 || !strings.HasPrefix(cts[0], c.prefix) {
				t.Fatalf("Content-Type headers = %q, want one starting %q", cts, c.prefix)
			}
			_, params, _ := mime.ParseMediaType(cts[0])
			if c.bound != "" && params["boundary"] != c.bound {
				t.Errorf("boundary = %q, want %q", params["boundary"], c.bound)
			}
			if !strings.HasPrefix(string(spec.Body), "--"+params["boundary"]+"\r\n") {
				t.Errorf("body doesn't use the header's boundary: %q", spec.Body)
			}
		})
	}

	// A body-less method sends no form, like a -d body.
	spec, err := materializeForm(RequestSpec{Method: "GET", Form: form})
	if err != nil || spec.Body != nil || len(spec.Headers) != 0 {
		t.Errorf("GET: body %q headers %+v err %v; want the spec untouched", spec.Body, spec.Headers, err)
	}
	// An unreadable upload fails the build.
	if _, err := materializeForm(RequestSpec{Method: "POST", Form: []FormField{{Name: "f", Kind: formFile, Value: "/no/such/file"}}}); err == nil {
		t.Error("a missing upload should error")
	}
}

// Export picks a form curl reads back as the same part: --form-string for
// text -F would misread, quoting otherwise, and never a bare @ or < that
// would turn a text value into a file read.
func TestCurlFormArgRoundTrip(t *testing.T) {
	fields := []FormField{
		{Name: "a", Value: "b"},
		{Name: "a", Value: ""},
		{Name: "a", Value: "x;y"},
		{Name: "a", Value: " padded "},
		{Name: "a", Value: "@/etc/passwd"},
		{Name: "a", Value: "</etc/passwd"},
		{Name: "a", Value: `"quoted`},
		{Name: "a", Value: "@/etc/passwd", Type: "text/plain"},
		{Name: "a", Value: `back\slash "q";`, Type: "text/plain;charset=utf-8", Filename: "f;n"},
		{Name: "odd name;\n", Value: "v"},
		{Name: "f", Kind: formFile, Value: "dir/a,b;c.txt", Type: "image/png", Filename: " sp "},
		{Name: "f", Kind: formFile, Value: `"q.txt`},
		{Name: "n", Kind: formFileText, Value: "note.txt"},
	}
	for _, f := range fields {
		flag, arg := curlFormArg(f)
		back, err := parseFormArg(arg, flag == "--form-string")
		if err != nil || back != f {
			t.Errorf("%s %q parses as %+v, %v; want %+v", flag, arg, back, err, f)
		}
		if f.Kind == formText && flag == "-F" && (strings.HasPrefix(arg, "a=@") || strings.HasPrefix(arg, "a=<")) {
			t.Errorf("text value exported as a file read: -F %q", arg)
		}
	}
}

// History must not store a secret -F field: it is blanked (and the entry
// won't replay), while the other parts stay.
func TestHistoryRedactsMultipart(t *testing.T) {
	spec, err := materializeForm(RequestSpec{Method: "POST", URL: "https://x/login", Form: []FormField{
		{Name: "user", Value: "alice"},
		{Name: "password", Value: "hunter2"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	e := newHistoryEntry(spec, Result{Method: "POST", URL: spec.URL, Status: 200})
	if strings.Contains(e.Body, "hunter2") || !strings.Contains(e.Body, "alice") || !e.Redacted {
		t.Errorf("stored body %q (redacted=%v): want the password blanked, the user kept", e.Body, e.Redacted)
	}
}
