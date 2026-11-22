package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// httpReqView flattens a parsed request for table comparison; includes render
// as the "< path" / "<@ path" line they came from.
type httpReqView struct {
	Index      int
	Name       string
	Title      string
	Method     string
	URL        string
	Headers    []Header
	Body       string
	NoRedirect bool
}

func viewHTTPRequest(r *httpRequest) httpReqView {
	v := httpReqView{Index: r.Index, Name: r.Name, Title: r.Title, Method: r.Method, URL: r.urlTemplate(), NoRedirect: r.NoRedirect}
	for _, h := range r.Headers {
		v.Headers = append(v.Headers, Header{Key: h.Key, Value: h.Value})
	}
	lines := make([]string, 0, len(r.Body))
	for _, l := range r.Body {
		switch {
		case l.Include && l.Expand:
			lines = append(lines, "<@ "+l.Text)
		case l.Include:
			lines = append(lines, "< "+l.Text)
		default:
			lines = append(lines, l.Text)
		}
	}
	v.Body = strings.Join(lines, "\n")
	return v
}

func TestParseHTTP(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []httpReqView
		vars map[string]string // checked when non-nil
	}{
		{
			name: "bare URL defaults to GET",
			src:  "https://example.com/health\n",
			want: []httpReqView{{Index: 1, Method: "GET", URL: "https://example.com/health"}},
		},
		{
			name: "method, version, headers, multi-line body",
			src: `POST https://x/users HTTP/1.1
Content-Type: application/json
Accept:*/*

{
  "name": "weeb"
}


`,
			want: []httpReqView{{
				Index: 1, Method: "POST", URL: "https://x/users",
				Headers: []Header{{"Content-Type", "application/json"}, {"Accept", "*/*"}},
				Body:    "{\n  \"name\": \"weeb\"\n}",
			}},
		},
		{
			name: "separators, titles and names",
			src: `@base = https://x

### List users
GET {{base}}/users

###
# @name create
POST {{base}}/users

#### Delete one
// @name = remove
DELETE {{base}}/users/1
`,
			want: []httpReqView{
				{Index: 1, Title: "List users", Method: "GET", URL: "{{base}}/users"},
				{Index: 2, Name: "create", Method: "POST", URL: "{{base}}/users"},
				{Index: 3, Name: "remove", Title: "Delete one", Method: "DELETE", URL: "{{base}}/users/1"},
			},
			vars: map[string]string{"base": "https://x"},
		},
		{
			name: "comments before the request and among headers; body lines are literal",
			src: `# a comment
// another one
POST https://x
# between headers
Accept: text/plain
// also between headers

# sent as body text
// this too
`,
			want: []httpReqView{{
				Index: 1, Method: "POST", URL: "https://x",
				Headers: []Header{{"Accept", "text/plain"}},
				Body:    "# sent as body text\n// this too",
			}},
		},
		{
			name: "lowercase and custom methods",
			src:  "get https://x\n###\nPURGE https://x/cache\n",
			want: []httpReqView{
				{Index: 1, Method: "GET", URL: "https://x"},
				{Index: 2, Method: "PURGE", URL: "https://x/cache"},
			},
		},
		{
			name: "query continuation lines",
			src: `GET https://x/search
    ?q={{term}}
    &page=2
Accept: application/json
`,
			want: []httpReqView{{
				Index: 1, Method: "GET", URL: "https://x/search?q={{term}}&page=2",
				Headers: []Header{{"Accept", "application/json"}},
			}},
		},
		{
			name: "references with spaces on the request line",
			src:  "GET {{$processEnv BASE}}/me\n###\n{{ base }}/health\n",
			want: []httpReqView{
				{Index: 1, Method: "GET", URL: "{{$processEnv BASE}}/me"},
				{Index: 2, Method: "GET", URL: "{{ base }}/health"},
			},
		},
		{
			name: "file includes",
			src: `POST https://x/upload
Content-Type: application/json

< ./payload.json
<@ ./template.json
`,
			want: []httpReqView{{
				Index: 1, Method: "POST", URL: "https://x/upload",
				Headers: []Header{{"Content-Type", "application/json"}},
				Body:    "< ./payload.json\n<@ ./template.json",
			}},
		},
		{
			name: "CRLF line endings and a BOM",
			src:  "\ufeff### one\r\n# @name a\r\nPOST https://x\r\nA: 1\r\n\r\nline1\r\nline2\r\n\r\n### two\r\nGET https://y\r\n",
			want: []httpReqView{
				{Index: 1, Name: "a", Title: "one", Method: "POST", URL: "https://x", Headers: []Header{{"A", "1"}}, Body: "line1\nline2"},
				{Index: 2, Title: "two", Method: "GET", URL: "https://y"},
			},
		},
		{
			name: "no-redirect directive",
			src:  "# @no-redirect\nGET https://x/old\n",
			want: []httpReqView{{Index: 1, Method: "GET", URL: "https://x/old", NoRedirect: true}},
		},
		{
			name: "JetBrains scripts and output redirects are skipped",
			src: `< {%
  request.variables.set("id", "1")
%}
GET https://x/{{id}}

> {%
  client.test("ok", function() {});
%}

###
POST https://x

{"a":1}

>> out.json
`,
			want: []httpReqView{
				{Index: 1, Method: "GET", URL: "https://x/{{id}}"},
				{Index: 2, Method: "POST", URL: "https://x", Body: `{"a":1}`},
			},
		},
		{
			name: "a variables-only block is not a request",
			src:  "@a = 1\n@b =  two words  \n\n###\nGET https://x\n",
			want: []httpReqView{{Index: 1, Method: "GET", URL: "https://x"}},
			vars: map[string]string{"a": "1", "b": "two words"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := parseHTTP(tt.src)
			if err != nil {
				t.Fatalf("parseHTTP: %v", err)
			}
			var got []httpReqView
			for _, r := range f.Requests {
				got = append(got, viewHTTPRequest(r))
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("requests:\n got %+v\nwant %+v", got, tt.want)
			}
			if tt.vars != nil {
				gotVars := map[string]string{}
				for k, v := range f.Vars {
					gotVars[k] = v.Value
				}
				if !reflect.DeepEqual(gotVars, tt.vars) {
					t.Errorf("vars = %v, want %v", gotVars, tt.vars)
				}
			}
		})
	}
}

func TestParseHTTPErrors(t *testing.T) {
	tests := []struct {
		name, src, want string
	}{
		{"header without a colon", "GET https://x\nnot a header\n", "line 2: expected a header"},
		{"body without a blank line", "POST https://x\n{\"a\": 1}\n", "line 2: expected a header"},
		{"variable without =", "@novalue\nGET https://x\n", "line 1: bad variable definition"},
		{"variable without a name", "@ = x\nGET https://x\n", "line 1: bad variable definition"},
		{"variable named like a dynamic one", "@$x = 1\nGET https://x\n", "line 1: bad variable definition"},
		{"duplicate name", "# @name a\nGET https://x\n###\n# @name a\nGET https://y\n", `line 4: duplicate request name "a" (first used on line 1)`},
		{"empty @name", "# @name\nGET https://x\n", "line 1: @name needs a name"},
		{"@name with no request", "# @name lonely\n###\nGET https://x\n", "line 1: @name lonely isn't followed by a request"},
		{"spaces in the URL", "GET https://x and more\n", `line 1: can't read request line "GET https://x and more"`},
		{"curl command", "###\ncurl -X POST https://x\n", "line 2: can't read request line"},
		{"method with no URL", "###\nDELETE\n", "line 2: DELETE has no URL"},
		{"include with no path", "POST https://x\n\n<  \n", "line 3: include needs a file path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseHTTP(tt.src)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("parseHTTP error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
	if _, err := parseHTTP("curl https://x -H 'a: b'\n"); err == nil || !strings.Contains(err.Error(), "use weeb curl") {
		t.Errorf("curl line should point at weeb curl, got %v", err)
	}
}

// writeHTTPTestFile writes name under dir and returns its path.
func writeHTTPTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// resolveHTTPTest parses src as if it lived in dir and resolves request n.
func resolveHTTPTest(t *testing.T, dir, src string, n int, env *httpEnv, hint string) (RequestSpec, *secretMask, error) {
	t.Helper()
	f, err := parseHTTP(src)
	if err != nil {
		t.Fatalf("parseHTTP: %v", err)
	}
	f.Dir = dir
	return f.resolve(f.Requests[n-1], env, hint)
}

func TestResolveHTTP(t *testing.T) {
	dir := t.TempDir()
	writeHTTPTestFile(t, dir, "payload.json", `{"raw": "{{notExpanded}}"}`)
	writeHTTPTestFile(t, dir, "template.json", `{"user": "{{user}}"}`)
	t.Setenv("WEEB_T_TOKEN", "tok-123")
	t.Setenv("WEEB_T_HOST", "api.example.com")
	devEnv := &httpEnv{vars: map[string]string{"host": "env.example.com", "port": "8443"}, private: map[string]bool{}}

	tests := []struct {
		name string
		src  string
		env  *httpEnv
		want RequestSpec
	}{
		{
			name: "file variables nest",
			src:  "@host = example.com\n@base = https://{{host}}/v1\nGET {{base}}/me\n",
			want: RequestSpec{Method: "GET", URL: "https://example.com/v1/me"},
		},
		{
			name: "process env in the URL, headers and body",
			src: `POST https://{{$env.WEEB_T_HOST}}/x
Authorization: Bearer {{$processEnv WEEB_T_TOKEN}}

{"t": "{{ $processEnv WEEB_T_TOKEN }}"}
`,
			want: RequestSpec{
				Method: "POST", URL: "https://api.example.com/x",
				Headers: []Header{{"Authorization", "Bearer tok-123"}},
				Body:    []byte(`{"t": "tok-123"}`),
			},
		},
		{
			name: "query continuation lines",
			src:  "@q = weeb\nGET https://x/s\n  ?q={{q}}\n  &n=1\n",
			want: RequestSpec{Method: "GET", URL: "https://x/s?q=weeb&n=1"},
		},
		{
			name: "raw and expanded includes",
			src:  "@user = ada\nPOST https://x\n\n< ./payload.json\n<@ ./template.json\n",
			want: RequestSpec{Method: "POST", URL: "https://x", Body: []byte("{\"raw\": \"{{notExpanded}}\"}\n{\"user\": \"ada\"}")},
		},
		{
			name: "env file variables, with file variables winning",
			src:  "@host = file.example.com\nGET https://{{host}}:{{port}}/\n",
			env:  devEnv,
			want: RequestSpec{Method: "GET", URL: "https://file.example.com:8443/"},
		},
		{
			name: "multipart bodies join with CRLF",
			src: `POST https://x/up
Content-Type: multipart/form-data; boundary=b

--b
Content-Disposition: form-data; name="f"

hi
--b--
`,
			want: RequestSpec{
				Method: "POST", URL: "https://x/up",
				Headers: []Header{{"Content-Type", "multipart/form-data; boundary=b"}},
				Body:    []byte("--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nhi\r\n--b--"),
			},
		},
		{
			name: "no-redirect sets NoFollow",
			src:  "# @no-redirect\nGET https://x\n",
			want: RequestSpec{Method: "GET", URL: "https://x", NoFollow: true},
		},
		{
			name: "an unclosed {{ is literal",
			src:  "GET https://x/{{oops\n",
			want: RequestSpec{Method: "GET", URL: "https://x/{{oops"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := resolveHTTPTest(t, dir, tt.src, 1, tt.env, "")
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("spec:\n got %+v (body %q)\nwant %+v (body %q)", got, got.Body, tt.want, tt.want.Body)
			}
		})
	}
}

func TestResolveHTTPDynamicVars(t *testing.T) {
	got, _, err := resolveHTTPTest(t, t.TempDir(), "GET https://x/{{$guid}}/{{$random.uuid}}?t={{$timestamp}}&iso={{$isoTimestamp}}\n", 1, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	uuid := `[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`
	re := regexp.MustCompile(`^https://x/` + uuid + `/` + uuid + `\?t=\d{10,}&iso=\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`)
	if !re.MatchString(got.URL) {
		t.Errorf("URL = %q, want generated uuid/timestamp values", got.URL)
	}
}

// Resolve errors name the variable and line, and never an env value.
func TestResolveHTTPErrors(t *testing.T) {
	// The OS wording for a missing file differs between Unix and Windows.
	_, openErr := os.Open(filepath.Join(t.TempDir(), "missing"))
	notFound := errors.Unwrap(openErr).Error()
	const secret = "s3cret-value-xyz"
	t.Setenv("WEEB_T_SECRET", secret)

	tests := []struct {
		name, src, hint, want string
	}{
		{"undefined in the URL", "GET https://x/{{nope}}\n", "", "line 1: undefined variable {{nope}}"},
		{"undefined in a header", "GET https://x\nAccept: a\nX-Key: {{missing}}\n", "", "line 3: undefined variable {{missing}}"},
		{"undefined in the body", "POST https://x\n\n{\n  \"a\": \"{{gone}}\"\n}\n", "", "line 4: undefined variable {{gone}}"},
		{"undefined with an --env hint", "GET https://{{host}}/\n", "; pick one with --env", "line 1: undefined variable {{host}}; pick one with --env"},
		{"unset env var", "GET https://x/{{$processEnv WEEB_T_UNSET}}\n", "", "line 1: environment variable WEEB_T_UNSET is not set (used as {{$processEnv WEEB_T_UNSET}})"},
		{"unset JetBrains env var", "GET https://x/{{$env.WEEB_T_UNSET}}\n", "", "line 1: environment variable WEEB_T_UNSET is not set"},
		{"response chaining", "# @name login\nPOST https://x/login\n###\nGET https://x/me\nAuthorization: Bearer {{login.response.body.$.token}}\n", "", "line 5: {{login.response.body.$.token}} reads another request's response"},
		{"variable cycle", "@a = {{b}}\n@b = {{a}}\nGET https://x/{{a}}\n", "", "variable {{a}} refers to itself (a -> b -> a)"},
		{"unsupported dynamic variable", "GET https://x/{{$randomInt 1 10}}\n", "", "line 1: unsupported dynamic variable {{$randomInt 1 10}}"},
		{"env-file indirection", "GET https://x/{{$processEnv %TOKEN}}\n", "", "{{$processEnv %TOKEN}} isn't supported"},
		{"empty reference", "GET https://x/{{ }}\n", "", "line 1: empty variable {{}}"},
		{"missing include named as written", "POST https://x\n\n< ./{{$processEnv WEEB_T_SECRET}}.json\n", "", "line 3: include ./{{$processEnv WEEB_T_SECRET}}.json: " + notFound},
		{"undefined after a secret expanded", "@tok = {{$processEnv WEEB_T_SECRET}}\nGET https://x/{{tok}}/{{nope}}\n", "", "line 2: undefined variable {{nope}}"},
		{"undefined inside an expanded include", "POST https://x\n\n<@ ./tmpl.json\n", "", "./tmpl.json (included on line 3): undefined variable {{who}}"},
	}
	dir := t.TempDir()
	writeHTTPTestFile(t, dir, "tmpl.json", `{"who": "{{who}}"}`)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := resolveHTTPTest(t, dir, tt.src, len(strings.Split(tt.src, "###")), nil, tt.hint)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("resolve error = %v, want it to contain %q", err, tt.want)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error leaks the env value: %v", err)
			}
		})
	}
}

func TestLoadHTTPEnv(t *testing.T) {
	dir := t.TempDir()
	writeHTTPTestFile(t, dir, httpEnvFile, `{
  "$shared": {"version": "v1", "host": "shared.example.com"},
  "dev": {"host": "dev.example.com", "port": 8080, "debug": true, "SSLConfiguration": {"verifyHostCertificate": false}},
  "prod": {"host": "prod.example.com"}
}`)
	writeHTTPTestFile(t, dir, httpPrivateEnvFile, `{"dev": {"token": "dev-secret-token"}}`)
	empty := t.TempDir()
	broken := t.TempDir()
	writeHTTPTestFile(t, broken, httpPrivateEnvFile, `{"dev": {"token": "zzz-secret-zzz"}`)

	tests := []struct {
		name, dir, env string
		want           map[string]string
		private        []string
		wantErr        string
	}{
		{name: "no --env applies $shared", dir: dir, want: map[string]string{"version": "v1", "host": "shared.example.com"}},
		{
			name: "dev merges shared, public and private", dir: dir, env: "dev",
			want:    map[string]string{"version": "v1", "host": "dev.example.com", "port": "8080", "debug": "true", "token": "dev-secret-token"},
			private: []string{"token"},
		},
		{name: "prod", dir: dir, env: "prod", want: map[string]string{"version": "v1", "host": "prod.example.com"}},
		{name: "unknown environment", dir: dir, env: "staging", wantErr: "--env staging: no such environment in http-client.env.json (have: dev, prod)"},
		{name: "no env files, no --env", dir: empty, want: map[string]string{}},
		{name: "no env files with --env", dir: empty, env: "dev", wantErr: "--env dev: no http-client.env.json next to the .http file"},
		{name: "malformed private file", dir: broken, env: "dev", wantErr: httpPrivateEnvFile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, _, err := loadHTTPEnv(tt.dir, tt.env)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				if strings.Contains(err.Error(), "secret") {
					t.Errorf("error leaks a value: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(env.vars, tt.want) {
				t.Errorf("vars = %v, want %v", env.vars, tt.want)
			}
			for k, p := range env.private {
				if want := strings.Contains(strings.Join(tt.private, ","), k); p != want {
					t.Errorf("private[%s] = %v, want %v", k, p, want)
				}
			}
		})
	}
}

// The mask resolve returns covers process env values and private env-file
// values, so the runner can scrub them from error text and logs.
func TestResolveHTTPMasksSecrets(t *testing.T) {
	t.Setenv("WEEB_T_SECRET", "s3cret value&x")
	env := &httpEnv{
		vars:    map[string]string{"token": "private-token-1", "host": "public.example.com"},
		private: map[string]bool{"token": true},
	}
	spec, mask, err := resolveHTTPTest(t, t.TempDir(), "GET https://{{host}}/{{token}}?k={{$processEnv WEEB_T_SECRET}}\n", 1, env, "")
	if err != nil {
		t.Fatal(err)
	}
	// What net/http would quote in an error: the parsed, re-encoded URL.
	u, err := url.Parse(strings.Replace(spec.URL, "?k="+"s3cret value&x", "?k="+url.QueryEscape("s3cret value&x"), 1))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{spec.URL, u.String()} {
		got := mask.apply(s)
		if strings.Contains(got, "s3cret") || strings.Contains(got, "private-token-1") {
			t.Errorf("mask.apply(%q) = %q, still holds a secret", s, got)
		}
		if !strings.Contains(got, "public.example.com") || !strings.Contains(got, "/{{token}}?k={{$processEnv WEEB_T_SECRET}}") {
			t.Errorf("mask.apply(%q) = %q, want the references in place of the values", s, got)
		}
	}
}

func TestSecretMask(t *testing.T) {
	type pair struct{ value, ref string }
	tests := []struct {
		name  string
		adds  []pair
		in    string
		want  string
		empty bool
	}{
		{"raw value", []pair{{"s3cret-token", "{{$processEnv T}}"}}, `Get "https://x/s3cret-token": refused`, `Get "https://x/{{$processEnv T}}": refused`, false},
		{"escaped forms", []pair{{"a b/c&d", "{{$env.X}}"}}, "p=a%20b%2Fc&d q=a+b%2Fc%26d", "p={{$env.X}} q={{$env.X}}", false},
		{"short values are left alone", []pair{{"abc", "{{A}}"}}, "abc 401", "abc 401", true},
		{"longest value wins", []pair{{"token", "{{A}}"}, {"token-long", "{{B}}"}}, "token-long token", "{{B}} {{A}}", false},
		{"nothing added", nil, "unchanged", "unchanged", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &secretMask{}
			for _, p := range tt.adds {
				m.add(p.value, p.ref)
			}
			if got := m.apply(tt.in); got != tt.want {
				t.Errorf("apply(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if m.empty() != tt.empty {
				t.Errorf("empty() = %v, want %v", m.empty(), tt.empty)
			}
			var buf strings.Builder
			if _, err := io.WriteString(m.writer(&buf), tt.in); err != nil || buf.String() != tt.want {
				t.Errorf("writer wrote %q (err %v), want %q", buf.String(), err, tt.want)
			}
		})
	}
	var nilMask *secretMask
	if nilMask.apply("x") != "x" || !nilMask.empty() {
		t.Error("a nil mask should pass text through")
	}
}

// The listing shows each request as written: an env reference, never its value.
func TestRenderHTTPList(t *testing.T) {
	t.Setenv("WEEB_T_TOKEN", "supersecretvalue")
	f, err := parseHTTP(`@base = https://api.example.com
### Log in
# @name login
POST {{base}}/login

### Who am I
GET {{base}}/me
  ?token={{$processEnv WEEB_T_TOKEN}}

###
https://x/health
`)
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	renderHTTPList(&buf, f)
	want := "  1  login     POST    {{base}}/login\n" +
		"  2  Who am I  GET     {{base}}/me?token={{$processEnv WEEB_T_TOKEN}}\n" +
		"  3  -         GET     https://x/health\n"
	if buf.String() != want {
		t.Errorf("listing:\n%s\nwant:\n%s", buf.String(), want)
	}
	if strings.Contains(buf.String(), "supersecretvalue") {
		t.Error("listing leaks an env value")
	}
}

// swapErrW redirects the stderr boundary writer into a buffer for the test.
func swapErrW(t *testing.T) *strings.Builder {
	t.Helper()
	var buf strings.Builder
	old := errW
	errW = &buf
	t.Cleanup(func() { errW = old })
	return &buf
}

// captureFile points *f (os.Stdout or os.Stderr) at a temp file for the test
// and returns a func that reads back what was written. A file, unlike a pipe,
// can't fill up and block the writer.
func captureFile(t *testing.T, f **os.File) func() string {
	t.Helper()
	tmp, err := os.CreateTemp(t.TempDir(), "capture")
	if err != nil {
		t.Fatal(err)
	}
	old := *f
	*f = tmp
	t.Cleanup(func() {
		*f = old
		_ = tmp.Close()
	})
	return func() string {
		b, err := os.ReadFile(tmp.Name())
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
}

func TestRunHTTPFileExitCodes(t *testing.T) {
	_, openErr := os.Open(filepath.Join(t.TempDir(), "missing"))
	notFound := errors.Unwrap(openErr).Error() // OS-specific wording
	const secret = "s3cret-run-value"
	t.Setenv("WEEB_T_SECRET", secret)
	dir := t.TempDir()
	api := writeHTTPTestFile(t, dir, "api.http", `@tok = {{$processEnv WEEB_T_SECRET}}
### Log in
# @name login
POST http://127.0.0.1:1/login?t={{tok}}

### Me
GET http://127.0.0.1:1/me/{{nope}}
`)
	empty := writeHTTPTestFile(t, dir, "empty.http", "# nothing here\n@a = 1\n")
	bad := writeHTTPTestFile(t, dir, "bad.http", "GET http://x\nnot a header\n")
	envDir := t.TempDir()
	writeHTTPTestFile(t, envDir, httpEnvFile, `{"dev": {"host": "dev.example.com"}, "prod": {}}`)
	hinted := writeHTTPTestFile(t, envDir, "hinted.http", "GET https://{{host}}/\n")

	tests := []struct {
		name    string
		args    []string
		want    int
		wantErr string
		wantOut string
	}{
		{"no file", nil, 2, "run needs a .http file", ""},
		{"missing file", []string{filepath.Join(dir, "nope.http")}, 2, notFound, ""},
		{"unknown flag", []string{api, "--nope"}, 2, `unknown flag "--nope"`, ""},
		{"extra argument", []string{api, "login", "extra"}, 2, `unexpected argument "extra"`, ""},
		{"--env without a value", []string{api, "login", "--env"}, 2, "--env needs a value", ""},
		{"list", []string{api}, 0, "", "  1  login  POST    http://127.0.0.1:1/login?t={{tok}}"},
		{"list ignores --env", []string{api, "--env", "nope"}, 0, "", "  2  Me     GET     http://127.0.0.1:1/me/{{nope}}"},
		{"no requests", []string{empty}, 2, "no requests in", ""},
		{"parse error", []string{bad}, 2, "bad.http: line 2: expected a header", ""},
		{"unknown name", []string{api, "logout"}, 2, `no request named "logout"`, ""},
		{"index out of range", []string{api, "9"}, 2, "no request 9 (the file has 2)", ""},
		{"undefined variable", []string{api, "2", "--no-tui"}, 2, "line 7: undefined variable {{nope}}", ""},
		{"unknown --env", []string{api, "login", "--env=dev"}, 2, "--env dev: no http-client.env.json", ""},
		{"undefined with env hint", []string{hinted, "1"}, 2, "undefined variable {{host}}; http-client.env.json defines environments (dev, prod), pick one with --env", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := swapOutW(t)
			errs := swapErrW(t)
			if got := runHTTPFile(tt.args); got != tt.want {
				t.Errorf("runHTTPFile(%q) = %d, want %d (stderr %q)", tt.args, got, tt.want, errs.String())
			}
			if !strings.Contains(errs.String(), tt.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", errs.String(), tt.wantErr)
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("stdout = %q, want it to contain %q", out.String(), tt.wantOut)
			}
			if strings.Contains(errs.String()+out.String(), secret) {
				t.Error("output leaks an env value")
			}
		})
	}
}

// TestRunHTTPFileEndToEnd runs requests from a .http file against a local
// server: selected by name and by index, with file and env-file variables, a
// process env token, query continuation lines, an expanded include, and the
// WEEB_HEADERS prefill — and the response body streamed to stdout.
func TestRunHTTPFileEndToEnd(t *testing.T) {
	type seen struct {
		method, uri, auth, ctype, team, body string
	}
	got := make(chan seen, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- seen{r.Method, r.URL.RequestURI(), r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.Header.Get("X-Team"), string(b)}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":7}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeHTTPTestFile(t, dir, "item.json", `{"name": "{{name}}"}`)
	writeHTTPTestFile(t, dir, httpEnvFile, `{"dev": {"name": "widget"}}`)
	api := writeHTTPTestFile(t, dir, "api.http", "@base = "+srv.URL+`
@token = {{$processEnv WEEB_T_TOKEN}}

### List
GET {{base}}/items

### Create one
# @name create
POST {{base}}/items
    ?dry=false
    &tag={{name}}
Content-Type: application/json
Authorization: Bearer {{token}}

<@ ./item.json
`)
	t.Setenv("WEEB_T_TOKEN", "tok-e2e-123")
	t.Setenv("WEEB_HEADERS", "X-Team: weeb")
	t.Setenv("WEEB_TOKEN", "")
	t.Setenv("WEEB_BASE_URL", "")

	tests := []struct {
		name string
		args []string
		want seen
	}{
		{"by name", []string{api, "create", "--env", "dev", "--no-tui"}, seen{
			method: "POST", uri: "/items?dry=false&tag=widget", auth: "Bearer tok-e2e-123",
			ctype: "application/json", team: "weeb", body: `{"name": "widget"}`,
		}},
		{"by index", []string{api, "1", "--headless"}, seen{method: "GET", uri: "/items", team: "weeb"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout := captureFile(t, &os.Stdout)
			errs := swapErrW(t)
			if code := runHTTPFile(tt.args); code != 0 {
				t.Fatalf("exit = %d, stderr %q", code, errs.String())
			}
			select {
			case s := <-got:
				if s != tt.want {
					t.Errorf("server saw %+v, want %+v", s, tt.want)
				}
			default:
				t.Fatal("the server saw no request")
			}
			if out := stdout(); out != `{"id":7}` {
				t.Errorf("stdout = %q, want the streamed response body", out)
			}
		})
	}
}

// A failed send quotes the URL in both the error line and Do's log line; an
// env value in that URL must show as its reference in both.
func TestRunHTTPFileMasksEnvValues(t *testing.T) {
	const secret = "s3cret-e2e-value"
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close() // nothing listens now, so the send fails with a transport error

	api := writeHTTPTestFile(t, t.TempDir(), "api.http", "GET "+base+"/k/{{$processEnv WEEB_T_SECRET}}\n")
	t.Setenv("WEEB_T_SECRET", secret)
	t.Setenv("WEEB_PERSONA", "plain")
	t.Setenv("WEEB_LOG", "warn")
	t.Setenv("WEEB_LOG_FILE", "")
	t.Setenv("WEEB_LOG_FORMAT", "text")
	logs := captureFile(t, &os.Stderr) // the CLI logger writes here
	captureFile(t, &os.Stdout)
	errs := swapErrW(t)

	if code := runHTTPFile([]string{api, "1", "--no-tui"}); code != 1 {
		t.Fatalf("exit = %d, want 1 for a transport failure", code)
	}
	for what, text := range map[string]string{"error line": errs.String(), "log": logs()} {
		if strings.Contains(text, secret) {
			t.Errorf("%s leaks the env value: %q", what, text)
		}
		if !strings.Contains(text, "/k/{{$processEnv WEEB_T_SECRET}}") {
			t.Errorf("%s = %q, want the reference in place of the value", what, text)
		}
	}
}

func TestCompletionRunSubcommand(t *testing.T) {
	for _, shell := range []string{"zsh", "bash"} {
		var buf strings.Builder
		if code := runCompletion([]string{shell}, &buf); code != 0 {
			t.Fatalf("%s: exit %d", shell, code)
		}
		for _, want := range []string{" run", "*.http"} {
			if !strings.Contains(buf.String(), want) {
				t.Errorf("%s completion missing %q", shell, want)
			}
		}
	}
}
