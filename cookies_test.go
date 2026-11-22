package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseCookieArg(t *testing.T) {
	cases := []struct {
		in, header, file string
		wantErr          bool
	}{
		{in: "a=1; b=2", header: "a=1; b=2"},
		{in: "a=", header: "a="},
		{in: "jar.txt", file: "jar.txt"},
		{in: ""},
		{in: "-", wantErr: true},
	}
	for _, c := range cases {
		h, f, err := parseCookieArg(c.in)
		if h != c.header || f != c.file || (err != nil) != c.wantErr {
			t.Errorf("parseCookieArg(%q) = %q, %q, %v", c.in, h, f, err)
		}
	}
}

// A Netscape cookie file loads into the jar with its rules intact (host-only
// vs domain, secure, expiry) and saves back in the same format, mode 0600.
func TestNetscapeCookieFileRoundTrip(t *testing.T) {
	future := time.Now().Add(24 * time.Hour).Unix()
	in := strings.Join([]string{
		"# Netscape HTTP Cookie File",
		"",
		"example.com\tFALSE\t/\tFALSE\t0\thost\th1",
		".example.org\tTRUE\t/\tTRUE\t" + itoa(future) + "\tdom\td1",
		"#HttpOnly_example.com\tFALSE\t/api\tFALSE\t0\thonly\tx",
		"example.com\tFALSE\t/\tFALSE\t1\texpired\tgone",
		"example.com\tFALSE\t/\tFALSE\t0\tempty", // six fields: an empty value
		"not a cookie line",
	}, "\r\n")
	s, err := newCookieSession(writeFile(t, "in.txt", []byte(in)))
	if err != nil {
		t.Fatal(err)
	}

	names := func(raw string) string {
		u, _ := url.Parse(raw)
		var out []string
		for _, c := range s.Cookies(u) {
			out = append(out, c.Name)
		}
		return strings.Join(out, ",")
	}
	for raw, want := range map[string]string{
		"https://example.com/":        "empty,host",
		"https://example.com/api/x":   "empty,honly,host",
		"https://www.example.com/":    "", // host-only cookies don't reach subdomains
		"https://a.example.org/":      "dom",
		"http://a.example.org/":       "", // secure
		"https://example.net/":        "",
		"https://example.com/expired": "empty,host",
	} {
		if got := sortedCSV(names(raw)); got != want {
			t.Errorf("cookies for %s = %q, want %q", raw, got, want)
		}
	}

	out := filepath.Join(t.TempDir(), "out.txt")
	if err := s.save(out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if l != "" && !strings.HasPrefix(l, "# ") {
			lines = append(lines, l)
		}
	}
	want := []string{
		"example.com\tFALSE\t/\tFALSE\t0\tempty\t",
		"example.com\tFALSE\t/\tFALSE\t0\thost\th1",
		"#HttpOnly_example.com\tFALSE\t/api\tFALSE\t0\thonly\tx",
		".example.org\tTRUE\t/\tTRUE\t" + itoa(future) + "\tdom\td1",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("saved jar:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
			t.Errorf("jar mode = %v, want 0600", fi.Mode().Perm())
		}
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func sortedCSV(s string) string {
	if s == "" {
		return ""
	}
	parts := strings.Split(s, ",")
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// The public suffix list keeps a server from planting a cookie on a whole
// registry, and a rejected cookie is never saved.
func TestCookieSessionPublicSuffix(t *testing.T) {
	s, err := newCookieSession("")
	if err != nil {
		t.Fatal(err)
	}
	from, _ := url.Parse("https://a.example.co.uk/")
	s.SetCookies(from, []*http.Cookie{
		{Name: "super", Value: "1", Domain: "co.uk"},
		{Name: "ok", Value: "1", Domain: "example.co.uk"},
	})
	other, _ := url.Parse("https://b.other.co.uk/")
	if got := s.Cookies(other); len(got) != 0 {
		t.Errorf("a co.uk cookie reached another site: %v", got)
	}
	sibling, _ := url.Parse("https://b.example.co.uk/")
	if got := s.Cookies(sibling); len(got) != 1 || got[0].Name != "ok" {
		t.Errorf("cookies for a sibling = %v, want the example.co.uk one", got)
	}
	out := filepath.Join(t.TempDir(), "jar.txt")
	if err := s.save(out); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(out); strings.Contains(string(data), "super") {
		t.Errorf("a rejected cookie was saved:\n%s", data)
	}
}

// --cookie-jar records cookies set along a redirect chain (the jar is live
// on every hop), and -b FILE sends them on the next run. Without either
// option weeb keeps no cookies at all.
func TestClientDoCookieJar(t *testing.T) {
	clearRequestEnv(t)
	var meCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/", HttpOnly: true})
			http.Redirect(w, r, "/me", http.StatusFound)
		case "/me":
			meCookie = r.Header.Get("Cookie")
		}
	}))
	defer srv.Close()

	jarPath := filepath.Join(t.TempDir(), "jar.txt")
	res := testClient().Do(RequestSpec{URL: srv.URL + "/login", CookieJar: jarPath})
	if !res.OK() {
		t.Fatalf("login: %v", res.Err)
	}
	if meCookie != "sid=abc" {
		t.Errorf("redirect hop sent Cookie %q, want sid=abc from the jar", meCookie)
	}
	data, err := os.ReadFile(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "#HttpOnly_127.0.0.1\tFALSE\t/\tFALSE\t0\tsid\tabc") {
		t.Errorf("jar file missing the session cookie:\n%s", data)
	}

	meCookie = ""
	if res := testClient().Do(RequestSpec{URL: srv.URL + "/me", CookieFile: jarPath}); !res.OK() || meCookie != "sid=abc" {
		t.Errorf("-b FILE: Cookie %q (err %v), want sid=abc", meCookie, res.Err)
	}

	meCookie = ""
	if res := testClient().Do(RequestSpec{URL: srv.URL + "/login"}); !res.OK() || meCookie != "" {
		t.Errorf("no jar: Cookie %q (err %v), want none", meCookie, res.Err)
	}

	// curl's `-b jar -c jar` on a first run: the jar file doesn't exist yet.
	fresh := filepath.Join(t.TempDir(), "new.txt")
	if res := testClient().Do(RequestSpec{URL: srv.URL + "/login", CookieFile: fresh, CookieJar: fresh}); !res.OK() {
		t.Errorf("missing -b FILE should be fine: %v", res.Err)
	}

	// A jar that can't be written fails the run on both seams.
	res = testClient().Do(RequestSpec{URL: srv.URL + "/me", CookieJar: filepath.Join(t.TempDir(), "no", "such", "dir", "jar.txt")})
	if res.Err == nil || !strings.Contains(res.DisplayErr, "cookie jar") {
		t.Errorf("unwritable jar: err %v, display %q", res.Err, res.DisplayErr)
	}
}

// On a redirect, jar cookies follow cookiejar's rules — host-based, ports
// ignored — while a -b 'a=1' Cookie header is the user's credential and is
// stripped by redirectPolicy on any cross-origin hop.
func TestRedirectJarCookieRules(t *testing.T) {
	clearRequestEnv(t)
	var got string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Cookie")
	}))
	defer target.Close()
	port := target.URL[strings.LastIndexByte(target.URL, ':')+1:]

	cases := []struct {
		name, to, want string
	}{
		// Another port on the same host: a different origin for credentials,
		// the same host for cookies.
		{"same host, other port", "http://127.0.0.1:" + port + "/", "jar=1"},
		// Another host: neither.
		{"other host", "http://localhost:" + port + "/", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hopper := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "jar", Value: "1"})
				http.Redirect(w, r, c.to, http.StatusFound)
			}))
			defer hopper.Close()
			got = "unset"
			res := testClient().Do(RequestSpec{
				URL:        hopper.URL,
				Headers:    []Header{{Key: "Cookie", Value: "user=1"}},
				CookieFile: filepath.Join(t.TempDir(), "none.txt"),
			})
			if !res.OK() {
				t.Fatalf("request failed: %v", res.Err)
			}
			if got != c.want {
				t.Errorf("target got Cookie %q, want %q", got, c.want)
			}
		})
	}
}

// writePrivateFile tightens an existing file to 0600 and writes through
// non-regular files (curl's -c /dev/null) instead of renaming over them.
func TestWritePrivateFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and /dev/null")
	}
	p := filepath.Join(t.TempDir(), "jar.txt")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Errorf("content = %q", b)
	}
	if err := writePrivateFile(os.DevNull, []byte("x")); err != nil {
		t.Errorf("writing %s: %v", os.DevNull, err)
	}
	if fi, err := os.Stat(os.DevNull); err != nil || fi.Mode().IsRegular() {
		t.Errorf("%s is no longer a device: %v", os.DevNull, err)
	}
}
