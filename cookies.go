package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// parseCookieArg splits a curl -b/--cookie value the way curl does: with an
// '=' it is cookie data ("a=1; b=2") sent as a Cookie header; without one it
// names a Netscape cookie file to load into a jar. An empty value (curl's
// "turn the engine on" spelling) yields neither.
func parseCookieArg(v string) (header, file string, err error) {
	switch {
	case v == "":
		return "", "", nil
	case strings.Contains(v, "="):
		return v, "", nil
	case v == "-":
		return "", "", fmt.Errorf("-b - (cookies from stdin) isn't supported; name a cookie file")
	}
	return "", v, nil
}

// checkCookieJarArg vets a -c/--cookie-jar path.
func checkCookieJarArg(v string) error {
	if v == "-" {
		return fmt.Errorf("-c - (cookies to stdout) isn't supported; name a file")
	}
	return nil
}

// cookieSession is one request's cookie engine, switched on by -b FILE or
// --cookie-jar FILE. A net/http/cookiejar.Jar, with the public suffix list,
// decides which cookies go to which URL on every hop, redirects included.
// The jar keeps cookie attributes private, so cookieSession also records
// each cookie it is handed; save writes back the ones the jar still holds.
type cookieSession struct {
	jar *cookiejar.Jar

	mu      sync.Mutex
	entries map[cookieKey]jarEntry
}

// cookieKey identifies a cookie the way the jar does.
type cookieKey struct{ domain, path, name string }

// jarEntry is one cookie with the attributes a Netscape cookie file stores.
type jarEntry struct {
	domain           string // lowercase, no leading dot
	hostOnly         bool   // sent to domain exactly, not its subdomains
	path             string
	secure, httpOnly bool
	expires          time.Time // zero: a session cookie
	name, value      string
}

// newCookieSession returns an empty session, loading cookieFile into it when
// one is named. A missing file is not an error: curl's `-b jar -c jar` works
// on a first run, before the jar exists.
func newCookieSession(cookieFile string) (*cookieSession, error) {
	// The public suffix list stops a server from setting a cookie for a whole
	// registry (Domain=co.uk) that would then go to every site under it.
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}
	s := &cookieSession{jar: jar, entries: map[cookieKey]jarEntry{}}
	if cookieFile == "" {
		return s, nil
	}
	data, err := os.ReadFile(cookieFile)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading cookies: %w", err)
	}
	now := time.Now()
	for _, line := range strings.Split(string(data), "\n") {
		e, ok := parseNetscapeLine(strings.TrimRight(line, "\r"), now)
		if !ok {
			continue
		}
		c := &http.Cookie{
			Name: e.name, Value: e.value, Path: e.path,
			Secure: e.secure, HttpOnly: e.httpOnly, Expires: e.expires,
		}
		if !e.hostOnly {
			c.Domain = e.domain
		}
		// Through SetCookies, so the jar applies the same domain rules to a
		// file's cookies as to a server's.
		s.SetCookies(cookieURL(e), []*http.Cookie{c})
	}
	return s, nil
}

// Cookies implements http.CookieJar.
func (s *cookieSession) Cookies(u *url.URL) []*http.Cookie { return s.jar.Cookies(u) }

// SetCookies implements http.CookieJar, recording what the jar was given.
func (s *cookieSession) SetCookies(u *url.URL, cookies []*http.Cookie) {
	s.jar.SetCookies(u, cookies)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, c := range cookies {
		e := jarEntry{name: c.Name, value: c.Value, secure: c.Secure, httpOnly: c.HttpOnly, path: c.Path}
		if c.Domain == "" {
			e.domain, e.hostOnly = strings.ToLower(u.Hostname()), true
		} else {
			e.domain = strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		}
		if !strings.HasPrefix(e.path, "/") {
			e.path = defaultCookiePath(u.Path)
		}
		key := cookieKey{e.domain, e.path, e.name}
		switch {
		case c.MaxAge < 0:
			delete(s.entries, key)
			continue
		case c.MaxAge > 0:
			e.expires = now.Add(time.Duration(c.MaxAge) * time.Second)
		case !c.Expires.IsZero():
			if !c.Expires.After(now) {
				delete(s.entries, key)
				continue
			}
			e.expires = c.Expires
		}
		s.entries[key] = e
	}
}

// defaultCookiePath is RFC 6265 section 5.1.4's default-path: the request
// path up to, but not including, its last '/'.
func defaultCookiePath(p string) string {
	i := strings.LastIndexByte(p, '/')
	if !strings.HasPrefix(p, "/") || i <= 0 {
		return "/"
	}
	return p[:i]
}

// cookieURL is a URL the cookie e applies to, for handing it to the jar or
// asking the jar about it.
func cookieURL(e jarEntry) *url.URL {
	host := e.domain
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6
	}
	return &url.URL{Scheme: "https", Host: host, Path: e.path}
}

// live reports whether the jar still holds e: it may have rejected it (a
// domain the setting host can't claim, a public suffix), expired it, or seen
// it replaced or deleted since.
func (s *cookieSession) live(e jarEntry) bool {
	for _, c := range s.jar.Cookies(cookieURL(e)) {
		if c.Name == e.name && c.Value == e.value {
			return true
		}
	}
	return false
}

// save writes every live cookie to path in Netscape format (curl's -c), mode
// 0600: cookie files hold sessions.
func (s *cookieSession) save(path string) error {
	s.mu.Lock()
	keys := make([]cookieKey, 0, len(s.entries))
	for k := range s.entries {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.domain != b.domain {
			return a.domain < b.domain
		}
		if a.path != b.path {
			return a.path < b.path
		}
		return a.name < b.name
	})
	var b strings.Builder
	b.WriteString("# Netscape HTTP Cookie File\n# https://curl.se/docs/http-cookies.html\n# This file was generated by weeb. Edit at your own risk.\n\n")
	for _, k := range keys {
		e := s.entries[k]
		// A tab or newline would shift the file's columns; net/http never
		// produces one, so this only guards against the impossible.
		if strings.ContainsAny(e.domain+e.path+e.name+e.value, "\t\r\n") || !s.live(e) {
			continue
		}
		b.WriteString(netscapeLine(e))
	}
	s.mu.Unlock()
	return writePrivateFile(path, []byte(b.String()))
}

// netscapeLine renders one cookie as a Netscape cookie-file line:
// domain, include-subdomains, path, secure, expiry (unix, 0 = session),
// name, value — tab-separated, with curl's #HttpOnly_ prefix.
func netscapeLine(e jarEntry) string {
	domain, sub := e.domain, "FALSE"
	if !e.hostOnly {
		domain, sub = "."+e.domain, "TRUE"
	}
	if e.httpOnly {
		domain = "#HttpOnly_" + domain
	}
	secure := "FALSE"
	if e.secure {
		secure = "TRUE"
	}
	var exp int64
	if !e.expires.IsZero() {
		exp = e.expires.Unix()
	}
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%d\t%s\t%s\n", domain, sub, e.path, secure, exp, e.name, e.value)
}

// parseNetscapeLine parses one Netscape cookie-file line. Comments, blanks,
// malformed lines and expired cookies report false and are skipped, as curl
// skips them.
func parseNetscapeLine(line string, now time.Time) (jarEntry, bool) {
	httpOnly := false
	if rest, ok := strings.CutPrefix(line, "#HttpOnly_"); ok {
		line, httpOnly = rest, true
	} else if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
		return jarEntry{}, false
	}
	f := strings.Split(line, "\t")
	if len(f) == 6 {
		f = append(f, "") // an empty value can lose its trailing tab
	}
	if len(f) != 7 {
		return jarEntry{}, false
	}
	e := jarEntry{
		domain:   strings.TrimPrefix(strings.ToLower(f[0]), "."),
		hostOnly: !strings.EqualFold(f[1], "TRUE"),
		path:     f[2],
		secure:   strings.EqualFold(f[3], "TRUE"),
		httpOnly: httpOnly,
		name:     f[5],
		value:    f[6],
	}
	if e.domain == "" || e.name == "" {
		return jarEntry{}, false
	}
	if !strings.HasPrefix(e.path, "/") {
		e.path = "/"
	}
	exp, err := strconv.ParseInt(f[4], 10, 64)
	if err != nil {
		return jarEntry{}, false
	}
	if exp != 0 {
		if e.expires = time.Unix(exp, 0); !e.expires.After(now) {
			return jarEntry{}, false
		}
	}
	return e, true
}

// writePrivateFile replaces path with data at mode 0600. A regular file is
// written beside the target and renamed over it, so it is never briefly
// readable under an old, looser mode and a crash can't leave half a file.
// Anything else — /dev/null (curl's "cookies on, but don't keep them"), a
// FIFO — is written through, never renamed over.
func writePrivateFile(path string, data []byte) error {
	if fi, err := os.Stat(path); err == nil && !fi.Mode().IsRegular() {
		return os.WriteFile(path, data, 0o600)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".weeb-cookies-*") // created 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
