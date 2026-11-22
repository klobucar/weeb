package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// .http files: the request format shared by the VS Code REST Client and the
// JetBrains HTTP Client. `weeb run FILE` lists a file's requests and
// `weeb run FILE NAME|N` runs one.
//
// Parsing keeps every URL, header and body line as written, with its line
// number; {{variables}} are substituted only by resolve, and only for the
// request being run. That split is what keeps environment values out of
// listings and errors: the listing prints the templates, and every error
// names a variable and a line, never a value.

// httpLine is one source line kept with its 1-based line number, so an error
// can point at the line a variable was used on.
type httpLine struct {
	Text string
	Line int
}

// httpBodyLine is a body line, or a "< path" / "<@ path" include whose Text
// is the path as written.
type httpBodyLine struct {
	httpLine
	Include bool // "< path": splice in the file's bytes as-is
	Expand  bool // "<@ path": splice in the file with {{variables}} substituted
}

type httpHeader struct {
	Key, Value string
	Line       int
}

// httpRequest is one request of a .http file, still in template form.
type httpRequest struct {
	Index      int    // 1-based position: what `weeb run FILE N` selects
	Name       string // from "# @name NAME"
	Title      string // the text after ###
	Line       int    // the request line
	Method     string
	URL        []httpLine // the request-line target, then any ?/& continuation lines
	Headers    []httpHeader
	Body       []httpBodyLine
	NoRedirect bool // "# @no-redirect"
}

// urlTemplate is the URL as written, continuation lines joined: what the
// listing shows.
func (r *httpRequest) urlTemplate() string {
	var b strings.Builder
	for _, l := range r.URL {
		b.WriteString(l.Text)
	}
	return b.String()
}

type httpVar struct {
	Value string
	Line  int
}

type httpFile struct {
	Path     string
	Dir      string // includes resolve against this
	Requests []*httpRequest
	Vars     map[string]httpVar // file-level "@name = value" definitions
}

// parseHTTPFile reads and parses a .http file.
func parseHTTPFile(path string) (*httpFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := parseHTTP(string(data))
	if err != nil {
		return nil, err
	}
	f.Path, f.Dir = path, filepath.Dir(path)
	return f, nil
}

type httpState int

const (
	stPre     httpState = iota // before the request line: comments, @name, @variables
	stURL                      // just after the request line: ?/& query continuation lines
	stHeaders                  // "Name: value" lines up to the first blank line
	stBody                     // everything up to the next ###
	stSkip                     // a response handler or output redirect: ignored up to the next ###
)

type httpParser struct {
	f          *httpFile
	st         httpState
	cur        *httpRequest // this block's request; nil until its request line
	title      string
	name       string
	nameLine   int
	noRedirect bool
	inScript   bool           // inside a multi-line "< {% … %}" pre-request script
	names      map[string]int // request name -> line, to refuse duplicates
}

// parseHTTP parses .http source. Requests are separated by lines starting
// with ###; within one, comments, directives and @variables come first, then
// the request line, headers, a blank line and the body.
func parseHTTP(src string) (*httpFile, error) {
	p := &httpParser{f: &httpFile{Vars: map[string]httpVar{}}, names: map[string]int{}}
	src = strings.TrimPrefix(src, "\ufeff")
	for i, line := range strings.Split(src, "\n") {
		if err := p.line(strings.TrimSuffix(line, "\r"), i+1); err != nil {
			return nil, err
		}
	}
	if err := p.endBlock(); err != nil {
		return nil, err
	}
	return p.f, nil
}

func (p *httpParser) line(line string, n int) error {
	if strings.HasPrefix(line, "###") {
		if err := p.endBlock(); err != nil {
			return err
		}
		p.title = strings.TrimSpace(strings.TrimLeft(line, "#"))
		return nil
	}
	t := strings.TrimSpace(line)
	switch p.st {
	case stPre:
		return p.preLine(t, n)
	case stURL:
		if strings.HasPrefix(t, "?") || strings.HasPrefix(t, "&") {
			p.cur.URL = append(p.cur.URL, httpLine{t, n})
			return nil
		}
		p.st = stHeaders
		return p.headerLine(t, n)
	case stHeaders:
		return p.headerLine(t, n)
	case stBody:
		return p.bodyLine(line, n)
	}
	return nil
}

func (p *httpParser) preLine(t string, n int) error {
	switch {
	case p.inScript:
		p.inScript = !strings.Contains(t, "%}")
	case t == "":
	case strings.HasPrefix(t, "#"), strings.HasPrefix(t, "//"):
		return p.directive(t, n)
	case strings.HasPrefix(t, "@"):
		return p.variable(t, n)
	case strings.HasPrefix(t, "<"):
		// A JetBrains pre-request script ("< {% … %}" or "< script.js").
		// Scripts only set variables, so skipping one leaves the variables
		// it would have set undefined, and resolve reports them by name.
		p.inScript = strings.Contains(t, "{%") && !strings.Contains(t, "%}")
	default:
		return p.requestLine(t, n)
	}
	return nil
}

// directive handles a comment line, picking out "# @name NAME" and
// "# @no-redirect". Other directives (@no-log, @no-cookie-jar, @timeout, ...)
// stay comments; a variable an @prompt would have asked for is reported as
// undefined when it's used.
func (p *httpParser) directive(t string, n int) error {
	rest, ok := strings.CutPrefix(t, "//")
	if !ok {
		rest = strings.TrimLeft(t, "#")
	}
	rest, ok = strings.CutPrefix(strings.TrimSpace(rest), "@")
	if !ok {
		return nil
	}
	key, val := rest, ""
	if i := strings.IndexAny(rest, " \t="); i >= 0 {
		key, val = rest[:i], rest[i:]
	}
	val = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(val), "="))
	switch key {
	case "name":
		if val == "" {
			return fmt.Errorf("line %d: @name needs a name", n)
		}
		p.name, p.nameLine = val, n
	case "no-redirect":
		p.noRedirect = true
	}
	return nil
}

func (p *httpParser) variable(t string, n int) error {
	name, val, ok := strings.Cut(t[1:], "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" || strings.HasPrefix(name, "$") || strings.ContainsAny(name, " \t{}") {
		return fmt.Errorf("line %d: bad variable definition (want @name = value)", n)
	}
	p.f.Vars[name] = httpVar{Value: strings.TrimSpace(val), Line: n}
	return nil
}

var httpVersionSuffix = regexp.MustCompile(`\s+HTTP/\d+(\.\d+)?$`)

var knownHTTPMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
	"HEAD": true, "OPTIONS": true, "CONNECT": true, "TRACE": true,
}

// requestLine parses "[METHOD] URL [HTTP/version]". The method is the first
// word when it's a known method (any case) or an all-caps custom one (PURGE,
// PROPFIND); without one the request is a GET.
func (p *httpParser) requestLine(t string, n int) error {
	line := httpVersionSuffix.ReplaceAllString(t, "")
	method, target := "GET", line
	tok, rest, spaced := line, "", false
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		tok, rest, spaced = line[:i], line[i+1:], true
	}
	switch {
	case spaced && isHTTPMethod(tok):
		method, target = strings.ToUpper(tok), strings.TrimSpace(rest)
	case !spaced && knownHTTPMethods[strings.ToUpper(tok)]:
		return fmt.Errorf("line %d: %s has no URL", n, tok)
	}
	if hasBareSpace(target) {
		hint := ""
		if tok == "curl" {
			hint = "; to run a curl command, use weeb curl"
		}
		return fmt.Errorf("line %d: can't read request line %q (want [METHOD] URL [HTTP/version])%s", n, t, hint)
	}
	p.cur = &httpRequest{
		Name: p.name, Title: p.title, Line: n, Method: method,
		URL: []httpLine{{target, n}}, NoRedirect: p.noRedirect,
	}
	p.st = stURL
	return nil
}

func isHTTPMethod(tok string) bool {
	if knownHTTPMethods[strings.ToUpper(tok)] {
		return true
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] < 'A' || tok[i] > 'Z' {
			return false
		}
	}
	return tok != ""
}

// hasBareSpace reports whitespace outside {{…}}: a URL has none, but a
// reference may ({{$processEnv HOST}}).
func hasBareSpace(s string) bool {
	for {
		i := strings.Index(s, "{{")
		if i < 0 {
			break
		}
		j := strings.Index(s[i:], "}}")
		if j < 0 {
			break
		}
		if strings.ContainsAny(s[:i], " \t") {
			return true
		}
		s = s[i+j+2:]
	}
	return strings.ContainsAny(s, " \t")
}

func (p *httpParser) headerLine(t string, n int) error {
	switch {
	case t == "":
		p.st = stBody
	case strings.HasPrefix(t, "#"), strings.HasPrefix(t, "//"):
		// a comment between headers
	case isResponseHandler(t):
		p.st = stSkip
	default:
		k, v, ok := strings.Cut(t, ":")
		k = strings.TrimSpace(k)
		if !ok || !validHeaderName(k) {
			return fmt.Errorf("line %d: expected a header (Name: value) or a blank line before the body, got %q", n, t)
		}
		p.cur.Headers = append(p.cur.Headers, httpHeader{Key: k, Value: strings.TrimSpace(v), Line: n})
	}
	return nil
}

// bodyLine takes body lines verbatim: a # or // line is body text here, since
// JSON, GraphQL and YAML bodies can legitimately hold one. Includes and
// response handlers must start at column 0.
func (p *httpParser) bodyLine(line string, n int) error {
	switch {
	case isResponseHandler(line):
		p.st = stSkip
	case strings.HasPrefix(line, "<@"):
		return p.include(strings.TrimSpace(line[2:]), true, n)
	case strings.HasPrefix(line, "< "), strings.HasPrefix(line, "<\t"):
		return p.include(strings.TrimSpace(line[1:]), false, n)
	default:
		p.cur.Body = append(p.cur.Body, httpBodyLine{httpLine: httpLine{line, n}})
	}
	return nil
}

func (p *httpParser) include(path string, expand bool, n int) error {
	if path == "" {
		return fmt.Errorf("line %d: include needs a file path, e.g. < ./body.json", n)
	}
	p.cur.Body = append(p.cur.Body, httpBodyLine{httpLine: httpLine{path, n}, Include: true, Expand: expand})
	return nil
}

// isResponseHandler reports a JetBrains post-response line: a handler script
// ("> {% … %}", "> check.js"), an output redirect (">> out.json", ">>! out")
// or a response reference ("<> previous.json"). They act on the response,
// never the request, so the rest of the request's block is skipped.
func isResponseHandler(s string) bool {
	switch {
	case strings.HasPrefix(s, ">>"), strings.HasPrefix(s, "<> "):
		return true
	case strings.HasPrefix(s, ">"):
		return len(s) == 1 || s[1] == ' ' || s[1] == '\t' || s[1] == '{'
	}
	return false
}

// validHeaderName reports an RFC 9110 token, which is what a header name is.
func validHeaderName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return s != ""
}

func (p *httpParser) endBlock() error {
	if r := p.cur; r != nil {
		r.Body = trimBlankBody(r.Body)
		if r.Name != "" {
			if first, dup := p.names[r.Name]; dup {
				return fmt.Errorf("line %d: duplicate request name %q (first used on line %d)", p.nameLine, r.Name, first)
			}
			p.names[r.Name] = p.nameLine
		}
		r.Index = len(p.f.Requests) + 1
		p.f.Requests = append(p.f.Requests, r)
	} else if p.name != "" {
		return fmt.Errorf("line %d: @name %s isn't followed by a request", p.nameLine, p.name)
	}
	p.cur, p.st, p.title, p.name, p.nameLine, p.noRedirect, p.inScript = nil, stPre, "", "", 0, false, false
	return nil
}

// trimBlankBody drops blank lines around the body: the separator before the
// next ### is formatting, not payload.
func trimBlankBody(b []httpBodyLine) []httpBodyLine {
	blank := func(l httpBodyLine) bool { return !l.Include && strings.TrimSpace(l.Text) == "" }
	for len(b) > 0 && blank(b[0]) {
		b = b[1:]
	}
	for len(b) > 0 && blank(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	return b
}

// find selects a request by @name, or else by 1-based index.
func (f *httpFile) find(sel string) (*httpRequest, error) {
	for _, r := range f.Requests {
		if r.Name == sel {
			return r, nil
		}
	}
	if n, err := strconv.Atoi(sel); err == nil {
		if n >= 1 && n <= len(f.Requests) {
			return f.Requests[n-1], nil
		}
		return nil, fmt.Errorf("no request %d (the file has %d)", n, len(f.Requests))
	}
	return nil, fmt.Errorf("no request named %q (run 'weeb run %s' to list them)", sel, f.Path)
}

// ---- variables ---------------------------------------------------------------

// httpExpandMax bounds what variables may expand to, so a file whose
// variables double each other can't exhaust memory.
const httpExpandMax = 64 << 20

type httpExpander struct {
	vars map[string]httpVar
	env  *httpEnv // --env variables; nil when none
	mask *secretMask
	hint string // appended to "undefined variable" errors
}

func lineAt(n int) string { return fmt.Sprintf("line %d", n) }

// expand substitutes every {{reference}} in s. at says where s came from
// ("line 12"); errors carry it, plus the reference, never a value.
func (x *httpExpander) expand(s, at string) (string, error) { return x.expandIn(s, at, nil) }

func (x *httpExpander) expandIn(s, at string, stack []string) (string, error) {
	var b strings.Builder
	for {
		i := strings.Index(s, "{{")
		if i < 0 {
			break
		}
		j := strings.Index(s[i+2:], "}}")
		if j < 0 {
			break // an unclosed {{ is literal text
		}
		b.WriteString(s[:i])
		v, err := x.lookup(strings.TrimSpace(s[i+2:i+2+j]), at, stack)
		if err != nil {
			return "", err
		}
		if b.Len()+len(v) > httpExpandMax {
			return "", fmt.Errorf("%s: variables expand past %s", at, humanSize(httpExpandMax))
		}
		b.WriteString(v)
		s = s[i+2+j+2:]
	}
	b.WriteString(s)
	return b.String(), nil
}

func (x *httpExpander) lookup(ref, at string, stack []string) (string, error) {
	switch {
	case ref == "":
		return "", fmt.Errorf("%s: empty variable {{}}", at)
	case ref == "$processEnv" || strings.HasPrefix(ref, "$processEnv "):
		name := strings.TrimSpace(strings.TrimPrefix(ref, "$processEnv"))
		return x.osEnv(name, "{{$processEnv "+name+"}}", at)
	case strings.HasPrefix(ref, "$env."):
		return x.osEnv(strings.TrimPrefix(ref, "$env."), "{{"+ref+"}}", at)
	case strings.HasPrefix(ref, "$"):
		return dynamicVar(ref, at)
	case slices.Contains(stack, ref):
		return "", fmt.Errorf("%s: variable {{%s}} refers to itself (%s)", at, ref, strings.Join(append(stack, ref), " -> "))
	}
	next := append(stack[:len(stack):len(stack)], ref)
	if v, ok := x.vars[ref]; ok {
		return x.expandIn(v.Value, lineAt(v.Line), next)
	}
	if x.env != nil {
		if v, ok := x.env.vars[ref]; ok {
			file := httpEnvFile
			if x.env.private[ref] {
				file = httpPrivateEnvFile
			}
			s, err := x.expandIn(v, file, next)
			if err == nil && x.env.private[ref] {
				x.mask.add(s, "{{"+ref+"}}") // the private file is where secrets live
			}
			return s, err
		}
	}
	if parts := strings.SplitN(ref, ".", 3); len(parts) > 1 && (parts[1] == "response" || parts[1] == "request") {
		return "", fmt.Errorf("%s: {{%s}} reads another request's response, and weeb doesn't chain requests; run that request on its own and pass the value in through an environment variable", at, ref)
	}
	return "", fmt.Errorf("%s: undefined variable {{%s}}%s", at, ref, x.hint)
}

// osEnv reads an environment variable for {{$processEnv NAME}} (VS Code) or
// {{$env.NAME}} (JetBrains). Its value goes into the mask: the error names
// only the variable, and anything printed about the request later is scrubbed.
func (x *httpExpander) osEnv(name, ref, at string) (string, error) {
	if name == "" || strings.ContainsAny(name, " \t%") {
		return "", fmt.Errorf("%s: %s isn't supported; name an environment variable, as in {{$processEnv TOKEN}}", at, ref)
	}
	v, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("%s: environment variable %s is not set (used as %s)", at, name, ref)
	}
	x.mask.add(v, ref)
	return v, nil
}

// dynamicVar covers the generated values both clients spell the same way.
func dynamicVar(ref, at string) (string, error) {
	switch ref {
	case "$guid", "$uuid", "$random.uuid":
		var b [16]byte
		_, _ = rand.Read(b[:])  // crypto/rand.Read never fails
		b[6] = b[6]&0x0f | 0x40 // version 4
		b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
		return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
	case "$timestamp":
		return strconv.FormatInt(time.Now().Unix(), 10), nil
	case "$isoTimestamp":
		return time.Now().UTC().Format(time.RFC3339), nil
	}
	return "", fmt.Errorf("%s: unsupported dynamic variable {{%s}}", at, ref)
}

// resolve expands one request into a RequestSpec. The returned mask holds
// every value that came from an environment variable or the private env file.
func (f *httpFile) resolve(r *httpRequest, env *httpEnv, hint string) (RequestSpec, *secretMask, error) {
	x := &httpExpander{vars: f.Vars, env: env, mask: &secretMask{}, hint: hint}
	spec := RequestSpec{Method: r.Method, NoFollow: r.NoRedirect}

	var u strings.Builder
	for _, l := range r.URL {
		s, err := x.expand(l.Text, lineAt(l.Line))
		if err != nil {
			return RequestSpec{}, nil, err
		}
		u.WriteString(s)
	}
	spec.URL = u.String()

	sep := "\n"
	for _, h := range r.Headers {
		v, err := x.expand(h.Value, lineAt(h.Line))
		if err != nil {
			return RequestSpec{}, nil, err
		}
		spec.Headers = append(spec.Headers, Header{Key: h.Key, Value: v})
		// Multipart framing is CRLF; servers are entitled to reject bare LF.
		if strings.EqualFold(h.Key, "Content-Type") && strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "multipart/") {
			sep = "\r\n"
		}
	}

	if len(r.Body) > 0 {
		parts := make([]string, 0, len(r.Body))
		for _, l := range r.Body {
			s, err := f.bodyPart(x, l)
			if err != nil {
				return RequestSpec{}, nil, err
			}
			parts = append(parts, s)
		}
		spec.Body = []byte(strings.Join(parts, sep))
	}
	return spec, x.mask, nil
}

func (f *httpFile) bodyPart(x *httpExpander, l httpBodyLine) (string, error) {
	at := lineAt(l.Line)
	if !l.Include {
		return x.expand(l.Text, at)
	}
	path, err := x.expand(l.Text, at)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(f.Dir, path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		// Name the path as written: the expanded one may hold an env value.
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return "", fmt.Errorf("%s: include %s: %v", at, l.Text, err)
	}
	if !l.Expand {
		return string(b), nil
	}
	return x.expand(string(b), fmt.Sprintf("%s (included on line %d)", l.Text, l.Line))
}

// ---- JetBrains environment files ---------------------------------------------

const (
	httpEnvFile        = "http-client.env.json"
	httpPrivateEnvFile = "http-client.private.env.json"
)

// httpEnv is the variable set --env selects.
type httpEnv struct {
	vars    map[string]string
	private map[string]bool // names whose value came from the private file
}

// loadHTTPEnv reads http-client.env.json and http-client.private.env.json
// from dir and merges the "$shared" environment with the named one (if any).
// Later layers win: $shared before the named environment, the public file
// before the private one. It also returns the environment names on offer.
func loadHTTPEnv(dir, name string) (*httpEnv, []string, error) {
	var layers [2]map[string]map[string]any
	found, seen := false, map[string]bool{}
	for i, file := range []string{httpEnvFile, httpPrivateEnvFile} {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err := dec.Decode(&layers[i]); err != nil {
			return nil, nil, fmt.Errorf("%s: %v", file, err)
		}
		found = true
		for k := range layers[i] {
			if k != "$shared" {
				seen[k] = true
			}
		}
	}
	names := make([]string, 0, len(seen))
	for k := range seen {
		names = append(names, k)
	}
	sort.Strings(names)

	if name != "" && !seen[name] {
		if !found {
			return nil, nil, fmt.Errorf("--env %s: no %s next to the .http file", name, httpEnvFile)
		}
		return nil, nil, fmt.Errorf("--env %s: no such environment in %s (have: %s)", name, httpEnvFile, strings.Join(names, ", "))
	}

	env := &httpEnv{vars: map[string]string{}, private: map[string]bool{}}
	for _, envName := range []string{"$shared", name} {
		if envName == "" {
			continue
		}
		for i, envs := range layers {
			for k, v := range envs[envName] {
				s, ok := envScalar(v)
				if !ok {
					continue // objects hold SSL/auth settings, not variables
				}
				env.vars[k], env.private[k] = s, i == 1
			}
		}
	}
	return env, names, nil
}

func envScalar(v any) (string, bool) {
	switch v := v.(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	case bool:
		return strconv.FormatBool(v), true
	}
	return "", false
}

// ---- masking -----------------------------------------------------------------

// secretMask maps values that came from environment variables (or the private
// env file) back to the reference that produced them. A transport error quotes
// the URL, and Do logs it, so a run scrubs both: the output reads
// {{$processEnv TOKEN}} where the token would have been.
type secretMask struct {
	refs map[string]string // value, and its URL-escaped forms -> reference
	r    *strings.Replacer // rebuilt by add, so apply never writes
}

// minMaskLen leaves very short values alone: they can't be meaningful secrets,
// and replacing every "1" or "80" would garble the text being cleaned.
const minMaskLen = 4

func (m *secretMask) add(value, ref string) {
	if len(value) < minMaskLen {
		return
	}
	if m.refs == nil {
		m.refs = map[string]string{}
	}
	for _, v := range []string{value, url.PathEscape(value), url.QueryEscape(value)} {
		if _, ok := m.refs[v]; !ok {
			m.refs[v] = ref
		}
	}
	olds := make([]string, 0, len(m.refs))
	for v := range m.refs {
		olds = append(olds, v)
	}
	// Longest first: strings.Replacer tries olds in argument order at each
	// position, so a value that contains another must come first.
	sort.Slice(olds, func(i, j int) bool {
		if len(olds[i]) != len(olds[j]) {
			return len(olds[i]) > len(olds[j])
		}
		return olds[i] < olds[j]
	})
	pairs := make([]string, 0, 2*len(olds))
	for _, v := range olds {
		pairs = append(pairs, v, m.refs[v])
	}
	m.r = strings.NewReplacer(pairs...)
}

func (m *secretMask) empty() bool { return m == nil || m.r == nil }

func (m *secretMask) apply(s string) string {
	if m.empty() {
		return s
	}
	return m.r.Replace(s)
}

// writer wraps w so everything written through it is masked. charm/log writes
// each record in one call, so a value is never split across writes.
func (m *secretMask) writer(w io.Writer) io.Writer { return maskWriter{w: w, m: m} }

type maskWriter struct {
	w io.Writer
	m *secretMask
}

func (mw maskWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(mw.w, mw.m.apply(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ---- weeb run ----------------------------------------------------------------

// renderHTTPList prints one line per request: index, name (or title), method
// and the URL as written, so {{$processEnv TOKEN}} shows as the reference,
// never its value.
func renderHTTPList(w io.Writer, f *httpFile) {
	const maxLabel = 40
	labels := make([]string, len(f.Requests))
	width := 0
	for i, r := range f.Requests {
		l := r.Name
		if l == "" {
			l = r.Title
		}
		if l == "" {
			l = "-"
		}
		if utf8.RuneCountInString(l) > maxLabel {
			l = string([]rune(l)[:maxLabel-1]) + "…"
		}
		labels[i] = l
		width = max(width, utf8.RuneCountInString(l))
	}
	for i, r := range f.Requests {
		fmt.Fprintf(w, "%3d  %-*s  %-7s %s\n", r.Index, width, labels[i], r.Method, r.urlTemplate())
	}
}

// runHTTPFile handles `weeb run FILE.http [NAME|N] [--env NAME] [--no-tui]`.
// Without a selector it lists the requests; with one it runs that request:
// prefilled in the TUI at a terminal, or headless (the runCurlImport path)
// when output is script-bound or --no-tui asks for it. Problems with the
// file are usage errors (2), as a bad command is for weeb curl.
func runHTTPFile(args []string) int {
	var path, sel, envName string
	noTUI := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--env":
			v, err := nextArg(args, &i, arg)
			if err != nil {
				fmt.Fprintln(errW, "weeb:", err)
				return 2
			}
			envName = v
		case strings.HasPrefix(arg, "--env="):
			envName = strings.TrimPrefix(arg, "--env=")
		case arg == "--no-tui" || arg == "--headless":
			noTUI = true
		case strings.HasPrefix(arg, "-") && arg != "-":
			fmt.Fprintf(errW, "weeb: unknown flag %q\n", arg)
			return 2
		case path == "":
			path = arg
		case sel == "":
			sel = arg
		default:
			fmt.Fprintf(errW, "weeb: unexpected argument %q\n", arg)
			return 2
		}
	}
	if path == "" {
		fmt.Fprintln(errW, "weeb: run needs a .http file, e.g. weeb run api.http [NAME|N]")
		return 2
	}

	f, err := parseHTTPFile(path)
	if err != nil {
		fmt.Fprintf(errW, "weeb: %s: %v\n", path, err)
		return 2
	}
	if len(f.Requests) == 0 {
		fmt.Fprintf(errW, "weeb: no requests in %s\n", path)
		return 2
	}
	if sel == "" {
		renderHTTPList(outW, f)
		return 0
	}
	r, err := f.find(sel)
	if err != nil {
		fmt.Fprintf(errW, "weeb: %s: %v\n", path, err)
		return 2
	}

	env, envNames, err := loadHTTPEnv(f.Dir, envName)
	if err != nil {
		fmt.Fprintln(errW, "weeb:", err)
		return 2
	}
	hint := ""
	if envName == "" && len(envNames) > 0 {
		hint = fmt.Sprintf("; %s defines environments (%s), pick one with --env", httpEnvFile, strings.Join(envNames, ", "))
	}
	spec, mask, err := f.resolve(r, env, hint)
	if err != nil {
		fmt.Fprintf(errW, "weeb: %s: %v\n", path, err)
		return 2
	}

	a := cliArgs{method: spec.Method, url: spec.URL, headers: spec.Headers, body: spec.Body, noFollow: spec.NoFollow, noTUI: noTUI}
	if !a.headless() {
		return runTUI(&a) // the form shows the values, like any prefill
	}

	if err := applyMaxBody(""); err != nil { // WEEB_MAX_BODY still applies
		fmt.Fprintln(errW, "weeb:", err)
		return 2
	}
	var wrap []func(io.Writer) io.Writer
	if !mask.empty() {
		wrap = append(wrap, mask.writer) // Do logs the URL
	}
	logger, _, cleanup := newLogger(modeCLI, wrap...)
	defer cleanup()
	client := newClient(logger, newErrorChan())
	if !stdoutIsTTY() {
		spec.BodySink = os.Stdout // piped: stream the raw bytes, uncapped
	}
	res := client.Do(spec)
	res.DisplayErr = mask.apply(res.DisplayErr) // transport errors quote the URL
	for i, u := range res.Redirects {
		res.Redirects[i] = mask.apply(u)
	}
	return emitResult(res, false, false, envBool("WEEB_PRETTY", true), false)
}
