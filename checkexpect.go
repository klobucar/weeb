package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"
)

// --expect-header and --expect-json: assertions on response headers and on
// fields of a JSON body, for --check. Both compile in checkOpts, so a
// malformed one is a usage error (UNKNOWN) before any request goes out. Both
// evaluate to checkAssertion rows: the plugin line leads with the first
// failure, and --json lists every row.

// checkAssertion is one evaluated assertion, as listed in the --json verdict.
type checkAssertion struct {
	Type    string  `json:"type"`              // status | body | header | json
	Expect  string  `json:"expect"`            // the assertion as given
	OK      bool    `json:"ok"`                // passed
	Actual  *string `json:"actual,omitempty"`  // what was observed, clipped; omitted when nothing was there
	Message string  `json:"message,omitempty"` // why it failed, worded as the plugin line would say it

	// skipped: not evaluated because the body was incomplete. It counts as
	// failed (nothing was verified) but is left out of the "+N more" count,
	// since the lead message already names the cause.
	skipped bool
}

// checkActualMax bounds observed values quoted in a verdict, in runes.
const checkActualMax = 80

// checkClip makes a server-supplied value safe and short enough for a
// verdict. Escapes and control characters go (C1 too: --json output ends up
// at terminals via jq -r), and past checkActualMax runes the value is cut
// with "…", so a hostile header or body can't flood the line.
func checkClip(s string) string { return clipText(s, false) }

// clipText is checkClip for a value the caller already shortened (cut), which
// gets the "…" even when what is left fits.
func clipText(s string, cut bool) string {
	if n := checkActualMax * 8; len(s) > n { // bound the work before stripping
		s, cut = s[:n], true
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return ' '
		}
		return r
	}, ansi.Strip(strings.ToValidUTF8(s, "�")))
	r := []rune(s)
	if len(r) > checkActualMax || (cut && len(r) >= checkActualMax) {
		r, cut = r[:checkActualMax-1], true
	}
	if cut {
		return string(r) + "…"
	}
	return s
}

// bodyExcerpt clips a body for display without first copying all of it
// into a string (it may be 64 MiB).
func bodyExcerpt(b []byte) string {
	n := checkActualMax * 8
	if len(b) > n {
		return clipText(string(b[:n]), true)
	}
	return clipText(string(b), false)
}

func strPtr(s string) *string { return &s }

// ---- --expect-header ----------------------------------------------------------

// headerExpect is one compiled --expect-header: 'Name' (present),
// 'Name: REGEX' (present, and some value matches), or '!Name' (absent).
type headerExpect struct {
	src    string         // as given, for messages
	name   string         // canonical, for lookup and messages
	absent bool           // '!Name'
	re     *regexp.Regexp // nil = presence is enough
}

func parseExpectHeader(spec string) (headerExpect, error) {
	src := strings.TrimSpace(spec)
	h := headerExpect{src: src}
	bad := func(format string, args ...any) error {
		return fmt.Errorf("bad --expect-header '%s': %s", src, fmt.Sprintf(format, args...))
	}
	rest := src
	if r, ok := strings.CutPrefix(rest, "!"); ok {
		h.absent, rest = true, strings.TrimSpace(r)
	}
	name, pat, hasPat := strings.Cut(rest, ":")
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return h, bad("missing header name (want 'Name', 'Name: REGEX' or '!Name')")
	case !isHeaderToken(name):
		return h, bad("%q is not a valid header name", name)
	}
	h.name = http.CanonicalHeaderKey(name)
	if !hasPat {
		return h, nil
	}
	if h.absent {
		return h, bad("'!%s' asserts absence and takes no pattern", name)
	}
	// An empty pattern would match anything, which is presence spelled
	// confusingly; more likely the value was lost to shell quoting.
	pat = strings.TrimSpace(pat)
	if pat == "" {
		return h, bad("empty pattern after ':' (use '%s' to assert presence, or '%s: ^$' for an empty value)", name, name)
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return h, bad("%v", err)
	}
	h.re = re
	return h, nil
}

// isHeaderToken reports whether s is an RFC 9110 token, the only legal shape
// for a field name. Anything else could never be present, so the assertion
// would be a silent typo.
func isHeaderToken(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
			strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0 {
			continue
		}
		return false
	}
	return s != ""
}

// eval checks the header against the response. A repeated header passes a
// pattern when any one of its values matches.
func (h headerExpect) eval(hdr http.Header) checkAssertion {
	a := checkAssertion{Type: "header", Expect: h.src}
	vals := hdr.Values(h.name)
	var seen string
	if len(vals) > 0 {
		seen = checkClip(strings.Join(vals, ", "))
		a.Actual = &seen
	}
	switch {
	case h.absent:
		a.OK = len(vals) == 0
		a.Message = fmt.Sprintf("header %s present (%q), expected absent", h.name, seen)
	case len(vals) == 0:
		a.Message = fmt.Sprintf("header %s missing", h.name)
	case h.re == nil:
		a.OK = true
	default:
		a.OK = slices.ContainsFunc(vals, h.re.MatchString)
		a.Message = fmt.Sprintf("header %s %q does not match %q", h.name, seen, h.re.String())
	}
	if a.OK {
		a.Message = ""
	}
	return a
}

// ---- --expect-json ------------------------------------------------------------

// jsonExpect is one compiled --expect-json: a jq-like path, an optional
// "| length", and an optional comparison. Without a comparison the value must
// exist and be neither null nor false (jq's truthiness).
//
//	expr  := path [ "|" "length" ] [ op value ]
//	path  := "." [ key | index ] { "." key | "." index | index }
//	key   := [A-Za-z_][A-Za-z0-9_]*
//	index := "[" ( integer | json-string ) "]"     negative integers count from the end
//	op    := "==" | "!=" | "<" | "<=" | ">" | ">=" | "=~"
//	value := JSON literal; for =~ a double-quoted Go regexp
type jsonExpect struct {
	src    string
	path   []jsonStep
	length bool
	op     string         // "" = truthiness
	want   any            // the decoded literal; numbers as json.Number
	re     *regexp.Regexp // =~ only
}

// jsonStep is one path step: an object key, or an array index.
type jsonStep struct {
	key   string
	index int
	isIdx bool
}

// Two-character operators come first so "<=" isn't read as "<".
var jsonOps = []string{"==", "!=", "<=", ">=", "=~", "<", ">"}

func parseExpectJSON(spec string) (*jsonExpect, error) {
	src := strings.TrimSpace(spec)
	e := &jsonExpect{src: src}
	p := &exprParser{s: src}
	if err := p.parse(e); err != nil {
		return nil, fmt.Errorf("bad --expect-json '%s': %w", src, err)
	}
	return e, nil
}

// exprParser is a cursor over an --expect-json expression. Errors carry the
// 1-based column they were found at.
type exprParser struct {
	s string
	i int
}

func (p *exprParser) eof() bool { return p.i >= len(p.s) }

func (p *exprParser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.s[p.i]
}

func (p *exprParser) space() {
	for !p.eof() && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

// near names what sits at the cursor, for error messages.
func (p *exprParser) near() string {
	if p.eof() {
		return "end of expression"
	}
	r, _ := utf8.DecodeRuneInString(p.s[p.i:])
	return strconv.QuoteRune(r)
}

func (p *exprParser) errf(format string, args ...any) error {
	col := utf8.RuneCountInString(p.s[:min(p.i, len(p.s))]) + 1
	return fmt.Errorf("%s at col %d", fmt.Sprintf(format, args...), col)
}

func (p *exprParser) parse(e *jsonExpect) error {
	if p.eof() {
		return errors.New("empty expression (want a path, e.g. .status)")
	}
	if p.peek() != '.' {
		return p.errf("a path starts with \".\" (e.g. .status), got %s", p.near())
	}
	p.i++
	if err := p.parsePath(e); err != nil {
		return err
	}
	p.space()
	if p.peek() == '|' {
		p.i++
		p.space()
		at := p.i
		if p.ident() != "length" {
			p.i = at
			return p.errf("only \"| length\" may follow a path, got %s", p.near())
		}
		e.length = true
		p.space()
	}
	if p.eof() {
		// Every length is truthy, so a bare "| length" could never fail.
		if e.length {
			return p.errf("\"| length\" needs a comparison, e.g. \"| length > 0\"")
		}
		return nil
	}
	if err := p.parseOp(e); err != nil {
		return err
	}
	p.space()
	if p.eof() {
		return p.errf("missing a value after %s", e.op)
	}
	if e.op == "=~" {
		return p.parsePattern(e)
	}
	return p.parseLiteral(e)
}

// parsePath reads the steps after the leading '.': an optional key or index
// glued to it (.key, .[0]), then any mix of .key, .[...] and [...]. A bare
// "." is the whole body.
func (p *exprParser) parsePath(e *jsonExpect) error {
	switch c := p.peek(); {
	case c == '[' || isIdentStart(c):
		if err := p.parseStep(e); err != nil {
			return err
		}
	case c == '.': // else the loop below would read "..a" as ".a"
		return p.errf("recursive descent \"..\" is not supported")
	}
	for {
		switch c := p.peek(); {
		case c == '.':
			p.i++
			if c := p.peek(); c != '[' && !isIdentStart(c) {
				if c >= '0' && c <= '9' {
					return p.errf("unexpected %s (an array index goes in brackets: [0])", p.near())
				}
				return p.errf("expected a key or \"[\" after \".\", got %s", p.near())
			}
			if err := p.parseStep(e); err != nil {
				return err
			}
		case c == '[':
			if err := p.parseStep(e); err != nil {
				return err
			}
		case p.eof() || strings.IndexByte(" \t|=!<>", c) >= 0:
			return nil
		case c >= '0' && c <= '9':
			return p.errf("unexpected %s (an array index goes in brackets: .[0])", p.near())
		default:
			return p.errf("unexpected %s (quote keys with other characters: .[\"my-key\"])", p.near())
		}
	}
}

// parseStep reads one key (at an identifier) or bracketed index (at '[').
func (p *exprParser) parseStep(e *jsonExpect) error {
	if p.peek() != '[' {
		e.path = append(e.path, jsonStep{key: p.ident()})
		return nil
	}
	open := p.i
	p.i++
	p.space()
	var st jsonStep
	switch c := p.peek(); {
	case c == '"':
		key, err := p.jsonString()
		if err != nil {
			return err
		}
		st.key = key
	case c == '-' || (c >= '0' && c <= '9'):
		n, err := p.integer()
		if err != nil {
			return err
		}
		st = jsonStep{index: n, isIdx: true}
	case c == ']':
		return p.errf("iterating with [] is not supported; pick an index such as [0]")
	default:
		return p.errf("expected an index or a \"key\" inside [], got %s", p.near())
	}
	p.space()
	if p.peek() != ']' {
		if p.eof() {
			p.i = open
			return p.errf("unclosed \"[\"")
		}
		return p.errf("expected \"]\", got %s", p.near())
	}
	p.i++
	e.path = append(e.path, st)
	return nil
}

func (p *exprParser) ident() string {
	start := p.i
	if isIdentStart(p.peek()) {
		p.i++
		for !p.eof() && isIdentChar(p.s[p.i]) {
			p.i++
		}
	}
	return p.s[start:p.i]
}

func (p *exprParser) integer() (int, error) {
	start := p.i
	if p.peek() == '-' {
		p.i++
	}
	for !p.eof() && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		p.i++
	}
	digits := p.s[start:p.i]
	if c := p.peek(); c == '.' || c == 'e' || c == 'E' {
		p.i = start
		return 0, p.errf("an index must be a whole number")
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		p.i = start
		return 0, p.errf("bad index %q", digits)
	}
	return n, nil
}

// jsonString reads a double-quoted JSON string (a bracketed key), escapes
// and all.
func (p *exprParser) jsonString() (string, error) {
	start := p.i
	for p.i++; !p.eof(); {
		switch p.s[p.i] {
		case '\\':
			p.i += 2
		case '"':
			p.i++
			var s string
			if err := json.Unmarshal([]byte(p.s[start:p.i]), &s); err != nil {
				p.i = start
				return "", p.errf("bad key string: %v", err)
			}
			return s, nil
		default:
			p.i++
		}
	}
	p.i = start
	return "", p.errf("unterminated string")
}

func (p *exprParser) parseOp(e *jsonExpect) error {
	for _, op := range jsonOps {
		if strings.HasPrefix(p.s[p.i:], op) {
			e.op = op
			p.i += len(op)
			return nil
		}
	}
	if p.peek() == '=' {
		return p.errf("\"=\" is not an operator; compare with ==")
	}
	return p.errf("expected an operator (==, !=, <, <=, >, >=, =~), got %s", p.near())
}

// parsePattern reads the =~ operand: a double-quoted Go regexp. It is not a
// JSON string: backslashes reach the regexp as written, so "^2\." means what
// it says instead of being a bad JSON escape. Only \" is unescaped (to a
// quote, which a regexp matches the same either way).
func (p *exprParser) parsePattern(e *jsonExpect) error {
	if e.length {
		return p.errf("=~ matches strings, but \"| length\" is a number")
	}
	if p.peek() != '"' {
		return p.errf("=~ needs a double-quoted pattern, e.g. =~ \"^2\\.\"; got %s", p.near())
	}
	start := p.i
	var b strings.Builder
	for p.i++; ; {
		if p.eof() {
			p.i = start
			return p.errf("unterminated pattern string")
		}
		c := p.s[p.i]
		if c == '"' {
			p.i++
			break
		}
		if c == '\\' && p.i+1 < len(p.s) {
			if p.s[p.i+1] != '"' {
				b.WriteByte('\\')
			}
			b.WriteByte(p.s[p.i+1])
			p.i += 2
			continue
		}
		b.WriteByte(c)
		p.i++
	}
	p.space()
	if !p.eof() {
		return p.errf("unexpected %s after the pattern", p.near())
	}
	re, err := regexp.Compile(b.String())
	if err != nil {
		p.i = start
		return p.errf("bad pattern: %v", err)
	}
	e.re = re
	return nil
}

// parseLiteral reads the comparison operand: the rest of the expression,
// which must be exactly one JSON value.
func (p *exprParser) parseLiteral(e *jsonExpect) error {
	lit := strings.TrimSpace(p.s[p.i:])
	if err := json.Unmarshal([]byte(lit), new(any)); err != nil {
		if isIdentStart(lit[0]) {
			return p.errf("value %s is not JSON; strings need double quotes: %s", lit, quoteJSONString(lit))
		}
		return p.errf("value %s is not JSON: %v", lit, err)
	}
	dec := json.NewDecoder(strings.NewReader(lit))
	dec.UseNumber() // exact comparisons for integers past 2^53
	var v any
	_ = dec.Decode(&v) // validated above
	e.want = v
	switch e.op {
	case "<", "<=", ">", ">=":
		switch v.(type) {
		case json.Number, string:
		default:
			return p.errf("%s compares numbers or strings, not %s", e.op, jsonTypeName(v))
		}
	}
	if _, isNum := v.(json.Number); e.length && !isNum {
		return p.errf("\"| length\" is a number; compare it with a number, not %s", jsonTypeName(v))
	}
	return nil
}

func isIdentStart(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || c == '_'
}

func isIdentChar(c byte) bool { return isIdentStart(c) || ('0' <= c && c <= '9') }

func isIdent(s string) bool {
	if s == "" || !isIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isIdentChar(s[i]) {
			return false
		}
	}
	return true
}

// decodeJSONBody parses the body once for all --expect-json assertions.
// Numbers stay json.Number so large IDs compare exactly, and encoding/json's
// nesting limit bounds how deep a hostile body can go.
func decodeJSONBody(body []byte) (any, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, errors.New("body is empty, not JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		var se *json.SyntaxError
		switch {
		case errors.As(err, &se):
			return nil, fmt.Errorf("body is not JSON: %s at offset %d", se.Error(), se.Offset)
		case errors.Is(err, io.ErrUnexpectedEOF):
			return nil, errors.New("body is not JSON: it ends mid-value")
		}
		return nil, fmt.Errorf("body is not JSON: %v", err)
	}
	end := dec.InputOffset()
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("body is not JSON: unexpected data after the value at offset %d", end)
	}
	return v, nil
}

// eval runs the expression against the decoded body. As in jq, a path that
// doesn't resolve reads as null, so ".a == null" holds for a missing key; a
// failure message still says which step went missing.
func (e *jsonExpect) eval(doc any) checkAssertion {
	a := checkAssertion{Type: "json", Expect: e.src}
	fail := func(detail string) checkAssertion {
		a.OK, a.Message = false, "json "+e.src+": "+detail
		return a
	}
	v, gone, err := e.resolve(doc)
	if err != nil {
		return fail(err.Error())
	}
	if e.length {
		if v, err = jsonLength(v, e.path); err != nil {
			return fail(err.Error())
		}
	}
	if gone == "" || e.length {
		a.Actual = strPtr(jsonPreview(v))
	}

	typeOK := true
	switch e.op {
	case "":
		a.OK = v != nil && v != false
	case "==":
		a.OK = jsonEqual(v, e.want)
	case "!=":
		a.OK = !jsonEqual(v, e.want)
	case "=~":
		s, isStr := v.(string)
		typeOK = isStr
		a.OK = isStr && e.re.MatchString(s)
	default:
		var c int
		c, typeOK = jsonCompare(v, e.want)
		a.OK = typeOK && opHolds(e.op, c)
	}
	switch {
	case a.OK:
		return a
	case gone != "" && e.length:
		return fail(fmt.Sprintf("got %s (%s)", *a.Actual, gone))
	case gone != "":
		return fail(gone)
	case !typeOK && e.op == "=~":
		return fail(fmt.Sprintf("got %s, not a string", *a.Actual))
	case !typeOK:
		return fail(fmt.Sprintf("got %s, not %s", *a.Actual, jsonTypeArticle(e.want)))
	}
	return fail("got " + *a.Actual)
}

// resolve walks the path. gone is set (and v is nil) when a step doesn't
// exist; err when a step can't apply to the value it meets, such as an index
// into an object — the body isn't shaped the way the assertion assumes.
func (e *jsonExpect) resolve(doc any) (v any, gone string, err error) {
	v = doc
	for i, st := range e.path {
		here := e.path[:i]
		switch cur := v.(type) {
		case nil:
			return nil, jsonSubject(here) + " is null", nil
		case map[string]any:
			if st.isIdx {
				return nil, "", fmt.Errorf("%s is an object, cannot index it with [%d]", jsonSubject(here), st.index)
			}
			next, ok := cur[st.key]
			if !ok {
				return nil, jsonPathString(e.path[:i+1]) + " is missing", nil
			}
			v = next
		case []any:
			if !st.isIdx {
				return nil, "", fmt.Errorf("%s is an array, cannot index it with %s", jsonSubject(here), quoteJSONString(st.key))
			}
			idx := st.index
			if idx < 0 {
				idx += len(cur)
			}
			if idx < 0 || idx >= len(cur) {
				return nil, fmt.Sprintf("%s is missing (%s has %d items)", jsonPathString(e.path[:i+1]), jsonSubject(here), len(cur)), nil
			}
			v = cur[idx]
		default:
			return nil, "", fmt.Errorf("%s is %s, cannot index it with %s", jsonSubject(here), jsonTypeArticle(cur), jsonStepString(st))
		}
	}
	return v, "", nil
}

// jsonLength is jq's length: characters of a string, items of an array or
// object, 0 for null, the absolute value of a number.
func jsonLength(v any, path []jsonStep) (any, error) {
	n := 0
	switch x := v.(type) {
	case nil:
	case string:
		n = utf8.RuneCountInString(x)
	case []any:
		n = len(x)
	case map[string]any:
		n = len(x)
	case json.Number:
		return json.Number(strings.TrimPrefix(string(x), "-")), nil
	default:
		return nil, fmt.Errorf("%s is %s, which has no length", jsonSubject(path), jsonTypeArticle(v))
	}
	return json.Number(strconv.Itoa(n)), nil
}

// jsonEqual is deep equality with jq's number rule: 1 == 1.0.
func jsonEqual(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case json.Number:
		y, ok := b.(json.Number)
		return ok && compareNumbers(string(x), string(y)) == 0
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !jsonEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			yv, ok := y[k]
			if !ok || !jsonEqual(xv, yv) {
				return false
			}
		}
		return true
	}
	return false
}

// jsonCompare orders two numbers or two strings (by byte, which for UTF-8 is
// code point order, like jq). Any other pairing reports false: ordering a
// string against a number is almost certainly a mistaken assertion, and jq's
// cross-type order would hide it.
func jsonCompare(a, b any) (int, bool) {
	switch x := a.(type) {
	case json.Number:
		if y, ok := b.(json.Number); ok {
			return compareNumbers(string(x), string(y)), true
		}
	case string:
		if y, ok := b.(string); ok {
			return strings.Compare(x, y), true
		}
	}
	return 0, false
}

func opHolds(op string, c int) bool {
	switch op {
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	case ">=":
		return c >= 0
	}
	return false
}

// compareNumbers compares two valid JSON numbers. Integers compare exactly
// at any size, by digits rather than through float64, which would make IDs
// past 2^53 equal to their neighbors; anything else goes through float64.
func compareNumbers(a, b string) int {
	if isJSONInt(a) && isJSONInt(b) {
		an, bn := a[0] == '-', b[0] == '-'
		a, b = strings.TrimPrefix(a, "-"), strings.TrimPrefix(b, "-")
		an, bn = an && a != "0", bn && b != "0" // -0 == 0
		if an != bn {
			if an {
				return -1
			}
			return 1
		}
		// JSON integers have no leading zeros, so more digits means bigger.
		c := cmp.Or(cmp.Compare(len(a), len(b)), strings.Compare(a, b))
		if an {
			return -c
		}
		return c
	}
	x, _ := strconv.ParseFloat(a, 64) // a huge exponent parses as ±Inf, which still orders
	y, _ := strconv.ParseFloat(b, 64)
	return cmp.Compare(x, y)
}

func isJSONInt(s string) bool {
	s = strings.TrimPrefix(s, "-")
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func jsonTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case json.Number:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

func jsonTypeArticle(v any) string {
	switch n := jsonTypeName(v); n {
	case "null":
		return n
	case "array", "object":
		return "an " + n
	default:
		return "a " + n
	}
}

// jsonPathString renders steps back in expression syntax (".items[0].id").
func jsonPathString(steps []jsonStep) string {
	if len(steps) == 0 {
		return "."
	}
	var b strings.Builder
	for i, st := range steps {
		if st.isIdx || !isIdent(st.key) {
			if i == 0 {
				b.WriteByte('.')
			}
			b.WriteString("[" + jsonStepString(st) + "]")
			continue
		}
		b.WriteString("." + st.key)
	}
	return b.String()
}

// jsonSubject names a path for a message, with the empty path as "the body".
func jsonSubject(steps []jsonStep) string {
	if len(steps) == 0 {
		return "the body"
	}
	return jsonPathString(steps)
}

// jsonStepString renders a step's operand: a number, or a quoted key.
func jsonStepString(st jsonStep) string {
	if st.isIdx {
		return strconv.Itoa(st.index)
	}
	return quoteJSONString(st.key)
}

// quoteJSONString quotes s as a JSON string, leaving <, > and & readable.
func quoteJSONString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	return strings.TrimSuffix(buf.String(), "\n")
}

// jsonPreview renders v as compact JSON for a verdict. It stops once it has
// more than fits in checkActualMax: v may be a 64 MiB array, of which only
// the first few dozen characters will be shown.
func jsonPreview(v any) string {
	var b strings.Builder
	limit := checkActualMax * 4
	writeJSONPreview(&b, v, limit)
	return clipText(b.String(), b.Len() > limit)
}

func writeJSONPreview(b *strings.Builder, v any, limit int) {
	clip := func(s string) string {
		if len(s) > limit {
			return s[:limit]
		}
		return s
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case json.Number:
		b.WriteString(clip(string(x)))
	case string:
		b.WriteString(quoteJSONString(clip(x)))
	case []any:
		b.WriteByte('[')
		for i, el := range x {
			if b.Len() > limit {
				return
			}
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONPreview(b, el, limit)
		}
		b.WriteByte(']')
	case map[string]any:
		b.WriteByte('{')
		for i, k := range slices.Sorted(maps.Keys(x)) {
			if b.Len() > limit {
				return
			}
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(quoteJSONString(clip(k)) + ":")
			writeJSONPreview(b, x[k], limit)
		}
		b.WriteByte('}')
	}
}
