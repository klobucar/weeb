package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
)

// formKind says where a -F part's content comes from.
type formKind uint8

const (
	formText     formKind = iota // name=value: a text field
	formFile                     // name=@path: upload the file as a file part
	formFileText                 // name=<path: the file's content as a text field
)

// FormField is one -F/--form part of a multipart/form-data body. Files are
// named, not read, until the request is built, so a spec stays cheap to copy,
// export and re-import.
type FormField struct {
	Name     string
	Value    string   // the text for formText; the local file path otherwise
	Kind     formKind //
	Type     string   // ;type= Content-Type of the part
	Filename string   // ;filename= sent in place of the local file name
}

// formSpace is curl's ISSPACE set, which it trims around -F words.
const formSpace = " \t\n\v\f\r"

// parseFormArg parses a -F/--form value the way curl does:
//
//	name=value                       a text field
//	name=@file[;type=mime][;filename=x]  a file upload
//	name=<file                       a text field read from the file
//
// A word may be double-quoted ("a;b", with \" and \\ escaped) to hold a ';',
// a ',' or surrounding blanks. literal (--form-string) takes the value as-is,
// with no @, < or ; handling. Things curl supports that weeb doesn't — stdin
// (@-), several files in one field (@a,b), headers= and encoder= — are errors
// rather than being sent as something else.
func parseFormArg(arg string, literal bool) (FormField, error) {
	name, rest, ok := strings.Cut(arg, "=")
	if !ok || name == "" {
		return FormField{}, fmt.Errorf("bad form part %q (want name=value, name=@file or name=<file)", arg)
	}
	f := FormField{Name: name}
	if literal {
		f.Value = rest
		return f, nil
	}

	switch {
	case strings.HasPrefix(rest, "@"):
		f.Kind, rest = formFile, rest[1:]
	case strings.HasPrefix(rest, "<"):
		f.Kind, rest = formFileText, rest[1:]
	}
	val, rest, quoted := formWord(rest)
	f.Value = val

	// After type= curl keeps reading parameters it doesn't know as part of
	// the content type ("type=text/plain;charset=utf-8") until filename=.
	typeOpen := false
	for rest != "" {
		rest = strings.TrimLeft(rest[1:], formSpace) // past the ';'
		switch low := strings.ToLower(rest); {
		case rest == "" || rest[0] == ';':
			continue // an empty parameter (";;", a trailing ";"): curl skips it
		case !typeOpen && strings.HasPrefix(low, "type="):
			var t string
			t, rest = cutSemi(rest[len("type="):])
			f.Type, typeOpen = strings.Trim(t, formSpace), true
		case strings.HasPrefix(low, "filename="):
			typeOpen = false
			f.Filename, rest, _ = formWord(rest[len("filename="):])
		case strings.HasPrefix(low, "headers="), strings.HasPrefix(low, "encoder="):
			return FormField{}, fmt.Errorf("form part %q: %s isn't supported", name, rest[:strings.IndexByte(rest, '=')+1])
		case typeOpen:
			var t string
			t, rest = cutSemi(rest)
			if t = strings.Trim(t, formSpace); t != "" {
				f.Type += ";" + t
			}
		default:
			seg, _ := cutSemi(rest)
			return FormField{}, fmt.Errorf("form part %q: unknown parameter %q (quote a value that contains ';')", name, seg)
		}
	}

	if f.Type != "" {
		if major, _ := cutSemi(f.Type); !strings.Contains(major, "/") {
			return FormField{}, fmt.Errorf("form part %q: type=%q isn't a MIME type (want e.g. text/plain)", name, f.Type)
		}
		// The type lands in a part header verbatim; a control byte could
		// split it into extra headers.
		if strings.ContainsFunc(f.Type, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return FormField{}, fmt.Errorf("form part %q: type= contains a control character", name)
		}
	}
	if f.Kind != formText {
		switch {
		case f.Value == "":
			return FormField{}, fmt.Errorf("form part %q: no file name after @ or <", name)
		case f.Value == "-":
			return FormField{}, fmt.Errorf("form part %q: reading a part from stdin isn't supported; save it to a file", name)
		case f.Kind == formFile && !quoted && strings.Contains(f.Value, ","):
			return FormField{}, fmt.Errorf("form part %q: several files in one field (@a,b) aren't supported; quote a file name that contains a comma", name)
		}
	}
	return f, nil
}

// formWord reads one -F word the way curl does: a double-quoted word runs to
// its closing quote (with \" and \\ escaped) and anything after that up to
// the next ';' is dropped; an unquoted word runs to the next ';' with
// surrounding blanks trimmed. rest starts at that ';' (or is empty). An
// unterminated quote is read as an unquoted word, like curl.
func formWord(s string) (word, rest string, quoted bool) {
	s = strings.TrimLeft(s, formSpace)
	if strings.HasPrefix(s, `"`) {
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			c := s[i]
			if c == '\\' && i+1 < len(s) && (s[i+1] == '\\' || s[i+1] == '"') {
				b.WriteByte(s[i+1])
				i++
				continue
			}
			if c == '"' {
				_, rest = cutSemi(s[i+1:])
				return b.String(), rest, true
			}
			b.WriteByte(c)
		}
	}
	word, rest = cutSemi(s)
	return strings.TrimRight(word, formSpace), rest, false
}

// cutSemi splits s at its first ';', which stays at the start of rest.
func cutSemi(s string) (before, rest string) {
	if i := strings.IndexByte(s, ';'); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

// formQuote renders a word so formWord reads it back unchanged, quoting only
// when it must: a ';' (or a ',' in a file name) would end it, surrounding
// blanks would be trimmed, and a leading quote would be read as quoting.
func formQuote(s string, comma bool) string {
	if !strings.ContainsAny(s, ";") && !(comma && strings.Contains(s, ",")) &&
		!strings.HasPrefix(s, `"`) && strings.Trim(s, formSpace) == s {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// curlFormArg is the curl flag and argument that recreate f: -F with curl's
// syntax, or --form-string for a plain text value -F would misread (one
// starting with @ or <, holding a ';', ...), which keeps it readable.
func curlFormArg(f FormField) (flag, arg string) {
	var v string
	switch f.Kind {
	case formFile:
		v = "@" + formQuote(f.Value, true)
	case formFileText:
		v = "<" + formQuote(f.Value, true)
	default:
		q := formQuote(f.Value, false)
		lead := strings.HasPrefix(f.Value, "@") || strings.HasPrefix(f.Value, "<")
		if f.Type == "" && f.Filename == "" && (lead || q != f.Value) {
			return "--form-string", f.Name + "=" + f.Value
		}
		if lead && q == f.Value {
			// -F reads a leading @ or < as a file; quoting keeps it text.
			q = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(f.Value) + `"`
		}
		v = q
	}
	if f.Type != "" {
		v += ";type=" + f.Type
	}
	if f.Filename != "" {
		v += ";filename=" + formQuote(f.Filename, false)
	}
	return "-F", f.Name + "=" + v
}

// curlFileTypes is curl's guess table for an upload's Content-Type, keyed by
// extension; anything else is application/octet-stream. A fixed table (not
// mime.TypeByExtension, which reads the system's mime.types) keeps the body
// the same on every machine and the same as curl's.
var curlFileTypes = map[string]string{
	".gif": "image/gif", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
	".png": "image/png", ".svg": "image/svg+xml", ".txt": "text/plain",
	".htm": "text/html", ".html": "text/html", ".pdf": "application/pdf",
	".xml": "application/xml",
}

// formEscape escapes a name or filename for a Content-Disposition quoted
// string the way curl (and HTML5) do: " CR and LF are percent-encoded, so a
// pasted name can't close the quote or inject a part header.
var formEscape = strings.NewReplacer(`"`, "%22", "\r", "%0D", "\n", "%0A").Replace

// redactMultipart blanks the content of secret-named parts (-F password=…,
// -F key=@id_rsa) in a multipart body for history, keeping the boundary and
// every other part. A body that doesn't parse is left alone, like any other
// unrecognized body.
func redactMultipart(body []byte, contentType string) ([]byte, bool) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return body, false
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if w.SetBoundary(params["boundary"]) != nil {
		return body, false
	}
	r := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	changed := false
	for {
		p, err := r.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return body, false
		}
		data, err := io.ReadAll(p)
		if err != nil {
			return body, false
		}
		if secretName(p.FormName()) {
			data, changed = []byte(redactedValue), true
		}
		pw, err := w.CreatePart(p.Header)
		if err != nil {
			return body, false
		}
		_, _ = pw.Write(data) // into a bytes.Buffer: can't fail
	}
	if !changed || w.Close() != nil {
		return body, false
	}
	return buf.Bytes(), true
}

// materializeForm turns spec.Form into the multipart body and Content-Type
// header it describes, reading upload files now. Doing it on the spec (not
// only on the http.Request) means history records the bytes actually sent.
// A user-supplied Content-Type is kept, with the boundary appended unless it
// already names one (then that boundary is used), as curl does.
func materializeForm(spec RequestSpec) (RequestSpec, error) {
	if len(spec.Form) == 0 || !methodAllowsBody(strings.ToUpper(strings.TrimSpace(spec.Method))) {
		return spec, nil
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	ct := "multipart/form-data"
	var headers []Header
	for _, h := range spec.Headers {
		if strings.EqualFold(strings.TrimSpace(h.Key), "Content-Type") {
			ct = strings.TrimSpace(h.Value)
			continue
		}
		headers = append(headers, h)
	}
	if _, params, err := mime.ParseMediaType(ct); err == nil && params["boundary"] != "" {
		if err := w.SetBoundary(params["boundary"]); err != nil {
			return spec, fmt.Errorf("Content-Type boundary: %w", err)
		}
	} else {
		ct += "; boundary=" + w.Boundary()
	}

	for _, f := range spec.Form {
		data := []byte(f.Value)
		filename, partType := f.Filename, f.Type
		if f.Kind != formText {
			b, err := os.ReadFile(f.Value)
			if err != nil {
				return spec, fmt.Errorf("-F %q: %w", f.Name, err)
			}
			data = b
		}
		if f.Kind == formFile {
			if filename == "" {
				filename = filepath.Base(f.Value)
			}
			if partType == "" {
				partType = curlFileTypes[strings.ToLower(filepath.Ext(filename))]
			}
			if partType == "" {
				partType = "application/octet-stream"
			}
		}
		h := textproto.MIMEHeader{}
		disp := `form-data; name="` + formEscape(f.Name) + `"`
		if filename != "" {
			disp += `; filename="` + formEscape(filename) + `"`
		}
		h.Set("Content-Disposition", disp)
		if partType != "" {
			h.Set("Content-Type", partType)
		}
		pw, err := w.CreatePart(h)
		if err != nil {
			return spec, err
		}
		if _, err := pw.Write(data); err != nil {
			return spec, err
		}
	}
	if err := w.Close(); err != nil {
		return spec, err
	}

	spec.Headers = append(headers, Header{Key: "Content-Type", Value: ct})
	spec.Body = buf.Bytes()
	return spec, nil
}
