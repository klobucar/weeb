package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"charm.land/lipgloss/v2"
)

// ---- export: RequestSpec -> curl -------------------------------------------

// toCurl renders a RequestSpec as a runnable curl command. When multiline is
// true each header / data flag goes on its own backslash-continued line (the
// "copy as cURL" shape); otherwise it's a single pipe-friendly line.
func toCurl(spec RequestSpec, multiline bool) string {
	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method == "" {
		method = "GET"
	}

	head := "curl"
	if method != "GET" {
		head += " -X " + method
	}
	head += " " + shellQuote(spec.URL)

	segs := []string{head}
	for _, h := range spec.Headers {
		if strings.TrimSpace(h.Key) == "" {
			continue
		}
		segs = append(segs, "-H "+shellQuote(h.Key+": "+h.Value))
	}
	if len(spec.Body) > 0 && methodAllowsBody(method) {
		segs = append(segs, "--data "+shellQuote(string(spec.Body)))
	}

	sep := " "
	if multiline {
		sep = " \\\n  "
	}
	return strings.Join(segs, sep)
}

// renderCurl is toCurl with light syntax color for display (TUI pane / a TTY).
// With color == false it is byte-identical to toCurl, so it stays copy-pasteable.
func renderCurl(spec RequestSpec, st styles, color, multiline bool) string {
	if !color {
		return toCurl(spec, multiline)
	}
	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method == "" {
		method = "GET"
	}
	flag := func(s string) string { return lipgloss.NewStyle().Bold(true).Foreground(cMauve).Render(s) }
	str := func(s string) string { return st.jsonStr.Render(s) }

	head := lipgloss.NewStyle().Bold(true).Foreground(cGreen).Render("curl")
	if method != "GET" {
		head += " " + flag("-X") + " " +
			lipgloss.NewStyle().Bold(true).Foreground(methodColor(method)).Render(method)
	}
	head += " " + lipgloss.NewStyle().Foreground(cBlue).Render(shellQuote(spec.URL))

	segs := []string{head}
	for _, h := range spec.Headers {
		if strings.TrimSpace(h.Key) == "" {
			continue
		}
		segs = append(segs, flag("-H")+" "+str(shellQuote(h.Key+": "+h.Value)))
	}
	if len(spec.Body) > 0 && methodAllowsBody(method) {
		segs = append(segs, flag("--data")+" "+str(shellQuote(string(spec.Body))))
	}

	sep := " "
	if multiline {
		sep = " \\\n  "
	}
	return strings.Join(segs, sep)
}

// shellQuote single-quotes s for a POSIX shell unless it is already a bare,
// safe token. Embedded single quotes become the standard '\” dance.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if shellSafe(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shellSafe(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("._-/:@", r):
		default:
			return false
		}
	}
	return true
}

// ---- import: curl -> RequestSpec -------------------------------------------

// parseCurl turns a tokenized curl command (with or without a leading "curl")
// into a RequestSpec. It understands the flags people actually paste — method,
// headers, data, basic auth, user-agent/cookie/referer shortcuts — infers the
// method (POST when there's a body, HEAD for -I), and silently ignores
// transfer-only flags like -L/-k/--compressed that don't change the request.
// Flags it does not recognize are an error: an unknown value-taking flag
// would otherwise leave its value to be mistaken for the URL.
func parseCurl(argv []string) (RequestSpec, error) {
	var spec RequestSpec
	var data []string
	methodSet, urlSet, forceGet, headOnly := false, false, false, false

	take := func(i *int, flag, attached string) (string, error) {
		if attached != "" {
			return attached, nil
		}
		if *i+1 >= len(argv) {
			return "", fmt.Errorf("curl: %s needs a value", flag)
		}
		*i++
		return argv[*i], nil
	}

	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if i == 0 && (arg == "curl" || strings.HasSuffix(arg, "/curl")) {
			continue
		}

		// Split an attached short-flag value, e.g. -XPOST or -H'K: V'.
		flag, attached := arg, ""
		if len(arg) > 2 && arg[0] == '-' && arg[1] != '-' {
			if strings.ContainsRune("XHduAbeom", rune(arg[1])) {
				flag, attached = arg[:2], arg[2:]
			}
		}

		switch flag {
		case "-X", "--request":
			v, err := take(&i, flag, attached)
			if err != nil {
				return spec, err
			}
			spec.Method, methodSet = strings.ToUpper(v), true

		case "-H", "--header":
			v, err := take(&i, flag, attached)
			if err != nil {
				return spec, err
			}
			if k, val, ok := strings.Cut(v, ":"); ok {
				spec.Headers = append(spec.Headers, Header{Key: strings.TrimSpace(k), Value: strings.TrimSpace(val)})
			}

		case "-d", "--data", "--data-raw", "--data-ascii", "--data-binary", "--data-urlencode":
			v, err := take(&i, flag, attached)
			if err != nil {
				return spec, err
			}
			if flag == "--data-urlencode" {
				// Not a raw --data alias: curl URL-encodes the content part.
				// Passing it through raw silently changes what the server
				// parses (an & in the value becomes a field separator).
				if v, err = urlencodeDataItem(v); err != nil {
					return spec, err
				}
			} else if flag != "--data-raw" && strings.HasPrefix(v, "@") {
				b, err := readDataFile(v[1:])
				if err != nil {
					return spec, err
				}
				v = string(b)
			}
			data = append(data, v)

		case "-u", "--user":
			v, err := take(&i, flag, attached)
			if err != nil {
				return spec, err
			}
			enc := base64.StdEncoding.EncodeToString([]byte(v))
			spec.Headers = append(spec.Headers, Header{Key: "Authorization", Value: "Basic " + enc})

		case "-A", "--user-agent":
			v, err := take(&i, flag, attached)
			if err != nil {
				return spec, err
			}
			spec.Headers = append(spec.Headers, Header{Key: "User-Agent", Value: v})

		case "-b", "--cookie":
			v, err := take(&i, flag, attached)
			if err != nil {
				return spec, err
			}
			spec.Headers = append(spec.Headers, Header{Key: "Cookie", Value: v})

		case "-e", "--referer":
			v, err := take(&i, flag, attached)
			if err != nil {
				return spec, err
			}
			spec.Headers = append(spec.Headers, Header{Key: "Referer", Value: v})

		case "--url":
			v, err := take(&i, flag, attached)
			if err != nil {
				return spec, err
			}
			spec.URL, urlSet = v, true

		case "-G", "--get":
			forceGet = true
		case "-I", "--head":
			headOnly = true

		// Flags that take a value we don't use — consume and drop it.
		case "-o", "--output", "-m", "--max-time", "--connect-timeout", "--retry",
			"-w", "--write-out", "-c", "--cookie-jar", "-T", "--upload-file",
			"-E", "--cert", "--cacert", "--key", "--proxy", "-x",
			"--max-redirs", "--retry-delay", "--retry-max-time", "--resolve",
			"--limit-rate", "--connect-to":
			if _, err := take(&i, flag, attached); err != nil {
				return spec, err
			}

		// Boolean transfer-only flags: they shape the transfer, not the request.
		case "-L", "--location", "--location-trusted", "-k", "--insecure",
			"--compressed", "-s", "--silent", "-S", "--show-error",
			"-v", "--verbose", "-f", "--fail", "-i", "--include",
			"-N", "--no-buffer", "-#", "--progress-bar", "-g", "--globoff",
			"-4", "--ipv4", "-6", "--ipv6",
			"--http1.0", "--http1.1", "--http2", "--http3":
			// ignored

		default:
			if strings.HasPrefix(arg, "-") && arg != "-" {
				// Clustered short bools ("-sSL", "-sIk") are one token; honor
				// the letters we know. Anything else must error: an unknown
				// value-taking flag would otherwise leave its value to be
				// mistaken for the URL.
				if rest, ok := strings.CutPrefix(arg, "-"); ok && !strings.HasPrefix(arg, "--") && isShortBoolCluster(rest) {
					for _, r := range rest {
						switch r {
						case 'I':
							headOnly = true
						case 'G':
							forceGet = true
						}
					}
					continue
				}
				return spec, fmt.Errorf("curl: unsupported flag %q", arg)
			}
			if !urlSet {
				spec.URL, urlSet = arg, true
			}
		}
	}

	if strings.TrimSpace(spec.URL) == "" {
		return spec, fmt.Errorf("curl: no URL found in command")
	}
	if len(data) > 0 {
		joined := strings.Join(data, "&")
		if forceGet {
			// -G sends the data as the URL query instead of a body, like curl.
			sep := "?"
			if strings.Contains(spec.URL, "?") {
				sep = "&"
			}
			spec.URL += sep + joined
		} else {
			spec.Body = []byte(joined)
		}
	}
	if !methodSet {
		switch {
		case headOnly:
			spec.Method = "HEAD"
		case forceGet:
			spec.Method = "GET"
		case len(data) > 0:
			spec.Method = "POST"
		default:
			spec.Method = "GET"
		}
	}
	return spec, nil
}

// urlencodeDataItem resolves one --data-urlencode value the way curl does:
//
//	content        encode all of it
//	=content       encode everything after the leading =
//	name=content   send name=<encoded content> (the name passes through)
//	@file          encode the file's contents
//	name@file      send name=<encoded file contents>
//
// The first = or @ decides the form, = winning, matching curl's parser.
func urlencodeDataItem(v string) (string, error) {
	name := ""
	if i := strings.IndexByte(v, '='); i >= 0 {
		name, v = v[:i], v[i+1:]
	} else if i := strings.IndexByte(v, '@'); i >= 0 {
		name, v = v[:i], v[i+1:]
		b, err := readDataFile(v)
		if err != nil {
			return "", err
		}
		v = string(b)
	}
	enc := curlEscape(v)
	if name != "" {
		return name + "=" + enc, nil
	}
	return enc, nil
}

// readDataFile resolves the file part of a --data @name value the way curl
// does: '-' reads stdin, anything else reads the named file.
func readDataFile(name string) ([]byte, error) {
	if name == "-" {
		return io.ReadAll(os.Stdin)
	}
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("curl: reading %q: %w", name, err)
	}
	return b, nil
}

// curlEscape percent-encodes s like curl_easy_escape: every byte outside
// ASCII alphanumerics and -._~ becomes %XX. url.QueryEscape almost matches
// but encodes space as +, which curl does not.
func curlEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// isShortBoolCluster reports whether every letter in a clustered short flag
// ("sSL" from "-sSL") is a boolean flag we understand: transfer-only ones we
// ignore plus -I/-G, which set the method.
func isShortBoolCluster(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("sSLkvfiIGN46g#", r) {
			return false
		}
	}
	return true
}

// tokenizeShell splits a pasted command line into argv the way a POSIX shell
// would: honoring single/double quotes, backslash escapes, and backslash-newline
// line continuations. It's intentionally small — enough to handle real curl
// commands people copy from docs or DevTools.
func tokenizeShell(s string) ([]string, error) {
	var toks []string
	var cur strings.Builder
	inTok := false
	flush := func() {
		if inTok {
			toks = append(toks, cur.String())
			cur.Reset()
			inTok = false
		}
	}

	for i := 0; i < len(s); {
		c := s[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			flush()
			i++
		case '\\':
			if i+1 < len(s) && s[i+1] == '\n' {
				i += 2 // line continuation
				continue
			}
			if i+2 < len(s) && s[i+1] == '\r' && s[i+2] == '\n' {
				i += 3
				continue
			}
			if i+1 < len(s) {
				cur.WriteByte(s[i+1])
				inTok = true
				i += 2
			} else {
				i++
			}
		case '\'':
			inTok = true
			i++
			for i < len(s) && s[i] != '\'' {
				cur.WriteByte(s[i])
				i++
			}
			if i >= len(s) {
				return nil, fmt.Errorf("unterminated single quote")
			}
			i++
		case '"':
			inTok = true
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					switch s[i+1] {
					case '"', '\\', '$', '`':
						cur.WriteByte(s[i+1])
						i += 2
						continue
					case '\n':
						i += 2
						continue
					}
				}
				cur.WriteByte(s[i])
				i++
			}
			if i >= len(s) {
				return nil, fmt.Errorf("unterminated double quote")
			}
			i++
		default:
			cur.WriteByte(c)
			inTok = true
			i++
		}
	}
	flush()
	return toks, nil
}
