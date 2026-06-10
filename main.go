package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/term"
)

// Build metadata, injected by GoReleaser via -ldflags -X (see .goreleaser.yaml).
// The defaults apply to a plain `go build` / `go install` outside a release.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// outW and errW are the process-wide print boundaries for stdout and stderr,
// resolved once at startup. When the fd is a terminal, every write passes
// through sanitizeTTY, so server-influenced text headed for a TTY — response
// bodies, cert subject/issuer/SANs, TLS leaf names, verify and transport
// error strings — is neutralized in one place and future print paths inherit
// the guard. Pipes and files get the exact bytes (no wrapper).
var (
	outW = ttySafeWriter(os.Stdout)
	errW = ttySafeWriter(os.Stderr)
)

func ttySafeWriter(f *os.File) io.Writer {
	if term.IsTerminal(f.Fd()) {
		return sanitizingWriter{w: f}
	}
	return f
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		os.Exit(runTUI(nil)) // bare invocation: empty interactive builder
	}

	switch args[0] {
	case "-h", "--help", "help":
		printHelp(os.Stdout)
		return
	case "version", "--version", "-V":
		printVersion(os.Stdout)
		return
	case "cert", "tls":
		os.Exit(runCert(args[1:]))
	case "curl", "import":
		os.Exit(runCurlImport(args[1:]))
	}

	parsed, err := parseCLI(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		fmt.Fprintln(os.Stderr, "run 'weeb --help' for usage")
		os.Exit(2)
	}

	// A URL opens the TUI prefilled by default; we fall back to a headless
	// one-shot when the output is clearly script-bound or asked to be.
	if parsed.headless() {
		if parsed.url == "" {
			fmt.Fprintln(os.Stderr, "weeb: no URL given")
			fmt.Fprintln(os.Stderr, "run 'weeb --help' for usage")
			os.Exit(2)
		}
		os.Exit(runCLI(parsed))
	}
	os.Exit(runTUI(&parsed)) // interactive — a URL is optional, fields can be filled in
}

// printVersion writes the build metadata. GoReleaser injects it via -ldflags; for
// a plain `go build`/`go install` (no ldflags) it falls back to what Go embeds in
// the binary — the module version for `go install pkg@vX`, or the VCS revision
// (short) when built from a checkout — so the output is still meaningful.
func printVersion(w io.Writer) {
	v, c := version, commit
	if v == "dev" || c == "none" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if v == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
				v = info.Main.Version
			}
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" && c == "none" && len(s.Value) >= 10 {
					c = s.Value[:10]
				}
			}
		}
	}
	fmt.Fprintf(w, "weeb %s (commit %s, built %s)\n", v, c, date)
}

// headless reports whether a parsed request should run as a one-shot CLI rather
// than opening the interactive TUI. We go headless when output is shaped for a
// pipe/script — stdout isn't a terminal, a body is piped into stdin, or the
// body goes to a file (-o) — or when a flag asks for it (--no-tui, --raw,
// --to-curl, --no-follow: the TUI form has no redirect toggle, so opening it
// would silently drop the flag).
func (a cliArgs) headless() bool {
	return a.noTUI || a.quiet || a.raw || a.toCurl || a.noFollow || a.output != "" || !stdoutIsTTY() || stdinIsPiped()
}

// ---- TUI mode --------------------------------------------------------------

func runTUI(seed *cliArgs) int {
	logger, dbg, cleanup := newLogger(modeTUI)
	defer cleanup()

	voice := newErrorChan()
	if seed != nil {
		mode, err := resolvePersona(seed.persona)
		if err != nil {
			fmt.Fprintln(os.Stderr, "weeb:", err)
			return 2
		}
		voice = errorChanFor(mode)
	}

	maxBody := ""
	if seed != nil {
		maxBody = seed.maxBody
	}
	if err := applyMaxBody(maxBody); err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 2
	}

	client := newClient(logger, voice)
	if seed != nil && seed.timeout > 0 {
		client.http.Timeout = seed.timeout
	}

	m := newModel(client, logger, dbg)
	if seed != nil {
		m.prefill(*seed) // open ready-to-send from `weeb METHOD URL …`
	}

	// AltScreen is now declared per-frame via View().AltScreen (v2), not a
	// program option.
	p := tea.NewProgram(m)
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 1
	}
	return 0
}

// ---- CLI mode --------------------------------------------------------------

type cliArgs struct {
	method   string
	url      string
	headers  []Header
	body     []byte
	timeout  time.Duration
	stats    bool
	pretty   bool   // --pretty: force the pretty/colored view on
	raw      bool   // --raw: force the raw view (server bytes as-is)
	noTUI    bool   // --no-tui: run headless even at a terminal
	quiet    bool   // -q/--quiet: headless, and suppress the stats block (body + errors only)
	toCurl   bool   // --to-curl: print the curl equivalent instead of sending
	persona  string // --persona: error voice for this run (overrides WEEB_PERSONA)
	output   string // -o/--output: stream the body to this file (uncapped, like curl -o)
	maxBody  string // --max-body: buffered-body cap, e.g. "256m" (overrides WEEB_MAX_BODY)
	noFollow bool   // --no-follow: don't follow redirects, show the 3xx itself
}

// prettyOn resolves the body view: pretty is on by default (and at a TTY), with
// --pretty / --raw / WEEB_PRETTY as overrides. (Pipes always get raw bytes; this
// only affects the colored TTY render in emitResult.)
func (a cliArgs) prettyOn() bool {
	p := envBool("WEEB_PRETTY", true)
	if a.pretty {
		p = true
	}
	if a.raw {
		p = false
	}
	return p
}

// runCLI fires a single request and routes output per the matrix:
//
//	stdout = response body only (clean, for pipes)
//	stderr = weeb error (errorchan) + charm/log diagnostics + (at a TTY) status line
//
// Color is applied to stdout ONLY when stdout is a terminal, so a pipe always
// receives the exact raw bytes the server sent (`weeb ... | jq` stays clean).
func runCLI(a cliArgs) int {
	spec := RequestSpec{Method: a.method, URL: a.url, Headers: a.headers, Body: a.body, NoFollow: a.noFollow}

	// --to-curl: export the request (with env prefills resolved, so it's a
	// faithful reproduction of what weeb would send) instead of sending it.
	if a.toCurl {
		color := stdoutIsTTY() && os.Getenv("NO_COLOR") == ""
		fmt.Fprintln(os.Stdout, renderCurl(resolveSpec(spec), newStyles(), color, true))
		return 0
	}

	persona, err := resolvePersona(a.persona)
	if err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 2
	}

	if err := applyMaxBody(a.maxBody); err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 2
	}

	logger, _, cleanup := newLogger(modeCLI)
	defer cleanup()

	client := newClient(logger, errorChanFor(persona))
	if a.timeout > 0 {
		client.http.Timeout = a.timeout
	}

	// Stream the body when it isn't being rendered: to -o FILE when asked, or
	// straight to a pipe (which always gets the raw bytes anyway). Constant
	// memory for arbitrarily large downloads — the 64 MiB cap applies only to
	// bodies weeb must hold to render — and the first bytes land immediately,
	// like curl.
	var outFile *os.File
	if a.output != "" {
		f, err := os.Create(a.output)
		if err != nil {
			fmt.Fprintln(os.Stderr, "weeb:", err)
			return 2
		}
		outFile = f
		spec.BodySink = f
	} else if !stdoutIsTTY() {
		spec.BodySink = os.Stdout
	}

	res := client.Do(spec)
	code := emitResult(res, a.stats, a.quiet, a.prettyOn())
	if outFile != nil {
		if err := outFile.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "weeb:", err)
			if code == 0 {
				code = 1
			}
		}
	}
	return code
}

// runCurlImport handles `weeb curl <command>`: parse a curl command and run it.
// The command may be one quoted string (we tokenize it) or already shell-split
// argv (e.g. `weeb curl curl https://x -H 'a: b'`).
func runCurlImport(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `weeb: curl needs a command, e.g. weeb curl 'curl https://api.example.com -H "Accept: application/json"'`)
		return 2
	}

	argv := args
	if len(args) == 1 {
		toks, err := tokenizeShell(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "weeb:", err)
			return 2
		}
		argv = toks
	}

	spec, err := parseCurl(argv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 2
	}

	if err := applyMaxBody(""); err != nil { // WEEB_MAX_BODY still applies
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 2
	}

	logger, _, cleanup := newLogger(modeCLI)
	defer cleanup()
	client := newClient(logger, newErrorChan())
	if !stdoutIsTTY() {
		spec.BodySink = os.Stdout // piped: stream the raw bytes, uncapped
	}
	res := client.Do(spec)
	return emitResult(res, false, false, envBool("WEEB_PRETTY", true))
}

// emitResult writes one finished request per the output matrix: body to stdout
// (raw when piped, colored at a TTY), and the stats block + weeb error to stderr.
// The stats block shows automatically at a TTY (or with --stats when piping)
// unless quiet suppresses it; the body and any error always go out.
// Everything goes through outW/errW: at a TTY that boundary sanitizes the
// server-influenced text (body, TLS leaf name, error strings); piped output
// is the writer itself, so pipes still get the exact server bytes.
func emitResult(res Result, wantStats, quiet, pretty bool) int {
	color := stdoutIsTTY() && os.Getenv("NO_COLOR") == ""

	if !quiet && (color || wantStats) && res.Status != 0 {
		st := newStyles()
		fmt.Fprintln(errW, statusBadge(res, st))
		if res.TLS != nil {
			fmt.Fprintln(errW, renderConnTLS(res.TLS, st))
		}
		fmt.Fprintln(errW, renderTiming(res.Timing, st, 50))
		if len(res.Redirects) > 0 {
			fmt.Fprintln(errW, renderRedirects(res.Redirects, st))
		}
	}

	// A streamed body (BodySink) was already written by Do and leaves
	// res.Body empty, so this block only fires for buffered responses.
	if len(res.Body) > 0 {
		switch {
		case color:
			// width 0 -> renderBody uses a sane default for markdown wrapping.
			fmt.Fprintln(outW, renderBody(res.Body, res.ContentType, res.URL, newStyles(), true, pretty, 0))
		case stdoutIsTTY():
			// NO_COLOR at a terminal: raw view, but still a terminal to protect.
			_, _ = io.WriteString(outW, string(res.Body))
		default:
			_, _ = outW.Write(res.Body) // pipe: exact server bytes, untouched
		}
	}

	if res.DisplayErr != "" {
		fmt.Fprintln(errW, res.DisplayErr)
	}

	if !res.OK() {
		return 1
	}
	return 0
}

// runCert handles `weeb cert <host>`: inspect a TLS endpoint and print a report.
//
//	weeb cert example.com
//	weeb cert https://example.com:8443 --json
//	weeb cert expired.badssl.com -k     # inspect anyway, don't fail on bad trust
//
// Exit code is non-zero when the chain is untrusted (unless -k) or expired, so
// it doubles as a monitoring check.
func runCert(args []string) int {
	logger, _, cleanup := newLogger(modeCLI)
	defer cleanup()

	var target, persona, clientCertPath, clientKeyPath string
	var insecure, asJSON, asPEM, brief bool
	opts := certOptions{timeout: defaultTimeout}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-k" || arg == "--insecure":
			insecure = true
		case arg == "--json":
			asJSON = true
		case arg == "--pem" || arg == "--showcerts":
			asPEM = true
		case arg == "--brief" || arg == "--short":
			brief = true
		case arg == "--sni" || arg == "--servername":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				fmt.Fprintln(os.Stderr, "weeb:", err)
				return 2
			}
			opts.sni = val
		case arg == "--starttls":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				fmt.Fprintln(os.Stderr, "weeb:", err)
				return 2
			}
			opts.startTLS = val
		case arg == "--alpn":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				fmt.Fprintln(os.Stderr, "weeb:", err)
				return 2
			}
			opts.alpn = splitList(val)
		case arg == "--tls":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				fmt.Fprintln(os.Stderr, "weeb:", err)
				return 2
			}
			v, err := parseTLSVersion(val)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}
			opts.minVersion, opts.maxVersion = v, v
		case arg == "--client-cert" || arg == "--cert":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				fmt.Fprintln(os.Stderr, "weeb:", err)
				return 2
			}
			clientCertPath = val
		case arg == "--client-key" || arg == "--key":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				fmt.Fprintln(os.Stderr, "weeb:", err)
				return 2
			}
			clientKeyPath = val
		case arg == "--persona":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				fmt.Fprintln(os.Stderr, "weeb:", err)
				return 2
			}
			persona = val
		case arg == "--timeout":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				fmt.Fprintln(os.Stderr, "weeb:", err)
				return 2
			}
			d, err := time.ParseDuration(val)
			if err != nil {
				fmt.Fprintf(os.Stderr, "weeb: bad --timeout %q: %v\n", val, err)
				return 2
			}
			opts.timeout = d
		case strings.HasPrefix(arg, "-") && arg != "-":
			fmt.Fprintf(os.Stderr, "weeb: unknown flag %q\n", arg)
			return 2
		default:
			if target != "" {
				fmt.Fprintf(os.Stderr, "weeb: unexpected argument %q\n", arg)
				return 2
			}
			target = arg
		}
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "weeb: cert needs a host, e.g. 'weeb cert example.com'")
		return 2
	}
	opts.insecure = insecure

	if (clientCertPath == "") != (clientKeyPath == "") {
		fmt.Fprintln(os.Stderr, "weeb: --client-cert and --client-key must be given together")
		return 2
	}
	if clientCertPath != "" {
		pair, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "weeb: load client cert: %v\n", err)
			return 2
		}
		opts.clientCert = &pair
	}

	personaMode, err := resolvePersona(persona)
	if err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 2
	}
	voice := errorChanFor(personaMode)

	rlog := logger.With("op", "cert", "target", target)
	rlog.Info("tls inspect")

	rep, err := fetchCertReport(target, opts)
	if err != nil {
		rlog.Error("tls inspect failed", "kind", KindTransport.String(), "err", err)
		fmt.Fprintln(errW, voice.Render(KindTransport, 0, err))
		return 1
	}
	rlog.Info("tls ok",
		"version", rep.TLSVersion, "verified", rep.Verified, "chain", len(rep.Chain))

	if asPEM {
		fmt.Fprint(outW, certPEM(rep))
		return certExit(rep, insecure)
	}
	if asJSON {
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Fprintln(outW, string(out))
		return certExit(rep, insecure)
	}

	// The report carries peer-controlled bytes (Subject/Issuer CNs, SANs, the
	// verify-error string — arbitrary for any self-signed cert); outW strips
	// hostile control sequences at a TTY.
	color := stdoutIsTTY() && os.Getenv("NO_COLOR") == ""
	fmt.Fprint(outW, renderCertReport(rep, newStyles(), color, terminalWidth(), !brief))
	return certExit(rep, insecure)
}

// terminalWidth returns stdout's column count, or 100 when it can't be detected
// (e.g. piped) — used to wrap the cert report's long values.
func terminalWidth() int {
	if w, _, err := term.GetSize(os.Stdout.Fd()); err == nil && w > 0 {
		return w
	}
	return 100
}

// stdoutIsTTY reports whether stdout is a terminal (not a pipe or file).
// x/term's check is platform-aware — on Windows a real console is detected
// properly, where the old Stat/ModeCharDevice idiom can mislead.
func stdoutIsTTY() bool {
	return term.IsTerminal(os.Stdout.Fd())
}

// parseCLI parses curl-flavoured args:
//
//	weeb [METHOD] URL [-H "K: V"]... [-d DATA] [--timeout DUR]
//
// METHOD is optional (defaults to GET, or POST when a body is present). -d
// DATA may be @file, '-' (stdin), or a literal string. When -d is omitted and
// stdin is piped, the pipe is read as the body.
func parseCLI(args []string) (cliArgs, error) {
	a := cliArgs{method: "GET"}
	methodSet := false
	urlSet := false
	bodySet := false

	known := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "PATCH": true,
		"DELETE": true, "HEAD": true, "OPTIONS": true,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-H" || arg == "--header":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			k, v, ok := strings.Cut(val, ":")
			if !ok {
				return a, fmt.Errorf("bad header %q (want \"Key: Value\")", val)
			}
			a.headers = append(a.headers, Header{Key: strings.TrimSpace(k), Value: strings.TrimSpace(v)})

		case arg == "-d" || arg == "--data":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			body, err := readData(val)
			if err != nil {
				return a, err
			}
			a.body = body
			bodySet = true

		case arg == "-X" || arg == "--request":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			a.method = strings.ToUpper(val)
			methodSet = true

		case arg == "--timeout":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			d, err := time.ParseDuration(val)
			if err != nil {
				return a, fmt.Errorf("bad --timeout %q: %w", val, err)
			}
			a.timeout = d

		case arg == "--stats" || arg == "-v" || arg == "--verbose":
			a.stats = true

		case arg == "--pretty":
			a.pretty = true

		case arg == "--raw":
			a.raw = true

		case arg == "--no-tui" || arg == "--headless":
			a.noTUI = true

		case arg == "-q" || arg == "--quiet":
			a.quiet = true

		case arg == "--persona":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			a.persona = val

		case arg == "--to-curl" || arg == "--curl":
			a.toCurl = true

		case arg == "-o" || arg == "--output":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			a.output = val

		case arg == "--max-body":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			a.maxBody = val

		case arg == "--no-follow":
			a.noFollow = true

		case strings.HasPrefix(arg, "-") && arg != "-":
			return a, fmt.Errorf("unknown flag %q", arg)

		default:
			// Positional: METHOD then URL, or just URL.
			if !methodSet && !urlSet && known[strings.ToUpper(arg)] {
				a.method = strings.ToUpper(arg)
				methodSet = true
				continue
			}
			if !urlSet {
				a.url = arg
				urlSet = true
				continue
			}
			return a, fmt.Errorf("unexpected argument %q", arg)
		}
	}

	// A missing URL is fine when we're opening the interactive builder (the
	// caller decides); it's only an error in headless mode (see main).

	// No explicit body but stdin is piped -> read the pipe as the body.
	if !bodySet && stdinIsPiped() {
		body, err := io.ReadAll(os.Stdin)
		if err != nil {
			return a, fmt.Errorf("reading stdin: %w", err)
		}
		if len(body) > 0 {
			a.body = body
		}
	}

	// A -d body with no explicit method implies POST, matching curl (and our
	// own curl importer) — the default GET would make buildRequest silently
	// drop the body the user just asked to send. The inference deliberately
	// does NOT fire for a body picked up from piped stdin: `some_cmd | weeb
	// URL` often pipes output that was never meant as a body, and invisibly
	// flipping GET to POST is worse than dropping the unrequested body.
	if !methodSet && bodySet && len(a.body) > 0 {
		a.method = "POST"
	}

	return a, nil
}

func nextArg(args []string, i *int, flag string) (string, error) {
	if *i+1 >= len(args) {
		return "", fmt.Errorf("%s needs a value", flag)
	}
	*i++
	return args[*i], nil
}

// readData resolves a -d value: @file reads a file, '-' reads stdin, anything
// else is a literal.
func readData(val string) ([]byte, error) {
	switch {
	case val == "-":
		return io.ReadAll(os.Stdin)
	case strings.HasPrefix(val, "@"):
		b, err := os.ReadFile(val[1:])
		if err != nil {
			return nil, fmt.Errorf("reading %q: %w", val[1:], err)
		}
		return b, nil
	default:
		return []byte(val), nil
	}
}

func stdinIsPiped() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice == 0
}

// ---- help ------------------------------------------------------------------

func printHelp(w io.Writer) {
	fmt.Fprint(w, `weeb — a terminal HTTP client (interactive TUI + scriptable CLI)

USAGE
  weeb                       launch the empty interactive TUI builder
  weeb [METHOD] URL [opts]   open the TUI prefilled with the request
  weeb cert HOST [opts]      inspect a TLS certificate / chain
  weeb curl '<curl cmd>'     run a pasted curl command (import)
  weeb version               print the build version

  METHOD defaults to GET. A URL opens the interactive builder, BUT weeb runs a
  headless one-shot instead when the output is script-bound — stdout isn't a
  terminal (piped/redirected), a body is piped into stdin, or you pass --no-tui,
  --raw, or --to-curl. In headless mode the response BODY goes to stdout (clean,
  so it pipes into jq); errors and logs go to stderr (or a log file).

OPTIONS
  -H, --header "K: V"   add a request header (repeatable)
  -d, --data DATA       request body; DATA may be:
                          @file   read the file
                          -       read stdin
                          string  a literal body
                        (if -d is omitted and stdin is piped, the pipe is the body)
  -X, --request METHOD  set the method explicitly
      --timeout DUR     request timeout, e.g. 10s, 500ms (default 30s)
      --no-follow       don't follow redirects — show the 3xx response itself
                        (status, Location header, body); by default weeb follows
                        up to 10 redirects (implies headless)
  -v, --stats           print a timing breakdown (dns/tcp/tls/send/wait/recv) and
                        the negotiated TLS to stderr, even when piping
      --pretty          force the pretty/colored body view (the default at a TTY:
                        indent + syntax color, markdown rendered via glamour,
                        and sniff of mislabeled JSON/XML/HTML)
      --raw             force the raw body view — exactly the bytes the server
                        sent, no reformatting or color (implies --no-tui)
      --no-tui          run a headless one-shot even at a terminal (alias --headless)
  -q, --quiet           headless, body only — suppress the stats block (errors still show)
      --persona MODE    error voice: plain (default) | dere | tsun | yan
                        (overrides WEEB_PERSONA for this run)
      --to-curl         print the curl equivalent of the request, don't send
  -o, --output FILE     stream the response body to FILE (uncapped, like curl -o;
                        implies headless)
      --max-body SIZE   cap for bodies weeb buffers to render (default 64m);
                        bytes or k/m/g, 0 = no cap. Piped/-o bodies are never capped
  -h, --help            show this help

CURL IMPORT (weeb curl '<command>')
  Paste a curl command (from docs, DevTools "Copy as cURL", etc.) and weeb runs
  it: -X/-H/-d/--data*, -u (basic auth), -A/-b/-e, @file bodies. Transfer-only
  flags (-L, -k, --compressed, …) are ignored. The command may be one quoted
  string or already shell-split.
    weeb curl 'curl -X POST https://api.example.com/u -H "Accept: application/json" -d @body.json'

CERT OPTIONS (weeb cert HOST)  — a friendlier 'openssl s_client'
  -k, --insecure        inspect even if the chain is untrusted/expired
      --json            emit the report as JSON (clean, for pipes/monitoring)
      --pem             dump the chain as PEM (like -showcerts); --showcerts alias
      --brief           show the leaf only, not full detail for every cert (--short)
      --sni NAME        present this SNI/servername (decoupled from the dial host,
                        so you can point at an IP); --servername alias
      --starttls PROTO  upgrade via smtp | imap | pop3 | ftp before the handshake
                        (default port follows the protocol: 587/143/110/21)
      --alpn LIST       advertise these ALPN protocols, e.g. "h2,http/1.1"
      --tls VERSION     pin the handshake to 1.0 | 1.1 | 1.2 | 1.3
      --client-cert F   client certificate for mTLS (--cert alias)
      --client-key  F   matching private key (--key alias; both required together)
      --timeout DUR     dial timeout (default 30s)
      --persona MODE    error voice for dial failures (see --persona above)
  exit code is non-zero when the chain is untrusted (unless -k) or expired,
  so 'weeb cert' doubles as a cron/monitoring check.

EXAMPLES
  weeb GET  https://api.example.com/me
  weeb POST https://api.example.com/users -H "Authorization: Bearer x" -d @body.json
  weeb POST https://api.example.com/users -H "Content-Type: application/json" -d '{"name":"a"}'
  echo '{"name":"a"}' | weeb POST https://api.example.com/users
  weeb cert example.com
  weeb cert https://example.com:8443 --json | jq .chain[0].days_until_expiry
  weeb cert smtp.gmail.com --starttls smtp
  weeb cert 93.184.216.34 --sni example.com
  weeb cert example.com --pem > chain.pem

TUI KEYS
  tab/shift+tab/↑↓ move between fields · ←→ pick method · ctrl+o/ctrl+r add/del header
  ctrl+s send · ctrl+t inspect TLS cert · ctrl+x export as curl · ctrl+p pretty · ctrl+y 🌈 · ctrl+g debug
  in the response pane: ↑↓ scroll · ←→ select section or node (JSON/XML/HTML/YAML) · enter fold · -/+ fold all

ENVIRONMENT (prefills, applied unless you override them)
  WEEB_BASE_URL    relative URLs ("/me") resolve against this base
  WEEB_HEADERS     default headers on every request, "K:V;K2:V2"
  WEEB_TOKEN       adds "Authorization: Bearer $WEEB_TOKEN" unless you set Authorization
  WEEB_PERSONA     error voice: plain (default) | dere | tsun | yan
  WEEB_RAINBOW     1/true to launch the TUI in 🌈 mode (toggle live with ctrl+y)
  WEEB_PRETTY      pretty body view; on by default, set 0/false for raw (toggle: ctrl+p)
  WEEB_MAX_BODY    cap for buffered bodies, e.g. 256m (default 64m, 0 = no cap;
                   --max-body wins; piped/-o bodies are never capped)

LOGGING (structured diagnostics; never on stdout)
  WEEB_LOG         debug|info|warn|error|off        (default: warn)
  WEEB_LOG_FORMAT  text|json|logfmt                 (default: text)
  WEEB_LOG_FILE    path; logs go here instead of stderr. In TUI mode logs always
                   go to a file (default: weeb/weeb.log in the user cache dir) so they
                   don't corrupt the screen; toggle the in-app debug pane with ctrl+g.
`)
}
