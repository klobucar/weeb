package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strconv"
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
	case "completion":
		os.Exit(runCompletion(args[1:], os.Stdout))
	case "history":
		os.Exit(runHistory(args[1:]))
	case "audit":
		os.Exit(runAudit(args[1:]))
	case "run":
		os.Exit(runHTTPFile(args[1:]))
	case "view":
		os.Exit(runView(args[1:]))
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
// --to-curl, --no-follow, -i, --check: the TUI form has no redirect toggle, so opening it
// would silently drop the flag; --repeat prints a summary, not a form).
func (a cliArgs) headless() bool {
	return a.noTUI || a.quiet || a.raw || a.toCurl || a.noFollow || a.include || a.check || a.output != "" || !stdoutIsTTY() || stdinIsPiped() ||
		a.repeat > 0
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
	if seed != nil {
		if err := preflightSpec(RequestSpec{TLS: seed.tls, Form: seed.form}); err != nil {
			fmt.Fprintln(os.Stderr, "weeb:", err)
			return 2
		}
	}

	client := newClient(logger, voice)
	if seed != nil && seed.timeout > 0 {
		client.SetTimeout(seed.timeout)
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
	include  bool   // -i/--include: print the status line + response headers before the body (curl -i)
	toCurl   bool   // --to-curl: print the curl equivalent instead of sending
	persona  string // --persona: error voice for this run (overrides WEEB_PERSONA)
	output   string // -o/--output: stream the body to this file (uncapped, like curl -o)
	maxBody  string // --max-body: buffered-body cap, e.g. "256m" (overrides WEEB_MAX_BODY)
	noFollow bool   // --no-follow: don't follow redirects, show the 3xx itself

	// curl-parity request options (see tlsopts.go, form.go, cookies.go).
	tls        TLSOptions  // -k, --cacert, -E/--cert, --key
	form       []FormField // -F/--form, --form-string: multipart body
	cookieFile string      // -b FILE: Netscape cookie file to load
	cookieJar  string      // --cookie-jar FILE: write cookies here after

	// Monitoring-plugin mode (see check.go). check replaces the whole output
	// matrix with one plugin line + a 0/1/2/3 exit; the others only apply with it.
	check        bool
	checkJSON    bool          // --json: render the verdict as a JSON object
	expectStatus string        // --expect-status: statuses that count as OK
	expectBody   string        // --expect-body: Go regexp the body must match
	expectHeader []string      // --expect-header (repeatable): 'Name', 'Name: RE', '!Name'
	expectJSON   []string      // --expect-json (repeatable): jq-like path + comparison
	warn, crit   time.Duration // -w/-c: response-time thresholds

	// Latency benchmark (see repeat.go). repeat replaces the body output with
	// a timing summary; --json (checkJSON above) renders that as JSON too.
	repeat      int  // --repeat N: send the request N times
	concurrency int  // --concurrency C: requests in flight at once (0 = 1)
	fresh       bool // --fresh: no keep-alive, every request dials anew
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
	spec.TLS, spec.Form, spec.CookieFile, spec.CookieJar = a.tls, a.form, a.cookieFile, a.cookieJar

	if a.repeat > 0 {
		// The same file checks and -k warning as a single send, once for the
		// whole run: a bad --cacert is one usage error, not N failures.
		if err := preflightSpec(spec); err != nil {
			fmt.Fprintln(os.Stderr, "weeb:", err)
			return 2
		}
		warnInsecure(os.Stderr, spec)
		return runRepeat(a, spec)
	}

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

	if !a.check && (len(a.expectHeader) > 0 || len(a.expectJSON) > 0) {
		fmt.Fprintln(os.Stderr, "weeb: --expect-header/--expect-json only apply with --check")
		return 2
	}

	// Monitoring-plugin mode: compile the assertions up front. A bad pattern
	// or flag combination is a usage error, which in plugin-land is UNKNOWN
	// on stdout, not weeb's usual stderr/2.
	var nopts checkHTTPOpts
	if a.check {
		o, err := a.checkOpts()
		if err != nil {
			return printCheck(outW, newCheckVerdict("http", checkUnknown, checkSafe(err.Error()), "", nil), a.checkJSON)
		}
		nopts = o
	} else if a.expectStatus != "" || a.expectBody != "" || a.warn > 0 || a.crit > 0 || a.checkJSON {
		fmt.Fprintln(os.Stderr, "weeb: --expect-status/--expect-body/-w/-c/--json only apply with --check")
		return 2
	}

	// Unreadable TLS material or -F files are usage errors, caught before
	// anything is sent (UNKNOWN in plugin mode, like the errors above).
	if err := preflightSpec(spec); err != nil {
		if a.check {
			return printCheck(outW, newCheckVerdict("http", checkUnknown, checkSafe(err.Error()), "", nil), a.checkJSON)
		}
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 2
	}
	warnInsecure(os.Stderr, spec)

	logger, _, cleanup := newLogger(modeCLI)
	defer cleanup()

	client := newClient(logger, errorChanFor(persona))
	if a.timeout > 0 {
		client.SetTimeout(a.timeout)
	}

	// Stream the body when it isn't being rendered: to -o FILE when asked, or
	// straight to a pipe (which always gets the raw bytes anyway). Constant
	// memory for arbitrarily large downloads — the 64 MiB cap applies only to
	// bodies weeb must hold to render — and the first bytes land immediately,
	// like curl. A --check run buffers for --expect-body; -i without -o also
	// buffers so headers print first. -o keeps streaming (headers to stdout,
	// body to file).
	var outFile *os.File
	if a.output != "" {
		f, err := os.Create(a.output)
		if err != nil {
			fmt.Fprintln(os.Stderr, "weeb:", err)
			return 2
		}
		outFile = f
		spec.BodySink = f
	} else if !stdoutIsTTY() && !a.include && !a.check {
		spec.BodySink = os.Stdout
	}
	if !a.check { // at a terminal, an event stream prints event by event as it arrives
		spec.OnStream = ttyStream(a.stats, a.quiet, a.prettyOn(), a.include)
	}

	res := client.Do(spec)
	if a.check {
		return printCheck(outW, checkHTTP(res, nopts), a.checkJSON)
	}
	code := emitResult(res, a.stats, a.quiet, a.prettyOn(), a.include)
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
	if err := preflightSpec(spec); err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 2
	}
	warnInsecure(os.Stderr, spec) // a pasted -k is as loud as a typed one

	logger, _, cleanup := newLogger(modeCLI)
	defer cleanup()
	client := newClient(logger, newErrorChan())
	if !stdoutIsTTY() {
		spec.BodySink = os.Stdout // piped: stream the raw bytes, uncapped
	}
	spec.OnStream = ttyStream(false, false, envBool("WEEB_PRETTY", true), false)
	res := client.Do(spec)
	return emitResult(res, false, false, envBool("WEEB_PRETTY", true), false)
}

// emitResult writes one finished request per the output matrix: body to stdout
// (raw when piped, colored at a TTY), and the stats block + weeb error to stderr.
// The stats block shows automatically at a TTY (or with --stats when piping)
// unless quiet suppresses it; the body and any error always go out.
// Everything goes through outW/errW: at a TTY that boundary sanitizes the
// server-influenced text (body, TLS leaf name, error strings); piped output
// is the writer itself, so pipes still get the exact server bytes.
func emitResult(res Result, wantStats, quiet, pretty, include bool) int {
	if res.Stream != streamNone { // printed live by ttyStream; only the close is left
		return emitStreamEnd(res, wantStats, quiet)
	}
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

	// -i/--include: the status line and response headers go to stdout before
	// the body, like curl -i. Header values are server-controlled; outW strips
	// hostile control sequences at a TTY.
	if include && res.Status != 0 {
		fmt.Fprintf(outW, "%s %d %s\n", res.Proto, res.Status, res.StatusText)
		for _, k := range sortedHeaderKeys(res.Headers) {
			for _, v := range res.Headers[k] {
				fmt.Fprintf(outW, "%s: %s\n", k, v)
			}
		}
		fmt.Fprintln(outW)
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
//	weeb cert ./chain.pem               # a local PEM/DER file instead (certfile.go)
//
// Exit code is non-zero when the chain is untrusted (unless -k) or expired, so
// it doubles as a monitoring check.
func runCert(args []string) int {
	logger, _, cleanup := newLogger(modeCLI)
	defer cleanup()

	var target, persona, clientCertPath, clientKeyPath string
	var certFile, fileHost string // -f/--file and --host: inspect a local cert file (certfile.go)
	var insecure, asJSON, asPEM, brief, checkMode bool
	warnDays, critDays := 30, 14 // --check expiry thresholds
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
		case arg == "--check" || arg == "--nagios":
			checkMode = true
		case arg == "-w" || arg == "--warn", arg == "-c" || arg == "--crit":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				fmt.Fprintln(os.Stderr, "weeb:", err)
				return 2
			}
			n, err := strconv.Atoi(val)
			if err != nil || n < 0 {
				fmt.Fprintf(os.Stderr, "weeb: bad %s %q (want days, e.g. 30)\n", arg, val)
				return 2
			}
			if arg == "-w" || arg == "--warn" {
				warnDays = n
			} else {
				critDays = n
			}
		case arg == "--sni" || arg == "--servername":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				fmt.Fprintln(os.Stderr, "weeb:", err)
				return 2
			}
			opts.sni = val
		case arg == "-f" || arg == "--file":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				fmt.Fprintln(os.Stderr, "weeb:", err)
				return 2
			}
			certFile = val
		case arg == "--host":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				fmt.Fprintln(os.Stderr, "weeb:", err)
				return 2
			}
			fileHost = val
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

	// A positional naming a local cert file (or "-" for stdin) is read, not
	// dialed; isCertFileTarget keeps a bare hostname a hostname.
	if certFile == "" && isCertFileTarget(target) {
		certFile, target = target, ""
	}
	if target == "" && certFile == "" {
		fmt.Fprintln(os.Stderr, "weeb: cert needs a host or a file, e.g. 'weeb cert example.com' or 'weeb cert chain.pem'")
		return 2
	}
	if certFile != "" && target != "" {
		fmt.Fprintf(os.Stderr, "weeb: unexpected argument %q (already reading %s)\n", target, certSourceName(certFile))
		return 2
	}
	if checkMode && critDays > warnDays {
		// A usage error in plugin mode is UNKNOWN on stdout, not stderr/2 —
		// the monitoring system is the one reading.
		msg := fmt.Sprintf("--crit %d days is above --warn %d days", critDays, warnDays)
		return printCheck(outW, newCheckVerdict("cert", checkUnknown, msg, "", nil), asJSON)
	}
	opts.insecure = insecure
	if certFile != "" {
		if flag := netOnlyCertFlag(opts, clientCertPath, clientKeyPath); flag != "" {
			fmt.Fprintf(os.Stderr, "weeb: %s needs a live endpoint; %s is a certificate file\n", flag, certSourceName(certFile))
			return 2
		}
	} else if fileHost != "" {
		fmt.Fprintln(os.Stderr, "weeb: --host checks a certificate file; for a live endpoint use --sni")
		return 2
	}

	if (clientCertPath == "") != (clientKeyPath == "") {
		fmt.Fprintln(os.Stderr, "weeb: --client-cert and --client-key must be given together")
		return 2
	}
	if clientCertPath != "" {
		pair, err := loadClientCert(clientCertPath, clientKeyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "weeb:", err)
			return 2
		}
		opts.clientCert = pair
	}

	personaMode, err := resolvePersona(persona)
	if err != nil {
		fmt.Fprintln(os.Stderr, "weeb:", err)
		return 2
	}
	voice := errorChanFor(personaMode)

	out := certOutput{
		insecure: insecure, asJSON: asJSON, asPEM: asPEM, brief: brief,
		check: checkMode, warnDays: warnDays, critDays: critDays,
	}
	if certFile != "" {
		// --sni names the host a live chain is checked against, so it means
		// the same for a file; --host is the spelling that reads right there.
		return runCertFile(certFile, orFallback(fileHost, opts.sni), voice, out, logger)
	}

	rlog := logger.With("op", "cert", "target", target)
	rlog.Info("tls inspect")

	rep, err := fetchCertReport(target, opts)
	if err != nil {
		rlog.Error("tls inspect failed", "kind", KindTransport.String(), "err", err)
		if checkMode {
			// Could not reach the endpoint at all: that's UNKNOWN, not
			// CRITICAL — the cert state was never observed.
			return printCheck(outW, newCheckVerdict("cert", checkUnknown, checkSafe(err.Error()), "", nil), asJSON)
		}
		fmt.Fprintln(errW, voice.Render(KindTransport, 0, err))
		return 1
	}
	rlog.Info("tls ok",
		"version", rep.TLSVersion, "verified", rep.Verified, "chain", len(rep.Chain))

	return out.emit(rep)
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
// DATA may be @file, '-' or '@-' (stdin), or a literal string. When -d is
// omitted and stdin is piped, the pipe is read as the body.
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

		case arg == "-i" || arg == "--include":
			a.include = true

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

		case arg == "--check" || arg == "--nagios":
			a.check = true

		case arg == "--json":
			a.checkJSON = true

		case arg == "--expect-status":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			a.expectStatus = val

		case arg == "--expect-body":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			a.expectBody = val

		case arg == "--expect-header":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			a.expectHeader = append(a.expectHeader, val)

		case arg == "--expect-json":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			a.expectJSON = append(a.expectJSON, val)

		case arg == "-w" || arg == "--warn", arg == "-c" || arg == "--crit":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			d, err := time.ParseDuration(val)
			if err != nil {
				return a, fmt.Errorf("bad %s %q: %w", arg, val, err)
			}
			if arg == "-w" || arg == "--warn" {
				a.warn = d
			} else {
				a.crit = d
			}

		case arg == "-k" || arg == "--insecure":
			a.tls.Insecure = true

		case arg == "--cacert", arg == "--key":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			if arg == "--cacert" {
				a.tls.CACert = val
			} else {
				a.tls.Key = val
			}

		case arg == "-E" || arg == "--cert":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			if a.tls.Cert, err = parseCertArg(val); err != nil {
				return a, err
			}

		case arg == "-F" || arg == "--form" || arg == "--form-string":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			f, err := parseFormArg(val, arg == "--form-string")
			if err != nil {
				return a, err
			}
			a.form = append(a.form, f)

		case arg == "-b" || arg == "--cookie":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			header, file, err := parseCookieArg(val)
			if err != nil {
				return a, err
			}
			if header != "" {
				a.headers = append(a.headers, Header{Key: "Cookie", Value: header})
			}
			if file != "" {
				a.cookieFile = file
			}

		case arg == "--cookie-jar": // curl's -c; weeb's -c is --crit
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			if err := checkCookieJarArg(val); err != nil {
				return a, err
			}
			a.cookieJar = val

		case arg == "--repeat" || arg == "--concurrency":
			val, err := nextArg(args, &i, arg)
			if err != nil {
				return a, err
			}
			n, err := strconv.Atoi(val)
			if err != nil || n < 1 {
				return a, fmt.Errorf("bad %s %q (want a whole number, 1 or more)", arg, val)
			}
			if arg == "--repeat" {
				a.repeat = n
			} else {
				a.concurrency = n
			}

		case arg == "--fresh":
			a.fresh = true

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

	// -F builds the body itself: it can't share it with -d, and a piped
	// stdin isn't read as a body behind its back. Like -d, it implies POST.
	if len(a.form) > 0 {
		if bodySet {
			return a, fmt.Errorf("-d and -F can't be combined (one request body)")
		}
		bodySet = true
		if !methodSet {
			a.method = "POST"
		}
	}

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

	if err := a.checkRepeatFlags(); err != nil {
		return a, err
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

// readData resolves a -d value: @file reads a file, '-' or '@-' reads stdin,
// anything else is a literal.
func readData(val string) ([]byte, error) {
	switch {
	case val == "-", val == "@-":
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
  weeb cert FILE [opts]      inspect a local PEM/DER certificate file ('-' = stdin)
  weeb curl '<curl cmd>'     run a pasted curl command (import)
  weeb completion SHELL      print shell completion script (zsh|bash|fish)
  weeb history [N|--clear]   list recent requests / re-run entry N / wipe history
  weeb audit URL [opts]      grade a page's security headers
  weeb run FILE [NAME|N]     list the requests in a .http file / run one
  weeb view [FILE|-] [opts]  browse a JSON/XML/HTML/YAML/Markdown file, foldable
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
                          -, @-   read stdin
                          string  a literal body
                        (if -d is omitted and stdin is piped, the pipe is the body)
  -X, --request METHOD  set the method explicitly
      --timeout DUR     request timeout, e.g. 10s, 500ms (default 30s). For
                        streamed bodies (-o / piped) the default bounds the wait
                        for headers, not the transfer; an explicit --timeout
                        caps the whole transfer. For event streams (see
                        STREAMING) it is an idle timeout instead
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
  -i, --include         print the status line and response headers on stdout before
                        the body, like curl -i (implies headless; when piped the body
                        buffers so headers come first, so the --max-body cap applies)
      --persona MODE    error voice: plain (default) | dere | tsun | yan
                        (overrides WEEB_PERSONA for this run)
      --to-curl         print the curl equivalent of the request, don't send
  -o, --output FILE     stream the response body to FILE (uncapped, like curl -o;
                        implies headless)
      --max-body SIZE   cap for bodies weeb buffers to render (default 64m);
                        bytes or k/m/g, 0 = no cap. Piped/-o bodies are never capped
  -k, --insecure        skip TLS certificate verification. Never silent: a warning
                        goes to stderr, and the TUI shows a red INSECURE badge
      --cacert FILE     trust the CA certificates in this PEM file INSTEAD of the
                        system roots, like curl (the server must chain to one)
  -E, --cert FILE       client certificate (PEM) for mTLS; the key may be in the
                        same file. curl's FILE:PASSWORD isn't supported (decrypt
                        the key first); write a colon in the name as \:
      --key FILE        the client certificate's private key (PEM), if separate
  -F, --form NAME=...   add a multipart/form-data part (repeatable; implies POST):
                          name=value                            a text field
                          name=@file[;type=MIME][;filename=N]   upload a file
                          name=<file                            text read from file
                        quote a value holding ';' as name="a;b". --form-string
                        NAME=VALUE sends VALUE as-is (no @, <, or ; handling)
  -b, --cookie DATA     send cookies "a=1; b=2"; DATA without '=' is a Netscape
                        cookie file loaded into a cookie jar (a missing file is fine)
      --cookie-jar FILE after the request, write the jar's cookies to FILE
                        (Netscape format, mode 0600) — curl's -c, which weeb
                        uses for --crit. -b FILE --cookie-jar FILE keeps a session
  -h, --help            show this help

MONITORING (--check; a check_http replacement)
      --check           monitoring-plugin mode (Nagios/Icinga/Sensu/Zabbix):
                        print one "HTTP OK - ... |perfdata" line on stdout and
                        exit 0/1/2/3 (OK/WARNING/CRITICAL/UNKNOWN) instead of
                        the normal output; perfdata carries response time, body
                        size, and days_until_expiry when the connection was TLS
                        (alias --nagios)
      --expect-status S statuses that count as OK: codes, ranges, or classes,
                        e.g. "200", "200-204,301", "2xx" (default: any < 400)
      --expect-body RE  CRITICAL unless the body matches this Go regexp
      --expect-header H CRITICAL unless the response header is: 'Name' present,
                        'Name: RE' present with a value matching the Go regexp,
                        or '!Name' absent (repeatable)
      --expect-json EXPR
                        CRITICAL unless the JSON body satisfies EXPR, a jq-like
                        path with an optional comparison (repeatable):
                          '.status == "ok"'   '.items[0].id != null'
                          '.count > 0'        '.version =~ "^2\."'
                          '.data.items | length >= 1'
                          '.a.b'  bare: must exist and be neither null nor false
                        paths: .key  .["any key"]  [N]  [-1] (from the end);
                        values are JSON literals; ops: == != < <= > >= =~ (a
                        quoted Go regexp); '| length' is the one function. A
                        non-JSON body is CRITICAL; a bad EXPR is UNKNOWN
  -w, --warn DUR        WARNING when the request takes longer, e.g. 500ms
  -c, --crit DUR        CRITICAL when the request takes longer, e.g. 2s
      --json            render the verdict as one JSON object instead of the
                        plugin line — {check, status, code, message, metrics}
                        — same exit code (for script_exporter & friends)
                        HTTP verdicts also list "assertions": each one's type,
                        expect, ok, and actual value (clipped)

STREAMING (text/event-stream, application/x-ndjson, jsonl, json-seq)
  Event streams render live as each event arrives. At a terminal (and in the
  TUI) each SSE event prints as a block, event:/id: on one line and JSON data
  pretty-printed; each NDJSON line is its own block. Piped or -o gets the exact
  bytes as they arrive. The default timeout bounds only the wait for headers,
  never the stream; an explicit --timeout ends a stream after DUR with no
  data. In the TUI, esc stops a stream and keeps what arrived; the pane keeps
  the newest 2000 events (at most 4 MB).

BENCHMARK (--repeat; a latency mini-benchmark)
      --repeat N        send the request N times and print a summary on stdout
                        instead of the body (bodies are discarded): min/p50/
                        p90/p99/max for dns, connect, tls, wait (TTFB) and
                        total, a status-code histogram, and the error count.
                        ctrl+c stops early and still prints it. Exit 1 if any
                        request failed or got a status >= 400 (implies headless)
      --concurrency C   requests in flight at once (default 1)
      --fresh           no keep-alive: every request pays for DNS, TCP and TLS
                        (what a first-time visitor sees). The default reuses
                        connections like a real client (steady-state latency)
      --json            with --repeat: the summary as one JSON object

CURL IMPORT (weeb curl '<command>')
  Paste a curl command (from docs, DevTools "Copy as cURL", etc.) and weeb runs
  it: -X/-H/-d/--data*, -u (basic auth), -A/-b/-e, @file bodies. Transfer-only
  flags (-L, --compressed, …) are ignored. The command may be one quoted
  string or already shell-split.
  Also honored: -F/--form/--form-string, -k/--insecure (with the same stderr
  warning), --cacert, -E/--cert, --key, -b FILE, and -c/--cookie-jar FILE.
    weeb curl 'curl -X POST https://api.example.com/u -H "Accept: application/json" -d @body.json'

HTTP FILES (weeb run FILE.http [NAME|N])
  Run requests from a VS Code REST Client / JetBrains HTTP Client .http file.
  With no NAME or N, list the requests; otherwise run one: the TUI opens
  prefilled at a terminal, headless when piped. Supports ### separators,
  # @name, @var = value, {{var}}, {{$processEnv VAR}} / {{$env.VAR}}, ?/& query
  lines and < ./file body includes. Response chaining isn't supported.
      --env NAME        take variables from environment NAME in
                        http-client.env.json (+ http-client.private.env.json)
      --no-tui          run headless even at a terminal (alias --headless)
    weeb run api.http             list the requests
    weeb run api.http login       run the request named login (or by number: 1)

CERT OPTIONS (weeb cert HOST)  — a friendlier 'openssl s_client'
  -k, --insecure        inspect even if the chain is untrusted/expired
      --json            emit the report as JSON (clean, for pipes/monitoring);
                        with --check, the evaluated VERDICT object instead
                        ({check, status, code, message, metrics})
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
      --check           monitoring-plugin mode: one "CERT OK - ..." line plus
                        exit 0/1/2/3; validates the chain by default and alerts
                        on the LEAF's expiry (alias --nagios)
  -w, --warn DAYS       with --check: WARNING when the leaf expires within
                        DAYS (default 30)
  -c, --crit DAYS       with --check: CRITICAL when within DAYS (default 14);
                        untrusted or expired is always CRITICAL (unless -k)
  -f, --file PATH       read certificates from PATH ('-' = stdin) instead of
                        dialing; PEM (any order, other blocks such as keys are
                        skipped and never printed) or DER. A bare argument is a
                        file when it is '-', or exists and has a '/' or a
                        .pem/.crt/.cer/.der extension; 'example.com' always dials
      --host NAME       with a file: also check the leaf against NAME (--sni
                        works too); without it there is no hostname check
  exit code is non-zero when the chain is untrusted (unless -k) or expired,
  so 'weeb cert' doubles as a cron/monitoring check.

AUDIT OPTIONS (weeb audit URL)  — grade a page's security headers
  GETs the URL, follows redirects, and grades the final response's HSTS, CSP,
  X-Content-Type-Options, clickjacking (frame-ancestors / X-Frame-Options),
  Referrer-Policy, Permissions-Policy, COOP/CORP, Set-Cookie flags, CORS, and
  version banners: pass / warn / fail, each with a reason. A bare host means
  https. Exits 0 once audited (1 if unreachable); --check grades the exit.
  -H, --header "K: V"   add a request header (repeatable)
      --timeout DUR     request timeout (default 30s)
      --json            emit the report as JSON; with --check, the verdict
                        object ({check, status, code, message, metrics})
      --check           monitoring-plugin mode: one "AUDIT WARNING - ..." line;
                        any fail is CRITICAL, any warn WARNING (alias --nagios)
      --persona MODE    error voice for fetch failures (see --persona above)
VIEW (weeb view [FILE|-])  — a local jless/fx, using the response pane
  Reads FILE, or stdin when FILE is - or omitted. At a terminal it opens the
  pretty, foldable viewer: the response-pane keys plus ctrl+p pretty/raw,
  ctrl+y 🌈, q or ctrl+c to quit. Piped, it prints the uncolored pretty render
  (JSON and XML reindented; HTML, YAML and Markdown as-is), so it doubles as a
  formatter. The format comes from the file extension, else a content sniff.
      --type T          force the format: json | xml | html | yaml | md
      --raw             piped: write the bytes unchanged; at a terminal: open
                        in the raw view (ctrl+p toggles)
      --max-body SIZE   refuse input larger than SIZE (default 64m, 0 = no cap;
                        overrides WEEB_MAX_BODY)

COMPLETION (weeb completion zsh|bash|fish)
  prints a static tab-completion script — zsh: save it as _weeb in your $fpath;
  bash: add 'eval "$(weeb completion bash)"' to ~/.bashrc;
  fish: weeb completion fish > ~/.config/fish/completions/weeb.fish

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
  weeb cert example.com --check -w 30 -c 14
  weeb cert ./chain.pem --host example.com
  cat chain.pem | weeb cert - --check -w 30 -c 14
  weeb https://api.example.com/health --check --expect-body '"status": *"ok"' -w 500ms -c 2s
  weeb https://api.example.com/health --repeat 200 --concurrency 8
  weeb https://api.example.com/health --repeat 50 --fresh --json | jq .phases.tls
  weeb audit example.com
  weeb audit https://example.com/login --check
  weeb https://api.example.com/health --check --expect-json '.status == "ok"' --expect-header '!X-Debug'
  weeb view data.json
  kubectl get pod web -o yaml | weeb view --type yaml
  weeb view data.json > pretty.json

TUI KEYS
  tab/shift+tab/↑↓ move between fields · ←→ pick method · ctrl+o/ctrl+r add/del header
  ctrl+s send · esc stop a request/stream · ctrl+t inspect TLS cert · ctrl+x export as curl
  ctrl+p pretty · ctrl+y 🌈 · ctrl+g debug
  in the response pane: ↑↓ scroll · ←→ select section or node (JSON/XML/HTML/YAML) · enter fold · -/+ fold all
  y copy the node's path (jq/XPath) · Y copy its value · ctrl+x also copies the curl (clipboard via OSC 52)

ENVIRONMENT (prefills, applied unless you override them)
  WEEB_BASE_URL    relative URLs ("/me") resolve against this base
  WEEB_HEADERS     default headers on every request, "K:V;K2:V2" (\; escapes a
                   semicolon inside a value, \\ a backslash)
  WEEB_TOKEN       adds "Authorization: Bearer $WEEB_TOKEN" unless you set Authorization
  WEEB_PERSONA     error voice: plain (default) | dere | tsun | yan
  WEEB_RAINBOW     1/true to launch the TUI in 🌈 mode (toggle live with ctrl+y)
  WEEB_PRETTY      pretty body view; on by default, set 0/false for raw (toggle: ctrl+p)
  WEEB_MAX_BODY    cap for buffered bodies, e.g. 256m (default 64m, 0 = no cap;
                   --max-body wins; piped/-o bodies are never capped)
  WEEB_HISTORY     request history for 'weeb history' (weeb/history.jsonl in the
                   user cache dir); on by default, set 0/false to disable.
                   Credential header values are never stored (redacted; replay
                   re-applies them from WEEB_TOKEN/WEEB_HEADERS)

LOGGING (structured diagnostics; never on stdout)
  WEEB_LOG         debug|info|warn|error|off        (default: warn)
  WEEB_LOG_FORMAT  text|json|logfmt                 (default: text)
  WEEB_LOG_FILE    path; logs go here instead of stderr. In TUI mode logs always
                   go to a file (default: weeb/weeb.log in the user cache dir) so they
                   don't corrupt the screen; toggle the in-app debug pane with ctrl+g.
`)
}
