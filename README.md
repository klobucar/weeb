<p align="center">
  <img src="assets/weeb-header.png" alt="weeb — a colorful terminal HTTP client" width="100%">
</p>

<h1 align="center">weeb</h1>

<p align="center">
  A colorful terminal HTTP client — an interactive TUI <em>and</em> a scriptable CLI, from one binary.
</p>

<p align="center">
  <a href="https://github.com/klobucar/weeb/actions/workflows/ci.yml"><img src="https://github.com/klobucar/weeb/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
</p>

---

`weeb` is an interactive HTTP client for your terminal — and a curl-shaped
one-liner when you pipe it. Give it a URL and it opens a full-screen request
builder, ready to send. Pipe the output (or pass `--no-tui`) and the same command
runs headless, so `weeb GET url | jq` just works. JSON, XML, YAML, and Markdown
bodies are pretty-printed and foldable, TLS certs are inspectable, and when a
request goes sideways an optional anime persona tells you about it.

## Demo

Build a request, fire it, flip between pretty and raw, then collapse the
response and fold open just the body (with a dash of 🌈):

<p align="center">
  <img src="assets/demo.gif" alt="Building a request, sending it, toggling pretty/raw, and folding the response" width="100%">
</p>

Inspect a live TLS certificate and chain with `ctrl+t` — here, Let's Encrypt's
own site, leaf → ISRG Root:

<p align="center">
  <img src="assets/cert.gif" alt="Inspecting letsencrypt.org's TLS certificate and chain, then toggling back" width="100%">
</p>

<sub>Demos recorded with <a href="https://github.com/charmbracelet/vhs">VHS</a>.</sub>

## Features

- **curl-shaped CLI** — `-H`, `-d @file`/`-`/stdin, `-X`, interleaved flags and positionals, just like you already type.
- **curl import & export** — paste a `curl` command to run it (`weeb curl '…'`), or turn any request into one (`--to-curl`, or `ctrl+x` in the TUI).
- **`.http` files** — run requests from VS Code REST Client / JetBrains HTTP Client files (`weeb run api.http login`).
- **Pretty bodies** — JSON, XML, HTML & YAML get syntax color and **collapsible folding**; Markdown gets a full [Glamour](https://github.com/charmbracelet/glamour) render. `--raw` for the exact bytes.
- **File viewer** — `weeb view data.json` (or `… | weeb view`) browses a local JSON/XML/HTML/YAML/Markdown file in the same foldable pane, like jless or fx; piped, it's a pretty-printer.
- **TLS inspection** — a friendlier `openssl s_client`: full chain, expiry, SANs, ciphers, OCSP/SCT, plus `--starttls`, `--sni` override, `--alpn`, version pinning, client certs, and `--pem` dump.
- **Timing breakdown** — per-phase DNS / TCP / TLS / send / wait / recv stats with a colored bar.
- **Two outputs, kept apart** — a human-facing error *voice* (configurable, optionally anime) and structured *logs* to a file.
- **🌈 mode** — because sometimes you want rainbow vomit. `ctrl+y`.

## Install

```sh
go install github.com/klobucar/weeb@latest
```

Requires Go 1.26+. Or build from source:

```sh
git clone https://github.com/klobucar/weeb && cd weeb
go build -o weeb .
```

## Quick start

**Interactive** — run it bare for an empty builder, or give it a URL to open
prefilled and ready to send:

```sh
weeb
weeb POST https://api.example.com/users -H "Content-Type: application/json" -d @body.json
```

Tab between fields, pick a method with ←/→, `ctrl+s` to send. The response lands
in a foldable pane below.

**Headless** — the same command goes one-shot the moment output is script-bound
(piped/redirected), or when you ask with `--no-tui`/`--raw`:

```sh
# piped -> headless automatically; body to stdout, clean for jq
weeb GET https://api.example.com/me | jq .

# force headless at a terminal
weeb GET https://api.example.com/me --no-tui

# a piped-in body is also headless
echo '{"name":"weeb"}' | weeb POST https://api.example.com/users
```

In headless mode the response **body** goes to stdout; weeb's errors, logs, and
(at a terminal) the stats block go to stderr — so pipes stay pristine.

## CLI options

| Flag | Description |
|------|-------------|
| `-H, --header "K: V"` | Add a request header (repeatable) |
| `-d, --data DATA` | Body: `@file`, `-` (stdin), or a literal string |
| `-X, --request METHOD` | Set the method explicitly |
| `--timeout DUR` | Request timeout, e.g. `10s`, `500ms` (default 30s) |
| `-v, --stats` | Print timing + negotiated TLS to stderr, even when piping |
| `--pretty` | Force the pretty/colored body view (the default at a TTY) |
| `--raw` | Force raw output — exactly the bytes the server sent (implies `--no-tui`) |
| `--no-tui` | Run a headless one-shot even at a terminal (alias `--headless`) |
| `-q, --quiet` | Headless, body only — suppress the stats block (errors still show) |
| `--persona MODE` | Error voice: `plain` (default) · `dere` · `tsun` · `yan` (overrides `WEEB_PERSONA`) |
| `--to-curl` | Print the `curl` equivalent instead of sending |
| `-o, --output FILE` | Stream the response body to a file, uncapped — like `curl -o` (implies headless) |
| `--max-body SIZE` | Cap for bodies weeb buffers to render, e.g. `256m` (default `64m`, `0` = no cap; piped/`-o` bodies are never capped) |
| `-h, --help` | Show help |

`METHOD` is optional and defaults to `GET`. A URL with no scheme defaults to
`http://` (port 80), so `weeb GET example.com:8080/health` just works — only
`weeb cert` defaults to `https`/443. Color and pretty-printing apply only at a
terminal; piped output is always the raw server bytes.

## Pretty, raw & folding

By default, bodies at a terminal are pretty-printed and syntax-colored, and
detected by Content-Type → URL extension → content sniff (so a GitHub raw
`README.md` served as `text/plain` still renders):

- **JSON / XML / HTML / YAML** — indented, colored, and **foldable** node-by-node (HTML via a real HTML5 parser, so messy real-world pages still fold).
- **Markdown** — rendered with Glamour (headings, lists, code blocks, the works).
- **Anything else** — shown as-is.

(YAML is detected by Content-Type or a `.yaml`/`.yml` URL only — never by content, since plain text and JSON are both valid YAML.)

`--pretty` / `--raw` (CLI) or `ctrl+p` (TUI) toggle it; `WEEB_PRETTY=0` starts in raw.

In the response pane, fold to cut the noise:

| Key | Action |
|-----|--------|
| `↑` / `↓` | Scroll |
| `←` / `→` | Select a section or JSON/XML/HTML/YAML node |
| `enter` | Fold / unfold the selection |
| `-` / `+` | Fold / unfold everything |

## Viewing files

`weeb view` points the response pane at a local file instead of a request, so
it works as a JSON/XML/HTML/YAML/Markdown viewer in the vein of jless or fx:

```sh
weeb view data.json
weeb view - < page.html
kubectl get pod web -o yaml | weeb view --type yaml
```

It reads FILE, or stdin when FILE is `-` or left out. There's no Content-Type,
so the format comes from the file extension, then a content sniff, just like a
response with a generic Content-Type. YAML is never sniffed, so piped YAML needs
`--type yaml`, and XML without an `<?xml …?>` declaration sniffs as HTML unless
you pass `--type xml`. The pane's Body summary shows the file name, size and
format.

At a terminal it opens a viewer-only TUI with no request form. Even with the
data piped in, keys come from the terminal (`/dev/tty`, or `CONIN$` on Windows).

| Key | Action |
|-----|--------|
| `↑` / `↓` | Scroll |
| `←` / `→` | Select a section or node |
| `enter` | Fold / unfold the selection |
| `-` / `+` | Fold / unfold everything |
| `ctrl+p` | Toggle pretty / raw |
| `ctrl+y` | Toggle 🌈 mode |
| `q` · `ctrl+c` | Quit |

Piped or redirected, it prints the pretty render without color instead, so it
doubles as a formatter: `weeb view data.json > pretty.json`. JSON and XML are
reindented; HTML, YAML and Markdown come out as their source, since their
pretty forms are color-only.

| Flag | Description |
|------|-------------|
| `--type T` | Force the format: `json` · `xml` · `html` · `yaml` · `md` |
| `--raw` | Piped: write the bytes unchanged. At a terminal: open in the raw view |
| `--max-body SIZE` | Refuse input larger than SIZE (default `64m`, `0` = no cap; overrides `WEEB_MAX_BODY`) |

Files are treated as untrusted, like response bodies (you may be viewing
something you just downloaded). Terminal control sequences in the content are
stripped before they reach the screen, and a file name containing control
characters is shown quoted.

## curl import & export

Paste a `curl` command — from API docs or your browser's "Copy as cURL" — and
weeb runs it:

```sh
weeb curl 'curl -X POST https://api.example.com/u -H "Accept: application/json" -d @body.json'
```

It handles whatever "Copy as cURL" produces: `-u` basic auth, `@file` bodies, and
method inference (POST when there's a body, HEAD for `-I`). Transfer-only flags
like `-L`, `-k`, and `--compressed` are ignored. Flags that change where the
request goes (`-x`/`--proxy` and the other proxy and SOCKS flags, `--resolve`,
`--connect-to`, `--interface`, `--unix-socket`, `--dns-*`/`--doh-*`) are
refused and nothing is sent; to use a proxy, set `HTTPS_PROXY`/`HTTP_PROXY`
(and `NO_PROXY`), which weeb honors.

Going the other way, turn the request you just built into a shareable command:

```sh
weeb POST https://api.example.com/users -H "Accept: application/json" -d '{"a":1}' --to-curl
```

In the TUI, `ctrl+x` shows the curl equivalent of the current form and copies
it to your clipboard.

## .http files

`weeb run` reads `.http` files, the plain-text request format shared by the
VS Code REST Client and the JetBrains HTTP Client, so a collection that lives
in your repo runs from the terminal too:

```http
@base = https://api.example.com
@token = {{$processEnv API_TOKEN}}

### Log in
# @name login
POST {{base}}/login
Content-Type: application/json

< ./login.json

### Who am I?
# @name me
GET {{base}}/me
    ?fields=id,name
    &verbose=true
Authorization: Bearer {{token}}
Accept: application/json
```

```sh
weeb run api.http                # list: index, name or title, method, URL
weeb run api.http me             # run one by @name…
weeb run api.http 2              # …or by number
weeb run api.http me --env dev   # with variables from http-client.env.json
```

At a terminal the request opens in the TUI, prefilled and ready to send;
piped (or with `--no-tui`) it runs headless, body to stdout. `WEEB_HEADERS`
and `WEEB_TOKEN` apply as they do to any request.

What's understood:

- `###` separates requests; text after it is a title. `# @name NAME` (or
  `// @name NAME`) names one, and `# @no-redirect` shows a 3xx instead of
  following it.
- `[METHOD] URL [HTTP/version]`, where the method defaults to `GET`, followed
  by optional `?…`/`&…` query lines, then headers up to a blank line, then
  the body up to the next `###`. Other `#` and `//` lines are comments before
  the request line and among headers; in a body they're sent as written.
- `< ./file` includes a file as the body (or part of it) byte for byte;
  `<@ ./file` substitutes variables in it first. Paths are relative to the
  `.http` file. Multipart bodies are sent with CRLF line endings.
- `@name = value` defines a file variable, used as `{{name}}` in the URL,
  headers and body; values can use other variables.
- `{{$processEnv VAR}}` (VS Code) and `{{$env.VAR}}` (JetBrains) read
  environment variables. `{{$guid}}`/`{{$uuid}}`, `{{$timestamp}}` and
  `{{$isoTimestamp}}` are generated.
- `--env NAME` takes variables from environment `NAME` in
  `http-client.env.json` next to the file, merged with
  `http-client.private.env.json` and the `$shared` environment. File
  variables win over environment-file ones.

An undefined variable is an error naming the variable and its line. Values
read from environment variables (and the private env file) never appear in
the listing, which shows `{{$processEnv TOKEN}}` as written, or in weeb's
errors and logs, which show the reference in place of the value.

Not supported: response chaining (`{{login.response.body.$.token}}` is an
error, so run the requests separately), JetBrains pre-request and response
handler scripts (skipped; a variable a script would set is reported as
undefined), `@prompt`, and other dynamic variables such as `$randomInt` or
`$datetime`.

## History

Every request weeb sends is recorded to `history.jsonl` in the private weeb
cache dir (newest 500 kept). List it, re-run an entry, or wipe it:

```sh
weeb history          # the last 20, newest first
weeb history 3        # re-run entry 3
weeb history --clear  # delete it all
```

Credentials are never written to disk. Credential headers (`Authorization`,
`Cookie`, anything named like a token/secret/key) are stored as `REDACTED`
and re-injected from `WEEB_TOKEN`/`WEEB_HEADERS` on replay. Secret-looking
URL query values, a `user:pass@` password, and secret fields in JSON or form
bodies are redacted too; since those can't be restored, such an entry is
listed but won't replay. Bodies over 4 KiB keep only their size. Set
`WEEB_HISTORY=0` to turn history off.

## TLS / certificate inspection

`weeb cert` is meant to fully replace `openssl s_client -connect` for the things
you actually use it for — and it prints a report you can read, with the full
chain detailed, not just dumped:

```sh
weeb cert example.com
weeb cert https://example.com:8443 --json | jq '.chain[0].days_until_expiry'

# STARTTLS for mail/etc. (port defaults to the protocol: 587/143/110/21)
weeb cert smtp.gmail.com --starttls smtp

# point at an IP but present a chosen SNI / servername
weeb cert 93.184.216.34 --sni example.com

# pull the chain as PEM (the `-showcerts` move) to grab intermediates
weeb cert example.com --pem > chain.pem
```

| Flag | Description |
|------|-------------|
| `-k, --insecure` | Inspect even if the chain is untrusted/expired |
| `--json` | Emit the report as JSON (for pipes/monitoring) |
| `--pem` | Dump the chain as PEM (alias `--showcerts`) |
| `--brief` | Show the leaf only, not full detail for every cert (alias `--short`) |
| `--sni NAME` | Present this SNI/servername, decoupled from the dial host (alias `--servername`) |
| `--starttls PROTO` | Upgrade via `smtp`/`imap`/`pop3`/`ftp` before the handshake |
| `--alpn LIST` | Advertise ALPN protocols, e.g. `h2,http/1.1` |
| `--tls VERSION` | Pin the handshake to `1.0`/`1.1`/`1.2`/`1.3` |
| `--client-cert F` · `--client-key F` | Present a client certificate for mTLS (aliases `--cert`/`--key`) |
| `--timeout DUR` | Dial timeout (default 30s) |
| `-f, --file PATH` | Read certificates from a local PEM/DER file (`-` = stdin) instead of dialing |
| `--host NAME` | With a file: also check the leaf against this hostname (`--sni` works too) |

The exit code is non-zero when the chain is untrusted (unless `-k`) or expired,
so `weeb cert` doubles as a cron/monitoring check. In the TUI, `ctrl+t` inspects
the cert of the URL you're pointed at — the report folds like a response, so each
cert in the chain is a collapsible section (the leaf shows on load; the CA certs
above it start folded — `←`/`→` to select, `enter` to open, `±` for all).

### Certificate files

`weeb cert` reads local certificates too, as a friendlier `openssl x509 -text`:

```sh
weeb cert ./chain.pem                     # PEM, any number of certs in any order
weeb cert server.der                      # or DER
cat chain.pem | weeb cert -               # or stdin
weeb cert server.crt --host example.com   # also check the leaf against a name
weeb cert bundle.pem --check -w 30 -c 14  # the same expiry check as a live host
```

An argument is read as a file when it's `-`, or when it exists and has a `/`
or a `.pem`/`.crt`/`.cer`/`.der` extension. A bare `example.com` is always
dialed, even if a file by that name exists; use `-f example.com` to read it.
weeb orders the certs leaf → root by issuer and verifies the leaf against
the system roots, with the file's other certs as intermediates. Without
`--host` there's no hostname check. The report, `--json`, `--pem`, `--brief`,
`--check` and the exit codes work as for a live host. Handshake details
(protocol, cipher, ALPN, OCSP stapling, SCTs) are left out because a file
doesn't have them. Other PEM blocks, such as a private key in a bundle, are
skipped and never printed. A certificate Go can't parse (a few legacy CA
roots) is skipped with a note rather than failing the whole file.

## Monitoring (`--check`)

`--check` (alias `--nagios`) turns either command into a proper monitoring
plugin (the format Nagios, Icinga, Sensu and Zabbix agents all consume):
exactly one `SERVICE STATUS - message|perfdata` line on stdout and the verdict
in the exit code — 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN. Unlike `check_http`,
the TLS chain is validated *by default*, and you get expiry early-warning for
free:

```sh
# cert check: WARNING within 30 days of expiry, CRITICAL within 14 (the defaults)
weeb cert example.com --check -w 30 -c 14
# CERT OK - example.com:443 expires in 87 days (2026-09-04)|days=87;30;14

# HTTP check: status, latency thresholds, and a body assertion
weeb https://api.example.com/health --check \
  --expect-status 2xx --expect-body '"status": *"ok"' -w 500ms -c 2s
# HTTP OK - 200 OK in 123 ms, 512 bytes|time=0.123s;0.500;2.000 size=512B days_until_expiry=87
```

`--expect-status` takes codes, ranges, or classes (`200`, `200-204,301`,
`2xx`); without it, any status under 400 is OK. `--expect-body` is a Go
regexp; no match is CRITICAL. The HTTP perfdata always includes the leaf
cert's `days_until_expiry` on TLS connections, so one check can feed both
latency and expiry alerting.

Headers and JSON fields can be asserted too. Both flags repeat, and any
failure is CRITICAL:

```sh
weeb https://api.example.com/health --check \
  --expect-header 'Content-Type: ^application/json' --expect-header '!X-Debug' \
  --expect-json '.status == "ok"' --expect-json '.data.items | length >= 1'
# HTTP CRITICAL - json .status == "ok": got "degraded" (+1 more failed)|time=0.123s;; size=512B days_until_expiry=87
```

| Flag | Passes when |
|------|-------------|
| `--expect-header 'Name'` | the response has the header |
| `--expect-header 'Name: RE'` | the header is present and a value matches the Go regexp |
| `--expect-header '!Name'` | the header is absent |
| `--expect-json 'EXPR'` | the body is JSON and satisfies `EXPR` |

`EXPR` is a small jq-like path with an optional comparison:
`.status == "ok"`, `.items[0].id != null`, `.count > 0`,
`.version =~ "^2\."`, `.data.items | length >= 1`. A bare path such as
`.a.b` must exist and be neither `null` nor `false`. Paths take `.key`,
`.["key with spaces"]` and `[N]` (negative counts from the end); values are
JSON literals; the operators are `==`, `!=`, `<`, `<=`, `>`, `>=` (numbers or
strings) and `=~` (a double-quoted Go regexp, backslashes passed through as
written). `| length` is the only function. As in jq, a missing key reads as
`null`. A body that isn't JSON is CRITICAL, and the body is the one already
read, so `--max-body` still caps it. A malformed expression or header spec is
UNKNOWN, like a bad `--expect-status`, with the column it went wrong at.

The plugin line reports the first failure (status, then `--expect-body`,
headers and JSON in flag order) and counts the rest.

Prefer structured output? Add `--json` and the same verdict (same exit code)
comes back as one JSON object instead of the plugin line:

```sh
weeb https://api.example.com/health --check --json -w 500ms | jq .
# {
#   "check": "http", "status": "OK", "code": 0,
#   "message": "200 OK in 123 ms, 512 bytes",
#   "metrics": { "http_status": 200, "time_ms": 123, "size_bytes": 512,
#                "warn_ms": 500, "days_until_expiry": 87 },
#   "assertions": [ { "type": "status", "expect": "status < 400",
#                     "ok": true, "actual": "200" } ]
# }
```

`assertions` lists every assertion in order with its outcome, the observed
value (clipped to 80 characters), and for failures the message.

Note the distinction on the cert side: plain `weeb cert HOST --json` emits the
full *report* (chain, SANs, fingerprints — no verdict), while
`weeb cert HOST --check --json` emits the evaluated *verdict* against your
thresholds. The report is for inspection; the verdict is for alerting.

No Prometheus exporter is planned — that's a daemon, and
[blackbox_exporter](https://github.com/prometheus/blackbox_exporter) already
is one. If you want these numbers in Prometheus anyway, `weeb cert --json`
plus the node_exporter textfile collector is a one-line cron job, or wire
`--check` output through
[script_exporter](https://github.com/ricoberger/script_exporter).

## TUI keys

| Key | Action |
|-----|--------|
| `tab` / `shift+tab` · `↑` / `↓` | Move between fields (↑/↓ scroll in the response pane; edit lines in the body) |
| `←` / `→` | Pick HTTP method (when the method field is focused) |
| `ctrl+o` / `ctrl+r` | Add / remove a header row |
| `ctrl+s` | Send the request |
| `ctrl+t` | Inspect the TLS cert |
| `ctrl+x` | Export the current request as `curl` and copy it to the clipboard |
| `y` / `Y` | Copy the selected node's path / value (response pane only) |
| `ctrl+p` | Toggle pretty / raw |
| `ctrl+y` | Toggle 🌈 mode |
| `ctrl+g` | Toggle the debug log pane |
| `ctrl+c` | Quit |

Copying uses OSC 52, so it works over SSH with nothing extra installed, as long
as your terminal allows it (iTerm2: *Applications in terminal may access
clipboard*; tmux: `set -g set-clipboard on`). `y` copies a jq path for JSON and
YAML (`.items[3]`, `.["weird key"]`) or an XPath-like one for XML and HTML
(`/root/item[3]`). `Y` copies the value: compact JSON, the YAML fragment, or the
element's source. On a section heading, `Y` copies that section, and on **Body**
the raw body. Copies are plain text, with styling and control characters
stripped, and anything over 75 KB is truncated (terminals drop larger OSC 52
writes); the status line says when that happens.

## Environment

Prefills are applied to every request unless you override them:

| Variable | Effect |
|----------|--------|
| `WEEB_BASE_URL` | Relative URLs (`/me`) resolve against this base |
| `WEEB_HEADERS` | Default headers on every request, `"K:V;K2:V2"` |
| `WEEB_TOKEN` | Adds `Authorization: Bearer $WEEB_TOKEN` unless you set Authorization |
| `WEEB_PERSONA` | Error voice: `plain` (default) · `dere` · `tsun` · `yan` (or `--persona`) |
| `WEEB_RAINBOW` | `1`/`true` launches the TUI in 🌈 mode |
| `WEEB_PRETTY` | Pretty body view; on by default, set `0`/`false` for raw |
| `WEEB_MAX_BODY` | Cap for buffered bodies, e.g. `256m` (default `64m`, `0` = no cap; `--max-body` wins) |
| `WEEB_HISTORY` | `0`/`false` turns off request history (recording and `weeb history`) |

Logging is structured diagnostics, kept off stdout entirely:

| Variable | Effect |
|----------|--------|
| `WEEB_LOG` | `debug` \| `info` \| `warn` \| `error` \| `off` (default `warn`) |
| `WEEB_LOG_FORMAT` | `text` \| `json` \| `logfmt` (default `text`) |
| `WEEB_LOG_FILE` | Log to this path. In TUI mode logs always go to a file (default `weeb/weeb.log` in the user cache dir) so they never corrupt the screen — view them live with `ctrl+g`. |

## The two seams

weeb deliberately keeps two concerns apart, joined at a single chokepoint:

- **The voice** — the human-facing error rendering, powered by
  [go-errorchan](https://github.com/klobucar/go-errorchan). Plain by default,
  with an opt-in cast of anime personas via `WEEB_PERSONA` (`dere` · `tsun` · `yan`):

  ```
  $ weeb GET https://nope.invalid
  dial tcp: lookup nope.invalid: no such host

  $ WEEB_PERSONA=tsun weeb GET https://nope.invalid
  anyothew ewwow. don't wook at me wike that, it's YOUW mess >:( — dial tcp: lookup nope.invalid: no such host
  ```

- **The record** — structured, leveled logs (`charm.land/log/v2`) that go to a
  file or stderr, never the TTY.

## Built with

[Bubble Tea](https://github.com/charmbracelet/bubbletea) · [Lip Gloss](https://github.com/charmbracelet/lipgloss) · [Bubbles](https://github.com/charmbracelet/bubbles) · [Glamour](https://github.com/charmbracelet/glamour) · [log](https://github.com/charmbracelet/log) · [go-errorchan](https://github.com/klobucar/go-errorchan)

## License

[MIT](LICENSE) © Jonathon Klobucar
