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
- **Pretty bodies** — JSON, XML, HTML & YAML get syntax color and **collapsible folding**; Markdown gets a full [Glamour](https://github.com/charmbracelet/glamour) render. `--raw` for the exact bytes.
- **TLS inspection** — chain, expiry, SANs, ciphers, OCSP/SCT from `weeb cert example.com`, without fighting `openssl`.
- **Timing breakdown** — per-phase DNS / TCP / TLS / send / wait / recv stats with a colored bar.
- **Two outputs, kept apart** — a human-facing error *voice* (configurable, optionally anime) and structured *logs* to a file.
- **🌈 mode** — because sometimes you want rainbow vomit. `ctrl+y`.

## Install

```sh
go install github.com/klobucar/weeb@latest
```

Requires Go 1.25+. Or build from source:

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
| `-h, --help` | Show help |

`METHOD` is optional and defaults to `GET`. Color and pretty-printing apply only
at a terminal; piped output is always the raw server bytes.

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

## curl import & export

Paste a `curl` command — from API docs or your browser's "Copy as cURL" — and
weeb runs it:

```sh
weeb curl 'curl -X POST https://api.example.com/u -H "Accept: application/json" -d @body.json'
```

It handles whatever "Copy as cURL" produces: `-u` basic auth, `@file` bodies, and
method inference (POST when there's a body, HEAD for `-I`). Transfer-only flags
like `-L`, `-k`, and `--compressed` are ignored.

Going the other way, turn the request you just built into a shareable command:

```sh
weeb POST https://api.example.com/users -H "Accept: application/json" -d '{"a":1}' --to-curl
```

In the TUI, `ctrl+x` shows the curl equivalent of the current form.

## TLS / certificate inspection

```sh
weeb cert example.com
weeb cert https://example.com:8443 --json | jq '.chain[0].days_until_expiry'
```

| Flag | Description |
|------|-------------|
| `-k, --insecure` | Inspect even if the chain is untrusted/expired |
| `--json` | Emit the report as JSON (for pipes/monitoring) |
| `--timeout DUR` | Dial timeout (default 30s) |

The exit code is non-zero when the chain is untrusted (unless `-k`) or expired,
so `weeb cert` doubles as a cron/monitoring check. In the TUI, `ctrl+t` inspects
the cert of the URL you're pointed at.

## TUI keys

| Key | Action |
|-----|--------|
| `tab` / `shift+tab` · `↑` / `↓` | Move between fields (↑/↓ scroll in the response pane; edit lines in the body) |
| `←` / `→` | Pick HTTP method (when the method field is focused) |
| `ctrl+o` / `ctrl+r` | Add / remove a header row |
| `ctrl+s` | Send the request |
| `ctrl+t` | Inspect the TLS cert |
| `ctrl+x` | Export the current request as `curl` |
| `ctrl+p` | Toggle pretty / raw |
| `ctrl+y` | Toggle 🌈 mode |
| `ctrl+g` | Toggle the debug log pane |
| `ctrl+c` | Quit |

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

Logging is structured diagnostics, kept off stdout entirely:

| Variable | Effect |
|----------|--------|
| `WEEB_LOG` | `debug` \| `info` \| `warn` \| `error` \| `off` (default `warn`) |
| `WEEB_LOG_FORMAT` | `text` \| `json` \| `logfmt` (default `text`) |
| `WEEB_LOG_FILE` | Log to this path. In TUI mode logs always go to a file (default `$TMPDIR/weeb.log`) so they never corrupt the screen — view them live with `ctrl+g`. |

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
