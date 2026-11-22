# HTTP from the command line

[Back to weeb](../README.md)

```text
weeb [METHOD] URL [OPTIONS]
```

The method defaults to `GET`, or `POST` when you supply a body without an explicit method. A host without a scheme uses `http://`. When `WEEB_BASE_URL` is set, you can use a relative URL such as `/me`. Flags can go before or after the method and URL.

A request opens the interactive builder in a terminal. Piping or redirecting stdout, piping a body into stdin, or passing a flag such as `--no-tui` runs a single request.

```sh
weeb https://api.example.com/me | jq .

weeb POST https://api.example.com/users \
  -H 'Content-Type: application/json' -d @body.json --no-tui

printf '%s\n' '{"name":"weeb"}' | weeb POST https://api.example.com/users \
  -H 'Content-Type: application/json'
```

## Request options

| Option | Effect |
| --- | --- |
| `-H, --header 'Name: value'` | Add a request header. Repeat for multiple headers. |
| `-d, --data DATA` | Send a literal string, load a body from `@file`, or read stdin with `-` or `@-`. A pipe on stdin supplies the body when this option is omitted. |
| `-X, --request METHOD` | Set the HTTP method explicitly. |
| `--timeout DURATION` | Set a timeout such as `500ms` or `10s`. The 30-second default covers the entire buffered request or the wait for headers on a streamed request. An explicit timeout also bounds the streamed transfer. For [event streams](#event-streams), it acts as an idle timeout. |
| `--no-follow` | Return the redirect response itself. The default follows up to 10 redirects. Implies headless mode. |

### Request TLS, multipart forms, and cookies

| Option | Effect |
| --- | --- |
| `-k, --insecure` | Skip certificate verification. weeb warns on stderr and displays an INSECURE badge in the TUI. |
| `--cacert FILE` | Replace the system trust store with the CAs in a PEM file. |
| `-E, --cert FILE` | Supply a PEM client certificate for mutual TLS. The file may also contain the private key. |
| `--key FILE` | Supply a separate PEM private key for the client certificate. |
| `-F, --form PART` | Add a multipart part and infer POST if no method is set. Repeat for multiple parts. |
| `--form-string NAME=VALUE` | Add a multipart field with a literal value. |
| `-b, --cookie DATA` | Send literal cookies such as `'a=1; b=2'`, or give a Netscape cookie file path without an equals sign. |
| `--cookie-jar FILE` | Save cookies in Netscape format with mode 0600. For curl-style `-c FILE`, use `--cookie-jar FILE` in weeb. |

Use `-F 'name=value'` for a field, `-F 'name=<file'` for a field filled from a file, and `-F 'name=@file;type=text/plain;filename=report.txt'` to upload a file with an explicit type and filename. Client certificate paths use PEM files without curl's `FILE:PASSWORD` syntax.

Use `-b jar.txt --cookie-jar jar.txt` to keep a session between runs. The first run can start with a missing jar. The jar records cookies received during redirects and sends them according to their domain and path rules. weeb drops literal cookies on cross-origin redirects.

## Output options

Headless requests write the response body to stdout. Errors go to stderr, and logs go to stderr or a [configured log file](configuration.md#logging). With color enabled at a terminal, weeb also prints response status, negotiated TLS, and timings to stderr. Timings cover DNS, TCP, TLS, send, wait, and receive.

| Option | Effect |
| --- | --- |
| `--no-tui`, `--headless` | Run one request and print the result. |
| `-v, --stats` | Print response stats even when stdout is piped. |
| `-q, --quiet` | Run headless and suppress response stats. Errors still print. |
| `--pretty` | Use the formatted body view at a color-enabled terminal. |
| `--raw` | Skip formatting and run headless. Pipes and files receive raw body bytes by default. |
| `-i, --include` | Print the status line and response headers to stdout before the body. Implies headless mode. |
| `-o, --output FILE` | Stream the body to a file. Implies headless mode. With `-i`, the status and headers still go to stdout. |
| `--max-body SIZE` | Cap buffered responses. The default is `64m`. Use bytes or a `k`, `m`, or `g` suffix. Use `0` for an unlimited buffer. |
| `--persona MODE` | Set the [error persona](configuration.md#error-messages) for this run. |
| `--to-curl` | Print the equivalent curl command without sending the request. |
| `-h, --help` | Show command help. |

Streaming to a pipe or file bypasses the buffer cap. Piped HTTP requests using `-i` buffer the body unless you also specify `-o`. HTTP checks buffer responses for evaluation. See [monitoring options](monitoring.md#http-checks) for status, body, and latency assertions.

## Event streams

weeb renders Server-Sent Events (`text/event-stream`) and JSON lines (`application/x-ndjson`, `application/jsonl`, or `application/json-seq`) as they arrive. The TUI and formatted terminal output show one block per event. SSE blocks show the event name and ID when available and format JSON data. With piped output or `-o`, weeb streams the raw bytes.

The 30-second default timeout covers the wait for headers. Set `--timeout` to close an event stream after that long without data. See the [interactive guide](tui.md#follow-an-event-stream) for scrolling, stopping, and retention.

## Import and export curl commands

Paste a curl command from API docs or your browser's **Copy as cURL** menu.

```sh
weeb curl 'curl https://api.example.com/users -H "Content-Type: application/json" -d @body.json'
```

Import supports request headers, Basic auth (`-u`), cookies (`-b`), a user agent (`-A`), and a referrer (`-e`). A body implies `POST`, `-I` selects `HEAD`, and `-G` puts data in the query string.

Import also accepts multipart forms (`-F`), TLS options (`-k`, `--cacert`, `-E` / `--cert`, and `--key`), and cookies (`-b` and `-c`). weeb applies its own transfer settings and ignores options such as `-L` and `--compressed`. Import rejects routing overrides such as `--proxy`, `--resolve`, and `--unix-socket`. Configure a proxy through `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`.

Use `--to-curl` to print the command, or press **Ctrl+X** in the interactive interface to show and copy it.

```sh
weeb POST https://api.example.com/users \
  -H 'Content-Type: application/json' -d '{"name":"weeb"}' --to-curl
```

## History

```sh
weeb history          # List the 20 most recent requests, newest first
weeb history 3        # Replay entry 3
weeb history --clear  # Delete local request history
```

weeb records attempted HTTP requests in `weeb/history.jsonl` under your user cache directory. The file is trimmed to the newest 500 entries when it grows past 1,000. Set `WEEB_HISTORY=0` to disable recording and the history command.

History redacts values from credential headers such as `Authorization` and `Cookie`, as well as headers whose names contain `token`, `secret`, or `key`. Replay can supply those headers from your current `WEEB_TOKEN` and `WEEB_HEADERS`. Replay is disabled for entries with redacted URL passwords, query values, or JSON or form fields. For request bodies over 4 KiB, history stores the size and disables replay.

## Shell completions

`weeb completion zsh` prints a script you can save as `_weeb` in a directory on your `fpath`. For Bash, add `eval "$(weeb completion bash)"` to your `~/.bashrc`. For fish, save the output of `weeb completion fish` to `~/.config/fish/completions/weeb.fish`.

Run `weeb version` to see the build version.
