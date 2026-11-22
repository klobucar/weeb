# weeb

<p align="center">
  <img src="assets/weeb-header.png" alt="weeb — a colorful terminal HTTP client" width="100%">
</p>

[![CI](https://github.com/klobucar/weeb/actions/workflows/ci.yml/badge.svg)](https://github.com/klobucar/weeb/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/klobucar/weeb)](https://github.com/klobucar/weeb/releases/latest)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

weeb is a terminal HTTP client. Build requests and browse responses in an interactive interface, or pipe the response body into tools like `jq`. You can paste a curl command, inspect a TLS certificate chain, or check an endpoint from a monitoring job.

## Install

Install with Go 1.26 or later.

```sh
go install github.com/klobucar/weeb@latest
```

To build from a checkout, run `go build -o weeb .` from the repository root.

## Send your first request

```sh
weeb https://example.com
```

Press **Ctrl+S** to send. Use **Tab** to move between fields and into the response pane, where you can expand and collapse sections. Run `weeb` on its own to start with an empty request.

![Building a request, sending it, toggling pretty and raw views, and folding the response](assets/demo.gif)

Pipe the same command to run it once and read the body from stdout. Use `--no-tui` to run it once directly in a terminal.

```sh
weeb https://api.example.com/me | jq .
weeb https://example.com --no-tui
```

## Documentation

| Guide | Covers |
| --- | --- |
| [HTTP from the command line](docs/http.md) | Request flags, output and timing, curl import and export, history, and shell completions |
| [Interactive interface](docs/tui.md) | Editing requests, folding responses, and keyboard shortcuts |
| [Request files](docs/request-files.md) | Running `.http` files, file variables, and environments |
| [TLS certificates](docs/tls.md) | Certificate chains, STARTTLS, SNI, mutual TLS, and PEM export |
| [Monitoring](docs/monitoring.md) | HTTP and certificate checks, thresholds, exit codes, and JSON verdicts |
| [Configuration](docs/configuration.md) | Environment variables, default headers, error personas, and logging |

Run `weeb --help` for the command-line reference. If you downloaded a release archive, find the guides in the [GitHub repository](https://github.com/klobucar/weeb).

## Security

To report a vulnerability, follow [SECURITY.md](SECURITY.md). Please don't open a public issue.

## License

[MIT](LICENSE) © Jonathon Klobucar
