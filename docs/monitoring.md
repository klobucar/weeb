# Monitoring

[Back to weeb](../README.md)

Add `--check` (alias `--nagios`) to an HTTP request, `weeb cert`, or `weeb audit` to use it as a monitoring plugin with tools such as Nagios and Icinga. The default format is a single verdict line on stdout, such as `HTTP OK - message|perfdata`. The exit code carries the same verdict.

| Exit code | Verdict |
| --- | --- |
| 0 | OK |
| 1 | WARNING |
| 2 | CRITICAL |
| 3 | UNKNOWN |

## HTTP checks

```sh
weeb https://api.example.com/health --check \
  --expect-status 2xx --expect-body '"status":[[:space:]]*"ok"' \
  -w 500ms -c 2s
```

| Option | Effect |
| --- | --- |
| `--expect-status STATUS` | Accept codes, ranges, or classes such as `200`, `200-204,301`, or `2xx`. The default accepts status codes below 400. |
| `--expect-body REGEXP` | Require a match against the response body using Go regular expression syntax. A failed match is CRITICAL. |
| `-w, --warn DURATION` | Set the response time threshold for WARNING, such as `500ms`. |
| `-c, --crit DURATION` | Set the response time threshold for CRITICAL, such as `2s`. |

For HTTPS responses, the performance data includes the leaf certificate's `days_until_expiry` alongside response time and body size. HTTPS checks validate the server certificate. Use a certificate check to alert on expiry thresholds.

### Header and JSON assertions

Repeat `--expect-header` and `--expect-json` to add assertions. Any failed assertion is CRITICAL.

```sh
weeb https://api.example.com/health --check \
  --expect-header 'Content-Type: ^application/json' --expect-header '!X-Debug' \
  --expect-json '.status == "ok"' --expect-json '.data.items | length >= 1'
```

| Option | Passes when |
| --- | --- |
| `--expect-header 'Name'` | The header is present. |
| `--expect-header 'Name: RE'` | A header value matches the Go regular expression. |
| `--expect-header '!Name'` | The header is absent. |
| `--expect-json 'EXPR'` | The response body is JSON and satisfies the expression. |

JSON assertions accept jq-like paths such as `.items[0].id` or `.["key with spaces"]`. Negative indices count from the end. A bare path passes when its value exists and is neither `null` nor `false`. A missing key reads as `null`.

Use `==` or `!=` with JSON literals, `<`, `<=`, `>`, or `>=` with numbers or strings, and `=~` with a double-quoted Go regular expression such as `.version =~ "^2\."`. `| length` is the supported function. The response is still subject to `--max-body`.

Invalid assertion syntax returns UNKNOWN. The plugin line gives the first failure and the number of additional failures. Assertions run in the order status, body regex, headers, then JSON. Repeated flags in the same group preserve their order.

## Certificate checks

```sh
weeb cert example.com --check -w 30 -c 14
```

`-w` / `--warn` sets the leaf expiry warning threshold in whole days (default 30). `-c` / `--crit` sets the critical threshold (default 14). An untrusted chain is CRITICAL unless you pass `-k`. An expired leaf is always CRITICAL. A failed connection or handshake is UNKNOWN.

Certificate checks accept the connection options and [local files](tls.md#inspect-a-certificate-file) described in the TLS guide.

## JSON verdicts

Add `--json` to a check to receive a single JSON object. The exit code still carries the verdict.

```sh
weeb https://api.example.com/health --check --json -w 500ms
weeb cert example.com --check --json
```

The object contains `check` (`http`, `cert`, or `audit`), `status`, `code`, and `message`. When measurements are available, `metrics` contains values such as `time_ms`, `size_bytes`, or `days_until_expiry`. HTTP checks also report their outcomes in `assertions`, with each expected condition, pass or fail, and the observed value when available. For the chain, SANs, fingerprints, and other certificate details, run `weeb cert HOST --json`.


## Latency benchmarks

Use `--repeat` to send the same request multiple times and report request counts, throughput, status codes, errors, and latency percentiles by phase. Benchmark runs discard response bodies and skip request history.

```sh
weeb https://api.example.com/health --repeat 200 --concurrency 8
weeb https://api.example.com/health --repeat 20 --fresh --json
```

| Option | Effect |
| --- | --- |
| `--repeat N` | Send N requests and report min, p50, p90, p99, and max timings. Implies headless mode. |
| `--concurrency C` | Run up to C requests at once. The default is 1. |
| `--fresh` | Disable connection reuse to measure the connection setup for each request. |
| `--json` | Emit the summary as one JSON object. |

With connection pooling, DNS, TCP connect, and TLS timings only include requests that incurred those phases. Wait measures time from sending the request to receiving the first response byte. Total includes the full request. `--timeout` applies per request. Benchmark mode is incompatible with `--check`, `-o`, `-i`, `--to-curl`, and `--cookie-jar`.

Press **Ctrl+C** to stop and print a summary of completed requests. Press it again to exit immediately. The exit code is 1 if any completed request failed or returned status 400 or higher. JSON metrics include `.phases.total.p99_ms`, `.status["200"]`, `.errors`, and `.error_causes`.

## Security header audits

`weeb audit` sends a GET and grades the final response's security headers after redirects. A bare host uses HTTPS.

```sh
weeb audit example.com
weeb audit https://example.com --check
weeb audit https://example.com --json | jq '.findings[] | select(.grade != "pass")'
```

At a terminal, the report shows each finding and its reason. JSON reports include `url`, `status`, `redirects`, `findings`, and the `pass`, `warn`, and `fail` totals. Cookie findings show names and attributes while keeping cookie values out of the report.

The audit exits 0 when the report is available and 1 when the fetch fails. With `--check`, findings affect the exit code. A fail produces CRITICAL, a warning produces WARNING, and a failed fetch produces UNKNOWN. Add `--json` for the verdict object. Use `-H` for repeatable request headers, `--timeout` for the fetch timeout, or `--persona` for fetch errors.

### Audit grading rules

| Check | Pass | Warn | Fail |
| --- | --- | --- | --- |
| `Strict-Transport-Security` | max-age ≥ 6 months with includeSubDomains | shorter max-age, no includeSubDomains, `preload` without the preload list's requirements | missing, no or zero max-age, page served over plain http |
| `Content-Security-Policy` | scripts restricted | `'unsafe-inline'` (without a nonce or hash), `'unsafe-eval'`, wildcard script sources (`*`, `https:`, …), no script-src/default-src, report-only | missing |
| `X-Content-Type-Options` | `nosniff` | | missing or any other value |
| Clickjacking | CSP `frame-ancestors`, or `X-Frame-Options` `DENY`/`SAMEORIGIN` | `ALLOW-FROM`, conflicting values | neither, or `frame-ancestors *` |
| `Referrer-Policy` | `no-referrer`, `same-origin`, `strict-origin`, `strict-origin-when-cross-origin` | missing, `origin`, `origin-when-cross-origin`, `no-referrer-when-downgrade` | `unsafe-url` |
| `Permissions-Policy` | set | missing, or only the legacy `Feature-Policy` | |
| `Cross-Origin-Opener-Policy` | `same-origin`, `same-origin-allow-popups` | missing, `unsafe-none` | |
| `Cross-Origin-Resource-Policy` | `same-origin`, `same-site` | missing, `cross-origin` | |
| `Set-Cookie` | every cookie `Secure`, `HttpOnly` and `SameSite` | a cookie without `HttpOnly` or `SameSite` | a cookie without `Secure` |
| CORS | no CORS headers, or `*` without credentials | `Allow-Origin: null` | `*` or `null` with `Allow-Credentials: true` |
| Info leaks | no version in `Server` | a version in `Server` or any `X-Powered-By`/`X-AspNet-Version` | |

HSTS preload is optional. When a response sends multiple enforced CSP policies, a CSP weakness counts only if all of the policies allow it.
