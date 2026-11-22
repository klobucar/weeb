# TLS certificates

[Back to weeb](../README.md)

Run `weeb cert HOST` to inspect an endpoint's TLS connection. The report includes the certificate chain, expiration dates, subject alternative names (SANs), fingerprints, negotiated protocol and cipher, and OCSP and certificate transparency details. The default port is 443 for direct TLS. You can pass a hostname, a host and port, or an HTTPS URL.

```sh
weeb cert example.com
weeb cert https://example.com:8443 --json | jq '.chain[0].days_until_expiry'
weeb cert example.com --pem > chain.pem
weeb cert mail.example.com --starttls smtp
weeb cert 192.0.2.10 --sni example.com
```

The last command dials an IP while using `example.com` for SNI and certificate verification.

| Option | Effect |
| --- | --- |
| `-k, --insecure` | Ignore chain verification errors when setting the exit status. The report marks verification as skipped and still shows expiry. |
| `--json` | Print the full certificate report as JSON. |
| `--pem`, `--showcerts` | Print the certificate chain in PEM format. |
| `--brief`, `--short` | Limit the text report to leaf certificate details. |
| `--sni NAME`, `--servername NAME` | Set the TLS server name independently of the dial host. |
| `--starttls PROTOCOL` | Upgrade an SMTP (587), IMAP (143), POP3 (110), or FTP (21) connection to TLS. An explicit port overrides the protocol default. |
| `--alpn LIST` | Advertise a comma-separated list of protocols, such as `h2,http/1.1`. |
| `--tls VERSION` | Pin TLS to `1.0`, `1.1`, `1.2`, or `1.3`. |
| `--client-cert FILE`, `--cert FILE` | Provide a client certificate for mutual TLS. Supply its private key as well. |
| `--client-key FILE`, `--key FILE` | Provide the matching private key. |
| `--timeout DURATION` | Set the dial timeout and a separate deadline for STARTTLS and the handshake. Each defaults to 30 seconds. |
| `-f, --file PATH` | Read PEM or DER certificates from a file. Use `-` for stdin. |
| `--host NAME` | Verify the leaf from a file against a hostname. `--sni` also accepts the name. |
| `--persona MODE` | Set the [error persona](configuration.md#error-messages) for this run. |

The inspection command exits nonzero for an expired leaf or a verification failure. `-k` lets the command succeed despite verification failures when the leaf is still valid. For alerting on upcoming expiry, use [certificate checks](monitoring.md#certificate-checks).

## Inspect a certificate file

```sh
weeb cert ./chain.pem
weeb cert server.der --host example.com
weeb cert - < chain.pem
weeb cert bundle.pem --check -w 30 -c 14
```

weeb treats an existing argument as a file if it has a path separator or a `.pem`, `.crt`, `.cer`, or `.der` extension. Use `-f` to force file mode for any filename. PEM files can contain multiple certificates in any order. weeb skips other PEM blocks, such as private keys, and reports certificates it could not parse.

weeb orders the chain leaf to root and verifies it against the system roots using the bundled certificates as intermediates. Pass `--host` for hostname verification. The text report, `--json`, `--pem`, `--brief`, and `--check` also work on files. Reports for local files omit handshake details.

## Inspect from the interactive interface

Press **Ctrl+T** to inspect the current URL. The leaf certificate opens by default. In the report pane, use **Left/Right** to select another certificate and **Enter** to expand it. Press **Ctrl+T** again to return to the HTTP response.

![Inspecting a certificate chain and returning to the HTTP response](../assets/cert.gif)
