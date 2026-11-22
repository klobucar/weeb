# Security policy

## Supported versions

weeb is pre-1.0, so only the latest release gets security fixes. Please
upgrade before reporting.

| Version | Supported |
|---------|-----------|
| 0.5.x   | ✅ |
| < 0.5   | ❌ |

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately through GitHub instead:

**[Report a vulnerability](https://github.com/klobucar/weeb/security/advisories/new)**
(or the repository's **Security** tab → **Report a vulnerability**)

It helps to include:

- the output of `weeb version` and your OS;
- what you ran, and what a server, file or pasted command needed to send
  or contain to trigger it (a minimal proof of concept is ideal);
- the impact as you see it.

weeb is maintained by one person, so responses are best effort, usually
within a week. Once a fix ships, you'll be credited in the advisory and the
release notes, unless you'd rather not be.

## Scope

weeb treats everything it receives as untrusted. Reports in these areas are
especially welcome:

- **Terminal output:** anything that gets escape sequences, cursor movement,
  clipboard writes (OSC 52) or similar from a response body, header, certificate
  or file onto your terminal, or that spoofs weeb's own output.
- **Credentials:** `WEEB_TOKEN`, `WEEB_HEADERS`, cookies or auth headers
  reaching a host they shouldn't (redirects, history replay, exports), or
  ending up somewhere on disk that they shouldn't.
- **Command and file safety:** a `weeb curl` import or a `--to-curl`/`ctrl+x`
  export that does something different from what it shows, such as shell
  injection, unexpected file reads or writes, or a different destination.
- **Resource exhaustion:** a small hostile response, `.http` file or
  certificate that crashes or hangs weeb, or makes it use memory far beyond
  the input's size.
- **TLS:** verification passing when it shouldn't (`-k` aside).

Out of scope:

- Vulnerabilities in Go itself or in a dependency. Report those upstream.
  weeb ships rebuilds with patched toolchains and modules.
- `-k`/`--insecure` disabling certificate verification. That's what it's for,
  and weeb warns loudly when it's on.
- Attacks that need someone who already controls your environment variables,
  your shell, or the files you pass to weeb.
