package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
)

// TLSOptions are a request's curl-style TLS settings. The zero value is Go's
// default: verify the server against the system roots, present no client
// certificate. Every field is a flag value (a bool or a path), so the struct
// is comparable and doubles as the Client's transport cache key.
type TLSOptions struct {
	Insecure bool   // -k/--insecure: skip server certificate verification
	CACert   string // --cacert: PEM CAs trusted INSTEAD of the system roots, like curl
	Cert     string // --cert/-E: client certificate (PEM) for mTLS; may hold the key too
	Key      string // --key: the client certificate's private key (PEM), when separate
}

func (o TLSOptions) isZero() bool { return o == TLSOptions{} }

// insecureWarning is printed to stderr for every headless request sent with
// -k (the TUI shows insecureBadge instead). Turning verification off must
// never be silent: a pasted curl command can carry -k without the user
// noticing it among a dozen other flags.
const insecureWarning = "weeb: warning: -k/--insecure: TLS certificate verification is OFF; anyone on the network path can read or change this request"

// warnInsecure prints insecureWarning when the spec skips verification.
func warnInsecure(w io.Writer, spec RequestSpec) {
	if spec.TLS.Insecure {
		fmt.Fprintln(w, insecureWarning)
	}
}

// config builds the tls.Config these options describe, loading the CA bundle
// and client key pair from disk.
func (o TLSOptions) config() (*tls.Config, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: o.Insecure, //nolint:gosec // -k, asked for explicitly and announced loudly (see warnInsecure)
	}
	if o.CACert != "" {
		pool, err := loadCAPool(o.CACert)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	switch {
	case o.Cert != "":
		pair, err := loadClientCert(o.Cert, o.Key)
		if err != nil {
			return nil, err
		}
		// GetClientCertificate rather than Certificates: with Certificates Go
		// sends nothing when the server's acceptable-CA list doesn't name our
		// issuer, and many servers send an incomplete list. curl always
		// presents the configured certificate; so do we.
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return pair, nil
		}
	case o.Key != "":
		return nil, fmt.Errorf("--key needs --cert (the client certificate it belongs to)")
	}
	return cfg, nil
}

// loadCAPool reads a PEM bundle into a pool that REPLACES the system roots,
// matching curl --cacert: the server must chain to one of these CAs.
func loadCAPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--cacert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("--cacert %s: no PEM certificates found", path)
	}
	return pool, nil
}

// parseCertArg resolves a curl --cert/-E value. curl reads "FILE:PASSWORD",
// splitting at the first colon that isn't escaped as "\:" ("\\" is a literal
// backslash, and on Windows a drive letter's colon doesn't count). Encrypted
// keys aren't supported, so a password is an error rather than being folded
// into the file name.
func parseCertArg(v string) (string, error) {
	if strings.HasPrefix(strings.ToLower(v), "pkcs11:") {
		return "", fmt.Errorf("--cert: PKCS#11 URIs aren't supported; give a PEM file")
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '\\' && i+1 < len(v) && (v[i+1] == '\\' || v[i+1] == ':'):
			b.WriteByte(v[i+1])
			i++
		case c == ':' && i == 1 && runtime.GOOS == "windows" && isDriveLetter(v):
			b.WriteByte(c)
		case c == ':':
			if i+1 < len(v) {
				return "", fmt.Errorf("--cert FILE:PASSWORD (an encrypted key) isn't supported; decrypt the key first (openssl pkey -in key.pem -out plain.pem), or write a colon in the file name as \\:")
			}
			return b.String(), nil // "FILE:" carries an empty password: curl ignores it
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

// isDriveLetter reports whether v starts like "C:\" or "C:/".
func isDriveLetter(v string) bool {
	c := v[0] | 0x20
	return len(v) > 2 && c >= 'a' && c <= 'z' && (v[2] == '\\' || v[2] == '/')
}

// certArgEscape is parseCertArg's inverse for export: curl would read a bare
// colon in the path as the start of a password.
func certArgEscape(path string) string {
	return strings.NewReplacer(`\`, `\\`, `:`, `\:`).Replace(path)
}

// tlsTransportKey picks a cached transport: the TLS settings, plus whether it
// is the streaming variant (which bounds time-to-headers, see newClient).
type tlsTransportKey struct {
	opts   TLSOptions
	stream bool
}

// httpClientFor returns the http.Client to send spec with. A request without
// TLS options or a cookie jar uses the Client's shared clients unchanged;
// otherwise it gets a shallow copy that keeps their timeout and redirect
// policy but swaps in a transport built for its TLS settings and/or the jar.
func (c *Client) httpClientFor(spec RequestSpec, jar *cookieSession) (*http.Client, error) {
	// Streaming with the default timeout: bound the wait for headers, never
	// the body copy. An explicit --timeout keeps the total cap even here.
	stream := spec.BodySink != nil && !c.explicitTimeout
	base := c.http
	if stream {
		base = c.stream
	}
	if spec.TLS.isZero() && jar == nil {
		return base, nil
	}
	hc := *base
	if !spec.TLS.isZero() {
		tr, err := c.tlsTransport(spec.TLS, stream)
		if err != nil {
			return nil, err
		}
		hc.Transport = tr
	}
	if jar != nil {
		hc.Jar = jar
	}
	return &hc, nil
}

// tlsTransport returns the transport for a set of TLS options, building it on
// first use. It is a clone of http.DefaultTransport — the default is shared
// process-wide and must never be mutated — so proxy-from-environment, the dial
// timeout and HTTP/2 all carry over. Transports are cached so repeated TUI
// sends reuse their connections; the key files are read once per process.
func (c *Client) tlsTransport(o TLSOptions, stream bool) (*http.Transport, error) {
	c.trMu.Lock()
	defer c.trMu.Unlock()
	key := tlsTransportKey{opts: o, stream: stream}
	if tr, ok := c.transports[key]; ok {
		return tr, nil
	}
	cfg, err := o.config()
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	if stream {
		tr.ResponseHeaderTimeout = defaultTimeout
	}
	if c.transports == nil {
		c.transports = map[tlsTransportKey]*http.Transport{}
	}
	c.transports[key] = tr
	return tr, nil
}

// preflightSpec checks the parts of a request that read local files — TLS
// material and -F uploads — so a bad path is a usage error before anything is
// sent instead of a failure mid-request. The cookie file is not checked: a
// missing -b FILE is fine (curl's `-b jar -c jar` idiom on a first run).
func preflightSpec(spec RequestSpec) error {
	if _, err := spec.TLS.config(); err != nil {
		return err
	}
	for _, f := range spec.Form {
		if f.Kind == formText {
			continue
		}
		fh, err := os.Open(f.Value)
		if err != nil {
			return fmt.Errorf("-F %q: %w", f.Name, err)
		}
		_ = fh.Close()
	}
	return nil
}
