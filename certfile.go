package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"charm.land/log/v2"
	"github.com/charmbracelet/x/term"
)

// `weeb cert FILE`: the offline counterpart of fetchCertReport, a friendlier
// `openssl x509 -text`. It builds the same certReport from certificates read
// off disk (or stdin), so the report, --json, --pem, --brief, --check and the
// exit codes all behave as they do for a live endpoint. Only the handshake
// fields stay empty, and the renderers leave them out instead of showing
// zero values as if they had been observed.

// certFileMax caps how much of a certificate file is read. Real bundles are
// small (the whole Mozilla root store is ~200 KiB); the cap only stops a path
// like /dev/zero from being read forever.
const certFileMax = 16 << 20

// certFileOptions configures certFileReport.
type certFileOptions struct {
	host     string         // check the leaf against this name; "" skips the hostname check
	insecure bool           // -k: skip the trust check, as the network path does
	roots    *x509.CertPool // trust anchors; nil means the system roots (tests inject their own)
}

// isCertFileTarget reports whether a `weeb cert` argument names a local
// certificate file rather than a host. "-" is stdin. Anything else must exist
// and look like a path: contain a separator, or end in .pem/.crt/.cer/.der.
// So a bare `example.com` stays a network target even when a file of that
// name sits in the working directory. The user typed a hostname, and quietly
// reading a stray file instead would report on the wrong thing; -f reads it
// on purpose. A URL is never a file.
func isCertFileTarget(arg string) bool {
	if arg == "-" {
		return true
	}
	if arg == "" || strings.Contains(arg, "://") {
		return false
	}
	if !strings.ContainsAny(arg, "/"+string(os.PathSeparator)) && !hasCertExt(arg) {
		return false
	}
	fi, err := os.Stat(arg)
	return err == nil && !fi.IsDir()
}

func hasCertExt(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".pem", ".crt", ".cer", ".der":
		return true
	}
	return false
}

// readCertSource reads a certificate file, or stdin for "-", up to
// certFileMax.
func readCertSource(path string, stdin io.Reader) ([]byte, error) {
	r := stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, certFileMax+1))
	if err != nil {
		return nil, err
	}
	if len(data) > certFileMax {
		return nil, fmt.Errorf("%s: larger than %d MiB; not a certificate file?", certSourceName(path), certFileMax>>20)
	}
	return data, nil
}

// certBundle is what parseCertBundle found in a file.
type certBundle struct {
	certs      []*x509.Certificate
	format     string   // "PEM" or "DER"
	skipped    []string // types of non-certificate PEM blocks
	unreadable []string // CERTIFICATE blocks x509 rejected, as "PEM block N: reason"
}

// parseCertBundle extracts certificates from PEM (any number of CERTIFICATE
// blocks, in any order, among other blocks and surrounding text) or from raw
// DER (one certificate, or several concatenated). Other PEM blocks are skipped
// and only their type is kept: a bundle often carries the private key, and its
// bytes must never reach the output. A CERTIFICATE block Go can't parse is
// skipped and noted rather than failing the file, because real CA bundles
// carry a few legacy roots (macOS's /etc/ssl/cert.pem has one with a negative
// serial) and one of them shouldn't hide all the others.
func parseCertBundle(data []byte) (certBundle, error) {
	var b certBundle
	rest, blocks := data, 0
	for {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		blocks++
		if block.Type != "CERTIFICATE" {
			b.skipped = append(b.skipped, block.Type)
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			b.unreadable = append(b.unreadable, fmt.Sprintf("PEM block %d: %v", blocks, err))
			continue
		}
		b.certs = append(b.certs, c)
	}
	if blocks > 0 {
		switch {
		case len(b.certs) > 0:
			b.format = "PEM"
			return b, nil
		case len(b.unreadable) > 0:
			return b, fmt.Errorf("no readable certificate: %s", strings.Join(b.unreadable, "; "))
		default:
			return b, fmt.Errorf("no CERTIFICATE block (found %s)", strings.Join(b.skipped, ", "))
		}
	}
	certs, err := x509.ParseCertificates(data)
	if err != nil || len(certs) == 0 {
		return b, errors.New("no certificate found (expected PEM or DER)")
	}
	b.certs, b.format = certs, "DER"
	return b, nil
}

// orderChain sorts a file's certificates leaf → root by matching each one's
// issuer to another's subject, since files list a chain in any order (some
// CAs ship them root first). The leaf is a cert that issued none of the
// others, preferring a non-CA, then file order. Certs not on the leaf's path,
// such as the rest of a CA bundle, come back separately, in file order.
// Exact duplicates are dropped.
//
// Lookups go through a subject index rather than comparing every pair, so a
// file at the certFileMax cap (tens of thousands of certs) still orders fast.
func orderChain(certs []*x509.Certificate) (chain, others []*x509.Certificate) {
	var uniq []*x509.Certificate
	seen := map[string]bool{}
	for _, c := range certs {
		if !seen[string(c.Raw)] {
			seen[string(c.Raw)] = true
			uniq = append(uniq, c)
		}
	}
	if len(uniq) == 0 {
		return nil, nil
	}
	bySubject := map[string][]int{} // RawSubject -> indexes into uniq, in file order
	for i, c := range uniq {
		bySubject[string(c.RawSubject)] = append(bySubject[string(c.RawSubject)], i)
	}
	// issuers yields the indexes of the certs in uniq that could have issued c.
	issuers := func(c *x509.Certificate) []int {
		var out []int
		for _, j := range bySubject[string(c.RawIssuer)] {
			if issuedBy(c, uniq[j]) {
				out = append(out, j)
			}
		}
		return out
	}

	issuesOther := make([]bool, len(uniq))
	for i, c := range uniq {
		for _, j := range issuers(c) {
			if j != i {
				issuesOther[j] = true
			}
		}
	}
	leaf := -1
	for i, c := range uniq {
		if issuesOther[i] {
			continue
		}
		if !c.IsCA {
			leaf = i
			break
		}
		if leaf < 0 {
			leaf = i
		}
	}
	if leaf < 0 {
		leaf = 0 // every cert issues another (a cross-signed loop): fall back to file order
	}

	used := make([]bool, len(uniq))
	used[leaf] = true
	chain = append(chain, uniq[leaf])
	for cur := uniq[leaf]; !issuedBy(cur, cur); {
		next := -1
		for _, j := range issuers(cur) {
			if !used[j] {
				next = j
				break
			}
		}
		if next < 0 {
			break
		}
		used[next] = true
		cur = uniq[next]
		chain = append(chain, cur)
	}
	for i, c := range uniq {
		if !used[i] {
			others = append(others, c)
		}
	}
	return chain, others
}

// issuedBy reports whether parent's subject matches child's issuer, with the
// key identifiers agreeing when both are present. This is the same name and
// key-ID match the x509 path builder uses to pick candidates; signatures are
// checked later, by Verify.
func issuedBy(child, parent *x509.Certificate) bool {
	if !bytes.Equal(child.RawIssuer, parent.RawSubject) {
		return false
	}
	if len(child.AuthorityKeyId) > 0 && len(parent.SubjectKeyId) > 0 {
		return bytes.Equal(child.AuthorityKeyId, parent.SubjectKeyId)
	}
	return true
}

// verifyCertFile checks the ordered chain against the trust roots, with every
// other cert in the file offered as an intermediate. A root shipped in the
// file is only an intermediate here, so a file can't vouch for itself.
func verifyCertFile(chain, others []*x509.Certificate, host string, roots *x509.CertPool) (bool, string) {
	if roots == nil {
		roots, _ = x509.SystemCertPool() // nil falls back to system roots inside Verify
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	for _, c := range others {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter}
	if host == "" {
		// With no hostname the question is "is this chain trusted?", not
		// "would it serve TLS for a name?", so any EKU passes, as with
		// `openssl verify` without -purpose. (On macOS the platform verifier
		// still applies its SSL policy to system roots.)
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	if _, err := chain[0].Verify(opts); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// certFileReport parses, orders and verifies the certificates in data and
// describes them in a certReport. name is the path as given ("-" for stdin).
func certFileReport(name string, data []byte, opts certFileOptions) (*certReport, error) {
	b, err := parseCertBundle(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", certSourceName(name), err)
	}
	chain, others := orderChain(b.certs)
	rep := &certReport{
		File:          name,
		Format:        b.format,
		Hostname:      opts.host,
		SkippedBlocks: b.skipped,
		Unreadable:    b.unreadable,
	}
	if opts.insecure {
		rep.Skipped = true
	} else {
		rep.Verified, rep.VerifyErr = verifyCertFile(chain, others, opts.host, opts.roots)
	}
	for _, c := range chain {
		rep.Chain = append(rep.Chain, describeCert(c))
		rep.rawCerts = append(rep.rawCerts, c.Raw)
	}
	for _, c := range others {
		rep.Others = append(rep.Others, describeCert(c))
		rep.rawCerts = append(rep.rawCerts, c.Raw)
	}
	return rep, nil
}

// netOnlyCertFlag names the first given flag that only means something during
// a handshake, or returns "" when there is none. A file has no handshake, so
// runCert rejects these instead of silently ignoring them. --timeout is let
// through: it bounds nothing here but is harmless in a shared command line.
func netOnlyCertFlag(opts certOptions, clientCert, clientKey string) string {
	switch {
	case opts.startTLS != "":
		return "--starttls"
	case opts.alpn != nil:
		return "--alpn"
	case opts.minVersion != 0 || opts.maxVersion != 0:
		return "--tls"
	case clientCert != "":
		return "--client-cert"
	case clientKey != "":
		return "--client-key"
	}
	return ""
}

// runCertFile is runCert for a certificate file: read, inspect, and hand the
// report to the same output path as a live endpoint.
func runCertFile(path, host string, voice ErrorChan, out certOutput, logger *log.Logger) int {
	if path == "-" && term.IsTerminal(os.Stdin.Fd()) {
		fmt.Fprintln(os.Stderr, "weeb: 'weeb cert -' reads certificates from stdin; pipe them in, e.g. 'cat chain.pem | weeb cert -'")
		return 2
	}
	rlog := logger.With("op", "cert", "file", path)
	rlog.Info("cert file inspect")

	data, err := readCertSource(path, os.Stdin)
	var rep *certReport
	if err == nil {
		rep, err = certFileReport(path, data, certFileOptions{host: host, insecure: out.insecure})
	}
	if err != nil {
		rlog.Error("cert file inspect failed", "kind", KindBadRequest.String(), "err", err)
		if out.check {
			// Nothing was observed to evaluate: UNKNOWN, as for an endpoint
			// that can't be reached.
			return printCheck(outW, newCheckVerdict("cert", checkUnknown, checkSafe(err.Error()), "", nil), out.asJSON)
		}
		fmt.Fprintln(errW, voice.Render(KindBadRequest, 0, err))
		return 1
	}
	rlog.Info("cert file ok", "format", rep.Format, "verified", rep.Verified, "certs", len(rep.rawCerts))

	omitted := slices.Clone(rep.SkippedBlocks)
	for range rep.Unreadable {
		omitted = append(omitted, "unreadable CERTIFICATE")
	}
	if out.asPEM && len(omitted) > 0 {
		// --pem prints only the certs it parsed. Say what was left out, so
		// piping a bundle through it to strip the key isn't a silent surprise.
		fmt.Fprintf(errW, "weeb: skipped %s (not printed)\n", skippedBlocksPhrase(omitted))
	}
	return out.emit(rep)
}

// skippedBlocksPhrase summarizes skipped PEM blocks by type and count, e.g.
// "1 PRIVATE KEY block". Only the type is named; contents never are.
func skippedBlocksPhrase(types []string) string {
	var order []string
	count := map[string]int{}
	for _, t := range types {
		if count[t] == 0 {
			order = append(order, t)
		}
		count[t]++
	}
	parts := make([]string, len(order))
	for i, t := range order {
		parts[i] = fmt.Sprintf("%d %s block", count[t], t)
		if count[t] > 1 {
			parts[i] += "s"
		}
	}
	return strings.Join(parts, ", ")
}

// certFileSection stands in for the Connection section of a live report: where
// the certs came from, what was skipped, and the trust verdict.
func certFileSection(rep *certReport, st styles, colorize bool, width int) certSection {
	var b strings.Builder
	certRow(&b, st, colorize, width, "File", certSourceName(rep.File))
	n, s := len(rep.Chain)+len(rep.Others), "s"
	if n == 1 {
		s = ""
	}
	certRow(&b, st, colorize, width, "Format", fmt.Sprintf("%s, %d certificate%s", rep.Format, n, s))
	if len(rep.SkippedBlocks) > 0 {
		certRow(&b, st, colorize, width, "Skipped", paintIf(colorize, st.meta, skippedBlocksPhrase(rep.SkippedBlocks)+" (not shown)"))
	}
	if len(rep.Unreadable) > 0 {
		certRow(&b, st, colorize, width, "Unreadable", paintIf(colorize, st.meta, strings.Join(rep.Unreadable, "; ")+" (skipped)"))
	}
	scope := "chain & hostname"
	if rep.Hostname != "" {
		certRow(&b, st, colorize, width, "Hostname", rep.Hostname)
	} else {
		certRow(&b, st, colorize, width, "Hostname", paintIf(colorize, st.meta, "— not checked (use --host NAME)"))
		scope = "chain"
	}
	certTrustRow(&b, rep, st, colorize, width, scope)
	return certSection{title: "📄 File", body: strings.TrimRight(b.String(), "\n")}
}

// certOthersSection lists the file's certs that aren't on the leaf's issuer
// path (the rest of a CA bundle, say), one line each, so they're shown
// without being passed off as part of the chain.
func certOthersSection(rep *certReport, colorize bool) certSection {
	var b strings.Builder
	for _, c := range rep.Others {
		b.WriteString("  " + c.name() + "  " + expiryPhrase(c.DaysUntilExpiry, colorize) + "\n")
	}
	return certSection{
		title:   "📦 Also in file",
		summary: fmt.Sprintf("%d not on the leaf's chain", len(rep.Others)),
		body:    strings.TrimRight(b.String(), "\n"),
	}
}

// certFileJSON is the --json shape of a file report. It leaves out the
// handshake fields (tls_version, cipher, alpn, ocsp_stapled, sct_count)
// rather than emitting zero values that would read as "checked, none found".
type certFileJSON struct {
	File          string     `json:"file"`
	Format        string     `json:"format"`
	Hostname      string     `json:"hostname,omitempty"`
	Verified      bool       `json:"verified"`
	VerifyErr     string     `json:"verify_error,omitempty"`
	Skipped       bool       `json:"trust_check_skipped"`
	SkippedBlocks []string   `json:"skipped_pem_blocks,omitempty"`
	Unreadable    []string   `json:"unreadable_certs,omitempty"`
	Chain         []certInfo `json:"chain"`
	Others        []certInfo `json:"other_certs,omitempty"`
}
