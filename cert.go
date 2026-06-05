package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"image/color"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

// certReport is the full result of a TLS inspection.
type certReport struct {
	Host        string     `json:"host"`
	Port        string     `json:"port"`
	TLSVersion  string     `json:"tls_version"`
	Cipher      string     `json:"cipher"`
	ALPN        string     `json:"alpn,omitempty"`
	Verified    bool       `json:"verified"`
	VerifyErr   string     `json:"verify_error,omitempty"`
	Skipped     bool       `json:"trust_check_skipped"`
	OCSPStapled bool       `json:"ocsp_stapled"`
	SCTCount    int        `json:"sct_count"`
	Chain       []certInfo `json:"chain"`
}

// certInfo describes a single certificate in the chain.
type certInfo struct {
	SubjectCN       string    `json:"subject_cn"`
	Subject         string    `json:"subject"`
	IssuerCN        string    `json:"issuer_cn"`
	Issuer          string    `json:"issuer"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
	DNSNames        []string  `json:"dns_names,omitempty"`
	Serial          string    `json:"serial"`
	SHA256          string    `json:"sha256_fingerprint"`
	KeyType         string    `json:"key_type"`
	SigAlg          string    `json:"signature_algorithm"`
	ExtKeyUsage     []string  `json:"ext_key_usage,omitempty"`
	IsCA            bool      `json:"is_ca"`
	SelfSigned      bool      `json:"self_signed"`
}

func (c certInfo) name() string {
	if c.SubjectCN != "" {
		return c.SubjectCN
	}
	return c.Subject
}

// fetchCertReport dials the target over TLS and inspects the presented chain.
// It always dials with verification skipped so the chain is captured even when
// it is invalid/expired; trust is then evaluated separately and reported.
func fetchCertReport(target string, timeout time.Duration, insecure bool) (*certReport, error) {
	host, port := splitHostPort(target)
	if host == "" {
		return nil, fmt.Errorf("no host in %q", target)
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp", net.JoinHostPort(host, port),
		&tls.Config{InsecureSkipVerify: true, ServerName: host}, //nolint:gosec // chain captured intentionally; trust reported separately
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	rep := &certReport{
		Host:       host,
		Port:       port,
		TLSVersion: tlsVersionName(state.Version),
		Cipher:     tls.CipherSuiteName(state.CipherSuite),
		ALPN:       state.NegotiatedProtocol,
	}

	rep.OCSPStapled = len(state.OCSPResponse) > 0
	rep.SCTCount = len(state.SignedCertificateTimestamps)

	if insecure {
		rep.Skipped = true // trust check intentionally skipped (--insecure)
	} else {
		rep.Verified, rep.VerifyErr = verifyChain(host, state.PeerCertificates)
	}

	for _, c := range state.PeerCertificates {
		rep.Chain = append(rep.Chain, describeCert(c))
	}
	return rep, nil
}

func verifyChain(host string, certs []*x509.Certificate) (bool, string) {
	if len(certs) == 0 {
		return false, "no certificates presented"
	}
	roots, _ := x509.SystemCertPool() // nil falls back to system roots inside Verify
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: inter,
	}); err != nil {
		return false, err.Error()
	}
	return true, ""
}

func describeCert(c *x509.Certificate) certInfo {
	return certInfo{
		SubjectCN:       c.Subject.CommonName,
		Subject:         c.Subject.String(),
		IssuerCN:        c.Issuer.CommonName,
		Issuer:          c.Issuer.String(),
		NotBefore:       c.NotBefore,
		NotAfter:        c.NotAfter,
		DaysUntilExpiry: int(time.Until(c.NotAfter).Hours() / 24),
		DNSNames:        c.DNSNames,
		Serial:          formatSerial(c.SerialNumber),
		SHA256:          fingerprintSHA256(c.Raw),
		KeyType:         keyType(c),
		SigAlg:          c.SignatureAlgorithm.String(),
		ExtKeyUsage:     extKeyUsages(c.ExtKeyUsage),
		IsCA:            c.IsCA,
		SelfSigned:      c.Subject.String() == c.Issuer.String(),
	}
}

func fingerprintSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func extKeyUsages(usages []x509.ExtKeyUsage) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageServerAuth:      "serverAuth",
		x509.ExtKeyUsageClientAuth:      "clientAuth",
		x509.ExtKeyUsageCodeSigning:     "codeSigning",
		x509.ExtKeyUsageEmailProtection: "emailProtection",
		x509.ExtKeyUsageOCSPSigning:     "OCSPSigning",
		x509.ExtKeyUsageTimeStamping:    "timeStamping",
	}
	var out []string
	for _, u := range usages {
		if n, ok := names[u]; ok {
			out = append(out, n)
		}
	}
	return out
}

func keyType(c *x509.Certificate) string {
	switch pk := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", pk.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", pk.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return c.PublicKeyAlgorithm.String()
	}
}

func formatSerial(n *big.Int) string {
	if n == nil {
		return "0"
	}
	b := n.Bytes()
	if len(b) == 0 {
		return "0"
	}
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":")
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// splitHostPort extracts host and port from a URL, a host:port, or a bare host,
// defaulting the port to 443.
func splitHostPort(target string) (host, port string) {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			host, port = u.Hostname(), u.Port()
		}
	}
	if host == "" {
		if h, p, err := net.SplitHostPort(target); err == nil {
			host, port = h, p
		} else {
			host = strings.TrimSuffix(target, "/")
		}
	}
	if port == "" {
		port = "443"
	}
	return host, port
}

// certExit gives a scriptable exit code: non-zero when the chain is untrusted
// (unless --insecure) or the leaf is expired, so `weeb cert` works in monitors.
func certExit(rep *certReport, insecure bool) int {
	if !insecure && !rep.Verified {
		return 1
	}
	if len(rep.Chain) > 0 && rep.Chain[0].DaysUntilExpiry < 0 {
		return 1
	}
	return 0
}

// renderCertReport produces the human-facing TLS report, colorized when color
// is true.
func renderCertReport(rep *certReport, st styles, color bool) string {
	paint := func(s lipgloss.Style, txt string) string {
		if color {
			return s.Render(txt)
		}
		return txt
	}
	ok := lipgloss.NewStyle().Bold(true).Foreground(cGreen)
	bad := lipgloss.NewStyle().Bold(true).Foreground(cRed)
	title := lipgloss.NewStyle().Bold(true).Foreground(cPink)

	var b strings.Builder
	b.WriteString(paint(title, fmt.Sprintf("🔒 TLS  %s:%s", rep.Host, rep.Port)) + "\n\n")

	row := func(k, v string) {
		b.WriteString("  " + paint(st.jsonKey, fmt.Sprintf("%-12s", k)) + " " + v + "\n")
	}

	b.WriteString(paint(st.paneTitle, "Connection") + "\n")
	row("Protocol", rep.TLSVersion)
	row("Cipher", rep.Cipher)
	if rep.ALPN != "" {
		row("ALPN", rep.ALPN)
	}
	switch {
	case rep.Skipped:
		row("Trust", paint(st.meta, "— not checked (insecure)"))
	case rep.Verified:
		row("Trust", paint(ok, "✓ chain & hostname trusted"))
	default:
		row("Trust", paint(bad, "✗ "+rep.VerifyErr))
	}
	row("OCSP", yesNo(rep.OCSPStapled, "stapled", "not stapled", st, ok, color))
	row("SCTs", fmt.Sprintf("%d embedded", rep.SCTCount))
	b.WriteString("\n")

	if len(rep.Chain) > 0 {
		leaf := rep.Chain[0]
		b.WriteString(paint(st.paneTitle, "Certificate (leaf)") + "\n")
		row("Subject", leaf.name())
		row("Issuer", leaf.Issuer)
		row("Valid from", leaf.NotBefore.Format("2006-01-02 15:04 MST"))
		row("Valid until", leaf.NotAfter.Format("2006-01-02 15:04 MST")+"  "+expiryPhrase(leaf.DaysUntilExpiry, color))
		if len(leaf.DNSNames) > 0 {
			row("SANs", strings.Join(leaf.DNSNames, ", "))
		}
		row("Key", leaf.KeyType)
		row("Sig alg", leaf.SigAlg)
		if len(leaf.ExtKeyUsage) > 0 {
			row("Usage", strings.Join(leaf.ExtKeyUsage, ", "))
		}
		row("Serial", leaf.Serial)
		row("SHA-256", leaf.SHA256)
		b.WriteString("\n")

		b.WriteString(paint(st.paneTitle, fmt.Sprintf("Chain (%d)", len(rep.Chain))) + "\n")
		for i, c := range rep.Chain {
			link := paint(st.meta, "← "+orFallback(c.IssuerCN, c.Issuer))
			if c.SelfSigned {
				link = paint(st.meta, "(self-signed root)")
			}
			b.WriteString(fmt.Sprintf("  %s  %s  %s\n",
				paint(st.meta, fmt.Sprintf("%d", i)), c.name(), link))
		}
	}
	return b.String()
}

// expiryPhrase renders a colored "(in N days)" / "(expired ...)" suffix.
func expiryPhrase(days int, colorize bool) string {
	var txt string
	var col color.Color
	switch {
	case days < 0:
		txt, col = fmt.Sprintf("(expired %d days ago)", -days), cRed
	case days < 7:
		txt, col = fmt.Sprintf("(in %d days!)", days), cRed
	case days < 30:
		txt, col = fmt.Sprintf("(in %d days)", days), cOrange
	default:
		txt, col = fmt.Sprintf("(in %d days)", days), cGreen
	}
	if colorize {
		return lipgloss.NewStyle().Bold(true).Foreground(col).Render(txt)
	}
	return txt
}

func yesNo(v bool, yes, no string, st styles, okStyle lipgloss.Style, color bool) string {
	if v {
		if color {
			return okStyle.Render("✓ " + yes)
		}
		return "✓ " + yes
	}
	if color {
		return st.meta.Render("— " + no)
	}
	return "— " + no
}

func orFallback(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
