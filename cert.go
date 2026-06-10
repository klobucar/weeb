package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"image/color"
	"math"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// certReport is the full result of a TLS inspection.
type certReport struct {
	Host        string     `json:"host"`
	Port        string     `json:"port"`
	SNI         string     `json:"sni"`
	StartTLS    string     `json:"starttls,omitempty"`
	TLSVersion  string     `json:"tls_version"`
	Cipher      string     `json:"cipher"`
	ALPN        string     `json:"alpn,omitempty"`
	Verified    bool       `json:"verified"`
	VerifyErr   string     `json:"verify_error,omitempty"`
	Skipped     bool       `json:"trust_check_skipped"`
	OCSPStapled bool       `json:"ocsp_stapled"`
	SCTCount    int        `json:"sct_count"`
	Chain       []certInfo `json:"chain"`

	rawCerts [][]byte // DER of each presented cert, for --pem (not serialized)
}

// certOptions configures a TLS inspection. The zero value dials the target's own
// host over plain TLS on port 443 with trust checked.
type certOptions struct {
	timeout    time.Duration
	insecure   bool             // capture chain but don't fail on bad trust
	sni        string           // ServerName override; "" uses the dial host
	startTLS   string           // opportunistic-TLS protocol: smtp/imap/pop3/ftp
	alpn       []string         // protocols to advertise (NextProtos)
	minVersion uint16           // 0 = library default
	maxVersion uint16           // 0 = library default
	clientCert *tls.Certificate // presented for mTLS when non-nil
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

// fetchCertReport dials the target and inspects the presented TLS chain. The
// handshake always runs with verification skipped so the chain is captured even
// when it is invalid/expired; trust is then evaluated separately and reported.
// With opts.startTLS set, it runs the protocol's plaintext upgrade first, so it
// covers `openssl s_client -starttls` as well as `-connect`.
func fetchCertReport(target string, opts certOptions) (*certReport, error) {
	host, port := splitHostPortDefault(target, defaultCertPort(opts.startTLS))
	if host == "" {
		return nil, fmt.Errorf("no host in %q", target)
	}
	serverName := host
	if opts.sni != "" {
		serverName = opts.sni // present a different vhost than we dial (e.g. an IP)
	}

	conn, err := (&net.Dialer{Timeout: opts.timeout}).Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if opts.timeout > 0 {
		// One deadline covers the STARTTLS dance and the handshake; we read the
		// state and close immediately after, so it never needs clearing.
		_ = conn.SetDeadline(time.Now().Add(opts.timeout))
	}

	if opts.startTLS != "" {
		if err := startTLS(conn, opts.startTLS); err != nil {
			return nil, err
		}
	}

	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // chain captured intentionally; trust reported separately
		ServerName:         serverName,
		NextProtos:         opts.alpn,
		MinVersion:         opts.minVersion,
		MaxVersion:         opts.maxVersion,
	}
	if opts.clientCert != nil {
		cfg.Certificates = []tls.Certificate{*opts.clientCert}
	}

	tconn := tls.Client(conn, cfg)
	if err := tconn.Handshake(); err != nil {
		return nil, err
	}

	state := tconn.ConnectionState()
	rep := &certReport{
		Host:       host,
		Port:       port,
		SNI:        serverName,
		StartTLS:   opts.startTLS,
		TLSVersion: tlsVersionName(state.Version),
		Cipher:     tls.CipherSuiteName(state.CipherSuite),
		ALPN:       state.NegotiatedProtocol,
	}

	rep.OCSPStapled = len(state.OCSPResponse) > 0
	rep.SCTCount = len(state.SignedCertificateTimestamps)

	if opts.insecure {
		rep.Skipped = true // trust check intentionally skipped (--insecure)
	} else {
		rep.Verified, rep.VerifyErr = verifyChain(serverName, state.PeerCertificates)
	}

	for _, c := range state.PeerCertificates {
		rep.Chain = append(rep.Chain, describeCert(c))
		rep.rawCerts = append(rep.rawCerts, c.Raw)
	}
	return rep, nil
}

// startTLS performs the plaintext command exchange that upgrades a connection to
// TLS for the named application protocol, mirroring `openssl s_client -starttls`.
func startTLS(conn net.Conn, proto string) error {
	br := bufio.NewReader(conn)
	switch strings.ToLower(proto) {
	case "smtp":
		if err := expectCode(br, "220"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(conn, "EHLO weeb\r\n"); err != nil {
			return err
		}
		if err := expectCode(br, "250"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
			return err
		}
		return expectCode(br, "220")
	case "ftp":
		if err := expectCode(br, "220"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(conn, "AUTH TLS\r\n"); err != nil {
			return err
		}
		return expectCode(br, "234")
	case "imap":
		if _, err := br.ReadString('\n'); err != nil { // untagged greeting
			return err
		}
		if _, err := fmt.Fprintf(conn, "a STARTTLS\r\n"); err != nil {
			return err
		}
		return expectTagged(br, "a")
	case "pop3":
		if err := expectPrefix(br, "+OK"); err != nil { // greeting
			return err
		}
		if _, err := fmt.Fprintf(conn, "STLS\r\n"); err != nil {
			return err
		}
		return expectPrefix(br, "+OK")
	default:
		return fmt.Errorf("weeb: unknown --starttls protocol %q (smtp, imap, pop3, ftp)", proto)
	}
}

// expectCode reads a (possibly multiline) numeric reply (SMTP/FTP style) and
// fails unless every line carries the wanted status code.
func expectCode(br *bufio.Reader, code string) error {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 || line[:3] != code {
			return fmt.Errorf("starttls: wanted %s, got %q", code, line)
		}
		if len(line) < 4 || line[3] != '-' { // '-' continues a multiline reply
			return nil
		}
	}
}

// expectTagged reads an IMAP response, skipping untagged lines, and requires the
// tagged completion to be OK.
func expectTagged(br *bufio.Reader, tag string) error {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, tag+" ") {
			if strings.HasPrefix(line, tag+" OK") {
				return nil
			}
			return fmt.Errorf("starttls: imap: %q", line)
		}
	}
}

// expectPrefix reads one line and requires it to start with prefix (POP3 +OK).
func expectPrefix(br *bufio.Reader, prefix string) error {
	line, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("starttls: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, prefix) {
		return fmt.Errorf("starttls: wanted %s, got %q", prefix, line)
	}
	return nil
}

// defaultCertPort picks the conventional port for a STARTTLS protocol, else 443.
func defaultCertPort(startTLS string) string {
	switch strings.ToLower(startTLS) {
	case "smtp":
		return "587" // submission port — STARTTLS-required, unlike MTA port 25
	case "imap":
		return "143"
	case "pop3":
		return "110"
	case "ftp":
		return "21"
	default:
		return "443"
	}
}

// certPEM renders the presented chain as concatenated PEM blocks, the analog of
// `openssl s_client -showcerts` — pipe it to a file to extract intermediates.
func certPEM(rep *certReport) string {
	var b strings.Builder
	for _, der := range rep.rawCerts {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return b.String()
}

// splitList splits a comma-separated flag value (e.g. ALPN "h2,http/1.1") into
// trimmed, non-empty items.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseTLSVersion maps a "1.0".."1.3" string to a tls.Version constant.
func parseTLSVersion(s string) (uint16, error) {
	switch strings.TrimPrefix(strings.ToLower(s), "tls") {
	case "1.0", "10":
		return tls.VersionTLS10, nil
	case "1.1", "11":
		return tls.VersionTLS11, nil
	case "1.2", "12":
		return tls.VersionTLS12, nil
	case "1.3", "13":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("weeb: bad --tls %q (use 1.0, 1.1, 1.2, or 1.3)", s)
	}
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
		SubjectCN: c.Subject.CommonName,
		Subject:   c.Subject.String(),
		IssuerCN:  c.Issuer.CommonName,
		Issuer:    c.Issuer.String(),
		NotBefore: c.NotBefore,
		NotAfter:  c.NotAfter,
		// Floor, not truncate: a cert expired by less than a day must report a
		// negative count so certExit's `< 0` check fires (int() rounds -0.5 to
		// 0, which kept monitors green for up to 24h after expiry).
		DaysUntilExpiry: int(math.Floor(time.Until(c.NotAfter).Hours() / 24)),
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
	return splitHostPortDefault(target, "443")
}

// splitHostPortDefault is splitHostPort with a caller-chosen default port, so a
// STARTTLS inspection can fall back to 25/143/110/21 instead of 443.
func splitHostPortDefault(target, def string) (host, port string) {
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
		port = def
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
func renderCertReport(rep *certReport, st styles, colorize bool, width int, detail bool) string {
	title := lipgloss.NewStyle().Bold(true).Foreground(cPink)

	var b strings.Builder
	b.WriteString(paintIf(colorize, title, fmt.Sprintf("🔒 TLS  %s:%s", rep.Host, rep.Port)) + "\n")
	for _, s := range certSections(rep, st, colorize, width, detail) {
		head := paintIf(colorize, st.paneTitle, s.title)
		if s.summary != "" {
			head += paintIf(colorize, st.meta, "  ("+s.summary+")")
		}
		b.WriteString("\n" + head + "\n" + s.body + "\n")
	}
	return b.String()
}

// certSection is one block of the TLS report — a heading, an optional parenthetical
// summary, and a body of rows. The same blocks render flat (CLI) or as foldable
// response-pane sections (TUI), so the two views never drift apart. defaultFold
// marks blocks the TUI collapses on first show (the CA certs above the leaf).
type certSection struct {
	title       string
	summary     string
	body        string
	defaultFold bool
}

// certSections builds the report's blocks: Connection, the Chain overview ladder,
// and one full-detail block per presented cert. With detail=false only the leaf's
// detail is included (the CLI --brief view); the TUI always passes detail=true and
// relies on folding to tuck the detail away.
func certSections(rep *certReport, st styles, colorize bool, width int, detail bool) []certSection {
	ok := lipgloss.NewStyle().Bold(true).Foreground(cGreen)
	bad := lipgloss.NewStyle().Bold(true).Foreground(cRed)

	var secs []certSection

	var cb strings.Builder
	if rep.StartTLS != "" {
		certRow(&cb, st, colorize, width, "STARTTLS", strings.ToLower(rep.StartTLS))
	}
	if rep.SNI != "" && rep.SNI != rep.Host {
		certRow(&cb, st, colorize, width, "SNI", rep.SNI)
	}
	certRow(&cb, st, colorize, width, "Protocol", rep.TLSVersion)
	certRow(&cb, st, colorize, width, "Cipher", rep.Cipher)
	if rep.ALPN != "" {
		certRow(&cb, st, colorize, width, "ALPN", rep.ALPN)
	}
	switch {
	case rep.Skipped:
		certRow(&cb, st, colorize, width, "Trust", paintIf(colorize, st.meta, "— not checked (insecure)"))
	case rep.Verified:
		certRow(&cb, st, colorize, width, "Trust", trustBadge("✓ TRUSTED", cGreen, colorize)+paintIf(colorize, st.meta, "  chain & hostname"))
	default:
		certRow(&cb, st, colorize, width, "Trust", trustBadge("✗ UNTRUSTED", cRed, colorize)+"  "+paintIf(colorize, bad, rep.VerifyErr))
	}
	certRow(&cb, st, colorize, width, "OCSP", yesNo(rep.OCSPStapled, "stapled", "not stapled", st, ok, colorize))
	certRow(&cb, st, colorize, width, "SCTs", fmt.Sprintf("%d embedded", rep.SCTCount))
	secs = append(secs, certSection{title: "🤝 Connection", body: strings.TrimRight(cb.String(), "\n")})

	if len(rep.Chain) == 0 {
		return secs
	}

	// Overview ladder: leaf → intermediates → root at a glance.
	var lb strings.Builder
	for level, c := range certLadder(rep.Chain) {
		pad := strings.Repeat("  ", level)
		conn := ""
		if level > 0 {
			conn = paintIf(colorize, st.meta, "└─ ")
		}
		lb.WriteString("  " + pad + conn + c.name + paintIf(colorize, st.meta, "  "+c.role) + "\n")
	}
	secs = append(secs, certSection{
		title:   "🔗 Chain",
		summary: fmt.Sprintf("%d presented", len(rep.Chain)),
		body:    strings.TrimRight(lb.String(), "\n"),
	})

	// Full detail per presented cert. Titles are unique (Intermediate 2, …) so the
	// TUI's title-keyed fold state stays stable across re-renders.
	inter := 0
	for i, c := range rep.Chain {
		if !detail && i > 0 {
			break // --brief: leaf only
		}
		role, icon := "Intermediate", "🔗"
		switch {
		case c.SelfSigned:
			role = "Root"
		case i == 0:
			role, icon = "Leaf", "📜"
		}
		label := icon + " " + role
		if role == "Intermediate" {
			if inter++; inter > 1 {
				label = fmt.Sprintf("%s %s %d", icon, role, inter)
			}
		}

		var db strings.Builder
		certRow(&db, st, colorize, width, "Subject", c.Subject)
		certRow(&db, st, colorize, width, "Issuer", c.Issuer)
		certRow(&db, st, colorize, width, "Valid from", c.NotBefore.Format("2006-01-02 15:04 MST"))
		certRow(&db, st, colorize, width, "Valid until", c.NotAfter.Format("2006-01-02 15:04 MST")+"  "+expiryPhrase(c.DaysUntilExpiry, colorize))
		if len(c.DNSNames) > 0 {
			certRow(&db, st, colorize, width, "SANs", strings.Join(c.DNSNames, ", "))
		}
		certRow(&db, st, colorize, width, "Key", c.KeyType)
		certRow(&db, st, colorize, width, "Sig alg", c.SigAlg)
		if len(c.ExtKeyUsage) > 0 {
			certRow(&db, st, colorize, width, "Usage", strings.Join(c.ExtKeyUsage, ", "))
		}
		certRow(&db, st, colorize, width, "Serial", c.Serial)
		certRow(&db, st, colorize, width, "SHA-256", c.SHA256)
		secs = append(secs, certSection{
			title:       label,
			summary:     c.name(),
			body:        strings.TrimRight(db.String(), "\n"),
			defaultFold: i != 0, // leaf shows on load; CA certs above it start folded
		})
	}
	return secs
}

// paintIf renders s only when colorize is set, else returns txt verbatim.
func paintIf(colorize bool, s lipgloss.Style, txt string) string {
	if colorize {
		return s.Render(txt)
	}
	return txt
}

// trustBadge renders a filled pill (ink on a colored background) when coloring,
// else plain text — used for the trust verdict.
func trustBadge(text string, c color.Color, colorize bool) string {
	if !colorize {
		return text
	}
	return lipgloss.NewStyle().Bold(true).Foreground(cInk).Background(c).Padding(0, 1).Render(text)
}

// certValueCol is where row values start: "  " + 12-wide label + " ".
const certValueCol = 2 + 12 + 1

// certRow writes one "  <label·12> <value>" line; long values word-wrap to width
// aligned under the value column (so SANs stay tidy, no mid-word breaks).
func certRow(b *strings.Builder, st styles, colorize bool, width int, k, v string) {
	b.WriteString("  " + paintIf(colorize, st.jsonKey, fmt.Sprintf("%-12s", k)) + " " + wrapValue(v, certValueCol, width) + "\n")
}

// wrapValue word-wraps a row value to the pane width, indenting continuation
// lines to the value column so wrapped lists (SANs) stay aligned and break at
// separators rather than mid-token. Returns v unchanged when it fits or width
// is unknown.
func wrapValue(v string, col, width int) string {
	avail := width - col
	if width <= 0 || avail < 8 || ansi.StringWidth(v) <= avail {
		return v
	}
	var wrapped string
	if strings.ContainsRune(v, ' ') {
		wrapped = ansi.Wordwrap(v, avail, "") // multi-word (SANs): break at spaces only
	} else {
		wrapped = ansi.Hardwrap(v, avail, true) // single long token (serial/fingerprint)
	}
	pad := strings.Repeat(" ", col)
	return strings.ReplaceAll(wrapped, "\n", "\n"+pad)
}

// ladderRung is one node in the issuance ladder (leaf → intermediate → root).
type ladderRung struct{ name, role string }

// certLadder turns the presented chain into a leaf→root issuance ladder,
// appending the final root issuer (which a server usually doesn't send).
func certLadder(chain []certInfo) []ladderRung {
	var out []ladderRung
	for i, c := range chain {
		role := "intermediate"
		switch {
		case c.SelfSigned:
			role = "root"
		case i == 0:
			role = "leaf"
		}
		out = append(out, ladderRung{c.name(), role})
	}
	if last := chain[len(chain)-1]; !last.SelfSigned {
		if root := orFallback(last.IssuerCN, last.Issuer); root != "" {
			out = append(out, ladderRung{root, "root"})
		}
	}
	return out
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

func yesNo(v bool, yes, no string, st styles, okStyle lipgloss.Style, colorize bool) string {
	if v {
		if colorize {
			return okStyle.Render("✓ " + yes)
		}
		return "✓ " + yes
	}
	if colorize {
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
