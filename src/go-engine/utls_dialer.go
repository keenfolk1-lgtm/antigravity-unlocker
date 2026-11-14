package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// DPIProfile mirrors C# DpiFragmentingStream fragmentation modes.
type DPIProfile int

const (
	DPIProfileStandardSplit  DPIProfile = 0
	DPIProfileSniMicroChunk  DPIProfile = 1
	DPIProfileTlsRecordSplit DPIProfile = 2
)

var (
	ErrCertPinMismatch = errors.New("tls certificate SPKI / X.509 pin mismatch")
	ErrMitmDetected    = errors.New("ssl interception / invalid chain detected")
)

// RecordSplitConn wraps a TCP connection to chunk or split the initial TLS ClientHello
// across TCP segments or multiple TLS handshake records to defeat DPI SNI extractors.
type RecordSplitConn struct {
	net.Conn
	sni       string
	profile   DPIProfile
	active    bool
	mu        sync.Mutex
	sentFirst bool
}

// NewRecordSplitConn wraps raw with DPI ClientHello splitting disabled once first flight is sent.
func NewRecordSplitConn(raw net.Conn, sni string, profile DPIProfile, enabled bool) *RecordSplitConn {
	return &RecordSplitConn{
		Conn:    raw,
		sni:     sni,
		profile: profile,
		active:  enabled,
	}
}

func (c *RecordSplitConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	shouldSplit := c.active && !c.sentFirst && len(b) >= 40 && b[0] == 0x16 && b[1] == 0x03
	if c.active && !c.sentFirst {
		c.sentFirst = true
		c.active = false
	}
	c.mu.Unlock()

	if !shouldSplit {
		return c.Conn.Write(b)
	}

	switch c.profile {
	case DPIProfileTlsRecordSplit:
		splitRecords := SplitTLSClientHelloRecord(b, c.sni)
		if err := writeAllSegments(c.Conn, splitRecords, 2*time.Millisecond); err != nil {
			return 0, err
		}
		return len(b), nil

	case DPIProfileSniMicroChunk:
		chunks := MicroChunkClientHello(b, c.sni)
		if err := writeAllSegments(c.Conn, chunks, time.Millisecond); err != nil {
			return 0, err
		}
		return len(b), nil

	default: // DPIProfileStandardSplit
		chunks := StandardSplitClientHello(b)
		if err := writeAllSegments(c.Conn, chunks, 2*time.Millisecond); err != nil {
			return 0, err
		}
		return len(b), nil
	}
}

func writeAllSegments(w net.Conn, segments [][]byte, gap time.Duration) error {
	for i, seg := range segments {
		if len(seg) == 0 {
			continue
		}
		if _, err := w.Write(seg); err != nil {
			return err
		}
		if i+1 < len(segments) && gap > 0 {
			time.Sleep(gap)
		}
	}
	return nil
}

// StandardSplitClientHello splits the initial TLS flight into small header/SNI/tail TCP writes.
func StandardSplitClientHello(raw []byte) [][]byte {
	if len(raw) <= 28 {
		return [][]byte{raw}
	}
	p1 := 5 + 4 + 15 // cross into ClientHello body before SNI
	if p1 >= len(raw) {
		p1 = len(raw) / 3
	}
	p2 := p1 + 32
	if p2 >= len(raw) {
		p2 = len(raw) - 1
	}
	return [][]byte{
		raw[:p1],
		raw[p1:p2],
		raw[p2:],
	}
}

// MicroChunkClientHello aggressively slices through the SNI extension region into 8-10 byte TCP chunks.
func MicroChunkClientHello(raw []byte, sni string) [][]byte {
	sniOff, sniLen := findSNIOffset(raw, sni)
	var out [][]byte
	out = append(out, raw[:5])
	pos := 5
	endSNI := len(raw)
	if sniOff > 0 {
		if sniOff > pos {
			out = append(out, raw[pos:sniOff])
			pos = sniOff
		}
		endSNI = sniOff + sniLen
		if endSNI > len(raw) {
			endSNI = len(raw)
		}
	}
	for pos < endSNI {
		step := 8
		if pos+step > endSNI {
			step = endSNI - pos
		}
		out = append(out, raw[pos:pos+step])
		pos += step
	}
	if pos < len(raw) {
		out = append(out, raw[pos:])
	}
	return out
}

// SplitTLSClientHelloRecord rewrites a single TLS 0x16 Handshake record into two valid
// TLS records split right across the middle of the SNI hostname bytes.
func SplitTLSClientHelloRecord(raw []byte, sni string) [][]byte {
	if len(raw) < 12 || raw[0] != 0x16 || raw[1] != 0x03 {
		return [][]byte{raw}
	}
	recLen := int(binary.BigEndian.Uint16(raw[3:5]))
	if recLen <= 0 || 5+recLen > len(raw) {
		return [][]byte{raw}
	}
	payload := raw[5 : 5+recLen]
	splitAt := len(payload) / 2
	if off, n := findSNIOffset(raw, sni); off >= 5 && n > 1 {
		mid := (off - 5) + n/2
		if mid > 8 && mid < len(payload)-4 {
			splitAt = mid
		}
	}
	if splitAt <= 4 || splitAt >= len(payload) {
		return [][]byte{raw}
	}

	verMajor, verMinor := raw[1], raw[2]
	rec1 := make([]byte, 5+splitAt)
	rec1[0], rec1[1], rec1[2] = 0x16, verMajor, verMinor
	binary.BigEndian.PutUint16(rec1[3:5], uint16(splitAt))
	copy(rec1[5:], payload[:splitAt])

	restLen := len(payload) - splitAt
	rec2 := make([]byte, 5+restLen)
	rec2[0], rec2[1], rec2[2] = 0x16, verMajor, verMinor
	binary.BigEndian.PutUint16(rec2[3:5], uint16(restLen))
	copy(rec2[5:], payload[splitAt:])

	var out [][]byte
	out = append(out, rec1, rec2)
	if 5+recLen < len(raw) {
		out = append(out, raw[5+recLen:])
	}
	return out
}

func findSNIOffset(raw []byte, sni string) (int, int) {
	if sni == "" {
		return -1, 0
	}
	needle := []byte(strings.ToLower(sni))
	if len(needle) == 0 || len(needle) > len(raw) {
		return -1, 0
	}
	for i := 5; i <= len(raw)-len(needle); i++ {
		matched := true
		for j := 0; j < len(needle); j++ {
			b := raw[i+j]
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if b != needle[j] {
				matched = false
				break
			}
		}
		if matched {
			return i, len(needle)
		}
	}
	return -1, 0
}

// UTLSDialOptions configures Chrome/Firefox uTLS dialing, DPI chunking, and cert pinning.
type UTLSDialOptions struct {
	Address          string // host:port or ip:port to connect TCP
	SNI              string // ClientHello SNI hostname
	Profile          string // "chrome" (default) or "firefox"
	DPIProfile       DPIProfile
	EnableSplit      bool
	MaskedDecoySNI   bool           // true when dialing raw IP with non-pixelstore decoy SNI
	Pins             []string       // lowercase hex SHA-256 of SPKI or full X.509 cert
	RequirePin       bool           // enforce pin match even if OS/RootCAs validate chain
	RootCAs          *x509.CertPool // custom CA pool for sandbox tests; nil = system roots
	ForceHTTP1ALPN   bool           // rewrite uTLS ALPN to ["http/1.1"] while preserving browser JA3/JA4 shape
	InsecureTestOnly bool
	ConnectTimeout   time.Duration
}

// UTLSDialResult contains the connected TLS socket and inspected peer certificate summary.
type UTLSDialResult struct {
	Conn       net.Conn
	Profile    string
	SPKISHA256 string
	CertSHA256 string
	Issuer     string
	Subject    string
	PinMatched bool
}

const defaultUTLSDialTimeout = 2500 * time.Millisecond

// onUTLSDialAttempt is an optional test-only hook invoked once per dialUTLSOnce attempt.
var onUTLSDialAttempt func(profile string)

// tcpConnectError wraps raw TCP dial failures before any TLS handshake begins
// so callers do not retry alternate TLS fingerprints against unreachable sockets.
type tcpConnectError struct {
	err error
}

func (e *tcpConnectError) Error() string {
	if e == nil || e.err == nil {
		return "tcp connect failed"
	}
	return e.err.Error()
}

func (e *tcpConnectError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func resolveUTLSDialTimeout(requested time.Duration) time.Duration {
	if requested <= 0 {
		return defaultUTLSDialTimeout
	}
	return requested
}

// DialUTLS establishes a TCP connection with optional ClientHello DPI splitting and
// wraps it with uTLS (HelloChrome_Auto, fallback HelloFirefox_Auto) + X.509/SPKI pinning.
func DialUTLS(ctx context.Context, opts UTLSDialOptions) (*UTLSDialResult, error) {
	timeout := resolveUTLSDialTimeout(opts.ConnectTimeout)

	profiles := []string{"chrome", "firefox"}
	if strings.EqualFold(opts.Profile, "firefox") {
		profiles = []string{"firefox", "chrome"}
	}

	var lastErr error
	for _, prof := range profiles {
		res, err := dialUTLSOnce(ctx, opts, prof, timeout)
		if err == nil {
			return res, nil
		}
		lastErr = err
		// Never fallback profile on cryptographic pinning mismatch or raw TCP connect failures
		var tcpErr *tcpConnectError
		if errors.Is(err, ErrCertPinMismatch) || errors.Is(err, ErrMitmDetected) || errors.As(err, &tcpErr) {
			return nil, err
		}
	}
	return nil, lastErr
}

func dialUTLSOnce(ctx context.Context, opts UTLSDialOptions, profileName string, timeout time.Duration) (*UTLSDialResult, error) {
	if onUTLSDialAttempt != nil {
		onUTLSDialAttempt(profileName)
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", opts.Address)
	if err != nil {
		return nil, &tcpConnectError{err: err}
	}

	splitConn := NewRecordSplitConn(rawConn, opts.SNI, opts.DPIProfile, opts.EnableSplit)

	pinSet := make(map[string]struct{}, len(opts.Pins))
	for _, p := range opts.Pins {
		norm := normalizeHexPin(p)
		if norm != "" {
			pinSet[norm] = struct{}{}
		}
	}

	var meta struct {
		spkiHex string
		certHex string
		issuer  string
		subject string
		pinned  bool
	}

	utlsCfg := &utls.Config{
		ServerName:         opts.SNI,
		RootCAs:            opts.RootCAs,
		InsecureSkipVerify: true, // Custom verification performs full CA + SPKI/X.509 checks below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("server presented empty certificate chain")
			}
			certs := make([]*x509.Certificate, 0, len(rawCerts))
			for i, der := range rawCerts {
				c, perr := x509.ParseCertificate(der)
				if perr != nil {
					return fmt.Errorf("parse peer cert %d: %w", i, perr)
				}
				certs = append(certs, c)
				spkiHex := HashSPKISHA256(c)
				certHex := HashCertSHA256(c)
				if i == 0 {
					meta.spkiHex = spkiHex
					meta.certHex = certHex
					meta.issuer = c.Issuer.CommonName
					if meta.issuer == "" && len(c.Issuer.Organization) > 0 {
						meta.issuer = c.Issuer.Organization[0]
					}
					meta.subject = c.Subject.CommonName
				}
				if _, ok := pinSet[spkiHex]; ok {
					meta.pinned = true
				}
				if _, ok := pinSet[certHex]; ok {
					meta.pinned = true
				}
			}

			if opts.InsecureTestOnly {
				return nil
			}

			// If decoy SNI is sent over raw server IP, server returns pinned PixelStore cert.
			if opts.MaskedDecoySNI {
				if len(pinSet) == 0 || !meta.pinned {
					return fmt.Errorf("%w: leaf spki=%s", ErrCertPinMismatch, meta.spkiHex)
				}
				return nil
			}

			// If pinning is required, fail immediately on mismatch (catches AV/corp SSL MITM proxies).
			if opts.RequirePin && len(pinSet) > 0 && !meta.pinned {
				return fmt.Errorf("%w: leaf spki=%s issuer=%q", ErrCertPinMismatch, meta.spkiHex, meta.issuer)
			}

			// Verify X.509 trust chain (against opts.RootCAs if provided, or system pool)
			// unless leaf matched an explicit cryptographic pin.
			if !meta.pinned || opts.RootCAs != nil {
				pool := opts.RootCAs
				if pool == nil {
					var sysErr error
					pool, sysErr = x509.SystemCertPool()
					if sysErr != nil || pool == nil {
						if meta.pinned {
							return nil
						}
						return fmt.Errorf("system cert pool unavailable: %w", sysErr)
					}
				}
				intermediates := x509.NewCertPool()
				for _, ic := range certs[1:] {
					intermediates.AddCert(ic)
				}
				verifyOpts := x509.VerifyOptions{
					DNSName:       opts.SNI,
					Roots:         pool,
					Intermediates: intermediates,
					CurrentTime:   time.Now(),
				}
				if _, err := certs[0].Verify(verifyOpts); err != nil {
					// If pin matched with no custom test RootCAs override, allow pinned key
					if meta.pinned && opts.RootCAs == nil {
						return nil
					}
					return fmt.Errorf("%w: %v", ErrMitmDetected, err)
				}
			}
			return nil
		},
	}

	helloID := utls.HelloChrome_Auto
	helloLabel := "HelloChrome_Auto"
	if profileName == "firefox" {
		helloID = utls.HelloFirefox_Auto
		helloLabel = "HelloFirefox_Auto"
	}

	var uconn *utls.UConn
	if opts.ForceHTTP1ALPN {
		spec, serr := utls.UTLSIdToSpec(helloID)
		if serr == nil {
			patchSpecForHTTP1(&spec)
			uconn = utls.UClient(splitConn, utlsCfg, utls.HelloCustom)
			if aerr := uconn.ApplyPreset(&spec); aerr != nil {
				uconn = utls.UClient(splitConn, utlsCfg, helloID)
			}
		} else {
			uconn = utls.UClient(splitConn, utlsCfg, helloID)
		}
	} else {
		uconn = utls.UClient(splitConn, utlsCfg, helloID)
	}

	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	return &UTLSDialResult{
		Conn:       uconn,
		Profile:    helloLabel,
		SPKISHA256: meta.spkiHex,
		CertSHA256: meta.certHex,
		Issuer:     meta.issuer,
		Subject:    meta.subject,
		PinMatched: meta.pinned,
	}, nil
}

// DialUTLSOverConn runs a Chrome uTLS handshake over an already-connected net.Conn (e.g. a MuxStream).
func DialUTLSOverConn(ctx context.Context, rawConn net.Conn, serverName string) (net.Conn, error) {
	cfg := &utls.Config{
		ServerName: serverName,
	}
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	var uconn *utls.UConn
	if err == nil {
		patchSpecForHTTP1(&spec)
		uconn = utls.UClient(rawConn, cfg, utls.HelloCustom)
		if aerr := uconn.ApplyPreset(&spec); aerr != nil {
			uconn = utls.UClient(rawConn, cfg, utls.HelloChrome_Auto)
		}
	} else {
		uconn = utls.UClient(rawConn, cfg, utls.HelloChrome_Auto)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uconn, nil
}

func patchSpecForHTTP1(spec *utls.ClientHelloSpec) {
	filtered := make([]utls.TLSExtension, 0, len(spec.Extensions))
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.ALPNExtension:
			e.AlpnProtocols = []string{"http/1.1"}
			filtered = append(filtered, e)
		case *utls.ApplicationSettingsExtensionNew:
			// ALPS extension for h2 would otherwise fail if h2 is not in ALPN
			continue
		default:
			filtered = append(filtered, ext)
		}
	}
	spec.Extensions = filtered
}

// HashSPKISHA256 computes lowercase SHA-256 hex over cert.RawSubjectPublicKeyInfo.
func HashSPKISHA256(cert *x509.Certificate) string {
	if cert == nil || len(cert.RawSubjectPublicKeyInfo) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// HashCertSHA256 computes lowercase SHA-256 hex over the full DER X.509 certificate.
func HashCertSHA256(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func normalizeHexPin(pin string) string {
	clean := strings.TrimSpace(strings.ToLower(pin))
	clean = strings.TrimPrefix(clean, "sha256:")
	clean = strings.ReplaceAll(clean, ":", "")
	clean = strings.ReplaceAll(clean, "-", "")
	if len(clean) == 64 {
		if _, err := hex.DecodeString(clean); err == nil {
			return clean
		}
	}
	return ""
}
