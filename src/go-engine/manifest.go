package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed embedded_nodes_v3.enc
var embeddedManifestPTM3 string

var (
	ErrManifestInvalidFormat = errors.New("invalid PTM3 envelope format")
	ErrManifestBadSignature  = errors.New("PTM3 ECDSA signature verification failed")
	ErrManifestRollback      = errors.New("manifest version rejected by anti-rollback check")
	ErrManifestExpired       = errors.New("manifest issued_utc outside valid window")
)

// PlatformAsset describes a platform binary URL and SHA-256 digest inside manifest.
type PlatformAsset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// ManifestDocument mirrors PixelStore signed manifest JSON v2/v3 payload.
type ManifestDocument struct {
	Ver            int64                    `json:"ver"`
	Version        int64                    `json:"version,omitempty"`
	Secret         string                   `json:"secret,omitempty"`
	IssuedUTC      string                   `json:"issued_utc"`
	LatestVersion  string                   `json:"latest_version,omitempty"`
	UpdateURL      string                   `json:"update_url,omitempty"`
	UpdateSHA256   string                   `json:"update_sha256,omitempty"`
	DonateURL      string                   `json:"donate_url,omitempty"`
	SPKISHA256     []string                 `json:"spki_sha256,omitempty"`
	CertPins       []string                 `json:"cert_pins,omitempty"`
	EdgeSNIs       []string                 `json:"edge_snis,omitempty"`
	DecoySNIs      []string                 `json:"decoy_snis,omitempty"`
	PlatformAssets map[string]PlatformAsset `json:"platform_assets,omitempty"`
	Nodes          []NodeConfig             `json:"nodes"`
}

// UnmarshalJSON accepts both "ver" and legacy/shared "version" (taking max/non-zero)
// and inherits top-level "secret" into any node whose per-node "secret" is empty.
func (d *ManifestDocument) UnmarshalJSON(data []byte) error {
	type manifestDocumentAlias ManifestDocument
	var raw manifestDocumentAlias
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*d = ManifestDocument(raw)
	d.normalize()
	return nil
}

func (d *ManifestDocument) normalize() {
	if d == nil {
		return
	}
	if d.Version > 0 && (d.Ver <= 0 || d.Version > d.Ver) {
		d.Ver = d.Version
	}
	if d.Ver > 0 && d.Version <= 0 {
		d.Version = d.Ver
	}
	topSecret := strings.TrimSpace(d.Secret)
	if topSecret != "" {
		d.Secret = topSecret
		for i := range d.Nodes {
			if strings.TrimSpace(d.Nodes[i].Secret) == "" {
				d.Nodes[i].Secret = topSecret
			}
		}
	}
}

// ManifestVerifierOptions allows sandbox unit tests to override keys or version persistence paths.
type ManifestVerifierOptions struct {
	PubKeyB64       string
	AesKeyHex       string
	VersionFilePath string
	CacheFilePath   string
	EdgeURLs        []string
	ClockNow        func() time.Time
	AllowSameVer    bool
	AllowExpired    bool
}

// DecodeCNGECDSA256PublicKey decodes Windows CNG ECS1 72-byte P-256 public key blob
// and checks elliptic.P256().IsOnCurve(X, Y).
func DecodeCNGECDSA256PublicKey(blob []byte) (*ecdsa.PublicKey, error) {
	if len(blob) != 72 {
		return nil, fmt.Errorf("invalid CNG ECS1 blob length %d (want 72)", len(blob))
	}
	if string(blob[0:4]) != "ECS1" {
		return nil, fmt.Errorf("unexpected CNG magic %q (want ECS1)", string(blob[0:4]))
	}
	cbKey := binary.LittleEndian.Uint32(blob[4:8])
	if cbKey != 32 {
		return nil, fmt.Errorf("unexpected P-256 key size %d (want 32)", cbKey)
	}
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(blob[8:40])
	y := new(big.Int).SetBytes(blob[40:72])
	p := curve.Params().P
	if x.Sign() < 0 || x.Cmp(p) >= 0 || y.Sign() < 0 || y.Cmp(p) >= 0 {
		return nil, errors.New("ECDSA P-256 coordinates out of field bounds")
	}
	if x.Sign() == 0 && y.Sign() == 0 {
		return nil, errors.New("ECDSA P-256 point at infinity")
	}
	// Explicit curve membership check matching requirement.
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("ECDSA P-256 public key not on curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// VerifyAndDecryptPTM3 verifies a signed PTM3.<b64url(iv||cipher)>.<b64url(sig64)> envelope,
// validates anti-rollback version file, checks issued_utc, and parses ManifestDocument.
func VerifyAndDecryptPTM3(envelope string, opts ManifestVerifierOptions) (*ManifestDocument, error) {
	trimmed := strings.TrimSpace(envelope)
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 || parts[0] != "PTM3" {
		return nil, ErrManifestInvalidFormat
	}

	ivAndCipher, err := decodeBase64Flexible(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload decode: %v", ErrManifestInvalidFormat, err)
	}
	sigRaw, err := decodeBase64Flexible(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: sig decode: %v", ErrManifestInvalidFormat, err)
	}
	if len(ivAndCipher) < 32 || (len(ivAndCipher)-16)%aes.BlockSize != 0 || len(sigRaw) != 64 {
		return nil, ErrManifestInvalidFormat
	}

	pubB64 := opts.PubKeyB64
	if pubB64 == "" {
		pubB64 = DefaultManifestPubKeyB64
	}
	pubBlob, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return nil, fmt.Errorf("decode manifest pubkey: %w", err)
	}
	pubKey, err := DecodeCNGECDSA256PublicKey(pubBlob)
	if err != nil {
		return nil, err
	}

	// ECDSA-SHA256 over ivAndCipher using raw IEEE P1363 R(32B)||S(32B) signature.
	digest := sha256.Sum256(ivAndCipher)
	r := new(big.Int).SetBytes(sigRaw[:32])
	s := new(big.Int).SetBytes(sigRaw[32:64])
	if r.Sign() <= 0 || s.Sign() <= 0 || !ecdsa.Verify(pubKey, digest[:], r, s) {
		return nil, ErrManifestBadSignature
	}

	aesHex := opts.AesKeyHex
	if aesHex == "" {
		aesHex = DefaultManifestAesHex
	}
	aesKey, err := hex.DecodeString(strings.TrimSpace(aesHex))
	if err != nil || len(aesKey) != 32 {
		return nil, errors.New("invalid AES-256 manifest key")
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	iv := ivAndCipher[:aes.BlockSize]
	ct := make([]byte, len(ivAndCipher)-aes.BlockSize)
	copy(ct, ivAndCipher[aes.BlockSize:])
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(ct, ct)

	plainJSON, err := pkcs7Unpad(ct, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("manifest decrypt unpad: %w", err)
	}

	var doc ManifestDocument
	if err := json.Unmarshal(plainJSON, &doc); err != nil {
		return nil, fmt.Errorf("manifest json unmarshal: %w", err)
	}
	doc.normalize()
	if doc.Ver <= 0 || len(doc.Nodes) == 0 {
		return nil, errors.New("manifest missing ver or nodes")
	}

	nowFn := opts.ClockNow
	if nowFn == nil {
		nowFn = time.Now
	}
	nowUTC := nowFn().UTC()
	if doc.IssuedUTC != "" && !opts.AllowExpired {
		issued, perr := parseFlexibleUTCTime(doc.IssuedUTC)
		if perr != nil {
			return nil, fmt.Errorf("%w: %v", ErrManifestExpired, perr)
		}
		if issued.Before(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) {
			return nil, fmt.Errorf("%w: pre-2025 timestamp", ErrManifestExpired)
		}
		if issued.Before(nowUTC.Add(-180*24*time.Hour)) || issued.After(nowUTC.Add(48*time.Hour)) {
			return nil, fmt.Errorf("%w: %s outside window", ErrManifestExpired, issued.Format(time.RFC3339))
		}
	}

	// Anti-rollback check + persistence.
	if opts.VersionFilePath != "" {
		prevVer := ReadPersistedManifestVersion(opts.VersionFilePath)
		if prevVer > 0 && (doc.Ver < prevVer || (!opts.AllowSameVer && doc.Ver == prevVer)) {
			return nil, fmt.Errorf("%w: got ver=%d, persisted=%d", ErrManifestRollback, doc.Ver, prevVer)
		}
		if err := WritePersistedManifestVersion(opts.VersionFilePath, doc.Ver); err != nil {
			return nil, fmt.Errorf("persist manifest version: %w", err)
		}
	}

	// Fill defaults on parsed nodes (pwp4_path when mux==true, EnableDpiSplit, inherited secret).
	for i := range doc.Nodes {
		if doc.Nodes[i].Port <= 0 {
			doc.Nodes[i].Port = 443
		}
		if doc.Nodes[i].Path == "" {
			doc.Nodes[i].Path = DefaultPWP3Path
		}
		if doc.Nodes[i].Mux && doc.Nodes[i].PWP4Path == "" {
			doc.Nodes[i].PWP4Path = DefaultPWP4Path
		}
		if strings.TrimSpace(doc.Nodes[i].Secret) == "" && doc.Secret != "" {
			doc.Nodes[i].Secret = doc.Secret
		}
		doc.Nodes[i].EnableDpiSplit = doc.Nodes[i].Frag
	}

	return &doc, nil
}

// ReadPersistedManifestVersion returns 0 if version file does not exist or is invalid.
func ReadPersistedManifestVersion(path string) int64 {
	if path == "" {
		return 0
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

// WritePersistedManifestVersion atomically updates the anti-rollback version file.
func WritePersistedManifestVersion(path string, ver int64) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(ver, 10)), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ApplyManifestToConfig merges verified nodes, SPKI pins, SNIs, and active node secret into cfg.
func ApplyManifestToConfig(cfg *EngineConfig, doc *ManifestDocument) {
	if cfg == nil || doc == nil {
		return
	}

	pinSet := make(map[string]struct{})
	addPin := func(p string) {
		if norm := normalizeHexPin(p); norm != "" {
			pinSet[norm] = struct{}{}
		}
	}
	addPin(DefaultPinnedSPKISHA256)
	for _, p := range cfg.PinnedSPKI {
		addPin(p)
	}
	for _, p := range doc.SPKISHA256 {
		addPin(p)
	}
	for _, p := range doc.CertPins {
		addPin(p)
	}
	cfg.PinnedSPKI = sortedSetKeys(pinSet)

	if len(doc.EdgeSNIs) > 0 {
		cfg.EdgeSNIs = append([]string(nil), doc.EdgeSNIs...)
	}
	if len(doc.DecoySNIs) > 0 {
		cfg.DecoySNIs = append([]string(nil), doc.DecoySNIs...)
	}

	doc.normalize()

	nodes := make([]NodeConfig, len(doc.Nodes))
	copy(nodes, doc.Nodes)
	for i := range nodes {
		if nodes[i].UUID == "" {
			nodes[i].UUID = cfg.ClientUUID
		}
		if strings.TrimSpace(nodes[i].Secret) == "" && doc.Secret != "" {
			nodes[i].Secret = doc.Secret
		}
	}
	cfg.Nodes = nodes

	if len(nodes) > 0 {
		chosen := nodes[0]
		if cfg.PreferredRegion != "" && !strings.EqualFold(cfg.PreferredRegion, "auto") {
			for _, n := range nodes {
				if strings.EqualFold(n.Region, cfg.PreferredRegion) || strings.EqualFold(n.Name, cfg.PreferredRegion) {
					chosen = n
					break
				}
			}
		} else if cfg.ActiveNode.Host != "" {
			for _, n := range nodes {
				if n.Host == cfg.ActiveNode.Host && n.Port == cfg.ActiveNode.Port {
					chosen = n
					break
				}
			}
		}
		if chosen.UUID == "" {
			chosen.UUID = cfg.ClientUUID
		}
		cfg.ActiveNode = chosen
		cfg.RebuildEffectiveRules()
	}
}

func manifestHasUsableSecret(doc *ManifestDocument) bool {
	if doc == nil {
		return false
	}
	if strings.TrimSpace(doc.Secret) != "" {
		return true
	}
	for _, n := range doc.Nodes {
		if strings.TrimSpace(n.Secret) != "" {
			return true
		}
	}
	return false
}

func defaultManifestCachePaths() []string {
	seen := make(map[string]struct{})
	var paths []string
	add := func(p string) {
		if p == "" {
			return
		}
		clean := filepath.Clean(p)
		if _, ok := seen[clean]; !ok {
			seen[clean] = struct{}{}
			paths = append(paths, clean)
		}
	}
	add(filepath.Join(DefaultStateDir(), "nodes_v3.cache.enc"))
	if ucd, err := os.UserCacheDir(); err == nil && ucd != "" {
		add(filepath.Join(ucd, "PixelTunnel", "nodes_v3.cache.enc"))
	}
	return paths
}

func defaultManifestCachePath() string {
	return filepath.Join(DefaultStateDir(), "nodes_v3.cache.enc")
}

// WriteCachedManifestEnvelope atomically persists a verified PTM3 envelope to disk.
func WriteCachedManifestEnvelope(path, envelope string) error {
	trimmed := strings.TrimSpace(envelope)
	if path == "" || trimmed == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(trimmed), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadCachedOrEmbeddedManifest loads the highest-version verified manifest from local cache
// or the compiled-in signed PTM3 fallback envelope, ensuring at least one usable node secret.
func LoadCachedOrEmbeddedManifest(opts ManifestVerifierOptions) (*ManifestDocument, string, error) {
	var embeddedDoc *ManifestDocument
	var embeddedErr error
	if strings.TrimSpace(embeddedManifestPTM3) != "" {
		embeddedDoc, embeddedErr = VerifyAndDecryptPTM3(embeddedManifestPTM3, ManifestVerifierOptions{
			PubKeyB64:    opts.PubKeyB64,
			AesKeyHex:    opts.AesKeyHex,
			AllowExpired: true,
		})
	}

	var cachePaths []string
	if opts.CacheFilePath != "" {
		cachePaths = []string{opts.CacheFilePath}
	} else {
		cachePaths = defaultManifestCachePaths()
	}

	var bestCached *ManifestDocument
	for _, cp := range cachePaths {
		raw, err := os.ReadFile(cp)
		if err != nil {
			continue
		}
		parsed, verr := VerifyAndDecryptPTM3(string(raw), ManifestVerifierOptions{
			PubKeyB64:    opts.PubKeyB64,
			AesKeyHex:    opts.AesKeyHex,
			AllowSameVer: true,
			AllowExpired: true,
		})
		if verr != nil || !manifestHasUsableSecret(parsed) {
			continue
		}
		if bestCached == nil || parsed.Ver > bestCached.Ver {
			bestCached = parsed
		}
	}

	if bestCached != nil && (embeddedDoc == nil || !manifestHasUsableSecret(embeddedDoc) || bestCached.Ver >= embeddedDoc.Ver) {
		return bestCached, "cache", nil
	}
	if embeddedDoc != nil {
		return embeddedDoc, "embedded", nil
	}
	if embeddedErr != nil {
		return nil, "", embeddedErr
	}
	return nil, "", errors.New("no cached or embedded manifest available")
}

type manifestURLCandidate struct {
	url string
	src string
	sni string
}

func defaultManifestURLs(githubURL string, overrideEdgeURLs []string) []manifestURLCandidate {
	if githubURL == "" {
		githubURL = DefaultGitHubManifestURL
	}
	var urls []manifestURLCandidate
	if len(overrideEdgeURLs) > 0 {
		for _, u := range overrideEdgeURLs {
			u = strings.TrimSpace(u)
			if u != "" {
				urls = append(urls, manifestURLCandidate{url: u, src: "edge"})
			}
		}
	} else {
		urls = append(urls,
			manifestURLCandidate{url: "https://ai.pixelstore.space/manifest/nodes_v3.enc", src: "edge", sni: DefaultSNI},
			manifestURLCandidate{url: "https://ai.pixelstore.space/nodes_v3.enc", src: "edge", sni: DefaultSNI},
			manifestURLCandidate{url: "https://185.103.103.162/manifest/nodes_v3.enc", src: "edge", sni: DefaultSNI},
			manifestURLCandidate{url: "https://185.103.103.162/nodes_v3.enc", src: "edge", sni: DefaultSNI},
		)
	}
	if githubURL != "" && githubURL != "-" {
		urls = append(urls, manifestURLCandidate{url: githubURL, src: "github"})
	}
	return urls
}

// FetchLatestManifest downloads PTM3 envelope via Edge/GitHub HTTPS first, then DoH TXT fallback (_v3.pixelstore.space).
func FetchLatestManifest(ctx context.Context, resolver *DohResolver, opts ManifestVerifierOptions, githubURL string) (doc *ManifestDocument, src string, err error) {
	dialFunc := func(dctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: 1800 * time.Millisecond}
		host, port, serr := net.SplitHostPort(addr)
		if serr != nil {
			return dialer.DialContext(dctx, network, addr)
		}
		if resolver != nil && net.ParseIP(host) == nil {
			if ips, rerr := resolver.LookupHost(dctx, host); rerr == nil && len(ips) > 0 {
				return dialer.DialContext(dctx, network, net.JoinHostPort(ips[0].String(), port))
			}
		}
		return dialer.DialContext(dctx, network, addr)
	}

	defaultClient := &http.Client{
		Timeout: 2500 * time.Millisecond,
		Transport: &http.Transport{
			DialContext: dialFunc,
		},
	}
	edgeIPClient := &http.Client{
		Timeout: 2500 * time.Millisecond,
		Transport: &http.Transport{
			DialContext: dialFunc,
			TLSClientConfig: &tls.Config{
				ServerName: DefaultSNI,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	parseOpts := opts
	parseOpts.VersionFilePath = ""

	commitVerified := func(parsed *ManifestDocument, rawEnv, source string) (*ManifestDocument, string, error) {
		if opts.VersionFilePath != "" {
			prevVer := ReadPersistedManifestVersion(opts.VersionFilePath)
			if prevVer > 0 && (parsed.Ver < prevVer || (!opts.AllowSameVer && parsed.Ver == prevVer)) {
				return nil, "", fmt.Errorf("%w: got ver=%d, persisted=%d", ErrManifestRollback, parsed.Ver, prevVer)
			}
			if werr := WritePersistedManifestVersion(opts.VersionFilePath, parsed.Ver); werr != nil {
				return nil, "", fmt.Errorf("persist manifest version: %w", werr)
			}
		}
		if opts.CacheFilePath != "" {
			_ = WriteCachedManifestEnvelope(opts.CacheFilePath, rawEnv)
		}
		return parsed, source, nil
	}

	var fallbackDoc *ManifestDocument
	var fallbackSrc string
	var fallbackEnv string

	failedDialHosts := make(map[string]bool)
	urls := defaultManifestURLs(githubURL, opts.EdgeURLs)

	for _, item := range urls {
		if ctx.Err() != nil {
			if err == nil {
				err = ctx.Err()
			}
			break
		}
		u, perr := url.Parse(item.url)
		if perr != nil {
			continue
		}
		hostKey := strings.ToLower(u.Host)
		if failedDialHosts[hostKey] {
			continue
		}

		reqCtx, reqCancel := context.WithTimeout(ctx, 2200*time.Millisecond)
		req, rerr := http.NewRequestWithContext(reqCtx, http.MethodGet, item.url, nil)
		if rerr != nil {
			reqCancel()
			continue
		}
		if item.sni != "" {
			req.Host = item.sni
		}

		c := defaultClient
		if item.sni != "" && net.ParseIP(u.Hostname()) != nil {
			c = edgeIPClient
		}

		resp, derr := c.Do(req)
		if derr != nil {
			reqCancel()
			failedDialHosts[hostKey] = true
			err = derr
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		_ = resp.Body.Close()
		reqCancel()
		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("HTTP %d from %s", resp.StatusCode, item.src)
			continue
		}
		rawBody := string(body)
		parsed, verr := VerifyAndDecryptPTM3(rawBody, parseOpts)
		if verr == nil {
			if manifestHasUsableSecret(parsed) {
				if committed, csrc, cerr := commitVerified(parsed, rawBody, item.src); cerr == nil {
					return committed, csrc, nil
				} else {
					err = cerr
				}
			} else if fallbackDoc == nil {
				fallbackDoc, fallbackSrc, fallbackEnv = parsed, item.src, rawBody
			}
			continue
		}
		err = verr
	}

	if resolver != nil && ctx.Err() == nil {
		txts, terr := resolver.LookupTXT(ctx, DefaultDohTXTDomain)
		if terr == nil {
			var combined strings.Builder
			for _, t := range txts {
				t = strings.TrimSpace(t)
				if strings.HasPrefix(t, "PTM3.") {
					if parsed, verr := VerifyAndDecryptPTM3(t, parseOpts); verr == nil {
						if manifestHasUsableSecret(parsed) {
							if committed, csrc, cerr := commitVerified(parsed, t, "doh_txt"); cerr == nil {
								return committed, csrc, nil
							} else {
								err = cerr
							}
						} else if fallbackDoc == nil {
							fallbackDoc, fallbackSrc, fallbackEnv = parsed, "doh_txt", t
						}
					} else {
						err = verr
					}
				} else {
					combined.WriteString(t)
				}
			}
			if s := combined.String(); strings.HasPrefix(s, "PTM3.") {
				if parsed, verr := VerifyAndDecryptPTM3(s, parseOpts); verr == nil {
					if manifestHasUsableSecret(parsed) {
						if committed, csrc, cerr := commitVerified(parsed, s, "doh_txt"); cerr == nil {
							return committed, csrc, nil
						} else {
							err = cerr
						}
					} else if fallbackDoc == nil {
						fallbackDoc, fallbackSrc, fallbackEnv = parsed, "doh_txt", s
					}
				} else {
					err = verr
				}
			}
		} else if err == nil {
			err = terr
		}
	}

	if fallbackDoc != nil {
		if committed, csrc, cerr := commitVerified(fallbackDoc, fallbackEnv, fallbackSrc); cerr == nil {
			return committed, csrc, nil
		} else {
			err = cerr
		}
	}

	return nil, "", err
}

func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.ContainsAny(s, "-_") {
		if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
			return b, nil
		}
		return base64.URLEncoding.DecodeString(s)
	}
	if b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid ciphertext alignment")
	}
	pad := int(data[len(data)-1])
	if pad <= 0 || pad > blockSize || pad > len(data) {
		return nil, errors.New("invalid pkcs7 padding byte")
	}
	var bad byte
	for i := len(data) - pad; i < len(data); i++ {
		bad |= data[i] ^ byte(pad)
	}
	if bad != 0 {
		return nil, errors.New("corrupt pkcs7 padding")
	}
	out := make([]byte, len(data)-pad)
	copy(out, data[:len(data)-pad])
	return out, nil
}

func parseFlexibleUTCTime(raw string) (time.Time, error) {
	s := strings.TrimSpace(raw)
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05Z",
		"2006-01-02",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), nil
		}
	}
	if !strings.HasSuffix(bytes.NewBufferString(s).String(), "Z") {
		if t, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable issued_utc %q", raw)
}
