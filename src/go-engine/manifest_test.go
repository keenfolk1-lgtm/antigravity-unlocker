package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func buildSignedTestPTM3(t *testing.T, priv *ecdsa.PrivateKey, doc ManifestDocument) (envelope, pubB64, aesHex string) {
	t.Helper()
	aesKey := make([]byte, 32)
	_, _ = rand.Read(aesKey)
	aesHex = hex.EncodeToString(aesKey)

	rawJSON, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}
	padLen := aes.BlockSize - (len(rawJSON) % aes.BlockSize)
	padded := append(rawJSON, bytes.Repeat([]byte{byte(padLen)}, padLen)...)

	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv)
	block, _ := aes.NewCipher(aesKey)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	ivAndCipher := append(iv, ct...)
	digest := sha256.Sum256(ivAndCipher)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	sig64 := make([]byte, 64)
	r.FillBytes(sig64[0:32])
	s.FillBytes(sig64[32:64])

	pubBlob := make([]byte, 72)
	copy(pubBlob[0:4], "ECS1")
	binary.LittleEndian.PutUint32(pubBlob[4:8], 32)
	priv.PublicKey.X.FillBytes(pubBlob[8:40])
	priv.PublicKey.Y.FillBytes(pubBlob[40:72])

	envelope = "PTM3." + base64.RawURLEncoding.EncodeToString(ivAndCipher) + "." + base64.RawURLEncoding.EncodeToString(sig64)
	pubB64 = base64.StdEncoding.EncodeToString(pubBlob)
	return envelope, pubB64, aesHex
}

func TestPTM3VerifyAntiRollbackAndAssets(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	verPath := filepath.Join(t.TempDir(), "manifest_ver.dat")

	doc10 := ManifestDocument{
		Ver:       2026111410,
		IssuedUTC: time.Now().UTC().Format(time.RFC3339),
		SPKISHA256: []string{
			DefaultPinnedSPKISHA256,
		},
		PlatformAssets: map[string]PlatformAsset{
			"darwin-arm64": {URL: "https://example.com/pixeltunnel-macos-arm64", SHA256: strings.Repeat("a", 64)},
		},
		Nodes: []NodeConfig{
			{
				Name:     "NL-AI-1",
				Region:   "EU",
				Host:     "201.34.152.97",
				Port:     443,
				SNI:      "ai.pixelstore.space",
				Secret:   "test-secret-key",
				TLS:      true,
				Mux:      true,
				Frag:     true,
				PWP4Path: "/api/v4/telemetry/events",
				Roles:    []string{"ai", "media"},
			},
		},
	}

	env10, pubB64, aesHex := buildSignedTestPTM3(t, priv, doc10)
	opts := ManifestVerifierOptions{
		PubKeyB64:       pubB64,
		AesKeyHex:       aesHex,
		VersionFilePath: verPath,
	}

	parsed, err := VerifyAndDecryptPTM3(env10, opts)
	if err != nil {
		t.Fatalf("VerifyAndDecryptPTM3 valid failed: %v", err)
	}
	if parsed.Ver != doc10.Ver || len(parsed.Nodes) != 1 || parsed.Nodes[0].EffectivePWP4Path() != "/api/v4/telemetry/events" {
		t.Fatalf("unexpected parsed manifest: %+v", parsed)
	}
	if !parsed.Nodes[0].HasRole("ai") || !parsed.Nodes[0].HasRole("media") {
		t.Fatalf("expected ai/media roles on node: %+v", parsed.Nodes[0].Roles)
	}
	if parsed.PlatformAssets["darwin-arm64"].URL == "" {
		t.Fatalf("missing platform_assets")
	}

	// Anti-rollback: older version must fail
	doc09 := doc10
	doc09.Ver = 2026111409
	env09, pub09, aes09 := buildSignedTestPTM3(t, priv, doc09)
	if _, err := VerifyAndDecryptPTM3(env09, ManifestVerifierOptions{PubKeyB64: pub09, AesKeyHex: aes09, VersionFilePath: verPath}); !errors.Is(err, ErrManifestRollback) {
		t.Fatalf("expected ErrManifestRollback, got %v", err)
	}

	// Signature tampering must fail
	parts := strings.Split(env10, ".")
	sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sigBytes[0] ^= 0xFF
	badSigEnv := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sigBytes)
	if _, err := VerifyAndDecryptPTM3(badSigEnv, ManifestVerifierOptions{PubKeyB64: pubB64, AesKeyHex: aesHex}); !errors.Is(err, ErrManifestBadSignature) {
		t.Fatalf("expected ErrManifestBadSignature, got %v", err)
	}

	// Off-curve CNG ECS1 point check
	pubRaw, _ := base64.StdEncoding.DecodeString(pubB64)
	pubRaw[8] ^= 0x01
	if _, err := DecodeCNGECDSA256PublicKey(pubRaw); err == nil {
		t.Fatalf("expected off-curve CNG public key to fail IsOnCurve")
	}
}

func TestDoHTXTFallbackManifestFetch(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	doc := ManifestDocument{
		Ver:       2026111420,
		IssuedUTC: time.Now().UTC().Format(time.RFC3339),
		Nodes: []NodeConfig{
			{Name: "TXT-Node", Host: "201.34.152.97", Port: 443, SNI: "ai.pixelstore.space", Secret: "s", TLS: true, Mux: true},
		},
	}
	env, pubB64, aesHex := buildSignedTestPTM3(t, priv, doc)

	dohSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		qWire := make([]byte, 64)
		n, _ := r.Body.Read(qWire)
		if n < 12 {
			http.Error(w, "bad query", 400)
			return
		}
		resp := buildFakeTXTDNSResponse(qWire[:n], env)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	}))
	defer dohSrv.Close()

	resolver := NewDohResolver([]DohEndpoint{{URL: dohSrv.URL}}, &tls.Config{InsecureSkipVerify: true})
	fetched, src, err := FetchLatestManifest(context.Background(), resolver, ManifestVerifierOptions{
		PubKeyB64: pubB64,
		AesKeyHex: aesHex,
	}, "http://127.0.0.1:1/unreachable")
	if err != nil {
		t.Fatalf("FetchLatestManifest DoH TXT fallback failed: %v", err)
	}
	if src != "doh_txt" || fetched.Ver != doc.Ver {
		t.Fatalf("expected doh_txt ver %d, got src=%s ver=%d", doc.Ver, src, fetched.Ver)
	}
}

func buildFakeTXTDNSResponse(query []byte, txtVal string) []byte {
	var out bytes.Buffer
	out.Write(query[0:2])                     // Transaction ID
	out.Write([]byte{0x81, 0x80})             // Standard response, no error
	out.Write(query[4:6])                     // QDCOUNT
	out.Write([]byte{0x00, 0x01})             // ANCOUNT=1
	out.Write([]byte{0x00, 0x00, 0x00, 0x00}) // NS, AR
	out.Write(query[12:])                     // Echo Question section

	// Answer pointer to name @12 (0xC0 0x0C), TYPE TXT (16), CLASS IN (1), TTL 60
	out.Write([]byte{0xC0, 0x0C, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C})
	var rdata bytes.Buffer
	for pos := 0; pos < len(txtVal); {
		step := len(txtVal) - pos
		if step > 250 {
			step = 250
		}
		rdata.WriteByte(byte(step))
		rdata.WriteString(txtVal[pos : pos+step])
		pos += step
	}
	var rdLen [2]byte
	binary.BigEndian.PutUint16(rdLen[:], uint16(rdata.Len()))
	out.Write(rdLen[:])
	out.Write(rdata.Bytes())
	return out.Bytes()
}

func encryptAndSignRawJSONPTM3(t *testing.T, priv *ecdsa.PrivateKey, rawJSON []byte) (envelope, pubB64, aesHex string) {
	t.Helper()
	aesKey := make([]byte, 32)
	_, _ = rand.Read(aesKey)
	aesHex = hex.EncodeToString(aesKey)

	padLen := aes.BlockSize - (len(rawJSON) % aes.BlockSize)
	padded := append(append([]byte(nil), rawJSON...), bytes.Repeat([]byte{byte(padLen)}, padLen)...)

	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv)
	block, _ := aes.NewCipher(aesKey)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	ivAndCipher := append(iv, ct...)
	digest := sha256.Sum256(ivAndCipher)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	sig64 := make([]byte, 64)
	r.FillBytes(sig64[0:32])
	s.FillBytes(sig64[32:64])

	pubBlob := make([]byte, 72)
	copy(pubBlob[0:4], "ECS1")
	binary.LittleEndian.PutUint32(pubBlob[4:8], 32)
	priv.PublicKey.X.FillBytes(pubBlob[8:40])
	priv.PublicKey.Y.FillBytes(pubBlob[40:72])

	envelope = "PTM3." + base64.RawURLEncoding.EncodeToString(ivAndCipher) + "." + base64.RawURLEncoding.EncodeToString(sig64)
	pubB64 = base64.StdEncoding.EncodeToString(pubBlob)
	return envelope, pubB64, aesHex
}

func TestManifestDualVersionAndSecretInheritance(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	nowStr := time.Now().UTC().Format(time.RFC3339)

	// 1. Legacy/shared "version" only + top-level "secret" inheritance + per-node override.
	legacyJSON := []byte(`{
		"version": 179467000,
		"issued_utc": "` + nowStr + `",
		"secret": "top-cluster-secret",
		"nodes": [
			{"name": "Inherited-Node", "region": "se", "host": "185.103.103.162", "port": 443, "sni": "ai.pixelstore.space", "tls": true, "mux": true},
			{"name": "Override-Node", "region": "nl", "host": "ws.pixelstore.space", "port": 443, "sni": "ws.pixelstore.space", "secret": "node-specific-secret", "tls": true, "mux": true}
		]
	}`)
	envLegacy, pubB64, aesHex := encryptAndSignRawJSONPTM3(t, priv, legacyJSON)
	parsed, err := VerifyAndDecryptPTM3(envLegacy, ManifestVerifierOptions{
		PubKeyB64: pubB64,
		AesKeyHex: aesHex,
	})
	if err != nil {
		t.Fatalf("VerifyAndDecryptPTM3 legacy version+secret failed: %v", err)
	}
	if parsed.Ver != 179467000 || parsed.Version != 179467000 {
		t.Fatalf("expected Ver=179467000, got Ver=%d Version=%d", parsed.Ver, parsed.Version)
	}
	if parsed.Nodes[0].Secret != "top-cluster-secret" {
		t.Fatalf("expected node[0] to inherit top-level secret, got %q", parsed.Nodes[0].Secret)
	}
	if parsed.Nodes[1].Secret != "node-specific-secret" {
		t.Fatalf("expected node[1] to preserve explicit per-node secret, got %q", parsed.Nodes[1].Secret)
	}

	// 2. Dual "ver" and "version" takes max/non-zero in either direction.
	for _, tc := range []struct {
		name string
		raw  string
		want int64
	}{
		{name: "version_gt_ver", raw: `{"ver": 100, "version": 250, "issued_utc": "` + nowStr + `", "secret": "s", "nodes": [{"host":"185.103.103.162"}]}`, want: 250},
		{name: "ver_gt_version", raw: `{"ver": 350, "version": 250, "issued_utc": "` + nowStr + `", "secret": "s", "nodes": [{"host":"185.103.103.162"}]}`, want: 350},
		{name: "ver_only", raw: `{"ver": 420, "issued_utc": "` + nowStr + `", "secret": "s", "nodes": [{"host":"185.103.103.162"}]}`, want: 420},
	} {
		env, pB64, aHex := encryptAndSignRawJSONPTM3(t, priv, []byte(tc.raw))
		doc, verr := VerifyAndDecryptPTM3(env, ManifestVerifierOptions{PubKeyB64: pB64, AesKeyHex: aHex})
		if verr != nil {
			t.Fatalf("%s: VerifyAndDecryptPTM3 failed: %v", tc.name, verr)
		}
		if doc.Ver != tc.want {
			t.Fatalf("%s: expected Ver=%d, got %d", tc.name, tc.want, doc.Ver)
		}
	}

	// 3. Embedded production nodes_v3.enc verifies with DefaultManifestPubKeyB64/DefaultManifestAesHex.
	embDoc, embSrc, embErr := LoadCachedOrEmbeddedManifest(ManifestVerifierOptions{
		CacheFilePath: filepath.Join(t.TempDir(), "nonexistent.cache.enc"),
	})
	if embErr != nil {
		t.Fatalf("embedded manifest verify failed: %v", embErr)
	}
	if embSrc != "embedded" || embDoc.Ver <= 0 || len(embDoc.Nodes) == 0 || !manifestHasUsableSecret(embDoc) {
		t.Fatalf("unexpected embedded manifest: src=%s ver=%d nodes=%d", embSrc, embDoc.Ver, len(embDoc.Nodes))
	}
	for i, n := range embDoc.Nodes {
		if n.Secret == "" {
			t.Fatalf("embedded node[%d] (%s) missing inherited secret", i, n.Name)
		}
	}
}

func TestFetchLatestManifestURLOrderFallbackAndCache(t *testing.T) {
	// Verify default URL order prioritizes ai.pixelstore.space and 185.103.103.162 (both paths), never 201.34.152.97 first.
	defURLs := defaultManifestURLs("", nil)
	wantOrder := []string{
		"https://ai.pixelstore.space/manifest/nodes_v3.enc",
		"https://ai.pixelstore.space/nodes_v3.enc",
		"https://185.103.103.162/manifest/nodes_v3.enc",
		"https://185.103.103.162/nodes_v3.enc",
		DefaultGitHubManifestURL,
	}
	if len(defURLs) != len(wantOrder) {
		t.Fatalf("expected %d default manifest URLs, got %d: %+v", len(wantOrder), len(defURLs), defURLs)
	}
	for i, want := range wantOrder {
		if defURLs[i].url != want {
			t.Fatalf("url[%d]: expected %s, got %s", i, want, defURLs[i].url)
		}
		if strings.Contains(defURLs[i].url, "201.34.152.97") {
			t.Fatalf("default manifest URLs must not include blocked 201.34.152.97: %s", defURLs[i].url)
		}
	}

	// Verify FetchLatestManifest skips unreachable & secret-less responses and succeeds on working fallback URL.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nowStr := time.Now().UTC().Format(time.RFC3339)
	secretlessEnv, pubB64, aesHex := encryptAndSignRawJSONPTM3(t, priv, []byte(`{"version": 100, "issued_utc": "`+nowStr+`", "nodes": [{"host":"185.103.103.162"}]}`))

	// Re-encrypt valid manifest with the same AES key / priv key for consistent verification options.
	validRaw := []byte(`{"version": 200, "issued_utc": "` + nowStr + `", "secret": "valid-fetched-secret", "nodes": [{"name":"SE","host":"185.103.103.162","port":443,"mux":true}]}`)
	aesKey, _ := hex.DecodeString(aesHex)
	padLen := aes.BlockSize - (len(validRaw) % aes.BlockSize)
	padded := append(append([]byte(nil), validRaw...), bytes.Repeat([]byte{byte(padLen)}, padLen)...)
	iv := make([]byte, aes.BlockSize)
	block, _ := aes.NewCipher(aesKey)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	ivAndCipher := append(iv, ct...)
	digest := sha256.Sum256(ivAndCipher)
	r, s, _ := ecdsa.Sign(rand.Reader, priv, digest[:])
	sig64 := make([]byte, 64)
	r.FillBytes(sig64[0:32])
	s.FillBytes(sig64[32:64])
	validEnv := "PTM3." + base64.RawURLEncoding.EncodeToString(ivAndCipher) + "." + base64.RawURLEncoding.EncodeToString(sig64)

	secretlessSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(secretlessEnv))
	}))
	defer secretlessSrv.Close()

	goodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(validEnv))
	}))
	defer goodSrv.Close()

	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "nodes_v3.cache.enc")
	verPath := filepath.Join(tmpDir, "manifest_ver.dat")

	doc, src, err := FetchLatestManifest(context.Background(), nil, ManifestVerifierOptions{
		PubKeyB64:       pubB64,
		AesKeyHex:       aesHex,
		VersionFilePath: verPath,
		CacheFilePath:   cachePath,
		EdgeURLs:        []string{"http://127.0.0.1:1/unreachable", secretlessSrv.URL + "/nodes_v3.enc", goodSrv.URL + "/manifest/nodes_v3.enc"},
	}, "-")
	if err != nil {
		t.Fatalf("FetchLatestManifest failed: %v", err)
	}
	if src != "edge" || doc.Ver != 200 || doc.Nodes[0].Secret != "valid-fetched-secret" {
		t.Fatalf("unexpected fetched doc: src=%s doc=%+v", src, doc)
	}

	// Verify cached file loads via LoadCachedOrEmbeddedManifest with the same pub/aes keys.
	cachedDoc, cachedSrc, cerr := LoadCachedOrEmbeddedManifest(ManifestVerifierOptions{
		PubKeyB64:     pubB64,
		AesKeyHex:     aesHex,
		CacheFilePath: cachePath,
	})
	if cerr != nil || cachedSrc != "cache" || cachedDoc.Ver != 200 || cachedDoc.Nodes[0].Secret != "valid-fetched-secret" {
		t.Fatalf("LoadCachedOrEmbeddedManifest failed: src=%s err=%v doc=%+v", cachedSrc, cerr, cachedDoc)
	}
}
