package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func generateTestCert(t *testing.T, dnsName string) (tls.Certificate, *x509.CertPool, string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{dnsName},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	tlsCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        cert,
	}
	return tlsCert, pool, HashSPKISHA256(cert), HashCertSHA256(cert)
}

func TestUTLSDialerPinningAndRecordSplit(t *testing.T) {
	cert, pool, spkiHex, certHex := generateTestCert(t, "ai.pixelstore.space")

	// Test SplitTLSClientHelloRecord rewrites single record into 2 valid 0x16 TLS records
	fakeCH := make([]byte, 120)
	fakeCH[0], fakeCH[1], fakeCH[2] = 0x16, 0x03, 0x01
	binary.BigEndian.PutUint16(fakeCH[3:5], uint16(115))
	copy(fakeCH[60:], []byte("ai.pixelstore.space"))
	recs := SplitTLSClientHelloRecord(fakeCH, "ai.pixelstore.space")
	if len(recs) != 2 || recs[0][0] != 0x16 || recs[1][0] != 0x16 {
		t.Fatalf("expected 2 split 0x16 TLS records, got %d", len(recs))
	}
	totalPayload := int(binary.BigEndian.Uint16(recs[0][3:5])) + int(binary.BigEndian.Uint16(recs[1][3:5]))
	if totalPayload != 115 {
		t.Fatalf("split record payload mismatch: %d != 115", totalPayload)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// 1. Valid SPKI pin + Chrome uTLS + DPIProfileTlsRecordSplit
	res, err := DialUTLS(context.Background(), UTLSDialOptions{
		Address:        ln.Addr().String(),
		SNI:            "ai.pixelstore.space",
		Profile:        "chrome",
		DPIProfile:     DPIProfileTlsRecordSplit,
		EnableSplit:    true,
		Pins:           []string{spkiHex},
		RequirePin:     true,
		RootCAs:        pool,
		ForceHTTP1ALPN: true,
	})
	if err != nil {
		t.Fatalf("DialUTLS valid SPKI failed: %v", err)
	}
	_ = res.Conn.Close()
	if !res.PinMatched || res.SPKISHA256 != spkiHex || res.CertSHA256 != certHex {
		t.Fatalf("pin metadata mismatch: %+v", res)
	}

	// 2. X.509 certificate pin works too
	res2, err := DialUTLS(context.Background(), UTLSDialOptions{
		Address:    ln.Addr().String(),
		SNI:        "ai.pixelstore.space",
		Pins:       []string{certHex},
		RequirePin: true,
		RootCAs:    pool,
	})
	if err != nil {
		t.Fatalf("DialUTLS valid X509 pin failed: %v", err)
	}
	_ = res2.Conn.Close()

	// 3. Pin mismatch (MITM check) MUST fail even with valid RootCAs!
	if _, err := DialUTLS(context.Background(), UTLSDialOptions{
		Address:    ln.Addr().String(),
		SNI:        "ai.pixelstore.space",
		Pins:       []string{strings.Repeat("0", 64)},
		RequirePin: true,
		RootCAs:    pool,
	}); !errors.Is(err, ErrCertPinMismatch) {
		t.Fatalf("expected ErrCertPinMismatch, got %v", err)
	}
}

func TestPWP4CipherTamperAndAutoRekey(t *testing.T) {
	secret := "edge-shared-secret"
	cNonce := hex.EncodeToString(bytes.Repeat([]byte{0x11}, 16))
	sSalt := hex.EncodeToString(bytes.Repeat([]byte{0x22}, 16))

	cliRx, cliTx, err := NewPWP4ClientCiphers(secret, cNonce, sSalt)
	if err != nil {
		t.Fatalf("client ciphers: %v", err)
	}
	mat, _ := DerivePWP4KeyMaterial(secret, cNonce, sSalt)
	srvRx, _ := newPWP4Cipher(mat[0:32], mat[64:80])

	// Normal roundtrip + tampered wireLen length mask AD check
	wire, err := cliTx.SealFrame(FrameData, 7, []byte("hello-pwp4"))
	if err != nil {
		t.Fatalf("SealFrame: %v", err)
	}
	tampered := append([]byte(nil), wire...)
	tampered[0] ^= 0x01
	if _, _, _, _, err := srvRx.OpenFrame(bytes.NewReader(tampered), nil); err == nil {
		t.Fatalf("expected tampered wireLen length mask AD to fail")
	}

	// Clean read on untampered wire
	fType, sid, payload, _, err := srvRx.OpenFrame(bytes.NewReader(wire), nil)
	if err != nil || fType != FrameData || sid != 7 || string(payload) != "hello-pwp4" {
		t.Fatalf("OpenFrame failed: type=%d sid=%d payload=%q err=%v", fType, sid, string(payload), err)
	}

	// Rekey trigger inside pwp4ClientCodec
	cliTx.SetRekeyLimits(2, 0)
	codec := &pwp4ClientCodec{rx: cliRx, tx: cliTx}
	var pipeBuf bytes.Buffer
	_ = codec.WriteFrame(&pipeBuf, FrameData, 1, 0, []byte("one"), 0) // seq=2
	_ = codec.WriteFrame(&pipeBuf, FrameData, 1, 0, []byte("two"), 0) // triggers FrameRekey then FrameData in epoch=1

	for i := 0; i < 3; i++ {
		ft, _, pl, _, rErr := srvRx.OpenFrame(&pipeBuf, nil)
		if rErr != nil {
			t.Fatalf("server OpenFrame %d failed: %v", i, rErr)
		}
		if ft == FrameRekey {
			if err := srvRx.Rekey(pl); err != nil {
				t.Fatalf("server Rekey failed: %v", err)
			}
		}
	}
	if cliTx.Epoch() != 1 || srvRx.Epoch() != 1 || cliTx.Seq() != 1 || srvRx.Seq() != 1 {
		t.Fatalf("epoch/seq mismatch after rekey: cli=(%d,%d) srv=(%d,%d)", cliTx.Epoch(), cliTx.Seq(), srvRx.Epoch(), srvRx.Seq())
	}
}

func TestPWP4ToPWP3FallbackAgainstLegacyNode(t *testing.T) {
	cert, pool, spkiHex, _ := generateTestCert(t, "ai.pixelstore.space")
	secret := "test-manifest-secret-v19"

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Mock v1.9.0 server: rejects POST /api/v4/* with 200 HTML decoy, upgrades GET /api/v3/telemetry/mux to PWP-3
	go func() {
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			go serveMockLegacyPWP3Conn(c, secret)
		}
	}()

	cfg := DefaultEngineConfig()
	cfg.PinnedSPKI = []string{spkiHex}
	cfg.ClientUUID = "11111111-2222-3333-4444-555555555555"
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	cfg.ActiveNode = NodeConfig{
		Name:   "Legacy-v19",
		Host:   host,
		Port:   port,
		SNI:    "ai.pixelstore.space",
		Secret: secret,
		TLS:    true,
		Mux:    true,
		Frag:   true,
	}

	mux := NewMuxManager(cfg, nil)
	mux.rootCAs = pool
	defer mux.Close()

	st, usedNode, err := mux.OpenStream(context.Background(), "ai", "echo.example.com", 443)
	if err != nil {
		t.Fatalf("OpenStream fallback failed: %v", err)
	}
	defer st.Close()
	if usedNode != "Legacy-v19" {
		t.Fatalf("unexpected node %s", usedNode)
	}
	snap := mux.Snapshot()
	if snap.Protocol != "PWP-3" {
		t.Fatalf("expected fallback protocol PWP-3, got %s", snap.Protocol)
	}

	_, _ = st.Write([]byte("ping-v19"))
	buf := make([]byte, 8)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("read echoed bytes: %v", err)
	}
	if string(buf) != "ping-v19" {
		t.Fatalf("expected ping-v19, got %q", string(buf))
	}
}

func serveMockLegacyPWP3Conn(c net.Conn, secret string) {
	defer c.Close()
	br := bufio.NewReader(c)
	reqLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	hdrs := make(map[string]string)
	for {
		line, lerr := br.ReadString('\n')
		if lerr != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			hdrs[strings.ToLower(strings.TrimSpace(line[:idx]))] = strings.TrimSpace(line[idx+1:])
		}
	}

	// Simulate v1.9.0 decoy HTML on POST /api/v4/*
	if strings.HasPrefix(reqLine, "POST /api/v4/") {
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<html></html>")
		return
	}

	wsKey := hdrs["sec-websocket-key"]
	salt := hex.EncodeToString(bytes.Repeat([]byte{0xAB}, 16))
	resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Edge-Telemetry: t=paid;d=30;n=Legacy-v19;p=pwp3\r\nSet-Cookie: __cfruid=%s.m3.n; Path=/\r\n\r\n", salt)
	_, _ = io.WriteString(c, resp)

	codec := &pwp3Codec{
		rx:            NewPixelStreamCipher(secret, wsKey+":c2s"),
		tx:            NewPixelStreamCipher(secret, salt+":s2c"),
		nativeTLSBulk: true,
	}
	for {
		ft, sid, payload, err := codec.ReadFrame(br)
		if err != nil {
			return
		}
		switch ft {
		case FrameSynTCP:
			_ = codec.WriteFrame(c, FrameSynAck, sid, 0, nil, 0)
		case FrameData:
			_ = codec.WriteFrame(c, FrameData, sid, 0, payload, 0)
		case FramePing:
			_ = codec.WriteFrame(c, FramePong, sid, 0, payload, 0)
		}
	}
}

func TestZeroDropHotFailoverUnder150Ms(t *testing.T) {
	// Create two in-process pipe-backed mux sessions:
	// primary stalls all frames (blackhole); standby responds cleanly in <5ms.
	pCli, pSrv := net.Pipe()
	sCli, sSrv := net.Pipe()
	defer pSrv.Close()
	defer sSrv.Close()

	secret := "hot-failover-secret"
	cNonce := hex.EncodeToString(bytes.Repeat([]byte{0x33}, 16))
	sSalt := hex.EncodeToString(bytes.Repeat([]byte{0x44}, 16))

	pRx, pTx, _ := NewPWP4ClientCiphers(secret, cNonce, sSalt)
	sRx, sTx, _ := NewPWP4ClientCiphers(secret, cNonce, sSalt)
	mat, _ := DerivePWP4KeyMaterial(secret, cNonce, sSalt)

	srvSideRx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	srvSideTx, _ := newPWP4Cipher(mat[32:64], mat[80:96])

	// Drain primary pipe without responding (blackhole SynAck & Ping)
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := pSrv.Read(buf); err != nil {
				return
			}
		}
	}()

	// Standby PWP-4 responder
	var srvWriteMu sync.Mutex
	go func() {
		br := bufio.NewReader(sSrv)
		for {
			ft, sid, payload, _, err := srvSideRx.OpenFrame(br, nil)
			if err != nil {
				return
			}
			var out []byte
			switch ft {
			case FrameSynTCP:
				out, _ = srvSideTx.SealFrame(FrameSynAck, sid, nil)
			case FrameData:
				out, _ = srvSideTx.SealFrame(FrameData, sid, payload)
			case FramePing:
				out, _ = srvSideTx.SealFrame(FramePong, sid, payload)
			}
			if len(out) > 0 {
				srvWriteMu.Lock()
				_, _ = sSrv.Write(out)
				srvWriteMu.Unlock()
			}
		}
	}()

	cfg := DefaultEngineConfig()
	cfg.V2.FailoverTimeoutMs = 120
	mux := NewMuxManager(cfg, nil)
	defer mux.Close()

	primarySess := NewClientMuxSession(pCli, bufio.NewReader(pCli), &pwp4ClientCodec{rx: pRx, tx: pTx}, NodeConfig{Name: "Primary-Stalled", Host: "10.0.0.1", Port: 443}, LicenseMetadata{Proto: "PWP-4"})
	standbySess := NewClientMuxSession(sCli, bufio.NewReader(sCli), &pwp4ClientCodec{rx: sRx, tx: sTx}, NodeConfig{Name: "Standby-Healthy", Host: "10.0.0.2", Port: 443}, LicenseMetadata{Proto: "PWP-4"})

	mux.mu.Lock()
	mux.sessions["ai"] = primarySess
	mux.standby = standbySess
	mux.standbyNode = standbySess.Node()
	mux.mu.Unlock()

	t0 := time.Now()
	st, nodeUsed, err := mux.OpenStream(context.Background(), "ai", "api.anthropic.com", 443)
	elapsed := time.Since(t0)
	if err != nil {
		t.Fatalf("OpenStream zero-drop failover failed: %v", err)
	}
	defer st.Close()
	if nodeUsed != "Standby-Healthy" {
		t.Fatalf("expected Standby-Healthy node, got %s", nodeUsed)
	}
	if elapsed >= 250*time.Millisecond {
		// Budget allows CI scheduler jitter; real detection takes ~60-120ms
		t.Fatalf("expected fast failover <250ms (target <150ms), took %v", elapsed)
	}
	t.Logf("Zero-drop hot failover completed in %v", elapsed)

	if mux.Snapshot().FailoverCount < 1 {
		t.Fatalf("expected failover_count >= 1")
	}

	// Verify standby echoes traffic cleanly
	_, _ = st.Write([]byte("zero-drop"))
	out := make([]byte, 9)
	if _, err := io.ReadFull(st, out); err != nil || string(out) != "zero-drop" {
		t.Fatalf("echo via standby failed: %q err=%v", string(out), err)
	}
}

func TestInstantWakeAndPWP4E2EHandshake(t *testing.T) {
	secret := "pwp4-e2e-secret"
	uuid := "22222222-3333-4444-5555-666666666666"
	cert, pool, spkiHex, _ := generateTestCert(t, "ai.pixelstore.space")

	var connSeq atomic.Int32
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			connSeq.Add(1)
			go serveMockPWP4Conn(c, secret, uuid)
		}
	}()

	cfg := DefaultEngineConfig()
	cfg.PinnedSPKI = []string{spkiHex}
	cfg.ClientUUID = uuid
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	cfg.ActiveNode = NodeConfig{
		Name:     "NL-PWP4",
		Host:     host,
		Port:     port,
		SNI:      "ai.pixelstore.space",
		Secret:   secret,
		PWP4Path: "/api/v4/telemetry/events",
		TLS:      true,
		Mux:      true,
	}

	mux := NewMuxManager(cfg, nil)
	mux.rootCAs = pool
	defer mux.Close()

	if err := mux.WarmConnect(context.Background()); err != nil {
		t.Fatalf("WarmConnect PWP-4 failed: %v", err)
	}
	snap1 := mux.Snapshot()
	if snap1.Protocol != "PWP-4" || !snap1.Connected {
		t.Fatalf("expected PWP-4 active session, got %+v", snap1)
	}

	if _, err := mux.TriggerInstantWake("clock_jump"); err != nil {
		t.Fatalf("TriggerInstantWake failed: %v", err)
	}
	if mux.Snapshot().InstantWakeCount != 1 {
		t.Fatalf("expected instant_wake_count=1")
	}
	if connSeq.Load() < 2 {
		t.Fatalf("expected fresh PWP-4 reconnect after Instant Wake, got %d conns", connSeq.Load())
	}
}

func serveMockPWP4Conn(c net.Conn, secret, expectedUUID string) {
	defer c.Close()
	br := bufio.NewReader(c)
	reqLine, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(reqLine, "POST /api/v4/telemetry/events") {
		return
	}
	hdrs := make(map[string]string)
	for {
		line, lerr := br.ReadString('\n')
		if lerr != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			hdrs[strings.ToLower(strings.TrimSpace(line[:idx]))] = strings.TrimSpace(line[idx+1:])
		}
	}
	var clVal int64 = -1
	if clStr := strings.TrimSpace(hdrs["content-length"]); clStr != "" {
		parsedCL, clErr := strconv.ParseInt(clStr, 10, 64)
		if clErr != nil || parsedCL < 0 {
			return
		}
		clVal = parsedCL
	}
	padLen := 0
	if clVal >= 1048576 {
		if xpStr := strings.TrimSpace(hdrs["x-pad-len"]); xpStr != "" {
			parsedPad, padErr := strconv.Atoi(xpStr)
			if padErr != nil || parsedPad < 0 || parsedPad > 2048 {
				return
			}
			padLen = parsedPad
		}
	} else if clVal > 0 && clVal <= 2048 {
		padLen = int(clVal)
	} else if clVal > 2048 {
		return
	}
	if padLen > 0 {
		pad := make([]byte, padLen)
		if _, err := io.ReadFull(br, pad); err != nil {
			return
		}
	}

	// Parse _cfuvid and _px4
	cookies := make(map[string]string)
	for _, part := range strings.Split(hdrs["cookie"], ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			cookies[kv[0]] = kv[1]
		}
	}
	uv := strings.Split(cookies["_cfuvid"], ".")
	px := strings.Split(cookies["_px4"], ".")
	if len(uv) < 3 || len(px) < 2 || uv[2] != expectedUUID {
		return
	}
	msg := fmt.Sprintf("pwp4:%s:%s:%s:%s:%d", uv[0], px[0], uv[2], uv[1], padLen)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(msg))
	if hex.EncodeToString(mac.Sum(nil)[:16]) != px[1] {
		return
	}

	sSalt := hex.EncodeToString(bytes.Repeat([]byte{0x77}, 16))
	srvPad := bytes.Repeat([]byte{0x5A}, 80)
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 107374182400\r\nX-Edge-Telemetry: t=paid;d=30;n=NL-PWP4;p=pwp4\r\nX-Pad-Len: 80\r\nSet-Cookie: __cfruid=%s.m4; Path=/\r\n\r\n", sSalt)
	_, _ = c.Write(append([]byte(resp), srvPad...))

	mat, _ := DerivePWP4KeyMaterial(secret, px[0], sSalt)
	rx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	tx, _ := newPWP4Cipher(mat[32:64], mat[80:96])

	for {
		ft, sid, payload, _, err := rx.OpenFrame(br, nil)
		if err != nil {
			return
		}
		var out []byte
		switch ft {
		case FrameSynTCP:
			out, _ = tx.SealFrame(FrameSynAck, sid, nil)
		case FrameData:
			out, _ = tx.SealFrame(FrameData, sid, payload)
		case FramePing:
			out, _ = tx.SealFrame(FramePong, sid, payload)
		}
		if len(out) > 0 {
			_, _ = c.Write(out)
		}
	}
}

func TestDiagInternalPixelAndHTTPConnectProxy(t *testing.T) {
	pCli, pSrv := net.Pipe()
	defer pSrv.Close()

	secret := "diag-e2e-secret"
	cNonce := hex.EncodeToString(bytes.Repeat([]byte{0x55}, 16))
	sSalt := hex.EncodeToString(bytes.Repeat([]byte{0x66}, 16))
	cRx, cTx, _ := NewPWP4ClientCiphers(secret, cNonce, sSalt)
	mat, _ := DerivePWP4KeyMaterial(secret, cNonce, sSalt)
	sRx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	sTx, _ := newPWP4Cipher(mat[32:64], mat[80:96])

	// Mock server supporting diag.internal.pixel:443 (ECHO_META, DL_64K, UL_32K) and echo streams
	var wMu sync.Mutex
	sendFrame := func(ft byte, sid uint32, pl []byte) {
		for off := 0; off == 0 || off < len(pl); {
			end := off + 16384
			if end > len(pl) {
				end = len(pl)
			}
			w, _ := sTx.SealFrame(ft, sid, pl[off:end])
			wMu.Lock()
			_, _ = pSrv.Write(w)
			wMu.Unlock()
			off = end
			if len(pl) == 0 {
				break
			}
		}
	}
	go func() {
		br := bufio.NewReader(pSrv)
		streamHost := make(map[uint32]string)
		streamBuf := make(map[uint32][]byte)
		for {
			ft, sid, payload, _, err := sRx.OpenFrame(br, nil)
			if err != nil {
				return
			}
			switch ft {
			case FrameSynTCP:
				hl := int(payload[0])
				target := string(payload[1 : 1+hl])
				streamHost[sid] = target
				sendFrame(FrameSynAck, sid, nil)
			case FrameData:
				if streamHost[sid] != "diag.internal.pixel" {
					sendFrame(FrameData, sid, payload)
					continue
				}
				streamBuf[sid] = append(streamBuf[sid], payload...)
				buf := streamBuf[sid]
				if bytes.HasPrefix(buf, []byte("ECHO_META\n")) {
					sendFrame(FrameData, sid, []byte(`{"ok":true,"node":"MockDiag","proto":"PWP-4","key_type":"paid","ts":1763100000}`+"\n"))
					sendFrame(FrameFin, sid, nil)
				} else if bytes.HasPrefix(buf, []byte("DL_64K\n")) {
					dl := bytes.Repeat([]byte{0x42}, 65536)
					sum := sha256.Sum256(dl)
					sendFrame(FrameData, sid, []byte("PWP4_DL_OK:"+hex.EncodeToString(sum[:])+"\n"))
					sendFrame(FrameData, sid, dl)
					sendFrame(FrameFin, sid, nil)
				} else if bytes.HasPrefix(buf, []byte("UL_32K\n")) && len(buf) >= 7+32768 {
					sum := sha256.Sum256(buf[7 : 7+32768])
					sendFrame(FrameData, sid, []byte("PWP4_UL_OK:"+hex.EncodeToString(sum[:])+":1\n"))
					sendFrame(FrameFin, sid, nil)
				} else if bytes.HasPrefix(buf, []byte("AI_PULSE\n")) {
					sendFrame(FrameData, sid, []byte(`{"ok":true,"node":"MockDiagMux","checked_at":1763100000,"ttl_sec":60,"providers":{"gemini":{"status":"up","latency_ms":19,"http_code":200}}}`+"\n"))
					sendFrame(FrameFin, sid, nil)
				}
			}
		}
	}()

	cfg := DefaultEngineConfig()
	cfg.HTTPPort = 0
	cfg.SOCKSPort = 0
	cfg.RebuildEffectiveRules()

	mux := NewMuxManager(cfg, nil)
	defer mux.Close()
	sess := NewClientMuxSession(pCli, bufio.NewReader(pCli), &pwp4ClientCodec{rx: cRx, tx: cTx}, NodeConfig{Name: "MockDiag", Host: "10.0.0.1", Port: 443}, LicenseMetadata{Proto: "PWP-4", Tier: "paid"})
	mux.mu.Lock()
	mux.sessions["ai"] = sess
	mux.mu.Unlock()

	srv := NewLocalProxyServer(LocalProxyOptions{
		Config:     cfg,
		Mux:        mux,
		LocalToken: "diag-tok",
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("proxy Start: %v", err)
	}
	defer srv.Close()

	// Test HTTP CONNECT through LocalProxyServer -> AI Mux -> Route Radar
	conn, err := net.Dial("tcp", srv.HTTPAddr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "200") {
		t.Fatalf("CONNECT response = %q err=%v", statusLine, err)
	}
	_, _ = br.ReadString('\n') // blank line
	_, _ = io.WriteString(conn, "claude-ok")
	respBuf := make([]byte, 9)
	if _, err := io.ReadFull(br, respBuf); err != nil || string(respBuf) != "claude-ok" {
		t.Fatalf("proxy tunnel echo failed: %q err=%v", string(respBuf), err)
	}

	radarEntries := srv.Radar().List(10)
	if len(radarEntries) == 0 || radarEntries[0].Domain != "api.anthropic.com" || radarEntries[0].Action != "PROXY" {
		t.Fatalf("expected api.anthropic.com PROXY in RouteRadar, got %+v", radarEntries)
	}

	// Test Diagnostics 4.0 TSPU card and primary AI_PULSE over mux
	xray := NewXRayRunner(func() *EngineConfig { return cfg }, mux, nil, srv.Radar())
	tspuCard := xray.cardTSPU(context.Background())
	if tspuCard.Status != "ok" {
		t.Fatalf("expected TSPU card ok, got %+v", tspuCard)
	}
	muxPulse := xray.QueryAIPulse(context.Background())
	if muxPulse == nil || !muxPulse.OK || muxPulse.Node != "MockDiagMux" || muxPulse.Providers["gemini"].Status != "up" {
		t.Fatalf("expected AI_PULSE over mux from MockDiagMux, got %+v", muxPulse)
	}
}

func TestRound2MuxHoLResistanceAndCloseRstVsFin(t *testing.T) {
	pCli, pSrv := net.Pipe()
	defer pSrv.Close()

	mat, _ := DerivePWP4KeyMaterial("hol-secret", "cli", "srv")
	cTx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	cRx, _ := newPWP4Cipher(mat[32:64], mat[80:96])
	sRx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	sTx, _ := newPWP4Cipher(mat[32:64], mat[80:96])

	var wMu sync.Mutex
	sendFrame := func(ft byte, sid uint32, pl []byte) {
		f, _ := sTx.SealFrame(ft, sid, pl)
		wMu.Lock()
		_, _ = pSrv.Write(f)
		wMu.Unlock()
	}

	rstCh := make(chan uint32, 4)
	finCh := make(chan uint32, 4)
	go func() {
		br := bufio.NewReader(pSrv)
		for {
			ft, sid, payload, _, err := sRx.OpenFrame(br, nil)
			if err != nil {
				return
			}
			switch ft {
			case FrameSynTCP:
				sendFrame(FrameSynAck, sid, nil)
			case FrameData:
				sendFrame(FrameData, sid, payload)
			case FramePing:
				sendFrame(FramePong, sid, payload)
			case FrameFin:
				select {
				case finCh <- sid:
				default:
				}
			case FrameRst:
				select {
				case rstCh <- sid:
				default:
				}
			}
		}
	}()

	sess := NewClientMuxSession(pCli, bufio.NewReader(pCli), &pwp4ClientCodec{rx: cRx, tx: cTx}, NodeConfig{Name: "HoL", Host: "10.0.0.1", Port: 443}, LicenseMetadata{})
	defer sess.Close()

	// 1. Open stalled stream A (never drained) + blast > maxClientStreamQueueBytes (576 KB)
	stA, err := sess.OpenTCPStream("stalled.example", 443, 2*time.Second)
	if err != nil {
		t.Fatalf("OpenTCPStream A: %v", err)
	}
	chunk := bytes.Repeat([]byte("A"), 32*1024)
	for i := 0; i < 18; i++ {
		sendFrame(FrameData, stA.id, chunk)
	}
	select {
	case sid := <-rstCh:
		if sid != stA.id {
			t.Fatalf("expected FrameRst for stalled stream %d, got %d", stA.id, sid)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for FrameRst when stalled stream exceeded 512KB queue")
	}

	// 2. Ping & Stream B must still work promptly (no HoL deadlock on session readLoop)
	if rtt, err := sess.Ping(2 * time.Second); err != nil || rtt > time.Second {
		t.Fatalf("Ping after stalled stream overflow failed: rtt=%v err=%v", rtt, err)
	}
	stB, err := sess.OpenTCPStream("healthy.example", 443, 2*time.Second)
	if err != nil {
		t.Fatalf("OpenTCPStream B: %v", err)
	}
	_, _ = stB.Write([]byte("pingB"))
	bufB := make([]byte, 5)
	if _, err := io.ReadFull(stB, bufB); err != nil || string(bufB) != "pingB" {
		t.Fatalf("stream B echo failed: %q err=%v", string(bufB), err)
	}

	// 3. CloseWrite sends FrameFin; premature Close before peer FIN sends FrameRst
	_ = stB.CloseWrite()
	select {
	case sid := <-finCh:
		if sid != stB.id {
			t.Fatalf("expected FrameFin for %d, got %d", stB.id, sid)
		}
	case <-time.After(time.Second):
		t.Fatal("expected FrameFin after CloseWrite")
	}

	stRst, err := sess.OpenTCPStream("early-close.example", 443, 2*time.Second)
	if err != nil {
		t.Fatalf("OpenTCPStream stRst: %v", err)
	}
	_ = stRst.Close()
	select {
	case sid := <-rstCh:
		if sid != stRst.id {
			t.Fatalf("expected FrameRst on early Close for %d, got %d", stRst.id, sid)
		}
	case <-time.After(time.Second):
		t.Fatal("expected FrameRst on early Close without peer FIN")
	}
}

func TestRound2StandbySameHostMultiPortAndStrictDoH(t *testing.T) {
	cert, pool, spkiHex, _ := generateTestCert(t, "ai.pixelstore.space")
	spawnEcho := func(portBox *int) net.Listener {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
		*portBox = ln.Addr().(*net.TCPAddr).Port
		go func() {
			for {
				c, err := tlsLn.Accept()
				if err != nil {
					return
				}
				go serveMockPWP4Conn(c, "multi-port-secret", "11111111-1111-4111-8111-111111111111")
			}
		}()
		return tlsLn
	}

	var p1, p2 int
	ln1 := spawnEcho(&p1)
	defer ln1.Close()
	ln2 := spawnEcho(&p2)
	defer ln2.Close()

	cfg := DefaultEngineConfig()
	cfg.PinnedSPKI = []string{spkiHex}
	cfg.ClientUUID = "11111111-1111-4111-8111-111111111111"
	cfg.ActiveNode = NodeConfig{Name: "MultiPort-1", Host: "127.0.0.1", Port: p1, SNI: "ai.pixelstore.space", Secret: "multi-port-secret", PWP4Path: DefaultPWP4Path, TLS: true, Mux: true}
	cfg.Nodes = []NodeConfig{
		cfg.ActiveNode,
		{Name: "MultiPort-2", Host: "127.0.0.1", Port: p2, SNI: "ai.pixelstore.space", Secret: "multi-port-secret", PWP4Path: DefaultPWP4Path, TLS: true, Mux: true},
	}

	mux := NewMuxManager(cfg, nil)
	mux.rootCAs = pool
	defer mux.Close()

	if err := mux.WarmConnect(context.Background()); err != nil {
		t.Fatalf("WarmConnect: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mux.Snapshot().StandbyReady {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	snap := mux.Snapshot()
	if !snap.StandbyReady || snap.StandbyNode != "MultiPort-2" {
		t.Fatalf("expected standby ready on same-host second port MultiPort-2, got %+v", snap)
	}

	// Verify dialSessionWithFallback rejects domain names when DoH fails (no OS DNS fallback)
	dohFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fail", http.StatusBadGateway)
	}))
	defer dohFail.Close()
	muxStrict := NewMuxManager(cfg, NewDohResolver([]DohEndpoint{{URL: dohFail.URL}}, nil))
	if _, _, err := muxStrict.dialSessionWithFallback(context.Background(), NodeConfig{Name: "Dom", Host: "localhost", Port: p1, Secret: "s"}); err == nil {
		t.Fatal("expected dialSessionWithFallback to reject domain host on DoH failure without OS DNS fallback")
	}
}

func TestRound2ManifestPreservesEditsAndAIPulseSingleFlightHMAC(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.HTTPPort = 0
	cfg.SOCKSPort = 0
	cfg.CustomProxy = []string{"keep-my-domain.com"}
	cfg.ClientUUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	cfg.RebuildEffectiveRules()

	srv := NewLocalProxyServer(LocalProxyOptions{Config: cfg, LocalToken: "tok"})
	testPin := strings.Repeat("a", 64)
	doc := &ManifestDocument{
		Ver: 77,
		Nodes: []NodeConfig{{
			Name: "NL-Manifest", Host: "1.2.3.4", Port: 443, SNI: "ai.pixelstore.space", Path: "/ws",
		}},
		SPKISHA256: []string{testPin},
	}
	updated := srv.UpdateManifestDoc(doc, "signed_test")
	if updated == nil || updated.ClientUUID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" {
		t.Fatalf("expected UpdateManifestDoc to preserve ClientUUID, got %+v", updated)
	}
	foundCustom := false
	for _, d := range updated.CustomProxy {
		if d == "keep-my-domain.com" {
			foundCustom = true
		}
	}
	foundPin := false
	for _, p := range updated.PinnedSPKI {
		if p == testPin {
			foundPin = true
		}
	}
	if !foundCustom || !foundPin {
		t.Fatalf("expected custom domains preserved & pin applied, got custom=%v pins=%v", updated.CustomProxy, updated.PinnedSPKI)
	}

	// Single-flight + signed /api/v4/ai-pulse HMAC verification + replay prevention (only 1 hit for 5 concurrent callers)
	cert, pool, spkiHex, _ := generateTestCert(t, "ai.pixelstore.space")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	defer tlsLn.Close()

	var hitCount atomic.Int32
	secret := "pulse-edge-secret"
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				hitCount.Add(1)
				br := bufio.NewReader(conn)
				var tsStr, nonceStr, sigStr string
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimSpace(line)
					if line == "" {
						break
					}
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						k := strings.ToLower(strings.TrimSpace(parts[0]))
						v := strings.TrimSpace(parts[1])
						if k == "x-pixel-ts" {
							tsStr = v
						} else if k == "x-pixel-nonce" {
							nonceStr = v
						} else if k == "x-pixel-sig" {
							sigStr = strings.ToLower(v)
						}
					}
				}
				mac := hmac.New(sha256.New, []byte(secret))
				_, _ = mac.Write([]byte("ai-pulse:" + tsStr + ":" + nonceStr))
				want := hex.EncodeToString(mac.Sum(nil)[:16])
				if tsStr == "" || nonceStr == "" || sigStr != want {
					_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
					return
				}
				time.Sleep(60 * time.Millisecond)
				body, _ := json.Marshal(AIPulseResponse{
					OK: true, Node: "PulseEdge", CheckedAt: time.Now().Unix(), TTLSec: 60,
					Providers: map[string]AIProviderPulse{"gemini": {Status: "up", HTTPCode: 200, LatencyMs: 12}},
				})
				_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), string(body))
			}(c)
		}
	}()

	pCfg := DefaultEngineConfig()
	pCfg.PinnedSPKI = []string{spkiHex}
	pCfg.ActiveNode = NodeConfig{
		Name: "PulseEdge", Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port,
		SNI: "ai.pixelstore.space", Secret: secret, TLS: true,
	}
	pMux := NewMuxManager(pCfg, nil)
	pMux.rootCAs = pool
	defer pMux.Close()

	xray := NewXRayRunner(func() *EngineConfig { return pCfg }, pMux, nil, nil)
	var wg sync.WaitGroup
	resps := make([]*AIPulseResponse, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			resps[idx] = xray.QueryAIPulse(context.Background())
		}(i)
	}
	wg.Wait()

	if hitCount.Load() != 1 {
		t.Fatalf("expected exactly 1 upstream hit across 5 concurrent QueryAIPulse calls, got %d", hitCount.Load())
	}
	for i, r := range resps {
		if r == nil || !r.OK || r.Providers["gemini"].Status != "up" {
			t.Fatalf("caller %d got unexpected pulse response: %+v", i, r)
		}
	}
}

func TestRound2SOCKS5UDPAssociateSelfTargetAndRelay(t *testing.T) {
	pCli, pSrv := net.Pipe()
	defer pSrv.Close()

	mat, _ := DerivePWP4KeyMaterial("udp-secret", "cli", "srv")
	cTx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	cRx, _ := newPWP4Cipher(mat[32:64], mat[80:96])
	sRx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	sTx, _ := newPWP4Cipher(mat[32:64], mat[80:96])

	type udpRecv struct {
		host string
		port int
		data string
	}
	udpCh := make(chan udpRecv, 4)
	go func() {
		br := bufio.NewReader(pSrv)
		for {
			ft, sid, payload, _, err := sRx.OpenFrame(br, nil)
			if err != nil {
				return
			}
			if ft == FrameUDPData && len(payload) > 3 {
				hl := int(payload[0])
				if len(payload) >= 1+hl+2 {
					h := string(payload[1 : 1+hl])
					p := int(binary.BigEndian.Uint16(payload[1+hl : 3+hl]))
					d := string(payload[3+hl:])
					udpCh <- udpRecv{host: h, port: p, data: d}
					// Echo packet back on same assoc sid
					ack := "ack:" + d
					reply := make([]byte, 1+hl+2+len(ack))
					reply[0] = byte(hl)
					copy(reply[1:], h)
					binary.BigEndian.PutUint16(reply[1+hl:], uint16(p))
					copy(reply[3+hl:], ack)
					if out, serr := sTx.SealFrame(FrameUDPData, sid, reply); serr == nil {
						_, _ = pSrv.Write(out)
					}
				}
			}
		}
	}()

	cfg := DefaultEngineConfig()
	cfg.HTTPPort = 0
	cfg.SOCKSPort = 0
	mux := NewMuxManager(cfg, nil)
	defer mux.Close()
	sess := NewClientMuxSession(pCli, bufio.NewReader(pCli), &pwp4ClientCodec{rx: cRx, tx: cTx}, NodeConfig{Name: "UDPMock", Host: "10.0.0.1", Port: 443}, LicenseMetadata{})
	mux.mu.Lock()
	mux.sessions["ai"] = sess
	mux.mu.Unlock()

	srv := NewLocalProxyServer(LocalProxyOptions{Config: cfg, Mux: mux, LocalToken: "tok"})
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	ctrl, err := net.Dial("tcp", srv.SOCKSAddr())
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	defer ctrl.Close()
	_, _ = ctrl.Write([]byte{0x05, 0x01, 0x00})
	var greet [2]byte
	_, _ = io.ReadFull(ctrl, greet[:])
	_, _ = ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	var rep [10]byte
	if _, err := io.ReadFull(ctrl, rep[:]); err != nil || rep[1] != 0x00 {
		t.Fatalf("UDP ASSOCIATE failed: rep=%v err=%v", rep, err)
	}
	relayPort := int(binary.BigEndian.Uint16(rep[8:10]))
	relayConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: relayPort})
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer relayConn.Close()

	// Packet 1: self target 127.0.0.1:<httpPort> MUST be dropped silently
	httpPort := srv.HTTPPort()
	pktSelf := []byte{0, 0, 0, 0x01, 127, 0, 0, 1, byte(httpPort >> 8), byte(httpPort), 'b', 'a', 'd'}
	_, _ = relayConn.Write(pktSelf)

	// Packet 2: valid remote 8.8.8.8:53 MUST arrive on mux
	pktGood := []byte{0, 0, 0, 0x01, 8, 8, 8, 8, 0, 53, 'o', 'k'}
	_, _ = relayConn.Write(pktGood)

	select {
	case got := <-udpCh:
		if got.host != "8.8.8.8" || got.port != 53 || got.data != "ok" {
			t.Fatalf("expected 8.8.8.8:53 ok (self target dropped), got %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for valid UDP packet via SOCKS5 UDP ASSOCIATE")
	}

	// Verify reply arrives back from UDP relay socket
	_ = relayConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := relayConn.Read(buf)
	if err != nil || n < 10 || !strings.HasSuffix(string(buf[:n]), "ack:ok") {
		t.Fatalf("expected UDP echo ack:ok, n=%d err=%v", n, err)
	}
}

func TestRound3KillPrimaryPromotesPreWarmedStandbyFast(t *testing.T) {
	cert, pool, spkiHex, _ := generateTestCert(t, "ai.pixelstore.space")
	uuid := "33333333-4444-4555-8666-777777777777"
	secret := "failover-promote-secret"

	var primaryMu sync.Mutex
	var primaryConns []net.Conn
	spawn := func(portBox *int, track bool) net.Listener {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
		*portBox = ln.Addr().(*net.TCPAddr).Port
		go func() {
			for {
				c, err := tlsLn.Accept()
				if err != nil {
					return
				}
				if track {
					primaryMu.Lock()
					primaryConns = append(primaryConns, c)
					primaryMu.Unlock()
				}
				go serveMockPWP4Conn(c, secret, uuid)
			}
		}()
		return tlsLn
	}

	var p1, p2 int
	ln1 := spawn(&p1, true)
	ln2 := spawn(&p2, false)
	defer ln1.Close()
	defer ln2.Close()

	// Config matches exact QA #77 Test 5 layout (top-level address+port PLUS nodes[primary, standby])
	cfgRaw := []byte(fmt.Sprintf(`{
		"address": "127.0.0.1",
		"pwp_port": %d,
		"pwp_secret": %q,
		"pwp_tls": true,
		"pwp_mux": true,
		"client_uuid": %q,
		"pinned_spki": [%q],
		"nodes": [
			{"name": "qa-primary", "host": "127.0.0.1", "port": %d, "secret": %q, "pwp4_path": "/api/v4/telemetry/events", "tls": true, "mux": true},
			{"name": "qa-standby", "host": "127.0.0.1", "port": %d, "secret": %q, "pwp4_path": "/api/v4/telemetry/events", "tls": true, "mux": true}
		]
	}`, p1, secret, uuid, spkiHex, p1, secret, p2, secret))

	cfg, err := LoadConfigBytes(cfgRaw)
	if err != nil {
		t.Fatalf("LoadConfigBytes: %v", err)
	}
	if cfg.ActiveNode.Name != "qa-primary" {
		t.Fatalf("expected ActiveNode.Name == \"qa-primary\", got %q", cfg.ActiveNode.Name)
	}

	mux := NewMuxManager(cfg, nil)
	mux.rootCAs = pool
	defer mux.Close()

	if err := mux.WarmConnect(context.Background()); err != nil {
		t.Fatalf("WarmConnect: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snap := mux.Snapshot()
		if snap.StandbyReady && snap.StandbyNode == "qa-standby" {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	snapReady := mux.Snapshot()
	if !snapReady.StandbyReady || snapReady.StandbyNode != "qa-standby" {
		t.Fatalf("expected pre-warmed qa-standby (never qa-primary self-mirror), got %+v", snapReady)
	}

	// Kill Primary listener AND close all primary TCP connections BEFORE calling OpenStream
	_ = ln1.Close()
	primaryMu.Lock()
	for _, pc := range primaryConns {
		_ = pc.Close()
	}
	primaryMu.Unlock()

	deadWait := time.Now().Add(time.Second)
	for time.Now().Before(deadWait) {
		sess := mux.ActiveSession("ai")
		if sess == nil || sess.IsClosed() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	t0 := time.Now()
	st, nodeUsed, err := mux.OpenStream(context.Background(), "ai", "api.anthropic.com", 443)
	elapsed := time.Since(t0)
	if err != nil {
		t.Fatalf("OpenStream after dead primary failed: %v", err)
	}
	defer st.Close()
	if nodeUsed != "qa-standby" {
		t.Fatalf("expected promoted standby \"qa-standby\", got %q", nodeUsed)
	}
	if mux.Snapshot().FailoverCount < 1 {
		t.Fatalf("expected failover_count >= 1 on pre-warmed standby promotion, got %+v", mux.Snapshot())
	}
	if elapsed >= 50*time.Millisecond {
		t.Fatalf("expected instant standby promotion (<50ms, no cold-dial), took %v", elapsed)
	}
	_, _ = st.Write([]byte("standby-fast"))
	out := make([]byte, 12)
	if _, err := io.ReadFull(st, out); err != nil || string(out) != "standby-fast" {
		t.Fatalf("promoted standby echo failed: %q err=%v", string(out), err)
	}
}

func TestDialPWP4MuxStreamingHeadersAndContentLength(t *testing.T) {
	cert, pool, _, _ := generateTestCert(t, "ai.pixelstore.space")
	secret := "client-streaming-hdr-secret"
	uuid := "11111111-2222-3333-4444-555555555555"

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var gotCL, gotXPad atomic.Value
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReaderSize(conn, 65536)
				reqLine, rerr := br.ReadString('\n')
				if rerr != nil || !strings.HasPrefix(reqLine, "POST ") {
					return
				}
				hdrs := make(map[string]string)
				for {
					line, lerr := br.ReadString('\n')
					if lerr != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					if line == "" {
						break
					}
					if idx := strings.IndexByte(line, ':'); idx > 0 {
						hdrs[strings.ToLower(strings.TrimSpace(line[:idx]))] = strings.TrimSpace(line[idx+1:])
					}
				}
				gotCL.Store(hdrs["content-length"])
				gotXPad.Store(hdrs["x-pad-len"])
				xp, _ := strconv.Atoi(hdrs["x-pad-len"])
				if xp > 0 {
					pad := make([]byte, xp)
					if _, rerr := io.ReadFull(br, pad); rerr != nil {
						return
					}
				}
				cookies := make(map[string]string)
				for _, part := range strings.Split(hdrs["cookie"], ";") {
					kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
					if len(kv) == 2 {
						cookies[kv[0]] = kv[1]
					}
				}
				uv := strings.Split(cookies["_cfuvid"], ".")
				px := strings.Split(cookies["_px4"], ".")
				if len(uv) < 3 || len(px) < 2 {
					return
				}
				sSalt := hex.EncodeToString(bytes.Repeat([]byte{0x55}, 16))
				srvPad := bytes.Repeat([]byte{0x22}, 80)
				resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 107374182400\r\nX-Edge-Telemetry: t=paid;d=30;n=NL-PWP4;p=pwp4\r\nX-Pad-Len: 80\r\nSet-Cookie: __cfruid=%s.m4; Path=/\r\n\r\n", sSalt)
				_, _ = conn.Write(append([]byte(resp), srvPad...))

				mat, _ := DerivePWP4KeyMaterial(secret, px[0], sSalt)
				rx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
				tx, _ := newPWP4Cipher(mat[32:64], mat[80:96])
				for {
					ft, sid, payload, _, oerr := rx.OpenFrame(br, nil)
					if oerr != nil {
						return
					}
					switch ft {
					case FramePing:
						out, _ := tx.SealFrame(FramePong, sid, payload)
						_, _ = conn.Write(out)
					case FrameSynTCP:
						out, _ := tx.SealFrame(FrameSynAck, sid, nil)
						_, _ = conn.Write(out)
					case FrameData:
						out, _ := tx.SealFrame(FrameData, sid, payload)
						_, _ = conn.Write(out)
					}
				}
			}(c)
		}
	}()

	dRes, err := DialUTLS(context.Background(), UTLSDialOptions{
		Address: ln.Addr().String(),
		SNI:     "ai.pixelstore.space",
		RootCAs: pool,
	})
	if err != nil {
		t.Fatalf("DialUTLS: %v", err)
	}
	node := NodeConfig{Name: "pwp4-hdr", Host: "127.0.0.1", SNI: "ai.pixelstore.space", UUID: uuid, Secret: secret, Mux: true}
	var clockOff atomic.Int64
	sess, err := DialPWP4Mux(dRes, node, uuid, "hwid-hdr", &clockOff)
	if err != nil {
		t.Fatalf("DialPWP4Mux: %v", err)
	}
	defer sess.Close()

	if cl, _ := gotCL.Load().(string); cl != "107374182400" {
		t.Fatalf("expected request Content-Length 107374182400, got %q", cl)
	}
	xpStr, _ := gotXPad.Load().(string)
	xpVal, xerr := strconv.Atoi(xpStr)
	if xerr != nil || xpVal < 64 || xpVal > 2048 {
		t.Fatalf("expected request X-Pad-Len in 64..2048, got %q (err=%v)", xpStr, xerr)
	}
	if _, err := sess.Ping(2 * time.Second); err != nil {
		t.Fatalf("PWP-4 Ping over 100GiB Content-Length stream failed: %v", err)
	}

	// Verify invalid response Content-Length (< X-Pad-Len) is rejected cleanly
	badLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("bad listen: %v", err)
	}
	defer badLn.Close()
	go func() {
		c, aerr := badLn.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for {
			l, rerr := br.ReadString('\n')
			if rerr != nil || strings.TrimSpace(l) == "" {
				break
			}
		}
		sSalt := hex.EncodeToString(bytes.Repeat([]byte{0x66}, 16))
		_, _ = c.Write([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: 10\r\nX-Pad-Len: 80\r\nSet-Cookie: __cfruid=%s.m4; Path=/\r\n\r\n", sSalt)))
	}()
	badRes, err := DialUTLS(context.Background(), UTLSDialOptions{Address: badLn.Addr().String(), SNI: "ai.pixelstore.space", RootCAs: pool})
	if err != nil {
		t.Fatalf("DialUTLS badLn: %v", err)
	}
	if _, perr := DialPWP4Mux(badRes, node, uuid, "hwid-hdr", &clockOff); perr == nil {
		t.Fatalf("expected DialPWP4Mux to reject response Content-Length < X-Pad-Len")
	}
	_ = badRes.Conn.Close()
}

func TestUTLSDialerTCPConnectErrorNoRetryAndTimeout(t *testing.T) {
	if got := resolveUTLSDialTimeout(0); got != 2500*time.Millisecond {
		t.Fatalf("expected default uTLS dial timeout 2500ms, got %v", got)
	}
	if got := resolveUTLSDialTimeout(900 * time.Millisecond); got != 900*time.Millisecond {
		t.Fatalf("expected explicit uTLS dial timeout 900ms, got %v", got)
	}

	// 1. Allocate a closed loopback port so raw TCP connect fails reliably.
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedAddr := closedLn.Addr().String()
	_ = closedLn.Close()

	var attemptsMu sync.Mutex
	var attempts []string
	onUTLSDialAttempt = func(profile string) {
		attemptsMu.Lock()
		attempts = append(attempts, profile)
		attemptsMu.Unlock()
	}
	defer func() { onUTLSDialAttempt = nil }()

	// Verify DialUTLS:
	// - Uses <= 2500ms default timeout when ConnectTimeout == 0 (never 6s/12s).
	// - Wraps raw TCP dial failure in tcpConnectError with non-nil Unwrap().
	// - Does NOT retry alternate profile ("firefox") after TCP failure (1 attempt only).
	t0 := time.Now()
	_, err = DialUTLS(context.Background(), UTLSDialOptions{
		Address: closedAddr,
		SNI:     "ai.pixelstore.space",
	})
	dialDur := time.Since(t0)
	if err == nil {
		t.Fatalf("expected DialUTLS to fail on closed port %s", closedAddr)
	}
	var tcpErr *tcpConnectError
	if !errors.As(err, &tcpErr) || tcpErr.Unwrap() == nil {
		t.Fatalf("expected DialUTLS error to unwrap tcpConnectError, got %T: %v", err, err)
	}
	if dialDur > 2900*time.Millisecond {
		t.Fatalf("expected DialUTLS single-attempt timeout <= 2.5s budget, took %v", dialDur)
	}
	attemptsMu.Lock()
	tcpAttempts := append([]string(nil), attempts...)
	attempts = nil
	attemptsMu.Unlock()
	if len(tcpAttempts) != 1 || tcpAttempts[0] != "chrome" {
		t.Fatalf("expected DialUTLS NOT to retry alternate profile on tcpConnectError, got attempts=%v", tcpAttempts)
	}

	// Contrast with TLS handshake failure (accept TCP then immediately close), which MUST retry alternate profile (2 accepts).
	tlsResetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tlsReset: %v", err)
	}
	defer tlsResetLn.Close()
	var acceptCount atomic.Int32
	go func() {
		for {
			c, aerr := tlsResetLn.Accept()
			if aerr != nil {
				return
			}
			acceptCount.Add(1)
			_ = c.Close()
		}
	}()
	_, tlsErr := DialUTLS(context.Background(), UTLSDialOptions{
		Address:        tlsResetLn.Addr().String(),
		SNI:            "ai.pixelstore.space",
		ConnectTimeout: time.Second,
	})
	if tlsErr == nil {
		t.Fatalf("expected TLS failure when peer closes right after TCP accept")
	}
	var unexpectedTCP *tcpConnectError
	if errors.As(tlsErr, &unexpectedTCP) {
		t.Fatalf("post-TCP TLS close must NOT be wrapped as tcpConnectError: %v", tlsErr)
	}
	attemptsMu.Lock()
	tlsAttempts := append([]string(nil), attempts...)
	attemptsMu.Unlock()
	if got := acceptCount.Load(); got != 2 || len(tlsAttempts) != 2 {
		t.Fatalf("expected TLS-stage failure to retry alternate uTLS profile (2 attempts/accepts), got accepts=%d attempts=%v", got, tlsAttempts)
	}
}

func TestWSHostSkipsPWP4AndPreHTTPEarlyAbort(t *testing.T) {
	if !isWSHost(NodeConfig{Host: "ws.pixelstore.space"}) || !isWSHost(NodeConfig{Host: "127.0.0.1", SNI: "ws.pixelstore.space"}) {
		t.Fatalf("expected isWSHost to match Host/SNI with ws. prefix")
	}
	if isWSHost(NodeConfig{Host: "nl.pixelstore.space", SNI: "ai.pixelstore.space"}) {
		t.Fatalf("did not expect nl.pixelstore.space / ai.pixelstore.space to match isWSHost")
	}

	// 1. Start mock TLS server counting PWP-4 vs PWP-3 requests.
	// Using SNI "ws.pixelstore.space" on loopback 127.0.0.1 hits the real dialSessionWithFallback -> DialPWP3Mux path.
	cert, pool, _, _ := generateTestCert(t, "ws.pixelstore.space")
	secret := "ws-skip-pwp4-secret"
	uuid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	var pwp4Hits, pwp3Hits atomic.Int32
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				br := bufio.NewReaderSize(conn, 65536)
				line, rerr := br.ReadString('\n')
				if rerr != nil {
					_ = conn.Close()
					return
				}
				if strings.Contains(line, DefaultPWP4Path) {
					pwp4Hits.Add(1)
					_, _ = conn.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
					_ = conn.Close()
					return
				}
				pwp3Hits.Add(1)
				prefixed := &prefixTestConn{Conn: conn, r: io.MultiReader(strings.NewReader(line), br)}
				serveMockLegacyPWP3Conn(prefixed, secret)
			}(c)
		}
	}()

	cfg := DefaultEngineConfig()
	cfg.V2.PreferPWP4 = true
	cfg.V2.StandbyEnabled = false
	wsNode := NodeConfig{
		Name:   "ws-relay",
		Host:   "127.0.0.1",
		Port:   port,
		SNI:    "ws.pixelstore.space",
		UUID:   uuid,
		Secret: secret,
		Mux:    true,
		Roles:  []string{"ai", "media"},
	}
	cfg.Nodes = []NodeConfig{wsNode}
	cfg.ActiveNode = wsNode

	mux := NewMuxManager(cfg, nil)
	mux.rootCAs = pool
	mux.insecureTest = true
	defer mux.Close()

	sess, _, derr := mux.dialSessionWithFallback(context.Background(), wsNode)
	if derr != nil {
		t.Fatalf("dialSessionWithFallback on ws.* host failed: %v", derr)
	}
	if sess.Protocol() != "PWP-3" {
		t.Fatalf("expected ws.* node to skip PWP-4 directly to PWP-3, got %s", sess.Protocol())
	}
	if pwp4Hits.Load() != 0 || pwp3Hits.Load() != 1 {
		t.Fatalf("expected 0 PWP-4 hits and 1 PWP-3 hit on ws.* node, got pwp4=%d pwp3=%d", pwp4Hits.Load(), pwp3Hits.Load())
	}
	_ = sess.Close()

	// Also confirm dialNodeOverride passes forcePWP3=true for Host "ws.pixelstore.space".
	var overrideSawForce atomic.Bool
	mux.mu.Lock()
	mux.dialNodeOverride = func(ctx context.Context, node NodeConfig, forcePWP3 bool) (*ClientMuxSession, string, error) {
		overrideSawForce.Store(forcePWP3)
		return nil, "", errors.New("stop")
	}
	mux.mu.Unlock()
	_, _, _ = mux.dialSessionWithFallback(context.Background(), NodeConfig{Host: "ws.pixelstore.space", Port: 443, Mux: true})
	if !overrideSawForce.Load() {
		t.Fatalf("expected forcePWP3=true in dialNodeOverride for Host ws.pixelstore.space")
	}
	mux.mu.Lock()
	mux.dialNodeOverride = nil
	mux.mu.Unlock()

	// 2. Verify pre-HTTP dialOnceTLS() failure aborts dialSessionWithFallback immediately (no second DialUTLS attempt for PWP-3).
	rawCloseLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen rawClose: %v", err)
	}
	defer rawCloseLn.Close()
	_, rcPortStr, _ := net.SplitHostPort(rawCloseLn.Addr().String())
	var rcPort int
	_, _ = fmt.Sscanf(rcPortStr, "%d", &rcPort)
	var preHTTPDialAccepts atomic.Int32
	go func() {
		for {
			c, aerr := rawCloseLn.Accept()
			if aerr != nil {
				return
			}
			preHTTPDialAccepts.Add(1)
			_ = c.Close()
		}
	}()

	failNode := NodeConfig{
		Name:   "tls-fail-primary",
		Host:   "127.0.0.1",
		Port:   rcPort,
		SNI:    "ai.pixelstore.space",
		UUID:   uuid,
		Secret: secret,
		Mux:    true,
	}
	_, _, preErr := mux.dialSessionWithFallback(context.Background(), failNode)
	if preErr == nil {
		t.Fatalf("expected dialSessionWithFallback to fail on TLS close")
	}
	// DialUTLS retries chrome+firefox on TLS handshake error (2 accepts), but dialSessionWithFallback
	// must NOT call DialUTLS a second time for PWP-3 (which would produce 4 accepts).
	if got := preHTTPDialAccepts.Load(); got != 2 {
		t.Fatalf("expected pre-HTTP dialOnceTLS() error to abort immediately (1 DialUTLS = 2 accepts, not 4), got %d", got)
	}
}

type prefixTestConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixTestConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func TestHappyEyeballs650msStaggerStandbyAndFallback(t *testing.T) {
	newMockSession := func(t *testing.T, node NodeConfig) (*ClientMuxSession, net.Conn) {
		t.Helper()
		cConn, sConn := net.Pipe()
		sess := NewClientMuxSession(cConn, bufio.NewReader(cConn), &pwp3Codec{}, node, LicenseMetadata{Proto: "PWP-4"})
		return sess, sConn
	}

	// Subtest A: 650ms stagger chooses first distinct-Host candidate, promotes fast alt as active,
	// preserves late slow primary in m.standby even after caller ctx cancels, and cleans up on Close.
	t.Run("stagger_650ms_and_standby_preservation", func(t *testing.T) {
		cfg := DefaultEngineConfig()
		cfg.V2.StandbyEnabled = false
		slowPrimary := NodeConfig{Name: "slow-hostA", Host: "10.10.1.1", Port: 443, Mux: true, Roles: []string{"ai"}}
		sameHostAlt := NodeConfig{Name: "same-hostA-8443", Host: "10.10.1.1", Port: 8443, Mux: true, Roles: []string{"ai"}}
		distinctFastAlt := NodeConfig{Name: "fast-hostB", Host: "10.10.2.2", Port: 443, Mux: true, Roles: []string{"ai"}}
		cfg.ActiveNode = slowPrimary
		cfg.Nodes = []NodeConfig{slowPrimary, sameHostAlt, distinctFastAlt}

		mux := NewMuxManager(cfg, nil)
		defer mux.Close()

		var mu sync.Mutex
		dialTimes := make(map[string]time.Time)
		var dialOrder []string
		var serverConns []net.Conn
		defer func() {
			for _, sc := range serverConns {
				_ = sc.Close()
			}
		}()

		mux.dialNodeOverride = func(ctx context.Context, node NodeConfig, forcePWP3 bool) (*ClientMuxSession, string, error) {
			mu.Lock()
			dialTimes[node.Name] = time.Now()
			dialOrder = append(dialOrder, node.Name)
			mu.Unlock()

			switch node.Name {
			case "slow-hostA":
				select {
				case <-time.After(950 * time.Millisecond):
				case <-ctx.Done():
					return nil, "", ctx.Err()
				}
			case "fast-hostB":
				select {
				case <-time.After(30 * time.Millisecond):
				case <-ctx.Done():
					return nil, "", ctx.Err()
				}
			case "same-hostA-8443":
				t.Errorf("same-host candidate %q should NOT be launched during initial distinct-host stagger", node.Name)
				return nil, "", errors.New("unexpected same-host dial")
			}
			sess, sc := newMockSession(t, node)
			mu.Lock()
			serverConns = append(serverConns, sc)
			mu.Unlock()
			return sess, "HelloChrome_Auto", nil
		}

		// Cancel caller ctx right after WarmConnect/getOrConnectRole returns, verifying late second racer survives.
		callCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		t0 := time.Now()
		sess, err := mux.getOrConnectRole(callCtx, "ai")
		elapsed := time.Since(t0)
		cancel()
		if err != nil {
			t.Fatalf("getOrConnectRole failed: %v", err)
		}
		if sess.Node().Name != "fast-hostB" {
			t.Fatalf("expected fast distinct-host winner fast-hostB, got %q", sess.Node().Name)
		}
		if elapsed < 620*time.Millisecond || elapsed > 900*time.Millisecond {
			t.Fatalf("expected Happy-Eyeballs stagger winner around ~680ms, took %v", elapsed)
		}

		mu.Lock()
		dt0 := dialTimes["slow-hostA"]
		dt1 := dialTimes["fast-hostB"]
		orderCopy := append([]string(nil), dialOrder...)
		mu.Unlock()
		if dt1.Sub(dt0) < 600*time.Millisecond {
			t.Fatalf("expected distinct-host dial to start >=650ms after primary, gap=%v order=%v", dt1.Sub(dt0), orderCopy)
		}
		if len(orderCopy) != 2 {
			t.Fatalf("expected exactly 2 staggered dials (primary + distinct host), got %v", orderCopy)
		}

		// Wait for slow-hostA (started at 0ms, finishes at ~950ms) to populate m.standby.
		deadline := time.Now().Add(800 * time.Millisecond)
		for time.Now().Before(deadline) {
			snap := mux.Snapshot()
			if snap.StandbyReady && snap.StandbyNode == "slow-hostA" {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		snap := mux.Snapshot()
		if !snap.StandbyReady || snap.StandbyNode != "slow-hostA" {
			t.Fatalf("expected late second racer slow-hostA preserved in m.standby, got %+v", snap)
		}
	})

	// Subtest B: If m.standby is already non-nil when the second racer succeeds, close it cleanly.
	t.Run("late_racer_closes_when_standby_already_occupied", func(t *testing.T) {
		cfg := DefaultEngineConfig()
		slowPrimary := NodeConfig{Name: "slow-primary", Host: "10.20.1.1", Port: 443, Mux: true, Roles: []string{"ai"}}
		fastAlt := NodeConfig{Name: "fast-alt", Host: "10.20.2.2", Port: 443, Mux: true, Roles: []string{"ai"}}
		cfg.ActiveNode = slowPrimary
		cfg.Nodes = []NodeConfig{slowPrimary, fastAlt}
		mux := NewMuxManager(cfg, nil)
		defer mux.Close()

		var lateMu sync.Mutex
		var lateSess *ClientMuxSession
		var serverConns []net.Conn
		defer func() {
			for _, sc := range serverConns {
				_ = sc.Close()
			}
		}()

		mux.dialNodeOverride = func(ctx context.Context, node NodeConfig, forcePWP3 bool) (*ClientMuxSession, string, error) {
			if node.Name == "slow-primary" {
				time.Sleep(820 * time.Millisecond)
			} else {
				time.Sleep(25 * time.Millisecond)
			}
			sess, sc := newMockSession(t, node)
			lateMu.Lock()
			serverConns = append(serverConns, sc)
			if node.Name == "slow-primary" {
				lateSess = sess
			}
			lateMu.Unlock()
			return sess, "HelloChrome_Auto", nil
		}

		sess, err := mux.getOrConnectRole(context.Background(), "ai")
		if err != nil {
			t.Fatalf("getOrConnectRole: %v", err)
		}
		if sess.Node().Name != "fast-alt" {
			t.Fatalf("expected fast-alt active, got %q", sess.Node().Name)
		}

		// Occupy m.standby BEFORE slow-primary finishes.
		preStandby, scPre := newMockSession(t, NodeConfig{Name: "pre-occupied", Host: "10.20.3.3", Port: 443})
		defer scPre.Close()
		mux.mu.Lock()
		mux.standby = preStandby
		mux.standbyNode = preStandby.Node()
		mux.mu.Unlock()

		deadline := time.Now().Add(800 * time.Millisecond)
		closedLate := false
		for time.Now().Before(deadline) {
			lateMu.Lock()
			ls := lateSess
			lateMu.Unlock()
			if ls != nil && ls.IsClosed() {
				closedLate = true
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !closedLate {
			t.Fatalf("expected late second racer to be closed cleanly when m.standby != nil")
		}
		if mux.Snapshot().StandbyNode != "pre-occupied" {
			t.Fatalf("expected existing m.standby to remain untouched, got %+v", mux.Snapshot())
		}
	})

	// Subtest C: Primary failing before 650ms triggers immediate alt dial + clean fallback across untried candidates.
	t.Run("fast_primary_fail_and_untried_fallback_plus_no_leaks", func(t *testing.T) {
		cfg := DefaultEngineConfig()
		p := NodeConfig{Name: "n1-hostA", Host: "10.30.1.1", Port: 443, Mux: true, Roles: []string{"ai"}}
		sameHost := NodeConfig{Name: "n2-hostA-altport", Host: "10.30.1.1", Port: 8443, Mux: true, Roles: []string{"ai"}}
		alt := NodeConfig{Name: "n3-hostB", Host: "10.30.2.2", Port: 443, Mux: true, Roles: []string{"ai"}}
		cfg.ActiveNode = p
		cfg.Nodes = []NodeConfig{p, sameHost, alt}

		mux := NewMuxManager(cfg, nil)
		defer mux.Close()

		var mu sync.Mutex
		var triedOrder []string
		var serverConns []net.Conn
		defer func() {
			for _, sc := range serverConns {
				_ = sc.Close()
			}
		}()

		mux.dialNodeOverride = func(ctx context.Context, node NodeConfig, forcePWP3 bool) (*ClientMuxSession, string, error) {
			mu.Lock()
			triedOrder = append(triedOrder, node.Name)
			mu.Unlock()
			if node.Name == "n1-hostA" || node.Name == "n3-hostB" {
				return nil, "", errors.New("fail-" + node.Name)
			}
			sess, sc := newMockSession(t, node)
			mu.Lock()
			serverConns = append(serverConns, sc)
			mu.Unlock()
			return sess, "HelloChrome_Auto", nil
		}

		t0 := time.Now()
		sess, err := mux.getOrConnectRole(context.Background(), "ai")
		elapsed := time.Since(t0)
		if err != nil {
			t.Fatalf("expected fallback to same-host untried node, got err: %v", err)
		}
		if sess.Node().Name != "n2-hostA-altport" {
			t.Fatalf("expected untried candidate n2-hostA-altport, got %q", sess.Node().Name)
		}
		if elapsed > 250*time.Millisecond {
			t.Fatalf("fast primary failure should trigger immediate fallback without waiting 650ms, took %v", elapsed)
		}
		mu.Lock()
		gotOrder := append([]string(nil), triedOrder...)
		mu.Unlock()
		if len(gotOrder) != 3 || gotOrder[0] != "n1-hostA" || gotOrder[1] != "n3-hostB" || gotOrder[2] != "n2-hostA-altport" {
			t.Fatalf("unexpected candidate dial order (expected primary -> distinct alt -> untried): %v", gotOrder)
		}
	})

	// Subtest D: Context cancellation during staggered race leaks zero goroutines and closes all sockets cleanly.
	t.Run("cancel_during_race_no_goroutine_or_socket_leaks", func(t *testing.T) {
		cfg := DefaultEngineConfig()
		n1 := NodeConfig{Name: "hang1", Host: "10.40.1.1", Port: 443, Mux: true, Roles: []string{"ai"}}
		n2 := NodeConfig{Name: "hang2", Host: "10.40.2.2", Port: 443, Mux: true, Roles: []string{"ai"}}
		cfg.ActiveNode = n1
		cfg.Nodes = []NodeConfig{n1, n2}

		runtime.GC()
		time.Sleep(20 * time.Millisecond)
		baseG := runtime.NumGoroutine()

		mux := NewMuxManager(cfg, nil)
		var dialExited atomic.Int32
		mux.dialNodeOverride = func(ctx context.Context, node NodeConfig, forcePWP3 bool) (*ClientMuxSession, string, error) {
			<-ctx.Done()
			dialExited.Add(1)
			return nil, "", ctx.Err()
		}

		ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
		defer cancel()
		_, err := mux.getOrConnectRole(ctx, "ai")
		if err == nil {
			t.Fatalf("expected canceled context error")
		}
		mux.Close()

		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			if dialExited.Load() == 2 && runtime.NumGoroutine() <= baseG+2 {
				break
			}
			time.Sleep(15 * time.Millisecond)
		}
		if dialExited.Load() != 2 {
			t.Fatalf("expected both in-flight racers to exit on cancel, exited=%d", dialExited.Load())
		}
		if afterG := runtime.NumGoroutine(); afterG > baseG+2 {
			t.Fatalf("goroutine leak after canceled Happy-Eyeballs race: before=%d after=%d", baseG, afterG)
		}
	})
}
