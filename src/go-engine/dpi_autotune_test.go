package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMultiRecordSplitClientHello_ValidTLSRecordsAndLiveHandshake(t *testing.T) {
	makeFakeCH := func(totalPayload int, sniOffset int, sniStr string, trailing []byte) []byte {
		raw := make([]byte, 5+totalPayload+len(trailing))
		raw[0], raw[1], raw[2] = 0x16, 0x03, 0x01
		binary.BigEndian.PutUint16(raw[3:5], uint16(totalPayload))
		raw[5] = 0x01 // ClientHello
		if sniOffset >= 5 && sniOffset+len(sniStr) <= 5+totalPayload {
			copy(raw[sniOffset:], []byte(sniStr))
		}
		if len(trailing) > 0 {
			copy(raw[5+totalPayload:], trailing)
		}
		return raw
	}

	tests := []struct {
		name           string
		raw            []byte
		sni            string
		wantRecs       int
		wantPayloadSum int
		wantTrailing   []byte
	}{
		{
			name:           "standard_sni",
			raw:            makeFakeCH(140, 60, "ai.pixelstore.space", nil),
			sni:            "ai.pixelstore.space",
			wantRecs:       3,
			wantPayloadSum: 140,
		},
		{
			name:           "uppercase_sni",
			raw:            makeFakeCH(140, 60, "AI.PIXELSTORE.SPACE", nil),
			sni:            "ai.pixelstore.space",
			wantRecs:       3,
			wantPayloadSum: 140,
		},
		{
			name:           "no_sni_payload",
			raw:            makeFakeCH(120, -1, "", nil),
			sni:            "missing.example.com",
			wantRecs:       3,
			wantPayloadSum: 120,
		},
		{
			name:           "short_buffer_passthrough",
			raw:            []byte{0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5},
			sni:            "ai.pixelstore.space",
			wantRecs:       1,
			wantPayloadSum: 5,
		},
		{
			name:           "trailing_flight_preserved",
			raw:            makeFakeCH(140, 60, "ai.pixelstore.space", []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}),
			sni:            "ai.pixelstore.space",
			wantRecs:       3,
			wantPayloadSum: 140,
			wantTrailing:   []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recs := MultiRecordSplitClientHello(tt.raw, tt.sni)
			expectedSlices := tt.wantRecs
			if len(tt.wantTrailing) > 0 {
				expectedSlices++
			}
			if len(recs) != expectedSlices {
				t.Fatalf("expected %d slices, got %d", expectedSlices, len(recs))
			}

			sum := 0
			for i := 0; i < tt.wantRecs; i++ {
				if recs[i][0] != 0x16 || recs[i][1] != 0x03 {
					t.Fatalf("record %d invalid TLS header: %x", i, recs[i][:5])
				}
				l := int(binary.BigEndian.Uint16(recs[i][3:5]))
				if l <= 0 || len(recs[i]) != 5+l {
					t.Fatalf("record %d length mismatch: hdr=%d actual=%d", i, l, len(recs[i])-5)
				}
				sum += l
			}
			if sum != tt.wantPayloadSum {
				t.Fatalf("payload sum mismatch: got %d, want %d", sum, tt.wantPayloadSum)
			}
			if len(tt.wantTrailing) > 0 && !bytes.Equal(recs[len(recs)-1], tt.wantTrailing) {
				t.Fatalf("trailing bytes mismatch: got %x, want %x", recs[len(recs)-1], tt.wantTrailing)
			}
		})
	}

	// Live TLS 1.3 handshake + echo over DPIProfileComboMultiRecord
	cert, pool, spkiHex, _ := generateTestCert(t, "ai.pixelstore.space")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
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

	res, err := DialUTLS(context.Background(), UTLSDialOptions{
		Address:        ln.Addr().String(),
		SNI:            "ai.pixelstore.space",
		Profile:        "chrome",
		DPIProfile:     DPIProfileComboMultiRecord,
		EnableSplit:    true,
		Pins:           []string{spkiHex},
		RequirePin:     true,
		RootCAs:        pool,
		ForceHTTP1ALPN: true,
	})
	if err != nil {
		t.Fatalf("DialUTLS ComboMultiRecord failed: %v", err)
	}
	defer res.Conn.Close()

	msg := []byte("combo-multi-record-ok")
	if _, err := res.Conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(res.Conn, buf); err != nil {
		t.Fatalf("readFull: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: got %q want %q", buf, msg)
	}
}

// readInitialTLSClientHello reads one complete TLS ClientHello (across 1+ TLS 0x16 records)
// and returns the raw wire bytes, reassembled handshake payload, and TLS record count.
func readInitialTLSClientHello(c net.Conn) (rawWire []byte, reassembled []byte, recCount int, err error) {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	targetHandshakeLen := -1
	var hdr [5]byte
	for {
		if _, rerr := io.ReadFull(c, hdr[:]); rerr != nil {
			return nil, nil, 0, rerr
		}
		if hdr[0] != 0x16 {
			return nil, nil, 0, errors.New("not a TLS handshake record")
		}
		recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		if recLen <= 0 || recLen > 32768 {
			return nil, nil, 0, errors.New("invalid TLS record length")
		}
		payload := make([]byte, recLen)
		if _, rerr := io.ReadFull(c, payload); rerr != nil {
			return nil, nil, 0, rerr
		}
		recCount++
		rawWire = append(rawWire, hdr[:]...)
		rawWire = append(rawWire, payload...)
		reassembled = append(reassembled, payload...)

		if targetHandshakeLen < 0 && len(reassembled) >= 4 {
			hsLen := int(reassembled[1])<<16 | int(reassembled[2])<<8 | int(reassembled[3])
			targetHandshakeLen = 4 + hsLen
		}
		if targetHandshakeLen > 0 && len(reassembled) >= targetHandshakeLen {
			return rawWire, reassembled, recCount, nil
		}
	}
}

type hostCapturingConn struct {
	net.Conn
	mu            sync.Mutex
	checked       bool
	gotHost       bool
	innerVerified *atomic.Bool
}

func (c *hostCapturingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		if !c.checked {
			c.checked = true
			if bytes.Contains(b[:n], []byte("Host: ai.pixelstore.space\r\n")) {
				c.gotHost = true
				if c.innerVerified != nil {
					c.innerVerified.Store(true)
				}
			}
		}
		c.mu.Unlock()
	}
	return n, err
}

func TestAdaptiveDPI_BeatsSNIBlacklistViaAutoDecoyAndPersistsCache(t *testing.T) {
	cert, pool, spkiHex, _ := generateTestCert(t, "ai.pixelstore.space")
	secret := "autotune-pwp4-secret"
	uuid := "22222222-2222-4222-8222-222222222222"

	var innerHostVerified atomic.Bool
	var observedDecoySNI atomic.Value

	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	defer tlsLn.Close()

	go func() {
		for {
			c, aErr := tlsLn.Accept()
			if aErr != nil {
				return
			}
			go func(raw net.Conn) {
				tc, ok := raw.(*tls.Conn)
				if !ok {
					_ = raw.Close()
					return
				}
				if err := tc.Handshake(); err != nil {
					_ = raw.Close()
					return
				}
				observedDecoySNI.Store(tc.ConnectionState().ServerName)
				capConn := &hostCapturingConn{Conn: tc, innerVerified: &innerHostVerified}
				serveMockPWP4Conn(capConn, secret, uuid)
				capConn.mu.Lock()
				if capConn.gotHost {
					innerHostVerified.Store(true)
				}
				capConn.mu.Unlock()
			}(c)
		}
	}()

	// Mock TSPU middlebox: reassembles TLS 0x16 records and drops ANY ClientHello mentioning pixelstore.space.
	dpiLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dpi listen: %v", err)
	}
	defer dpiLn.Close()

	var totalAccepts atomic.Int32
	go func() {
		for {
			cli, aErr := dpiLn.Accept()
			if aErr != nil {
				return
			}
			totalAccepts.Add(1)
			go func(clientConn net.Conn) {
				rawWire, reassembled, _, rerr := readInitialTLSClientHello(clientConn)
				if rerr != nil {
					_ = clientConn.Close()
					return
				}
				if bytes.Contains(bytes.ToLower(reassembled), []byte("pixelstore.space")) {
					// Simulate DPI TCP RST/close on blacklisted SNI
					_ = clientConn.Close()
					return
				}
				up, uerr := net.DialTimeout("tcp", tlsLn.Addr().String(), 2*time.Second)
				if uerr != nil {
					_ = clientConn.Close()
					return
				}
				if _, werr := up.Write(rawWire); werr != nil {
					_ = up.Close()
					_ = clientConn.Close()
					return
				}
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					_, _ = io.Copy(up, clientConn)
					_ = up.Close()
				}()
				go func() {
					defer wg.Done()
					_, _ = io.Copy(clientConn, up)
					_ = clientConn.Close()
				}()
				wg.Wait()
			}(cli)
		}
	}()

	dpiPort := dpiLn.Addr().(*net.TCPAddr).Port
	cachePath := filepath.Join(t.TempDir(), "dpi_autotune_v1.json")

	makeCfg := func() *EngineConfig {
		cfg := DefaultEngineConfig()
		cfg.PinnedSPKI = []string{spkiHex}
		cfg.DecoySNIs = []string{"dl.google.com", "www.microsoft.com"}
		cfg.ClientUUID = uuid
		cfg.V2.StandbyEnabled = false
		cfg.ActiveNode = NodeConfig{
			Name:     "TSPU-Guarded-Edge",
			Region:   "EU",
			Host:     "127.0.0.1",
			Port:     dpiPort,
			SNI:      DefaultSNI,
			Secret:   secret,
			PWP4Path: DefaultPWP4Path,
			TLS:      true,
			Mux:      true,
			Frag:     true,
		}
		cfg.Nodes = []NodeConfig{cfg.ActiveNode}
		return cfg
	}

	tuner1 := NewDPIAutoTuner(cachePath)
	mux1 := NewMuxManager(makeCfg(), nil)
	mux1.rootCAs = pool
	mux1.SetAutoTuner(tuner1)
	mux1.netFP.Store("wifi-isp-1")
	defer mux1.Close()

	st, nodeName, err := mux1.OpenStream(context.Background(), "ai", "echo.test", 443)
	if err != nil {
		t.Fatalf("OpenStream under SNI-blacklisting DPI failed: %v", err)
	}
	if nodeName != "TSPU-Guarded-Edge" {
		t.Fatalf("unexpected node name: %s", nodeName)
	}
	payload := []byte("hello-over-auto-decoy-pwp4")
	if _, err := st.Write(payload); err != nil {
		t.Fatalf("stream write: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(st, echo); err != nil {
		t.Fatalf("stream read: %v", err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("echo mismatch: got %q want %q", echo, payload)
	}
	_ = st.Close()

	snap := mux1.Snapshot()
	if !strings.HasPrefix(snap.DPIStrategy, "decoy:") {
		t.Fatalf("expected decoy strategy in snapshot, got %q", snap.DPIStrategy)
	}
	if snap.AutoTunePromotions < 1 {
		t.Fatalf("expected AutoTunePromotions >= 1, got %d", snap.AutoTunePromotions)
	}
	if gotSNI, _ := observedDecoySNI.Load().(string); gotSNI == "" || strings.Contains(gotSNI, "pixelstore.space") {
		t.Fatalf("expected decoy external SNI on TLS server, got %q", gotSNI)
	}
	mux1.Close()
	if !innerHostVerified.Load() {
		t.Fatalf("expected inner PWP-4 HTTP request to keep Host: ai.pixelstore.space")
	}

	// Second instance with persisted cache file MUST hit on the very first TCP accept (0 wasted retries)
	beforeSecond := totalAccepts.Load()
	tuner2 := NewDPIAutoTuner(cachePath)
	mux2 := NewMuxManager(makeCfg(), nil)
	mux2.rootCAs = pool
	mux2.SetAutoTuner(tuner2)
	mux2.netFP.Store("wifi-isp-1")
	defer mux2.Close()

	if err := mux2.WarmConnect(context.Background()); err != nil {
		t.Fatalf("second mux WarmConnect via persisted cache failed: %v", err)
	}
	acceptsUsed := totalAccepts.Load() - beforeSecond
	if acceptsUsed != 1 {
		t.Fatalf("expected cached Auto Decoy strategy to connect in 1 TCP accept, took %d", acceptsUsed)
	}
	if snap2 := mux2.Snapshot(); snap2.AutoTunePromotions != 0 {
		t.Fatalf("expected cache hit to have 0 new escalations, got %d", snap2.AutoTunePromotions)
	}
}

func TestAdaptiveDPI_SoftFallbackOnUnpinnedReplicaAndSelfHealInvalidation(t *testing.T) {
	t.Run("unpinned_replica_skips_decoy_cleanly", func(t *testing.T) {
		unpinnedCert, _, _, _ := generateTestCert(t, "unpinned.replica.invalid")
		trustedCert, trustedPool, trustedSPKI, _ := generateTestCert(t, "ai.pixelstore.space")
		_ = trustedCert

		tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{unpinnedCert},
			MinVersion:   tls.VersionTLS13,
		})
		if err != nil {
			t.Fatalf("tls listen: %v", err)
		}
		defer tlsLn.Close()
		go func() {
			for {
				c, aErr := tlsLn.Accept()
				if aErr != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					_ = conn.(*tls.Conn).Handshake()
				}(c)
			}
		}()

		// Middlebox drops native SNI ClientHello, forwards decoy SNI to unpinned replica
		dpiLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("dpi listen: %v", err)
		}
		defer dpiLn.Close()

		var decoyAttempts atomic.Int32
		go func() {
			for {
				cli, aErr := dpiLn.Accept()
				if aErr != nil {
					return
				}
				go func(clientConn net.Conn) {
					rawWire, reassembled, _, rerr := readInitialTLSClientHello(clientConn)
					if rerr != nil {
						_ = clientConn.Close()
						return
					}
					if bytes.Contains(bytes.ToLower(reassembled), []byte("pixelstore.space")) {
						_ = clientConn.Close()
						return
					}
					decoyAttempts.Add(1)
					up, uerr := net.DialTimeout("tcp", tlsLn.Addr().String(), time.Second)
					if uerr != nil {
						_ = clientConn.Close()
						return
					}
					_, _ = up.Write(rawWire)
					go func() { _, _ = io.Copy(up, clientConn); _ = up.Close() }()
					_, _ = io.Copy(clientConn, up)
					_ = clientConn.Close()
				}(cli)
			}
		}()

		tuner := NewDPIAutoTuner(filepath.Join(t.TempDir(), "unpinned.json"))
		_, _, dialErr := tuner.DialAdaptiveTLS(context.Background(), AdaptiveDialOptions{
			Address:         dpiLn.Addr().String(),
			SNI:             DefaultSNI,
			BaseUTLSProfile: "chrome",
			BaseDPIProfile:  DPIProfileStandardSplit,
			EnableSplit:     true,
			DecoySNIs:       []string{"dl.google.com", "www.microsoft.com"},
			AllowDecoySNI:   true,
			Pins:            []string{trustedSPKI},
			RequirePin:      true,
			RootCAs:         trustedPool,
			ForceHTTP1ALPN:  true,
			StepTimeout:     time.Second,
			NetFingerprint:  "net-unpinned",
		})
		if dialErr == nil {
			t.Fatalf("expected DialAdaptiveTLS to fail when native SNI is dropped and decoy cert is unpinned")
		}
		if errors.Is(dialErr, ErrCertPinMismatch) {
			t.Fatalf("expected soft fallback to preserve transport error rather than returning ErrCertPinMismatch on decoy, got: %v", dialErr)
		}
		if decoyAttempts.Load() != 1 {
			t.Fatalf("expected soft fallback to stop remaining decoys after 1st unpinned mismatch, got %d decoy attempts", decoyAttempts.Load())
		}

		// Verify ws.pixelstore.space (AllowDecoySNI=false) never plans any decoy step
		wsLadder, _ := tuner.BuildAdaptiveLadder(AdaptiveDialOptions{
			Address:         "127.0.0.1:443",
			SNI:             "ws.pixelstore.space",
			BaseUTLSProfile: "chrome",
			EnableSplit:     true,
			DecoySNIs:       []string{"dl.google.com"},
			AllowDecoySNI:   false,
			Pins:            []string{trustedSPKI},
		})
		for _, s := range wsLadder {
			if s.UseDecoySNI {
				t.Fatalf("ws host ladder must never include Decoy-SNI: %+v", wsLadder)
			}
		}
	})

	t.Run("cache_invalidation_self_heals", func(t *testing.T) {
		cert, pool, spkiHex, _ := generateTestCert(t, "ai.pixelstore.space")
		tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		})
		if err != nil {
			t.Fatalf("tls listen: %v", err)
		}
		defer tlsLn.Close()
		go func() {
			for {
				c, aErr := tlsLn.Accept()
				if aErr != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					_, _ = io.Copy(conn, conn)
				}(c)
			}
		}()

		// Middlebox rejects single-TLS-record ClientHello (StandardSplit / SniMicroChunk)
		// and allows multi-TLS-record ClientHello (first record carries only part of handshake).
		dpiLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("dpi listen: %v", err)
		}
		defer dpiLn.Close()

		var accepts atomic.Int32
		go func() {
			for {
				cli, aErr := dpiLn.Accept()
				if aErr != nil {
					return
				}
				accepts.Add(1)
				go func(clientConn net.Conn) {
					rawWire, reassembled, recCount, rerr := readInitialTLSClientHello(clientConn)
					if rerr != nil {
						_ = clientConn.Close()
						return
					}
					if recCount < 2 {
						// Drop single-record ClientHello (blocks cached StandardSplit!)
						_ = clientConn.Close()
						return
					}
					up, uerr := net.DialTimeout("tcp", tlsLn.Addr().String(), time.Second)
					if uerr != nil {
						_ = clientConn.Close()
						return
					}
					_, _ = up.Write(rawWire)
					_ = reassembled
					go func() { _, _ = io.Copy(up, clientConn); _ = up.Close() }()
					_, _ = io.Copy(clientConn, up)
					_ = clientConn.Close()
				}(cli)
			}
		}()

		cacheFile := filepath.Join(t.TempDir(), "dpi_autotune_v1.json")
		tuner := NewDPIAutoTuner(cacheFile)
		addr := dpiLn.Addr().String()
		// Seed stale strategy that DPI now blocks
		tuner.RecordSuccess("net-heal", addr, DPIStrategy{
			DPIProfile:  DPIProfileStandardSplit,
			UTLSProfile: "chrome",
		}, false)

		res, strat, err := tuner.DialAdaptiveTLS(context.Background(), AdaptiveDialOptions{
			Address:         addr,
			SNI:             "ai.pixelstore.space",
			BaseUTLSProfile: "chrome",
			BaseDPIProfile:  DPIProfileStandardSplit,
			EnableSplit:     true,
			AllowDecoySNI:   false,
			Pins:            []string{spkiHex},
			RequirePin:      true,
			RootCAs:         pool,
			ForceHTTP1ALPN:  true,
			StepTimeout:     time.Second,
			NetFingerprint:  "net-heal",
		})
		if err != nil {
			t.Fatalf("DialAdaptiveTLS self-heal failed: %v", err)
		}
		_ = res.Conn.Close()

		if strat.DPIProfile == DPIProfileStandardSplit {
			t.Fatalf("expected self-heal to switch away from blocked StandardSplit, got %+v", strat)
		}
		if tuner.Promotions() != 1 {
			t.Fatalf("expected 1 promotion after invalidating stale cache, got %d", tuner.Promotions())
		}

		// Reload tuner from disk and confirm the updated winner works on 1st attempt
		beforeReload := accepts.Load()
		reloaded := NewDPIAutoTuner(cacheFile)
		res2, strat2, err := reloaded.DialAdaptiveTLS(context.Background(), AdaptiveDialOptions{
			Address:         addr,
			SNI:             "ai.pixelstore.space",
			BaseUTLSProfile: "chrome",
			BaseDPIProfile:  DPIProfileStandardSplit,
			EnableSplit:     true,
			AllowDecoySNI:   false,
			Pins:            []string{spkiHex},
			RequirePin:      true,
			RootCAs:         pool,
			ForceHTTP1ALPN:  true,
			StepTimeout:     time.Second,
			NetFingerprint:  "net-heal",
		})
		if err != nil {
			t.Fatalf("reloaded DialAdaptiveTLS failed: %v", err)
		}
		_ = res2.Conn.Close()
		if strat2.DPIProfile != strat.DPIProfile {
			t.Fatalf("reloaded strategy mismatch: got %+v, want %+v", strat2, strat)
		}
		if got := accepts.Load() - beforeReload; got != 1 {
			t.Fatalf("expected reloaded winner to connect in 1 TCP accept, took %d", got)
		}
	})
}

func TestDohResolver_StaggeredRaceSWRAndSingleflight(t *testing.T) {
	t.Run("staggered_race_and_preferred_stickiness", func(t *testing.T) {
		var slowHits, fastHits atomic.Int32

		slowSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slowHits.Add(1)
			qWire, _ := io.ReadAll(io.LimitReader(r.Body, 512))
			select {
			case <-time.After(1200 * time.Millisecond):
				if len(qWire) >= 12 {
					w.Header().Set("Content-Type", "application/dns-message")
					_, _ = w.Write(buildFakeADNSResponse(qWire, [4]byte{93, 184, 216, 34}))
				}
			case <-r.Context().Done():
				return
			}
		}))
		defer slowSrv.Close()

		fastSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fastHits.Add(1)
			qWire, _ := io.ReadAll(io.LimitReader(r.Body, 512))
			if len(qWire) < 12 {
				http.Error(w, "bad query", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(buildFakeADNSResponse(qWire, [4]byte{93, 184, 216, 34}))
		}))
		defer fastSrv.Close()

		resolver := NewDohResolver([]DohEndpoint{
			{URL: slowSrv.URL, ServerName: "slow.dns.test"},
			{URL: fastSrv.URL, ServerName: "fast.dns.test"},
		}, &tls.Config{InsecureSkipVerify: true})

		t0 := time.Now()
		ips, err := resolver.LookupHost(context.Background(), "example.com")
		elapsed := time.Since(t0)
		if err != nil || len(ips) == 0 || ips[0].String() != "93.184.216.34" {
			t.Fatalf("staggered LookupHost failed: ips=%v err=%v", ips, err)
		}
		if elapsed >= 850*time.Millisecond {
			t.Fatalf("expected 350ms staggered race to beat 1200ms slow endpoint, took %v", elapsed)
		}
		if up := resolver.ActiveUpstream(); !strings.Contains(up, "fast.dns.test") {
			t.Fatalf("expected active upstream fast.dns.test, got %q", up)
		}

		// Second lookup for a different domain must prefer fastSrv directly without slowSrv delay
		slowBefore := slowHits.Load()
		t1 := time.Now()
		ips2, err2 := resolver.LookupHost(context.Background(), "second.example.org")
		elapsed2 := time.Since(t1)
		if err2 != nil || len(ips2) == 0 {
			t.Fatalf("second LookupHost failed: %v", err2)
		}
		if elapsed2 >= 250*time.Millisecond {
			t.Fatalf("expected preferred upstream fast path <250ms, took %v", elapsed2)
		}
		if slowHits.Load() != slowBefore {
			t.Fatalf("expected preferred fastSrv to avoid hitting slowSrv on 2nd lookup")
		}
	})

	t.Run("stale_while_revalidate_0ms_and_background_update", func(t *testing.T) {
		var serveNewIP atomic.Bool
		refreshedCh := make(chan struct{}, 2)

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			qWire, _ := io.ReadAll(io.LimitReader(r.Body, 512))
			if len(qWire) < 12 {
				http.Error(w, "bad query", http.StatusBadRequest)
				return
			}
			ip := [4]byte{93, 184, 216, 10}
			if serveNewIP.Load() {
				ip = [4]byte{93, 184, 216, 20}
			}
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(buildFakeADNSResponse(qWire, ip))
			if serveNewIP.Load() {
				select {
				case refreshedCh <- struct{}{}:
				default:
				}
			}
		}))
		defer srv.Close()

		resolver := NewDohResolver([]DohEndpoint{{URL: srv.URL, ServerName: "swr.dns.test"}}, &tls.Config{InsecureSkipVerify: true})
		ips, err := resolver.LookupHost(context.Background(), "swr.example.com")
		if err != nil || ips[0].String() != "93.184.216.10" {
			t.Fatalf("initial LookupHost failed: ips=%v err=%v", ips, err)
		}

		// Expire fresh TTL while keeping entry inside staleUntil grace window
		resolver.mu.Lock()
		ent := resolver.cache["A:swr.example.com"]
		ent.expiresAt = time.Now().Add(-time.Second)
		ent.staleUntil = time.Now().Add(5 * time.Minute)
		resolver.cache["A:swr.example.com"] = ent
		resolver.mu.Unlock()

		serveNewIP.Store(true)
		t0 := time.Now()
		staleIPs, err := resolver.LookupHost(context.Background(), "swr.example.com")
		elapsed := time.Since(t0)
		if err != nil || len(staleIPs) == 0 || staleIPs[0].String() != "93.184.216.10" {
			t.Fatalf("expected immediate stale IP 93.184.216.10, got %v (err=%v)", staleIPs, err)
		}
		if elapsed >= 50*time.Millisecond {
			t.Fatalf("expected SWR immediate return <50ms, took %v", elapsed)
		}

		select {
		case <-refreshedCh:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for background SWR refresh")
		}

		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			freshIPs, ferr := resolver.LookupHost(context.Background(), "swr.example.com")
			if ferr == nil && len(freshIPs) > 0 && freshIPs[0].String() == "93.184.216.20" {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("expected cache to contain refreshed IP 93.184.216.20")
	})

	t.Run("singleflight_coalesces_concurrent_cold_lookups", func(t *testing.T) {
		var reqCount atomic.Int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqCount.Add(1)
			qWire, _ := io.ReadAll(io.LimitReader(r.Body, 512))
			time.Sleep(40 * time.Millisecond)
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(buildFakeADNSResponse(qWire, [4]byte{93, 184, 216, 77}))
		}))
		defer srv.Close()

		baseGoroutines := runtime.NumGoroutine()
		resolver := NewDohResolver([]DohEndpoint{{URL: srv.URL, ServerName: "sf.dns.test"}}, &tls.Config{InsecureSkipVerify: true})

		const callers = 16
		var wg sync.WaitGroup
		errCh := make(chan error, callers)
		startGate := make(chan struct{})
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-startGate
				ips, err := resolver.LookupHost(context.Background(), "cold-sf.example.net")
				if err != nil {
					errCh <- err
					return
				}
				if len(ips) == 0 || ips[0].String() != "93.184.216.77" {
					errCh <- errors.New("unexpected IP returned")
				}
			}()
		}
		close(startGate)
		wg.Wait()
		close(errCh)

		for err := range errCh {
			t.Fatalf("concurrent LookupHost failed: %v", err)
		}
		if got := reqCount.Load(); got != 1 {
			t.Fatalf("expected singleflight to coalesce 16 concurrent cold lookups into 1 DoH request, got %d", got)
		}
		srv.CloseClientConnections()
		time.Sleep(40 * time.Millisecond)
		if after := runtime.NumGoroutine(); after > baseGoroutines+6 {
			t.Fatalf("potential goroutine leak after singleflight: before=%d after=%d", baseGoroutines, after)
		}
	})
}
