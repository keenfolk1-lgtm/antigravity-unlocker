package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSmartNodeSelectorColdAutoAndTieBreaking(t *testing.T) {
	t.Parallel()

	makeNodes := func() (us1, nl1, de1, offline NodeConfig) {
		us1 = NodeConfig{Name: "US-1", Region: "US", Host: "10.0.1.1", Port: 443, Roles: []string{"ai", "media"}}
		nl1 = NodeConfig{Name: "NL-1", Region: "NL", Host: "10.0.2.1", Port: 443, Roles: []string{"ai", "media"}}
		de1 = NodeConfig{Name: "DE-1", Region: "DE", Host: "10.0.3.1", Port: 443, Roles: []string{"ai", "media"}}
		offline = NodeConfig{Name: "FR-dead", Region: "FR", Host: "10.0.4.1", Port: 443, Roles: []string{"ai", "media"}}
		return
	}

	tests := []struct {
		name      string
		role      string
		region    string
		setup     func(sel *SmartNodeSelector, us1, nl1, de1, offline NodeConfig)
		input     func(us1, nl1, de1, offline NodeConfig) []NodeConfig
		wantOrder []string
	}{
		{
			name:   "cold auto picks lowest-RTT probed node rather than nodes[0]",
			role:   "auto",
			region: "auto",
			setup: func(sel *SmartNodeSelector, us1, nl1, de1, offline NodeConfig) {
				sel.RecordProbe(nl1, true, 45)
				sel.RecordProbe(de1, true, 32)
				sel.RecordProbe(offline, false, 0)
				// us1 intentionally unprobed
			},
			input: func(us1, nl1, de1, offline NodeConfig) []NodeConfig {
				return []NodeConfig{us1, nl1, de1, offline}
			},
			wantOrder: []string{"DE-1", "NL-1", "US-1", "FR-dead"},
		},
		{
			name:   "ewma smoothing (old*3+new)/4 reverses initial lead after latency spike",
			role:   "ai",
			region: "",
			setup: func(sel *SmartNodeSelector, us1, nl1, de1, offline NodeConfig) {
				// nl1: 100 -> (100*3+60)/4=90 -> (90*3+50)/4=80
				sel.RecordProbe(nl1, true, 100)
				sel.RecordProbe(nl1, true, 60)
				sel.RecordProbe(nl1, true, 50)
				// de1: 40 -> (40*3+240)/4=90
				sel.RecordProbe(de1, true, 40)
				sel.RecordProbe(de1, true, 240)
				// zero/negative RTT should not alter EWMA
				sel.RecordProbe(nl1, true, 0)
				sel.RecordProbe(nl1, true, -5)
			},
			input: func(us1, nl1, de1, offline NodeConfig) []NodeConfig {
				return []NodeConfig{de1, nl1}
			},
			wantOrder: []string{"NL-1", "DE-1"},
		},
		{
			name:   "unprobed nodes preserve manifest order on tie after probed healthy nodes",
			role:   "ai",
			region: "auto",
			setup: func(sel *SmartNodeSelector, us1, nl1, de1, offline NodeConfig) {
				sel.RecordProbe(de1, true, 28)
			},
			input: func(us1, nl1, de1, offline NodeConfig) []NodeConfig {
				return []NodeConfig{us1, nl1, de1}
			},
			wantOrder: []string{"DE-1", "US-1", "NL-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sel := NewSmartNodeSelector()
			us1, nl1, de1, offline := makeNodes()
			if tt.setup != nil {
				tt.setup(sel, us1, nl1, de1, offline)
			}
			in := tt.input(us1, nl1, de1, offline)
			snapshot := append([]NodeConfig(nil), in...)
			got := sel.RankCandidates(tt.role, tt.region, in)

			if len(got) != len(tt.wantOrder) {
				t.Fatalf("RankCandidates len=%d, want %d", len(got), len(tt.wantOrder))
			}
			for i, wantName := range tt.wantOrder {
				if got[i].Name != wantName {
					t.Fatalf("got[%d]=%q, want %q (full=%v)", i, got[i].Name, wantName, got)
				}
			}
			// Defensive copy checks: input slice & nested Roles remain untouched.
			for i := range in {
				if in[i].Name != snapshot[i].Name {
					t.Fatalf("input slice mutated at %d: %q != %q", i, in[i].Name, snapshot[i].Name)
				}
			}
			if len(got) > 0 {
				got[0].Name = "MUTATED"
				if len(got[0].Roles) > 0 {
					got[0].Roles[0] = "MUTATED_ROLE"
				}
				if in[0].Name == "MUTATED" || (len(in[0].Roles) > 0 && in[0].Roles[0] == "MUTATED_ROLE") {
					t.Fatalf("RankCandidates failed defensive deep copy on input slice")
				}
			}
		})
	}

	if got := NewSmartNodeSelector().RankCandidates("ai", "auto", nil); got != nil {
		t.Fatalf("expected nil for empty candidates, got %+v", got)
	}
}

func TestSmartNodeSelectorStickyAIAndMediaSplit(t *testing.T) {
	t.Parallel()

	nl1 := NodeConfig{Name: "NL-1", Region: "NL", Host: "10.1.0.1", Port: 443}
	nl2 := NodeConfig{Name: "NL-2", Region: "NL", Host: "10.1.0.2", Port: 443}
	de1 := NodeConfig{Name: "DE-1", Region: "DE", Host: "10.1.0.3", Port: 443}

	tests := []struct {
		name      string
		role      string
		region    string
		setup     func(sel *SmartNodeSelector)
		cands     []NodeConfig
		wantOrder []string
	}{
		{
			name:   "sticky NL-1 at 45ms stays first for ai even when DE-1 is 32ms",
			role:   "ai",
			region: "auto",
			setup: func(sel *SmartNodeSelector) {
				sel.RecordProbe(nl1, true, 45)
				sel.RecordProbe(de1, true, 32)
				sel.NotifyConnected("ai", nl1)
			},
			cands:     []NodeConfig{de1, nl1},
			wantOrder: []string{"NL-1", "DE-1"},
		},
		{
			name:   "sticky NL-1 at 45ms stays first for auto role",
			role:   "auto",
			region: "",
			setup: func(sel *SmartNodeSelector) {
				sel.RecordProbe(nl1, true, 45)
				sel.RecordProbe(de1, true, 32)
				sel.NotifyConnected("ai", nl1)
			},
			cands:     []NodeConfig{de1, nl1},
			wantOrder: []string{"NL-1", "DE-1"},
		},
		{
			name:   "media ignores sticky AI pinning and picks lowest RTT DE-1",
			role:   "media",
			region: "auto",
			setup: func(sel *SmartNodeSelector) {
				sel.RecordProbe(nl1, true, 45)
				sel.RecordProbe(de1, true, 32)
				sel.NotifyConnected("ai", nl1)
			},
			cands:     []NodeConfig{nl1, de1},
			wantOrder: []string{"DE-1", "NL-1"},
		},
		{
			name:   "preferredRegion keeps region matches first even when other region has lower RTT",
			role:   "ai",
			region: "NL",
			setup: func(sel *SmartNodeSelector) {
				sel.RecordProbe(nl1, true, 60)
				sel.RecordProbe(nl2, true, 40)
				sel.RecordProbe(de1, true, 20)
				sel.NotifyConnected("ai", de1)
			},
			cands:     []NodeConfig{de1, nl1, nl2},
			wantOrder: []string{"NL-2", "NL-1", "DE-1"},
		},
		{
			name:   "preferredRegion avoids degraded sticky node in region when clean region match exists",
			role:   "ai",
			region: "NL",
			setup: func(sel *SmartNodeSelector) {
				sel.RecordProbe(nl1, true, 25)
				sel.RecordProbe(nl2, true, 50)
				sel.RecordProbe(de1, true, 20)
				sel.NotifyConnected("ai", nl1)
				sel.RecordAIPulse(nl1, AIPulseResponse{
					OK:        true,
					Providers: map[string]AIProviderPulse{"claude": {Status: "down", HTTPCode: 403}},
				})
			},
			cands:     []NodeConfig{nl1, nl2, de1},
			wantOrder: []string{"NL-2", "DE-1", "NL-1"},
		},
		{
			name:   "preferredRegion matching node Name prioritizes exact node",
			role:   "media",
			region: "NL-1",
			setup: func(sel *SmartNodeSelector) {
				sel.RecordProbe(nl1, true, 60)
				sel.RecordProbe(nl2, true, 30)
				sel.RecordProbe(de1, true, 20)
			},
			cands:     []NodeConfig{de1, nl2, nl1},
			wantOrder: []string{"NL-1", "DE-1", "NL-2"},
		},
		{
			name:   "sticky stays first if ALL candidates are aiDegraded",
			role:   "ai",
			region: "auto",
			setup: func(sel *SmartNodeSelector) {
				sel.RecordProbe(nl1, true, 45)
				sel.RecordProbe(de1, true, 32)
				sel.NotifyConnected("ai", nl1)
				deg := AIPulseResponse{
					OK:        true,
					Providers: map[string]AIProviderPulse{"openai": {Status: "degraded", HTTPCode: 429}},
				}
				sel.RecordAIPulse(nl1, deg)
				sel.RecordAIPulse(de1, deg)
			},
			cands:     []NodeConfig{de1, nl1},
			wantOrder: []string{"NL-1", "DE-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sel := NewSmartNodeSelector()
			tt.setup(sel)
			got := sel.RankCandidates(tt.role, tt.region, tt.cands)
			if len(got) != len(tt.wantOrder) {
				t.Fatalf("len=%d, want %d", len(got), len(tt.wantOrder))
			}
			for i, w := range tt.wantOrder {
				if got[i].Name != w {
					t.Fatalf("got[%d]=%q, want %q", i, got[i].Name, w)
				}
			}
		})
	}
}

func TestSmartNodeSelectorAIPulseMigration(t *testing.T) {
	t.Parallel()

	nl1 := NodeConfig{Name: "NL-1", Region: "NL", Host: "10.2.0.1", Port: 443}
	de1 := NodeConfig{Name: "DE-1", Region: "DE", Host: "10.2.0.2", Port: 443}
	cands := []NodeConfig{nl1, de1}

	tests := []struct {
		name           string
		pulse          AIPulseResponse
		de1Degraded    bool
		de1Offline     bool
		wantMigrate    bool
		wantFirstAfter string
	}{
		{
			name: "claude 403/down triggers migration to clean DE-1",
			pulse: AIPulseResponse{
				OK:        true,
				Providers: map[string]AIProviderPulse{"claude": {Status: "down", HTTPCode: 403}},
			},
			wantMigrate:    true,
			wantFirstAfter: "DE-1",
		},
		{
			name: "openai 429 triggers migration even if status is degraded",
			pulse: AIPulseResponse{
				OK:        true,
				Providers: map[string]AIProviderPulse{"openai": {Status: "degraded", HTTPCode: 429}},
			},
			wantMigrate:    true,
			wantFirstAfter: "DE-1",
		},
		{
			name: "gemini down with 200 triggers migration",
			pulse: AIPulseResponse{
				OK:        true,
				Providers: map[string]AIProviderPulse{"gemini": {Status: "down", HTTPCode: 0}},
			},
			wantMigrate:    true,
			wantFirstAfter: "DE-1",
		},
		{
			name: "all providers healthy keeps sticky NL-1 without migration",
			pulse: AIPulseResponse{
				OK: true,
				Providers: map[string]AIProviderPulse{
					"claude": {Status: "ok", HTTPCode: 200},
					"openai": {Status: "ok", HTTPCode: 200},
					"gemini": {Status: "up", HTTPCode: 200},
				},
			},
			wantMigrate:    false,
			wantFirstAfter: "NL-1",
		},
		{
			name: "no migration when alternative DE-1 is also degraded",
			pulse: AIPulseResponse{
				OK:        true,
				Providers: map[string]AIProviderPulse{"claude": {Status: "down", HTTPCode: 403}},
			},
			de1Degraded:    true,
			wantMigrate:    false,
			wantFirstAfter: "NL-1",
		},
		{
			name: "no migration when alternative DE-1 is known offline",
			pulse: AIPulseResponse{
				OK:        true,
				Providers: map[string]AIProviderPulse{"claude": {Status: "down", HTTPCode: 403}},
			},
			de1Offline:     true,
			wantMigrate:    false,
			wantFirstAfter: "NL-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sel := NewSmartNodeSelector()
			sel.RecordProbe(nl1, true, 45)
			if tt.de1Offline {
				sel.RecordProbe(de1, false, 0)
			} else {
				sel.RecordProbe(de1, true, 32)
			}
			sel.NotifyConnected("ai", nl1)

			if sel.StickyAINode() != "NL-1" {
				t.Fatalf("StickyAINode=%q, want NL-1", sel.StickyAINode())
			}
			if sel.AIMigrations() != 0 {
				t.Fatalf("initial AIMigrations=%d, want 0", sel.AIMigrations())
			}

			// Media connections must never alter sticky AI or migration counter.
			sel.NotifyConnected("media", de1)
			if sel.StickyAINode() != "NL-1" || sel.AIMigrations() != 0 {
				t.Fatalf("media NotifyConnected altered AI state: sticky=%q migrations=%d", sel.StickyAINode(), sel.AIMigrations())
			}

			sel.RecordAIPulse(nl1, tt.pulse)
			if tt.de1Degraded {
				sel.RecordAIPulse(de1, tt.pulse)
			}

			if got := sel.ShouldMigrateAI(cands); got != tt.wantMigrate {
				t.Fatalf("ShouldMigrateAI=%v, want %v", got, tt.wantMigrate)
			}
			ranked := sel.RankCandidates("ai", "auto", cands)
			if ranked[0].Name != tt.wantFirstAfter {
				t.Fatalf("ranked[0]=%q, want %q", ranked[0].Name, tt.wantFirstAfter)
			}

			if tt.wantMigrate {
				sel.NotifyConnected("ai", ranked[0])
				if sel.AIMigrations() != 1 {
					t.Fatalf("AIMigrations=%d, want 1 after switch", sel.AIMigrations())
				}
				if sel.StickyAINode() != "DE-1" {
					t.Fatalf("StickyAINode=%q, want DE-1", sel.StickyAINode())
				}
				// Reconnecting same node does not increment migrations again.
				sel.NotifyConnected("ai", de1)
				if sel.AIMigrations() != 1 {
					t.Fatalf("same-node reconnect incremented AIMigrations to %d", sel.AIMigrations())
				}
			}
		})
	}

	t.Run("offline sticky triggers ShouldMigrateAI and clean recovery clears it", func(t *testing.T) {
		t.Parallel()
		sel := NewSmartNodeSelector()
		sel.RecordProbe(nl1, true, 40)
		sel.NotifyConnected("ai", nl1)
		sel.RecordProbe(nl1, false, 0)
		if !sel.ShouldMigrateAI(cands) {
			t.Fatalf("expected ShouldMigrateAI=true when sticky NL-1 goes offline")
		}
		sel.RecordProbe(nl1, true, 42)
		if sel.ShouldMigrateAI(cands) {
			t.Fatalf("expected ShouldMigrateAI=false after NL-1 comes back online")
		}
	})
}

func TestSmartNodeProbeSessionAIPulseAndConcurrency(t *testing.T) {
	t.Run("signed HTTP HMAC /api/v4/ai-pulse records degradation and triggers migration", func(t *testing.T) {
		cert, _, spkiHex, _ := generateTestCert(t, "ai.pixelstore.space")
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
		defer tlsLn.Close()

		secret := "smart-pulse-secret"
		go func() {
			for {
				c, err := tlsLn.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					br := bufio.NewReader(conn)
					var reqLine, tsStr, nonceStr, sigStr string
					for i := 0; ; i++ {
						line, rErr := br.ReadString('\n')
						if rErr != nil {
							return
						}
						line = strings.TrimSpace(line)
						if i == 0 {
							reqLine = line
						}
						if line == "" {
							break
						}
						if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
							switch strings.ToLower(strings.TrimSpace(parts[0])) {
							case "x-pixel-ts":
								tsStr = strings.TrimSpace(parts[1])
							case "x-pixel-nonce":
								nonceStr = strings.TrimSpace(parts[1])
							case "x-pixel-sig":
								sigStr = strings.ToLower(strings.TrimSpace(parts[1]))
							}
						}
					}
					if !strings.HasPrefix(reqLine, "GET /api/v4/ai-pulse ") {
						_, _ = io.WriteString(conn, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
						return
					}
					mac := hmac.New(sha256.New, []byte(secret))
					_, _ = mac.Write([]byte("ai-pulse:" + tsStr + ":" + nonceStr))
					wantSig := hex.EncodeToString(mac.Sum(nil)[:16])
					if tsStr == "" || nonceStr == "" || sigStr != wantSig {
						_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
						return
					}
					body, _ := json.Marshal(AIPulseResponse{
						OK:        true,
						Node:      "NL-1",
						CheckedAt: time.Now().Unix(),
						TTLSec:    60,
						Providers: map[string]AIProviderPulse{
							"claude": {Status: "down", HTTPCode: 403, LatencyMs: 85},
							"openai": {Status: "ok", HTTPCode: 200, LatencyMs: 42},
							"gemini": {Status: "ok", HTTPCode: 200, LatencyMs: 31},
						},
					})
					_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), string(body))
				}(c)
			}
		}()

		port := ln.Addr().(*net.TCPAddr).Port
		nl1 := NodeConfig{Name: "NL-1", Region: "NL", Host: "127.0.0.1", Port: port, SNI: "ai.pixelstore.space", Secret: secret, TLS: true}
		de1 := NodeConfig{Name: "DE-1", Region: "DE", Host: "10.9.9.2", Port: 443, Secret: secret, TLS: true}
		cfg := DefaultEngineConfig()
		cfg.PinnedSPKI = []string{spkiHex}

		sel := NewSmartNodeSelector()
		sel.RecordProbe(nl1, true, 45)
		sel.RecordProbe(de1, true, 50)
		sel.NotifyConnected("ai", nl1)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err := sel.ProbeSessionAIPulse(ctx, nil, nl1, cfg)
		if err != nil {
			t.Fatalf("ProbeSessionAIPulse HTTP/HMAC failed: %v", err)
		}
		if resp.Providers["claude"].HTTPCode != 403 {
			t.Fatalf("unexpected pulse response: %+v", resp)
		}
		if !sel.ShouldMigrateAI([]NodeConfig{nl1, de1}) {
			t.Fatalf("expected ShouldMigrateAI=true after HTTP/HMAC claude 403")
		}
		ranked := sel.RankCandidates("ai", "auto", []NodeConfig{nl1, de1})
		if ranked[0].Name != "DE-1" {
			t.Fatalf("expected DE-1 promoted first, got %q", ranked[0].Name)
		}
		sel.NotifyConnected("ai", ranked[0])
		if sel.AIMigrations() != 1 || sel.StickyAINode() != "DE-1" {
			t.Fatalf("unexpected migration state: sticky=%q migrations=%d", sel.StickyAINode(), sel.AIMigrations())
		}
	})

	t.Run("in-band mux diag.internal.pixel AI_PULSE over ClientMuxSession", func(t *testing.T) {
		pCli, pSrv := net.Pipe()
		defer pSrv.Close()

		mat, _ := DerivePWP4KeyMaterial("mux-pulse-secret", "cli", "srv")
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

		go func() {
			sBr := bufio.NewReader(pSrv)
			streamBuf := make(map[uint32][]byte)
			for {
				ft, sid, pl, _, err := sRx.OpenFrame(sBr, nil)
				if err != nil {
					return
				}
				switch ft {
				case FrameSynTCP:
					sendFrame(FrameSynAck, sid, nil)
				case FrameData:
					streamBuf[sid] = append(streamBuf[sid], pl...)
					if bytes.HasPrefix(streamBuf[sid], []byte("AI_PULSE\n")) {
						sendFrame(FrameData, sid, []byte(`{"ok":true,"node":"NL-Mux","checked_at":1763100000,"ttl_sec":60,"providers":{"claude":{"status":"degraded","http_code":429,"latency_ms":50}}}`+"\n"))
						sendFrame(FrameFin, sid, nil)
					}
				}
			}
		}()

		nl1 := NodeConfig{Name: "NL-Mux", Region: "NL", Host: "10.8.8.1", Port: 443}
		de1 := NodeConfig{Name: "DE-Clean", Region: "DE", Host: "10.8.8.2", Port: 443}
		sess := NewClientMuxSession(pCli, bufio.NewReader(pCli), &pwp4ClientCodec{rx: cRx, tx: cTx}, nl1, LicenseMetadata{Proto: "PWP-4"})
		defer sess.Close()

		sel := NewSmartNodeSelector()
		sel.NotifyConnected("ai", nl1)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		resp, err := sel.ProbeSessionAIPulse(ctx, sess, nl1, nil)
		if err != nil {
			t.Fatalf("ProbeSessionAIPulse mux diag failed: %v", err)
		}
		if resp.Providers["claude"].HTTPCode != 429 {
			t.Fatalf("unexpected mux diag pulse: %+v", resp)
		}
		if !sel.ShouldMigrateAI([]NodeConfig{nl1, de1}) {
			t.Fatalf("expected ShouldMigrateAI=true after mux diag 429")
		}
	})

	t.Run("concurrent telemetry and ranking race safety", func(t *testing.T) {
		sel := NewSmartNodeSelector()
		nodes := []NodeConfig{
			{Name: "N1", Region: "NL", Host: "10.5.0.1", Port: 443},
			{Name: "N2", Region: "DE", Host: "10.5.0.2", Port: 443},
			{Name: "N3", Region: "FI", Host: "10.5.0.3", Port: 443},
		}
		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for i := 0; i < 50; i++ {
					n := nodes[(id+i)%len(nodes)]
					sel.RecordProbe(n, (i%5) != 0, int64(20+(i%30)))
					sel.RecordAIPulse(n, AIPulseResponse{
						OK:        true,
						Providers: map[string]AIProviderPulse{"claude": {Status: "ok", HTTPCode: 200}},
					})
					sel.NotifyConnected("ai", n)
					_ = sel.RankCandidates("ai", "auto", nodes)
					_ = sel.RankCandidates("media", "auto", nodes)
					_ = sel.ShouldMigrateAI(nodes)
					_ = sel.StickyAINode()
					_ = sel.AIMigrations()
				}
			}(g)
		}
		wg.Wait()
	})
}

func TestTelegramSocialDomainsAndDCIPs(t *testing.T) {
	t.Parallel()

	cfg := DefaultEngineConfig()
	cfg.ProxyAll = false
	cfg.Categories = map[string]bool{
		"antigravity": true,
		"ai":          false,
		"mcp":         false,
		"media":       false,
		"social":      true,
	}
	cfg.RebuildEffectiveRules()

	matcher := NewDomainRuleMatcher(cfg)
	proxyTargets := []string{
		"t.me",
		"tx.me",
		"web.telegram.org",
		"telegram-cdn.org",
		"cdn-telegram.org",
		"149.154.167.50",
		"91.108.56.100",
		"91.105.192.10",
		"185.76.151.12",
	}
	for _, host := range proxyTargets {
		act := matcher.Classify(host)
		if act.Action != "PROXY" {
			t.Fatalf("Classify(%q) = %+v, want Action=PROXY when social=true", host, act)
		}
	}

	directTargets := []string{"ya.ru", "77.88.8.8", "8.8.8.8", "youtube.com"}
	for _, host := range directTargets {
		act := matcher.Classify(host)
		if act.Action != "DIRECT" {
			t.Fatalf("Classify(%q) = %+v, want Action=DIRECT when only social=true and proxy_all=false", host, act)
		}
	}

	pac := GenerateSmartPACJS(cfg, "127.0.0.1")
	if !strings.Contains(pac, "var ROUTE_TG_DC = true;") {
		t.Fatalf("expected ROUTE_TG_DC = true in Smart PAC when social=true")
	}
	if !strings.Contains(pac, "function _isTelegramDCIP(h)") {
		t.Fatalf("expected _isTelegramDCIP helper in Smart PAC")
	}
	for _, dom := range []string{"t.me", "web.telegram.org", "telegram-cdn.org"} {
		if !strings.Contains(pac, `"`+dom+`"`) {
			t.Fatalf("expected Smart PAC PROXY_RULES to include %q", dom)
		}
	}
}

func TestV212LegacyHostNormalizationAndDiscordVoiceCIDR(t *testing.T) {
	t.Parallel()

	pk, err := ParseKeyInput("vless://11111111-2222-3333-4444-555555555555@201.34.152.97:8443?sni=www.amd.com#Old")
	if err != nil {
		t.Fatalf("ParseKeyInput failed: %v", err)
	}
	if pk.Host != DefaultHost || pk.Port != 443 || pk.SNI != DefaultSNI {
		t.Fatalf("expected normalized host=%s port=443 sni=%s, got host=%s port=%d sni=%s",
			DefaultHost, DefaultSNI, pk.Host, pk.Port, pk.SNI)
	}

	rawCfg := `{
		"address": "201.34.152.97",
		"serverName": "www.amd.com",
		"pwpSecret": "explicit-secret-test",
		"pwpPort": 8443,
		"v2": { "proxy_all": false, "categories": { "media": true } }
	}`
	cfg, err := LoadConfigBytes([]byte(rawCfg))
	if err != nil {
		t.Fatalf("LoadConfigBytes failed: %v", err)
	}
	if cfg.ActiveNode.Host != DefaultHost {
		t.Fatalf("expected ActiveNode.Host normalized to %s, got %q", DefaultHost, cfg.ActiveNode.Host)
	}
	if cfg.ActiveNode.SNI != DefaultSNI {
		t.Fatalf("expected ActiveNode.SNI normalized to %s, got %q", DefaultSNI, cfg.ActiveNode.SNI)
	}

	matcher := NewDomainRuleMatcher(cfg)
	actVoice := matcher.Classify("66.22.244.10")
	if actVoice.Action != "PROXY" || actVoice.Role != "media" {
		t.Fatalf("expected Discord voice CIDR 66.22.244.10 -> PROXY/media when media=true, got %+v", actVoice)
	}

	cfgOff := DefaultEngineConfig()
	cfgOff.ProxyAll = false
	cfgOff.Categories = map[string]bool{"antigravity": true, "media": false}
	cfgOff.RebuildEffectiveRules()
	matcherOff := NewDomainRuleMatcher(cfgOff)
	if actOff := matcherOff.Classify("66.22.244.10"); actOff.Action != "DIRECT" {
		t.Fatalf("expected Discord voice CIDR -> DIRECT when media=false, got %+v", actOff)
	}
}

func TestGoogleAIStudioBrowserRoutingAndPAC(t *testing.T) {
	t.Parallel()

	// Case 1: Only "ai" enabled (antigravity=false, media=false, social=false)
	cfgAIOnly := DefaultEngineConfig()
	cfgAIOnly.ProxyAll = false
	cfgAIOnly.Categories = map[string]bool{
		"antigravity": false,
		"ai":          true,
		"mcp":         false,
		"media":       false,
		"social":      false,
	}
	cfgAIOnly.RebuildEffectiveRules()
	mAI := NewDomainRuleMatcher(cfgAIOnly)

	aiStudioTargets := []string{
		"aistudio.google.com",
		"ai.studio",
		"demo.scf.usercontent.goog",
		"alkalimakersuite-pa.clients6.google.com",
		"webchannel-alkalimakersuite-pa.clients6.google.com",
		"generativelanguage.googleapis.com",
		"payments.cloud.google",
		"gemini.google.com",
		"demo-app.run.app",
		"accounts.google.com",
	}
	for _, host := range aiStudioTargets {
		act := mAI.Classify(host)
		if act.Action != "PROXY" || act.Role != "ai" {
			t.Fatalf("ai=true: Classify(%q) = %+v, want Action=PROXY Role=ai", host, act)
		}
	}
	for _, directHost := range []string{"ya.ru", "youtube.com"} {
		act := mAI.Classify(directHost)
		if act.Action != "DIRECT" {
			t.Fatalf("ai=true: Classify(%q) = %+v, want Action=DIRECT", directHost, act)
		}
	}

	pac := GenerateSmartPACJS(cfgAIOnly, "127.0.0.1")
	for _, dom := range []string{"aistudio.google.com", "ai.studio", "usercontent.goog", "cloud.google", "run.app"} {
		if !strings.Contains(pac, `"`+dom+`"`) {
			t.Fatalf("expected Smart PAC PROXY_RULES to include %q when ai=true", dom)
		}
	}

	// Case 2: Only "antigravity" enabled (ai=false, media=false, social=false)
	cfgAGOnly := DefaultEngineConfig()
	cfgAGOnly.ProxyAll = false
	cfgAGOnly.Categories = map[string]bool{
		"antigravity": true,
		"ai":          false,
		"mcp":         false,
		"media":       false,
		"social":      false,
	}
	cfgAGOnly.RebuildEffectiveRules()
	mAG := NewDomainRuleMatcher(cfgAGOnly)

	for _, host := range []string{"aistudio.google.com", "ai.studio", "demo.scf.usercontent.goog", "payments.cloud.google"} {
		act := mAG.Classify(host)
		if act.Action != "PROXY" || act.Role != "ai" {
			t.Fatalf("antigravity=true: Classify(%q) = %+v, want Action=PROXY Role=ai", host, act)
		}
	}
	for _, directHost := range []string{"api.anthropic.com", "youtube.com", "ya.ru"} {
		act := mAG.Classify(directHost)
		if act.Action != "DIRECT" {
			t.Fatalf("antigravity=true: Classify(%q) = %+v, want Action=DIRECT", directHost, act)
		}
	}
}
