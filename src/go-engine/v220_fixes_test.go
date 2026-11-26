package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestV220RuleDeletionPrecedenceSanitizationAndPAC(t *testing.T) {
	t.Parallel()

	rawCfg := `{
		"v2": {
			"proxy_all": false,
			"categories": {"antigravity": true, "ai": true, "mcp": true, "media": false, "social": false},
			"custom_proxy_domains": ["https://user:pass@Custom-AI.example:8443/path?x=1#frag", "habr.ru", "evil.com');alert(1);//"],
			"custom_direct_domains": ["github.com"]
		},
		"routing": {
			"rules": [
				{"type": "field", "outboundTag": "proxy", "domain": ["habr.ru", "static-proxy.example"]},
				{"type": "field", "outboundTag": "direct", "domain": ["github.com", "static-direct.example"]}
			]
		}
	}`
	cfg, err := LoadConfigBytes([]byte(rawCfg))
	if err != nil {
		t.Fatalf("LoadConfigBytes: %v", err)
	}
	matcher := NewDomainRuleMatcher(cfg)

	// Tier 0: non-overridable self-bypass
	if a := matcher.Classify("ai.pixelstore.space"); a.Action != "DIRECT" || a.Rule != "self_bypass" {
		t.Fatalf("pixelstore.space must be Tier 0 DIRECT self_bypass, got %+v", a)
	}
	if a := matcher.Classify(DefaultHost); a.Action != "DIRECT" {
		t.Fatalf("DefaultHost must be Tier 0 DIRECT, got %+v", a)
	}

	// Tier 1: custom_proxy_domains beats .ru and sanitized URL/port/frag
	if a := matcher.Classify("custom-ai.example"); a.Action != "PROXY" || a.Rule != "custom_proxy" {
		t.Fatalf("sanitized custom-ai.example must be PROXY, got %+v", a)
	}
	if a := matcher.Classify("habr.ru"); a.Action != "PROXY" || a.Rule != "custom_proxy" {
		t.Fatalf("Tier 1 custom_proxy must override .ru, got %+v", a)
	}

	// Tier 2: custom_direct_domains beats enabled mcp category
	if a := matcher.Classify("github.com"); a.Action != "DIRECT" || a.Rule != "custom_direct" {
		t.Fatalf("Tier 2 custom_direct must beat enabled mcp category for github.com, got %+v", a)
	}

	// Tier 3: unified BuiltinDirectDomains
	for _, dirDom := range []string{"store.steampowered.com", "cdn.steamstatic.com", "ctldl.windowsupdate.com", "launcher.epicgames.com", "eu.battle.net", "wargaming.net"} {
		if a := matcher.Classify(dirDom); a.Action != "DIRECT" {
			t.Fatalf("BuiltinDirectDomains %q must be DIRECT, got %+v", dirDom, a)
		}
	}

	// PAC injection sanitization check
	pac := GenerateSmartPACJS(cfg, "127.0.0.1")
	if strings.Contains(pac, "alert(1)") {
		t.Fatalf("PAC must reject JS injection payload")
	}
	if !strings.Contains(pac, `"custom-ai.example"`) || !strings.Contains(pac, `"habr.ru"`) {
		t.Fatalf("PAC missing sanitized CUSTOM_PROXY_RULES")
	}
	customProxyIdx := strings.Index(pac, "CUSTOM_PROXY_RULES")
	ruTLDIdx := strings.Index(pac, "_endsWith(h, '.ru')")
	if customProxyIdx < 0 || ruTLDIdx < 0 || customProxyIdx > ruTLDIdx {
		t.Fatalf("PAC must evaluate CUSTOM_PROXY_RULES before .ru TLD")
	}

	// Now delete custom_proxy_domains & custom_direct_domains and rebuild: deletions must take effect!
	cfg.CustomProxy = nil
	cfg.CustomDirect = nil
	cfg.RebuildEffectiveRules()
	matcher.UpdateFromConfig(cfg)

	if a := matcher.Classify("habr.ru"); a.Action != "DIRECT" {
		t.Fatalf("after deleting habr.ru from CustomProxy, habr.ru must revert to DIRECT, got %+v", a)
	}
	if a := matcher.Classify("custom-ai.example"); a.Action != "DIRECT" {
		t.Fatalf("after deleting custom-ai.example from CustomProxy, must revert to DIRECT, got %+v", a)
	}
	if a := matcher.Classify("github.com"); a.Action != "PROXY" {
		t.Fatalf("after deleting github.com from CustomDirect, must revert to PROXY via mcp, got %+v", a)
	}
}

func TestV220TemporaryProxyTTLInstantWakeAndConcurrentWSLReload(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "active_config.json")

	cfg := DefaultEngineConfig()
	cfg.HTTPPort = 0
	cfg.SOCKSPort = 0
	cfg.ProxyAll = false
	cfg.Categories = map[string]bool{"antigravity": false, "ai": false, "mcp": false, "media": false, "social": false}
	cfg.ConfigPath = cfgPath
	cfg.RebuildEffectiveRules()

	mux := NewMuxManager(cfg, nil)
	defer mux.Close()

	srv := NewLocalProxyServer(LocalProxyOptions{
		Config:     cfg,
		Mux:        mux,
		LocalToken: "v220-tok",
	})
	var wslToggleMu sync.Mutex
	var wslActive atomic.Bool
	srv.findWSLBridgeIPFn = func() (string, error) {
		return "172.25.10.1", nil
	}
	srv.listenWSLFunc = func(network, address string) (net.Listener, error) {
		wslToggleMu.Lock()
		defer wslToggleMu.Unlock()
		wslActive.Store(true)
		return net.Listen(network, "127.0.0.1:0")
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start: %v", err)
	}
	defer srv.Close()

	baseURL := "http://" + srv.HTTPAddr()
	client := &http.Client{Timeout: 3 * time.Second}

	// 1. Set temporary_proxy_domains with short TTL (1s) and instant_wake=false
	reqTemp, _ := http.NewRequest(http.MethodPost, baseURL+"/__pixelcore/v4/reload-rules",
		strings.NewReader(`{"temporary_proxy_domains":["oauth-temp.ru"],"temporary_proxy_ttl_sec":1,"instant_wake":false}`))
	reqTemp.Header.Set("X-Pixel-Local-Token", "v220-tok")
	respTemp, err := client.Do(reqTemp)
	if err != nil {
		t.Fatalf("POST temp rules: %v", err)
	}
	var outTemp struct {
		OK            bool   `json:"ok"`
		PACRev        uint64 `json:"pac_rev"`
		InstantWake   bool   `json:"instant_wake"`
		TempDomains   int    `json:"temporary_proxy_domains"`
	}
	_ = json.NewDecoder(respTemp.Body).Decode(&outTemp)
	_ = respTemp.Body.Close()
	if respTemp.StatusCode != http.StatusOK || !outTemp.OK || outTemp.InstantWake || outTemp.TempDomains != 1 {
		t.Fatalf("unexpected reload response: status=%d out=%+v", respTemp.StatusCode, outTemp)
	}
	if act := srv.matcher.Classify("oauth-temp.ru"); act.Action != "PROXY" || act.Rule != "temporary_proxy" {
		t.Fatalf("expected active temporary_proxy to override .ru, got %+v", act)
	}
	// Verify temporary_proxy_domains are NOT persisted to disk
	diskBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if strings.Contains(string(diskBytes), "oauth-temp.ru") {
		t.Fatalf("temporary_proxy_domains must NEVER be saved to disk: %s", string(diskBytes))
	}
	if mux.isInstantWakeEnabled() {
		t.Fatalf("expected instant_wake=false on MuxManager")
	}

	// Wait for automatic 1s expiry -> must bump pacRev and revert oauth-temp.ru to DIRECT
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.PACRev() > outTemp.PACRev && srv.matcher.Classify("oauth-temp.ru").Action == "DIRECT" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if srv.PACRev() <= outTemp.PACRev || srv.matcher.Classify("oauth-temp.ru").Action != "DIRECT" {
		t.Fatalf("temporary_proxy did not auto-expire and bump pacRev (rev=%d vs %d, act=%+v)",
			srv.PACRev(), outTemp.PACRev, srv.matcher.Classify("oauth-temp.ru"))
	}

	// 2. Verify ttl==0 and empty slice [] clearing
	for _, clearBody := range []string{`{"temporary_proxy_ttl_sec":0}`, `{"temporary_proxy_domains":[]}`} {
		rSet, _ := http.NewRequest(http.MethodPost, baseURL+"/__pixelcore/v4/reload-rules",
			strings.NewReader(`{"temporary_proxy_domains":["temp-clear.example"],"temporary_proxy_ttl_sec":60}`))
		rSet.Header.Set("X-Pixel-Local-Token", "v220-tok")
		respS, _ := client.Do(rSet)
		_ = respS.Body.Close()
		if srv.matcher.Classify("temp-clear.example").Action != "PROXY" {
			t.Fatalf("expected temp-clear.example PROXY before clear")
		}

		rClr, _ := http.NewRequest(http.MethodPost, baseURL+"/__pixelcore/v4/reload-rules", strings.NewReader(clearBody))
		rClr.Header.Set("X-Pixel-Local-Token", "v220-tok")
		respC, _ := client.Do(rClr)
		_ = respC.Body.Close()
		if srv.matcher.Classify("temp-clear.example").Action != "DIRECT" {
			t.Fatalf("expected temp-clear.example cleared to DIRECT by %s", clearBody)
		}
	}

	// 3. Concurrent /reload-rules wsl_bridge toggling must converge to authoritative s.cfg state
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			want := idx%2 == 0
			req, _ := http.NewRequest(http.MethodPost, baseURL+"/__pixelcore/v4/reload-rules",
				strings.NewReader(fmt.Sprintf(`{"wsl_bridge":%t}`, want)))
			req.Header.Set("X-Pixel-Local-Token", "v220-tok")
			resp, rerr := client.Do(req)
			if rerr == nil {
				_ = resp.Body.Close()
			}
		}(i)
	}
	wg.Wait()

	// Final deterministic toggle OFF and ON check
	for _, want := range []bool{false, true, false} {
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/__pixelcore/v4/reload-rules",
			strings.NewReader(fmt.Sprintf(`{"wsl_bridge":%t}`, want)))
		req.Header.Set("X-Pixel-Local-Token", "v220-tok")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("final wsl toggle %t: %v", want, err)
		}
		_ = resp.Body.Close()
		if (srv.WSLBridgeIP() != "") != want {
			t.Fatalf("after serialized reload wsl_bridge=%t, got WSLBridgeIP=%q", want, srv.WSLBridgeIP())
		}
	}
}

func TestV220TUNNonBlockingUDPRXNATKeyAndRadarCoalescing(t *testing.T) {
	// 1. Non-blocking RX when mux.GetOrConnectSession blocks
	cfg := DefaultEngineConfig()
	cfg.ProxyAll = true
	cfg.RebuildEffectiveRules()
	matcher := NewDomainRuleMatcher(cfg)

	blockDial := make(chan struct{})
	mux := NewMuxManager(cfg, nil)
	mux.dialNodeOverride = func(ctx context.Context, node NodeConfig, forcePWP3 bool) (*ClientMuxSession, string, error) {
		select {
		case <-blockDial:
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
		return nil, "", context.DeadlineExceeded
	}
	defer func() {
		close(blockDial)
		mux.Close()
	}()

	radar := NewRouteRadar(100)
	proc := NewTUNPacketProcessor(TUNOptions{
		ClassifyFn: matcher.Classify,
		Mux:        mux,
		Radar:      radar,
	}, net.IPv4(198, 18, 0, 1), 40010, func(pkt []byte) error { return nil })
	defer proc.Close()

	// Flood > MaxTUNUDPQueue (48) packets to a single flow while dial is blocked: ProcessPacket must return immediately!
	clientIP := net.IPv4(198, 18, 0, 1)
	dstFake := proc.FakeIP.Assign("voice.discord.gg")
	t0 := time.Now()
	for i := 0; i < MaxTUNUDPQueue+30; i++ {
		proc.ProcessPacket(buildIPv4UDPPacket(clientIP, dstFake, 57001, 50001, []byte("udp-burst")))
	}
	if elapsed := time.Since(t0); elapsed > 200*time.Millisecond {
		t.Fatalf("ProcessPacket blocked on UDP dial/queue: took %v", elapsed)
	}

	// 2. TUNNATTable keyed by (srcIP, srcPort) isolates two distinct srcIPs sharing the same srcPort
	nat := NewTUNNATTable(net.IPv4(198, 18, 0, 1), 40011, proc.FakeIP, 32)
	c1 := net.IPv4(198, 18, 0, 10)
	c2 := net.IPv4(198, 18, 0, 11)
	d1 := proc.FakeIP.Assign("api.anthropic.com")
	d2 := proc.FakeIP.Assign("api.openai.com")
	if _, ok := nat.TranslateOutbound(buildIPv4TCPPacket(c1, d1, 55555, 443, 1, 0, tcpFlagSYN, nil)); !ok {
		t.Fatal("TranslateOutbound c1 failed")
	}
	if _, ok := nat.TranslateOutbound(buildIPv4TCPPacket(c2, d2, 55555, 443, 1, 0, tcpFlagSYN, nil)); !ok {
		t.Fatal("TranslateOutbound c2 failed")
	}
	if nat.Count() != 2 {
		t.Fatalf("expected 2 NAT entries for distinct (srcIP, srcPort), got %d", nat.Count())
	}
	h1, _, _, ok1 := nat.LookupOriginalTargetForClient(c1, 55555)
	h2, _, _, ok2 := nat.LookupOriginalTargetForClient(c2, 55555)
	if !ok1 || !ok2 || h1 != "api.anthropic.com" || h2 != "api.openai.com" {
		t.Fatalf("NAT collision across distinct srcIPs: h1=%q (%v) h2=%q (%v)", h1, ok1, h2, ok2)
	}

	// 3. RouteRadar TUN-UDP coalescing + <=30 slot cap protects TCP/AI routes
	r := NewRouteRadar(100)
	for i := 0; i < 10; i++ {
		r.Record(RouteRadarEntry{
			Proto:  "CONNECT",
			Domain: fmt.Sprintf("ai-endpoint-%d.googleapis.com", i),
			Port:   443,
			Action: "PROXY",
		})
	}
	for i := 0; i < 80; i++ {
		// Each STUN host sent twice -> should coalesce
		dom := fmt.Sprintf("198.51.100.%d", i+1)
		r.Record(RouteRadarEntry{Proto: "TUN-UDP", Domain: dom, Port: 3478, Action: "PROXY", BytesUp: 100})
		r.Record(RouteRadarEntry{Proto: "TUN-UDP", Domain: dom, Port: 3478, Action: "PROXY", BytesUp: 50})
	}
	entries := r.List(100)
	tcpCount, udpCount := 0, 0
	for _, e := range entries {
		if e.Proto == "CONNECT" {
			tcpCount++
		} else if e.Proto == "TUN-UDP" {
			udpCount++
		}
	}
	if tcpCount != 10 {
		t.Fatalf("STUN/ICE UDP burst evicted TCP/AI routes: got %d CONNECT entries, want 10", tcpCount)
	}
	if udpCount > 30 {
		t.Fatalf("TUN-UDP lane exceeded 30-slot cap: got %d", udpCount)
	}
}

func TestV220OpenStreamCtxCancelAndSharedClearRoleSession(t *testing.T) {
	pCli, pSrv := net.Pipe()
	defer pCli.Close()
	defer pSrv.Close()

	// Drain server reads so WriteFrame doesn't block, but NEVER send SynAck back
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := pSrv.Read(buf); err != nil {
				return
			}
		}
	}()

	mat, err := DerivePWP4KeyMaterial("ctx-cancel-secret", "cli-c", "srv-c")
	if err != nil {
		t.Fatalf("DerivePWP4KeyMaterial: %v", err)
	}
	cTx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	cRx, _ := newPWP4Cipher(mat[32:64], mat[80:96])

	cfg := DefaultEngineConfig()
	cfg.V2.FailoverTimeoutMs = 4000
	mux := NewMuxManager(cfg, nil)
	defer mux.Close()

	node := NodeConfig{Name: "SharedEdge", Host: "10.0.0.9", Port: 443, Mux: true}
	sess := NewClientMuxSession(pCli, bufio.NewReader(pCli), &pwp4ClientCodec{rx: cRx, tx: cTx}, node, LicenseMetadata{Proto: "PWP-4"})

	mux.mu.Lock()
	mux.sessions["ai"] = sess
	mux.sessions["media"] = sess
	mux.mu.Unlock()
	mux.recordPrimaryPing(sess, 42)

	// OpenStream must abort promptly when ctx is canceled
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	_, _, oerr := mux.OpenStream(ctx, "ai", "api.anthropic.com", 443)
	if oerr == nil {
		t.Fatal("expected OpenStream to return error on canceled ctx")
	}
	if time.Since(t0) > 600*time.Millisecond {
		t.Fatalf("OpenStream ignored ctx.Done() and blocked for %v", time.Since(t0))
	}

	// clearRoleSession("media", sess) must clear BOTH "media" and "ai" AND lastPingSess
	mux.clearRoleSession("media", sess)
	snap := mux.Snapshot()
	if snap.Connected || snap.PingMs != 0 {
		t.Fatalf("expected shared clearRoleSession to clear ai and PingMs, got Connected=%v PingMs=%d", snap.Connected, snap.PingMs)
	}
	mux.mu.Lock()
	aiSess := mux.sessions["ai"]
	mediaSess := mux.sessions["media"]
	lastPingSess := mux.lastPingSess
	mux.mu.Unlock()
	if aiSess != nil || mediaSess != nil || lastPingSess != nil {
		t.Fatalf("expected all matching roles and lastPingSess cleared, got ai=%v media=%v ping=%v", aiSess, mediaSess, lastPingSess)
	}
}

func TestV220WakeDedupeDialMediaConnectGenUDPFlushAndQUICRateLimit(t *testing.T) {
	// 1. TriggerInstantWake 2s dedupe window + dialFreshMediaSession connectGen check
	cfg := DefaultEngineConfig()
	cfg.Nodes = []NodeConfig{{Name: "N1", Host: "10.0.0.1", Port: 443, Mux: true, Roles: []string{"ai", "media"}}}
	cfg.ActiveNode = cfg.Nodes[0]
	mux := NewMuxManager(cfg, nil)
	defer mux.Close()

	var dials atomic.Int32
	mux.dialNodeOverride = func(ctx context.Context, node NodeConfig, forcePWP3 bool) (*ClientMuxSession, string, error) {
		dials.Add(1)
		pCli, pSrv := net.Pipe()
		go func() {
			buf := make([]byte, 1024)
			for {
				if _, err := pSrv.Read(buf); err != nil {
					return
				}
			}
		}()
		mat, _ := DerivePWP4KeyMaterial("wake-dedupe-sec", "cli", "srv")
		cTx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
		cRx, _ := newPWP4Cipher(mat[32:64], mat[80:96])
		sess := NewClientMuxSession(pCli, bufio.NewReader(pCli), &pwp4ClientCodec{rx: cRx, tx: cTx}, node, LicenseMetadata{Proto: "PWP-4"})
		return sess, "HelloChrome_Auto", nil
	}

	if _, err := mux.TriggerInstantWake("power_resume"); err != nil {
		t.Fatalf("first TriggerInstantWake failed: %v", err)
	}
	// Second simultaneous wake within 2s must be deduped (instantWakeCount stays 1)
	if _, err := mux.TriggerInstantWake("clock_jump"); err != nil {
		t.Fatalf("second TriggerInstantWake failed: %v", err)
	}
	if snap := mux.Snapshot(); snap.InstantWakeCount != 1 {
		t.Fatalf("expected TriggerInstantWake 2s dedupe to keep InstantWakeCount=1, got %d", snap.InstantWakeCount)
	}

	// dialFreshMediaSession racing with connectGen bump must abort
	mux2 := NewMuxManager(cfg, nil)
	defer mux2.Close()
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	mux2.dialNodeOverride = func(ctx context.Context, node NodeConfig, forcePWP3 bool) (*ClientMuxSession, string, error) {
		close(dialStarted)
		<-releaseDial
		pCli, pSrv := net.Pipe()
		_ = pSrv.Close()
		mat, _ := DerivePWP4KeyMaterial("gen-race-sec", "cli", "srv")
		cTx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
		cRx, _ := newPWP4Cipher(mat[32:64], mat[80:96])
		return NewClientMuxSession(pCli, bufio.NewReader(pCli), &pwp4ClientCodec{rx: cRx, tx: cTx}, node, LicenseMetadata{Proto: "PWP-4"}), "HelloChrome_Auto", nil
	}
	errCh := make(chan error, 1)
	go func() {
		_, derr := mux2.dialFreshMediaSession(context.Background())
		errCh <- derr
	}()
	<-dialStarted
	mux2.connectGen.Add(1)
	close(releaseDial)
	if derr := <-errCh; derr == nil {
		t.Fatalf("expected dialFreshMediaSession to reject stale connectGen after wake")
	}

	// 2. Atomic UDP flow bytesUp/bytesDown flush on GC/close + rate-limited QUIC UDP:443 signal
	radar := NewRouteRadar(100)
	var icmpCount atomic.Int32
	proc := NewTUNPacketProcessor(TUNOptions{
		ClassifyFn: func(host string) RuleAction {
			return RuleAction{Action: "PROXY", Rule: "test", Role: "media"}
		},
		Mux:   mux,
		Radar: radar,
	}, net.IPv4(198, 18, 0, 1), 40012, func(pkt []byte) error {
		if len(pkt) >= 28 && pkt[9] == 1 && pkt[20] == 3 && pkt[21] == 3 {
			icmpCount.Add(1)
		}
		return nil
	})
	defer proc.Close()

	clientIP := net.IPv4(198, 18, 0, 1)
	quicFake := proc.FakeIP.Assign("quic.example.com")
	for i := 0; i < 10; i++ {
		proc.ProcessPacket(buildIPv4UDPPacket(clientIP, quicFake, 58001, 443, []byte("quic-chlo")))
	}
	if icmpCount.Load() != 1 {
		t.Fatalf("expected rate-limited QUIC UDP:443 to emit 1 ICMP signal for burst, got %d", icmpCount.Load())
	}

	// Verify UDP flow bytesUp/bytesDown flush to RouteRadar on GC
	var key udpFlowKey
	copy(key.clientIP[:], clientIP.To4())
	key.clientPort = 58002
	flow := proc.getOrCreateUDPFlow(key, true, "media")
	seq := proc.recordTUNRoute("TUN-UDP", "voice-flush.example", 50005, RuleAction{Action: "PROXY", Rule: "test", Role: "media"}, "N1", 10, 50, "")
	flow.primaryRadarSeq.Store(seq)
	flow.bytesUp.Add(300)
	flow.bytesDown.Add(700)
	proc.gcIdleUDPFlows(time.Now().Add(2*DefaultTUNUDPIdleTimeout), DefaultTUNUDPIdleTimeout)

	var foundFlushed bool
	for _, e := range radar.List(10) {
		if e.Domain == "voice-flush.example" && e.Proto == "TUN-UDP" {
			foundFlushed = true
			if e.BytesUp != 350 || e.BytesDown != 700 {
				t.Fatalf("expected flushed UDP traffic Up=350 Down=700, got Up=%d Down=%d", e.BytesUp, e.BytesDown)
			}
		}
	}
	if !foundFlushed {
		t.Fatalf("expected voice-flush.example entry in RouteRadar")
	}
}
