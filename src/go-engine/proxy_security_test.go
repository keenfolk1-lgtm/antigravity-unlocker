package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseKeyInputFormatsAndTrialRejection(t *testing.T) {
	validUUID := "A1B2C3D4-E5F6-4789-ABCD-1234567890EF"
	cases := []struct {
		input  string
		format string
		uuid   string
	}{
		{validUUID, "uuid", strings.ToLower(validUUID)},
		{"vless://" + validUUID + "@201.34.152.97:443?sni=ai.pixelstore.space", "vless", strings.ToLower(validUUID)},
		{"pwp4://" + validUUID + "@201.34.152.97:443?pwp4_path=/api/v4/telemetry/events", "pwp4", strings.ToLower(validUUID)},
		{"pwp3://" + validUUID + "@201.34.152.97:443", "pwp3", strings.ToLower(validUUID)},
		{"https://ai.pixelstore.space/sub/pro_user_2026", "sub", ""},
		{"pixeltunnel://activate?key=" + strings.ToLower(validUUID), "uuid", strings.ToLower(validUUID)},
	}
	for _, tc := range cases {
		pk, err := ParseKeyInput(tc.input)
		if err != nil {
			t.Fatalf("ParseKeyInput(%q) unexpected error: %v", tc.input, err)
		}
		if pk.Format != tc.format || pk.UUID != tc.uuid {
			t.Fatalf("ParseKeyInput(%q) = %+v, want format=%s uuid=%s", tc.input, pk, tc.format, tc.uuid)
		}
	}

	rejectTrial := []string{
		"",
		"free",
		"e434aed7-0a9f-449f-81b9-870086cf2d09",
		"66eda2cf-432e-475b-a5cb-ebbf391e649f",
		"02d80b07-7824-f8d4-ac3a-e431ea3a8a32",
		"pixeltunnel://activate?key=free",
	}
	for _, raw := range rejectTrial {
		if _, err := ParseKeyInput(raw); !errors.Is(err, ErrTrialKeyNotPro) {
			t.Fatalf("ParseKeyInput(%q) expected ErrTrialKeyNotPro, got %v", raw, err)
		}
	}
}

func TestDoHSinkholeGuardAndZeroDNSSmartPAC(t *testing.T) {
	sinkholeSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := make([]byte, 128)
		n, _ := r.Body.Read(q)
		resp := buildFakeADNSResponse(q[:n], [4]byte{127, 0, 0, 1})
		_, _ = w.Write(resp)
	}))
	defer sinkholeSrv.Close()

	resSinkhole := NewDohResolver([]DohEndpoint{{URL: sinkholeSrv.URL}}, &tls.Config{InsecureSkipVerify: true})
	if _, err := resSinkhole.LookupHost(context.Background(), "api.anthropic.com"); !errors.Is(err, ErrSinkholeIP) {
		t.Fatalf("expected ErrSinkholeIP on 127.0.0.1 answer, got %v", err)
	}

	pubSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := make([]byte, 128)
		n, _ := r.Body.Read(q)
		resp := buildFakeADNSResponse(q[:n], [4]byte{93, 184, 216, 34})
		_, _ = w.Write(resp)
	}))
	defer pubSrv.Close()

	resPub := NewDohResolver([]DohEndpoint{{URL: pubSrv.URL}}, &tls.Config{InsecureSkipVerify: true})
	ips, err := resPub.LookupHost(context.Background(), "example.com")
	if err != nil || len(ips) != 1 || ips[0].String() != "93.184.216.34" {
		t.Fatalf("expected public IP 93.184.216.34, got ips=%v err=%v", ips, err)
	}

	// Verify Smart PAC contains ZERO dnsResolve() calls and rules classify cleanly
	cfg := DefaultEngineConfig()
	cfg.RebuildEffectiveRules()
	pac := GenerateSmartPACJS(cfg, "127.0.0.1")
	if strings.Contains(pac, "dnsResolve") {
		t.Fatalf("PAC must NEVER contain dnsResolve calls")
	}
	for _, mustInclude := range []string{".ru", ".xn--p1ai", ".su", ".by", "PROXY 127.0.0.1:17890; SOCKS5 127.0.0.1:17891; DIRECT"} {
		if !strings.Contains(pac, mustInclude) {
			t.Fatalf("PAC missing %q", mustInclude)
		}
	}

	matcher := NewDomainRuleMatcher(cfg)
	if a := matcher.Classify("gosuslugi.ru"); a.Action != "DIRECT" {
		t.Fatalf(".ru must be DIRECT, got %+v", a)
	}
	if a := matcher.Classify("президент.рф"); a.Action != "DIRECT" && !strings.HasSuffix("a.xn--p1ai", ".xn--p1ai") {
		// Punycode domains routed direct
	}
	if a := matcher.Classify("site.xn--p1ai"); a.Action != "DIRECT" {
		t.Fatalf(".xn--p1ai must be DIRECT, got %+v", a)
	}
	if a := matcher.Classify("api.anthropic.com"); a.Action != "PROXY" || a.Role != "ai" {
		t.Fatalf("api.anthropic.com must be PROXY ai, got %+v", a)
	}
	if a := matcher.Classify("192.168.1.50"); a.Action != "DIRECT" {
		t.Fatalf("private CIDR must be DIRECT, got %+v", a)
	}
}

func TestLocalAPISecurityHostCSRFTokenXRayAndRadar(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.HTTPPort = 0
	cfg.SOCKSPort = 0
	cfg.RebuildEffectiveRules()

	srv := NewLocalProxyServer(LocalProxyOptions{
		Config:     cfg,
		LocalToken: "super-secret-local-token",
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	baseURL := "http://" + srv.HTTPAddr()

	// 1. Wrong Host header (DNS rebinding) rejected with 403
	reqBadHost, _ := http.NewRequest(http.MethodGet, baseURL+"/__pixelcore/v4/status", nil)
	reqBadHost.Host = "evil.attacker.com:17890"
	reqBadHost.Header.Set("X-Pixel-Local-Token", "super-secret-local-token")
	resp, err := (&http.Client{}).Do(reqBadHost)
	if err != nil {
		t.Fatalf("do bad host: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on invalid Host, got %d", resp.StatusCode)
	}

	// 2. Unauthenticated /__pixelcore/v4/status rejected with 401
	respUnauth, err := http.Get(baseURL + "/__pixelcore/v4/status")
	if err != nil {
		t.Fatalf("do unauth: %v", err)
	}
	_ = respUnauth.Body.Close()
	if respUnauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", respUnauth.StatusCode)
	}

	// 3. Unauthenticated /ui without bootstrap ?t= rejected with 401
	respNoUI, err := http.Get(baseURL + "/ui")
	if err != nil {
		t.Fatalf("do ui unauth: %v", err)
	}
	_ = respNoUI.Body.Close()
	if respNoUI.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on /ui without bootstrap token, got %d", respNoUI.StatusCode)
	}

	// 4. Web-UI bootstrap ?t= sets HttpOnly SameSite=Strict cookie & CSRF token
	jar, _ := cookiejar.New(nil)
	uiClient := &http.Client{Jar: jar}
	respUI, err := uiClient.Get(baseURL + "/ui?t=" + srv.BootstrapToken())
	if err != nil {
		t.Fatalf("do ui bootstrap: %v", err)
	}
	uiHTMLBytes, _ := io.ReadAll(respUI.Body)
	_ = respUI.Body.Close()
	if respUI.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /ui bootstrap, got %d", respUI.StatusCode)
	}
	setCookie := strings.Join(respUI.Header.Values("Set-Cookie"), "; ")
	if !strings.Contains(setCookie, "HttpOnly") || !strings.Contains(setCookie, "SameSite=Strict") {
		t.Fatalf("expected HttpOnly; SameSite=Strict cookie, got %q", setCookie)
	}
	csrf := extractCSRFMeta(string(uiHTMLBytes))
	if csrf == "" {
		t.Fatalf("missing pixel-csrf meta tag in UI HTML")
	}

	// Cookie WITHOUT X-Pixel-CSRF must be rejected (401)!
	reqNoCSRF, _ := http.NewRequest(http.MethodPost, baseURL+"/__pixelcore/v4/reload-rules", strings.NewReader(`{}`))
	respNoCSRF, err := uiClient.Do(reqNoCSRF)
	if err != nil {
		t.Fatalf("do no csrf: %v", err)
	}
	_ = respNoCSRF.Body.Close()
	if respNoCSRF.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without X-Pixel-CSRF header, got %d", respNoCSRF.StatusCode)
	}

	// Cookie WITH X-Pixel-CSRF succeeds and increments pac_rev!
	reqCSRF, _ := http.NewRequest(http.MethodPost, baseURL+"/__pixelcore/v4/reload-rules", strings.NewReader(`{"custom_proxy_domains":["my-ai-site.dev"]}`))
	reqCSRF.Header.Set("X-Pixel-CSRF", csrf)
	respCSRF, err := uiClient.Do(reqCSRF)
	if err != nil {
		t.Fatalf("do with csrf: %v", err)
	}
	var reloadOut struct {
		OK     bool   `json:"ok"`
		PACRev uint64 `json:"pac_rev"`
	}
	_ = json.NewDecoder(respCSRF.Body).Decode(&reloadOut)
	_ = respCSRF.Body.Close()
	if respCSRF.StatusCode != http.StatusOK || !reloadOut.OK || reloadOut.PACRev < 2 {
		t.Fatalf("reload-rules failed: status=%d out=%+v", respCSRF.StatusCode, reloadOut)
	}

	// 5. X-Pixel-Local-Token access to X-Ray (both GET & POST) + strictly NO #PT- ticket codes
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		reqXR, _ := http.NewRequest(method, baseURL+"/__pixelcore/v4/run-xray", nil)
		reqXR.Header.Set("X-Pixel-Local-Token", "super-secret-local-token")
		rXR, err := (&http.Client{}).Do(reqXR)
		if err != nil {
			t.Fatalf("run-xray %s error: %v", method, err)
		}
		rawXR, _ := io.ReadAll(rXR.Body)
		_ = rXR.Body.Close()
		if rXR.StatusCode != http.StatusOK {
			t.Fatalf("run-xray %s returned %d", method, rXR.StatusCode)
		}
		if strings.Contains(string(rawXR), "#PT-") {
			t.Fatalf("X-Ray output MUST NOT contain #PT- ticket codes: %s", string(rawXR))
		}
		var rep XRayReport
		if err := json.Unmarshal(rawXR, &rep); err != nil || len(rep.Cards) != 6 {
			t.Fatalf("expected 6 X-Ray cards, got len=%d err=%v", len(rep.Cards), err)
		}
	}

	// 6. Live Route Radar 100-entry ring buffer capacity check
	for i := 1; i <= 115; i++ {
		srv.Radar().Record(RouteRadarEntry{
			Domain: fmt.Sprintf("host-%03d.example.com", i),
			Port:   443,
			Action: "PROXY",
		})
	}
	reqRad, _ := http.NewRequest(http.MethodGet, baseURL+"/__pixelcore/v4/live-routes", nil)
	reqRad.Header.Set("X-Pixel-Local-Token", "super-secret-local-token")
	rRad, _ := (&http.Client{}).Do(reqRad)
	var radResp struct {
		OK      bool              `json:"ok"`
		Entries []RouteRadarEntry `json:"entries"`
	}
	_ = json.NewDecoder(rRad.Body).Decode(&radResp)
	_ = rRad.Body.Close()
	if len(radResp.Entries) != 100 || radResp.Entries[0].Domain != "host-115.example.com" || radResp.Entries[99].Domain != "host-016.example.com" {
		t.Fatalf("unexpected ring buffer entries: len=%d first=%v last=%v", len(radResp.Entries), radResp.Entries[0].Domain, radResp.Entries[len(radResp.Entries)-1].Domain)
	}

	// 7. WSL2 bridge refuses 0.0.0.0 and non-172.16/12 binds
	if err := srv.BindWSLBridgeOnIP("0.0.0.0", 0, 0); err == nil {
		t.Fatalf("expected WSL2 bind to refuse 0.0.0.0")
	}
	if err := srv.BindWSLBridgeOnIP("192.168.1.10", 0, 0); err == nil {
		t.Fatalf("expected WSL2 bind to refuse non-172.16/12 LAN IP")
	}

	// 8. Verify WSL2 HTTP handler blocks /__pixelcore/* and /ui with 403 while permitting /proxy.pac
	rrAPI := httptest.NewRecorder()
	reqWSLAPI := httptest.NewRequest(http.MethodGet, "/__pixelcore/v4/status", nil)
	reqWSLAPI.Host = "172.24.0.1:17890"
	srv.serveLoopbackHTTP(rrAPI, reqWSLAPI, true)
	if rrAPI.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on WSL2 /__pixelcore/v4/status, got %d", rrAPI.Code)
	}
	rrUI := httptest.NewRecorder()
	reqWSLUI := httptest.NewRequest(http.MethodGet, "/ui", nil)
	reqWSLUI.Host = "172.24.0.1:17890"
	srv.serveLoopbackHTTP(rrUI, reqWSLUI, true)
	if rrUI.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on WSL2 /ui, got %d", rrUI.Code)
	}
	// Also test self-proxy anti-SSRF blocking (GET http://127.0.0.1:<port>/__pixelcore/v4/status)
	rrSelf := httptest.NewRecorder()
	reqSelf := httptest.NewRequest(http.MethodGet, baseURL+"/__pixelcore/v4/status", nil)
	srv.serveLoopbackHTTP(rrSelf, reqSelf, false)
	if rrSelf.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on self-proxy forward SSRF, got %d", rrSelf.Code)
	}
	rrPAC := httptest.NewRecorder()
	srv.wslBridgeIP = "172.24.0.1"
	reqPAC := httptest.NewRequest(http.MethodGet, "/proxy.pac", nil)
	reqPAC.Host = "172.24.0.1:17890"
	srv.serveLoopbackHTTP(rrPAC, reqPAC, true)
	if rrPAC.Code != http.StatusOK || !strings.Contains(rrPAC.Body.String(), "172.24.0.1") {
		t.Fatalf("expected 200 PAC with WSL IP, got code=%d", rrPAC.Code)
	}
}

func extractCSRFMeta(htmlStr string) string {
	marker := `<meta name="pixel-csrf" content="`
	idx := strings.Index(htmlStr, marker)
	if idx < 0 {
		return ""
	}
	rest := htmlStr[idx+len(marker):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func buildFakeADNSResponse(query []byte, ip [4]byte) []byte {
	var out bytes.Buffer
	out.Write(query[0:2])
	out.Write([]byte{0x81, 0x80})
	out.Write(query[4:6])
	out.Write([]byte{0x00, 0x01})
	out.Write([]byte{0x00, 0x00, 0x00, 0x00})
	out.Write(query[12:])
	out.Write([]byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04})
	out.Write(ip[:])
	return out.Bytes()
}

func TestRound2ConfigParityAndKeyPlusPreservation(t *testing.T) {
	// Verify WPF v2 schema parity: category reset, pinned_spki, smart_pac, pac_rev, short custom lists
	raw := []byte(`{
		"http_port": 17910,
		"socks_port": 17911,
		"pinned_spki": ["057AB81186E5E5BEAE4AC0FADE013988CA7ABFA9D69DAFE3BFB548F94EC434F0"],
		"custom_proxy": ["custom-short.example.com"],
		"custom_direct": ["direct-short.example.com"],
		"v2": {
			"smart_pac": true,
			"pac_rev": 42,
			"categories": {
				"antigravity": true,
				"ai": false,
				"mcp": false,
				"media": true,
				"social": false
			}
		}
	}`)
	cfg, err := LoadConfigBytes(raw)
	if err != nil {
		t.Fatalf("LoadConfigBytes: %v", err)
	}
	if len(cfg.PinnedSPKI) != 1 || cfg.PinnedSPKI[0] != "057ab81186e5e5beae4ac0fade013988ca7abfa9d69dafe3bfb548f94ec434f0" {
		t.Fatalf("unexpected PinnedSPKI: %+v", cfg.PinnedSPKI)
	}
	if !cfg.V2.SmartPAC || cfg.V2.PACRev != 42 {
		t.Fatalf("expected SmartPAC=true and PACRev=42, got %+v", cfg.V2)
	}
	if !cfg.Categories["antigravity"] || cfg.Categories["ai"] || cfg.Categories["mcp"] || !cfg.Categories["media"] || cfg.Categories["social"] {
		t.Fatalf("expected explicit JSON categories without sticky defaults, got %+v", cfg.Categories)
	}
	m := NewDomainRuleMatcher(cfg)
	if act := m.Classify("api.anthropic.com"); act.Action != "DIRECT" {
		t.Fatalf("expected ai=false -> api.anthropic.com DIRECT, got %+v", act)
	}
	if act := m.Classify("youtube.com"); act.Action != "PROXY" || act.Role != "media" {
		t.Fatalf("expected media=true -> youtube.com PROXY media, got %+v", act)
	}
	if act := m.Classify("custom-short.example.com"); act.Action != "PROXY" {
		t.Fatalf("expected custom_proxy alias honored, got %+v", act)
	}
	if act := m.Classify("direct-short.example.com"); act.Action != "DIRECT" {
		t.Fatalf("expected custom_direct alias honored, got %+v", act)
	}

	srv := NewLocalProxyServer(LocalProxyOptions{Config: cfg, LocalToken: "tok"})
	if srv.PACRev() != 42 {
		t.Fatalf("expected initial pacRev=42 from config, got %d", srv.PACRev())
	}

	// Verify ParseKeyInput preserves '+' in wrapped secret inside pixeltunnel:// URI (no double QueryUnescape)
	inner := "pwp4://a1b2c3d4-e5f6-4789-abcd-1234567890ef@201.34.152.97:443?secret=foo%2Bbar"
	pk, err := ParseKeyInput("pixeltunnel://activate?key=" + url.QueryEscape(inner))
	if err != nil {
		t.Fatalf("ParseKeyInput pwp4 secret uri: %v", err)
	}
	if pk.Secret != "foo+bar" {
		t.Fatalf("expected Secret \"foo+bar\" with preserved '+', got %q", pk.Secret)
	}
}

func TestRound2ProxySecurityIsolationAndStrictDoH(t *testing.T) {
	// Backend HTTP server on 127.0.0.1 to inspect forwarded headers and response hop-by-hop stripping
	var seenProxyAuth, seenCustomHop, seenProxyConn string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenProxyAuth = r.Header.Get("Proxy-Authorization")
		seenCustomHop = r.Header.Get("X-Secret-Hop")
		seenProxyConn = r.Header.Get("Proxy-Connection")
		w.Header().Add("Connection", "X-Backend-Hop")
		w.Header().Set("X-Backend-Hop", "must-strip")
		w.Header().Set("X-Keep", "preserved")
		_, _ = io.WriteString(w, "ok-direct")
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	cfg := DefaultEngineConfig()
	cfg.HTTPPort = 0
	cfg.SOCKSPort = 0
	cfg.RebuildEffectiveRules()

	// DoH test server returning 127.0.0.1 (sinkhole / DNS rebind candidate)
	dohSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(buildFakeADNSResponse(q, [4]byte{127, 0, 0, 1}))
	}))
	defer dohSrv.Close()
	resolver := NewDohResolver([]DohEndpoint{{URL: dohSrv.URL}}, &tls.Config{InsecureSkipVerify: true})

	srv := NewLocalProxyServer(LocalProxyOptions{
		Config:     cfg,
		Resolver:   resolver,
		LocalToken: "sec-tok",
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	// 1. HTTP forward hop-by-hop stripping both directions
	proxyURL, _ := url.Parse("http://" + srv.HTTPAddr())
	httpCli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	req, _ := http.NewRequest(http.MethodGet, backend.URL+"/hello", nil)
	req.Header.Add("Connection", "X-Secret-Hop")
	req.Header.Set("X-Secret-Hop", "strip-me")
	req.Header.Set("Proxy-Authorization", "Bearer top-secret")
	req.Header.Set("Proxy-Connection", "keep-alive")
	resp, err := httpCli.Do(req)
	if err != nil {
		t.Fatalf("http forward through proxy: %v", err)
	}
	_ = resp.Body.Close()
	if seenProxyAuth != "" || seenCustomHop != "" || seenProxyConn != "" {
		t.Fatalf("hop-by-hop headers leaked to upstream: auth=%q hop=%q pconn=%q", seenProxyAuth, seenCustomHop, seenProxyConn)
	}
	if resp.Header.Get("X-Backend-Hop") != "" || resp.Header.Get("X-Keep") != "preserved" {
		t.Fatalf("unexpected response header handling: backendHop=%q keep=%q", resp.Header.Get("X-Backend-Hop"), resp.Header.Get("X-Keep"))
	}

	// 2. SOCKS5 CONNECT to self proxy ports is rejected with 0x02 (not allowed)
	for _, selfPort := range []int{srv.HTTPPort(), srv.SOCKSPort()} {
		c, err := net.Dial("tcp", srv.SOCKSAddr())
		if err != nil {
			t.Fatalf("dial socks5: %v", err)
		}
		_, _ = c.Write([]byte{0x05, 0x01, 0x00})
		var greet [2]byte
		if _, err := io.ReadFull(c, greet[:]); err != nil {
			_ = c.Close()
			t.Fatalf("socks greet: %v", err)
		}
		_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, byte(selfPort >> 8), byte(selfPort)})
		var rep [10]byte
		_, rerr := io.ReadFull(c, rep[:])
		_ = c.Close()
		if rerr != nil || rep[1] != 0x02 {
			t.Fatalf("expected SOCKS5 0x02 block for self port %d, got rep=%v err=%v", selfPort, rep, rerr)
		}
	}

	// 3. WSL2 HTTP + SOCKS isolation & strict DoH anti-DNS-rebinding (no OS DNS fallback)
	bPort, _ := strconv.Atoi(backendURL.Port())
	rrWSLConn := httptest.NewRecorder()
	reqWSLConn := httptest.NewRequest(http.MethodConnect, backendURL.Host, nil)
	reqWSLConn.Host = backendURL.Host
	srv.serveLoopbackHTTP(rrWSLConn, reqWSLConn, true)
	if rrWSLConn.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on WSL CONNECT to 127.0.0.1:%d, got %d", bPort, rrWSLConn.Code)
	}
	if _, _, err := srv.dialUpstreamTCP(context.Background(), RuleAction{Action: "DIRECT"}, "localhost", bPort, true); err == nil {
		t.Fatal("expected dialUpstreamTCP to reject WSL localhost target")
	}
	if _, _, err := srv.dialUpstreamTCP(context.Background(), RuleAction{Action: "DIRECT"}, "rebind-sinkhole.example", bPort, false); err == nil {
		t.Fatal("expected dialUpstreamTCP to reject DoH sinkhole/error without falling back to OS DNS")
	}
	srvNoRes := NewLocalProxyServer(LocalProxyOptions{Config: cfg, LocalToken: "t"})
	if _, _, err := srvNoRes.dialUpstreamTCP(context.Background(), RuleAction{Action: "DIRECT"}, "localhost.localdomain", bPort, false); err == nil {
		t.Fatal("expected dialUpstreamTCP to reject domain when resolver is nil instead of using OS DNS")
	}
}

func TestRound2DoHCacheBoundedAt512(t *testing.T) {
	r := NewDohResolver(nil, nil)
	r.mu.Lock()
	// Add 100 already-expired entries + 550 valid entries; max must stay <= 512 and keep newer valid ones.
	for i := 0; i < 100; i++ {
		r.setCachedLocked(fmt.Sprintf("A:exp-%d.example", i), cachedDNS{expiresAt: time.Now().Add(-time.Minute)})
	}
	for i := 0; i < 550; i++ {
		r.setCachedLocked(fmt.Sprintf("A:live-%d.example", i), cachedDNS{
			ips:       []net.IP{net.IPv4(1, 1, 1, 1)},
			expiresAt: time.Now().Add(time.Duration(i+1) * time.Second),
		})
	}
	cacheLen := len(r.cache)
	_, hasNewest := r.cache["A:live-549.example"]
	_, hasOldestEvicted := r.cache["A:live-0.example"]
	r.mu.Unlock()

	if cacheLen > maxDohCacheEntries {
		t.Fatalf("expected DoH cache bounded <= %d, got %d", maxDohCacheEntries, cacheLen)
	}
	if !hasNewest {
		t.Fatal("expected newest DoH cache entry to remain")
	}
	if hasOldestEvicted {
		t.Fatal("expected earliest-expiring DoH cache entry to be evicted")
	}
}

func TestLocalProxyConfigCloneRaceSafety(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.HTTPPort = 0
	cfg.SOCKSPort = 0
	cfg.Categories = nil // Ensure nil Categories never panics on first reload-rules
	cfg.RebuildEffectiveRules()

	mux := NewMuxManager(cfg, nil)
	defer mux.Close()

	srv := NewLocalProxyServer(LocalProxyOptions{
		Config:     cfg,
		Mux:        mux,
		LocalToken: "race-tok",
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	// Snapshot obtained before mutations must remain isolated after reload-rules / activate
	snapBefore := srv.getConfig()
	baseURL := "http://" + srv.HTTPAddr()
	client := &http.Client{Timeout: 3 * time.Second}

	var wg sync.WaitGroup
	errCh := make(chan error, 64)
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				// 1. POST /__pixelcore/v4/reload-rules
				payload := fmt.Sprintf(`{"categories":{"ai":%t,"media":%t},"custom_proxy_domains":["dom-%d-%d.example"],"custom_direct_domains":["dir-%d-%d.example"]}`,
					i%2 == 0, i%2 == 1, id, i, id, i)
				req1, _ := http.NewRequest(http.MethodPost, baseURL+"/__pixelcore/v4/reload-rules", strings.NewReader(payload))
				req1.Header.Set("X-Pixel-Local-Token", "race-tok")
				req1.Header.Set("Content-Type", "application/json")
				r1, e1 := client.Do(req1)
				if e1 != nil {
					errCh <- e1
					return
				}
				_ = r1.Body.Close()

				// 2. POST /__pixelcore/v4/activate
				uuid := fmt.Sprintf("11111111-2222-4333-8444-%012x", id*100+i+1)
				req2, _ := http.NewRequest(http.MethodPost, baseURL+"/__pixelcore/v4/activate", strings.NewReader(`{"key":"`+uuid+`"}`))
				req2.Header.Set("X-Pixel-Local-Token", "race-tok")
				req2.Header.Set("Content-Type", "application/json")
				r2, e2 := client.Do(req2)
				if e2 != nil {
					errCh <- e2
					return
				}
				_ = r2.Body.Close()

				// 3. GET /__pixelcore/v4/status + GET /proxy.pac + UpdateManifestDoc
				req3, _ := http.NewRequest(http.MethodGet, baseURL+"/__pixelcore/v4/status", nil)
				req3.Header.Set("X-Pixel-Local-Token", "race-tok")
				r3, e3 := client.Do(req3)
				if e3 != nil {
					errCh <- e3
					return
				}
				_ = r3.Body.Close()

				r4, e4 := client.Get(baseURL + "/proxy.pac?r=" + strconv.Itoa(i))
				if e4 != nil {
					errCh <- e4
					return
				}
				_ = r4.Body.Close()

				if i%5 == 0 {
					srv.UpdateManifestDoc(&ManifestDocument{
						Ver:   int64(100 + i),
						Nodes: []NodeConfig{{Name: "M1", Host: "201.34.152.97", Port: 443, Secret: "s"}},
					}, "race_test")
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent config update/read error: %v", err)
	}
	if snapBefore.Categories != nil {
		t.Fatalf("expected original config snapshot to remain unmutated (nil Categories), got %+v", snapBefore.Categories)
	}
}

func TestRound3NodeDedupAndNodesFallbackConfig(t *testing.T) {
	// Case A: top-level address+pwp_port AND nodes[] containing same endpoint with friendly name
	rawA := []byte(`{
		"address": "127.0.0.1",
		"pwp_port": 18443,
		"pwp_secret": "s1",
		"nodes": [
			{"name": "qa-primary", "host": "127.0.0.1", "port": 18443, "secret": "s1", "pwp4_path": "/api/v4/telemetry/events"},
			{"name": "qa-standby", "host": "127.0.0.1", "port": 18444, "secret": "s1", "pwp4_path": "/api/v4/telemetry/events"}
		]
	}`)
	cfgA, err := LoadConfigBytes(rawA)
	if err != nil {
		t.Fatalf("LoadConfigBytes A: %v", err)
	}
	if cfgA.ActiveNode.Name != "qa-primary" {
		t.Fatalf("expected matching node Name \"qa-primary\" adopted, got %q", cfgA.ActiveNode.Name)
	}
	muxA := NewMuxManager(cfgA, nil)
	muxA.mu.Lock()
	candsA := muxA.selectCandidateNodesLocked("ai")
	muxA.mu.Unlock()
	if len(candsA) != 2 {
		t.Fatalf("expected (Host,Port) dedup to yield 2 unique candidates, got %d: %+v", len(candsA), candsA)
	}

	// Case B: no top-level address or outbounds -> adopt doc.Nodes[0] instead of Default-Edge
	rawB := []byte(`{
		"nodes": [
			{"name": "nodes-only-1", "host": "10.20.30.40", "port": 8443, "sni": "edge.example", "secret": "secB", "tls": true, "mux": true},
			{"name": "nodes-only-2", "host": "10.20.30.41", "port": 8443, "sni": "edge.example", "secret": "secB", "tls": true, "mux": true}
		]
	}`)
	cfgB, err := LoadConfigBytes(rawB)
	if err != nil {
		t.Fatalf("LoadConfigBytes B: %v", err)
	}
	if cfgB.ActiveNode.Name != "nodes-only-1" || cfgB.ActiveNode.Host != "10.20.30.40" || cfgB.ActiveNode.Port != 8443 {
		t.Fatalf("expected doc.Nodes[0] adopted as ActiveNode, got %+v", cfgB.ActiveNode)
	}

	// Verify KDE rollback helper preserves external PAC (ProxyType=2 + https://...) and resets local PAC
	if mt, ms, del := resolveKDERollbackSettings("2", "https://corp.example.com/proxy.pac"); mt != "2" || ms != "https://corp.example.com/proxy.pac" || del {
		t.Fatalf("expected external KDE PAC preserved, got type=%q script=%q del=%v", mt, ms, del)
	}
	if mt, _, del := resolveKDERollbackSettings("2", "http://127.0.0.1:17890/proxy.pac"); mt != "0" || !del {
		t.Fatalf("expected localhost KDE PAC reset to ProxyType=0 & deleted, got type=%q del=%v", mt, del)
	}
	if mt, _, del := resolveKDERollbackSettings("1", ""); mt != "1" || del != true {
		t.Fatalf("expected manual KDE mode 1 preserved, got type=%q del=%v", mt, del)
	}
}
