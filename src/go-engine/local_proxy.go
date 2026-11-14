package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// LocalProxyServer serves HTTP/CONNECT proxy, SOCKS5h TCP+UDP proxy, optional WSL2 bridge,
// Zero-DNS PAC endpoint, /__pixelcore/telemetry, strict Host/Token/CSRF-protected v4 API, and Web-UI.
type LocalProxyServer struct {
	mu          sync.RWMutex
	cfg         *EngineConfig
	matcher     *DomainRuleMatcher
	mux         *MuxManager
	resolver    *DohResolver
	radar       *RouteRadar
	xray        *XRayRunner
	headless    bool
	manifestVer int64
	manifestSrc string

	localToken  string
	uiHandler   http.Handler // mounted at /ui* when standalone
	uiCSRFStore *WebSessionStore

	httpListener net.Listener
	socksLn      net.Listener
	wslHTTPLn    net.Listener
	wslSOCKSLn   net.Listener
	wslBridgeIP  string
	wslHTTPPort  int
	wslSOCKSPort int

	pacRev      atomic.Uint64
	activeConns atomic.Int64
	bytesUp     atomic.Int64
	bytesDown   atomic.Int64
	startedAt   time.Time

	onRulesReloaded func(cfg *EngineConfig, pacRev uint64)
	stopOnce        sync.Once
	stopCh          chan struct{}
}

// LocalProxyOptions configures LocalProxyServer startup.
type LocalProxyOptions struct {
	Config          *EngineConfig
	Mux             *MuxManager
	Resolver        *DohResolver
	Headless        bool
	LocalToken      string
	ManifestVer     int64
	ManifestSrc     string
	OnRulesReloaded func(cfg *EngineConfig, pacRev uint64)
}

// NewLocalProxyServer initializes the server without starting listeners yet.
func NewLocalProxyServer(opts LocalProxyOptions) *LocalProxyServer {
	cfg := opts.Config
	if cfg == nil {
		cfg = DefaultEngineConfig()
	}
	token := strings.TrimSpace(opts.LocalToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("PIXEL_LOCAL_TOKEN"))
	}
	if token == "" {
		var rnd [24]byte
		_, _ = rand.Read(rnd[:])
		token = hex.EncodeToString(rnd[:])
	}

	radar := NewRouteRadar(100)
	matcher := NewDomainRuleMatcher(cfg)

	srv := &LocalProxyServer{
		cfg:             cfg,
		matcher:         matcher,
		mux:             opts.Mux,
		resolver:        opts.Resolver,
		radar:           radar,
		headless:        opts.Headless,
		manifestVer:     opts.ManifestVer,
		manifestSrc:     opts.ManifestSrc,
		localToken:      token,
		uiCSRFStore:     NewWebSessionStore(),
		startedAt:       time.Now(),
		onRulesReloaded: opts.OnRulesReloaded,
		stopCh:          make(chan struct{}),
	}
	initRev := uint64(1)
	if cfg.V2.PACRev > 1 {
		initRev = cfg.V2.PACRev
	}
	srv.pacRev.Store(initRev)
	srv.xray = NewXRayRunner(srv.getConfig, opts.Mux, opts.Resolver, radar)
	srv.uiHandler = srv.buildWebUIHandler()
	return srv
}

func (s *LocalProxyServer) LocalToken() string     { return s.localToken }
func (s *LocalProxyServer) BootstrapToken() string { return s.uiCSRFStore.BootstrapToken() }
func (s *LocalProxyServer) PACRev() uint64         { return s.pacRev.Load() }
func (s *LocalProxyServer) WSLBridgeIP() string    { return s.wslBridgeIP }
func (s *LocalProxyServer) Radar() *RouteRadar     { return s.radar }
func (s *LocalProxyServer) HTTPAddr() string {
	if s.httpListener != nil {
		return s.httpListener.Addr().String()
	}
	return ""
}
func (s *LocalProxyServer) SOCKSAddr() string {
	if s.socksLn != nil {
		return s.socksLn.Addr().String()
	}
	return ""
}
func (s *LocalProxyServer) HTTPPort() int {
	if s.httpListener != nil {
		if ta, ok := s.httpListener.Addr().(*net.TCPAddr); ok {
			return ta.Port
		}
	}
	return s.getConfig().HTTPPort
}
func (s *LocalProxyServer) SOCKSPort() int {
	if s.socksLn != nil {
		if ta, ok := s.socksLn.Addr().(*net.TCPAddr); ok {
			return ta.Port
		}
	}
	return s.getConfig().SOCKSPort
}

// Start binds HTTP/CONNECT + SOCKS5h strictly on 127.0.0.1 and (if enabled) binds WSL2 bridge
// strictly to vEthernet (WSL) 172.16.0.0/12 (NEVER 0.0.0.0).
func (s *LocalProxyServer) Start() error {
	cfg := s.getConfig()
	httpBind := fmt.Sprintf("127.0.0.1:%d", cfg.HTTPPort)
	socksBind := fmt.Sprintf("127.0.0.1:%d", cfg.SOCKSPort)

	httpLn, err := net.Listen("tcp", httpBind)
	if err != nil {
		return fmt.Errorf("listen HTTP proxy %s: %w", httpBind, err)
	}
	socksLn, err := net.Listen("tcp", socksBind)
	if err != nil {
		_ = httpLn.Close()
		return fmt.Errorf("listen SOCKS5 proxy %s: %w", socksBind, err)
	}
	s.httpListener = httpLn
	s.socksLn = socksLn

	httpSrv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serveLoopbackHTTP(w, r, false) }),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = httpSrv.Serve(httpLn) }()
	go s.acceptSOCKSLoop(socksLn, false)

	if cfg.EnableWSLBridge {
		if wslIP, wErr := FindWSLBridgeIP(); wErr == nil && wslIP != "" && wslIP != "0.0.0.0" {
			_ = s.bindWSLBridge(wslIP, cfg.HTTPPort, cfg.SOCKSPort)
		}
	}
	return nil
}

// BindWSLBridgeOnIP allows tests or explicit callers to bind WSL listeners on a validated 172.16.0.0/12 IP.
func (s *LocalProxyServer) BindWSLBridgeOnIP(ipStr string, httpPort, socksPort int) error {
	return s.bindWSLBridge(ipStr, httpPort, socksPort)
}

func (s *LocalProxyServer) bindWSLBridge(ipStr string, httpPort, socksPort int) error {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil || ip.IsUnspecified() || !isIPIn17216Range(ip) {
		return fmt.Errorf("refusing non-WSL2 bind IP %q (must be 172.16.0.0/12, never 0.0.0.0)", ipStr)
	}
	wHTTP, err := net.Listen("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(httpPort)))
	if err != nil {
		return err
	}
	wSOCKS, err := net.Listen("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(socksPort)))
	if err != nil {
		_ = wHTTP.Close()
		return err
	}
	s.mu.Lock()
	s.wslBridgeIP = ip.String()
	s.wslHTTPLn = wHTTP
	s.wslSOCKSLn = wSOCKS
	if ta, ok := wHTTP.Addr().(*net.TCPAddr); ok {
		s.wslHTTPPort = ta.Port
	}
	if ta, ok := wSOCKS.Addr().(*net.TCPAddr); ok {
		s.wslSOCKSPort = ta.Port
	}
	s.mu.Unlock()

	wslSrv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serveLoopbackHTTP(w, r, true) }),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = wslSrv.Serve(wHTTP) }()
	go s.acceptSOCKSLoop(wSOCKS, true)
	return nil
}

// Close closes all listeners safely.
func (s *LocalProxyServer) Close() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		if s.httpListener != nil {
			_ = s.httpListener.Close()
		}
		if s.socksLn != nil {
			_ = s.socksLn.Close()
		}
		if s.wslHTTPLn != nil {
			_ = s.wslHTTPLn.Close()
		}
		if s.wslSOCKSLn != nil {
			_ = s.wslSOCKSLn.Close()
		}
	})
}

func (s *LocalProxyServer) getConfig() *EngineConfig {
	s.mu.RLock()
	c := s.cfg
	s.mu.RUnlock()
	return c
}

func (s *LocalProxyServer) manifestInfo() (int64, string) {
	s.mu.RLock()
	ver, src := s.manifestVer, s.manifestSrc
	s.mu.RUnlock()
	return ver, src
}

// UpdateManifestDoc atomically clones the latest active config under lock, merges verified
// manifest nodes/pins/SNIs (preserving user rules and PRO UUID), and updates the matcher/PAC.
func (s *LocalProxyServer) UpdateManifestDoc(doc *ManifestDocument, src string) *EngineConfig {
	if doc == nil {
		return nil
	}
	var cb func(*EngineConfig, uint64)
	var rev uint64
	var updated *EngineConfig

	s.mu.Lock()
	s.manifestVer = doc.Ver
	s.manifestSrc = src
	if s.cfg != nil {
		updated = s.cfg.Clone()
		ApplyManifestToConfig(updated, doc)
		s.cfg = updated
		if s.mux != nil {
			s.mux.UpdateConfig(updated)
		}
		s.matcher.UpdateFromConfig(updated)
		rev = s.pacRev.Add(1)
		cb = s.onRulesReloaded
	}
	s.mu.Unlock()

	if cb != nil && updated != nil {
		cb(updated, rev)
	}
	return updated
}

func (s *LocalProxyServer) isSelfTarget(host string, port int) bool {
	s.mu.RLock()
	wslIP := s.wslBridgeIP
	wslHTTP := s.wslHTTPPort
	wslSOCKS := s.wslSOCKSPort
	s.mu.RUnlock()

	if port <= 0 {
		return false
	}
	isOwnPort := port == s.HTTPPort() || port == s.SOCKSPort() ||
		(wslHTTP > 0 && port == wslHTTP) || (wslSOCKS > 0 && port == wslSOCKS)
	if !isOwnPort {
		return false
	}
	h := normalizeHostForMatch(host)
	if h == "127.0.0.1" || h == "localhost" || h == "::1" || (wslIP != "" && h == wslIP) {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return true
	}
	return false
}

func (s *LocalProxyServer) isWSLRestrictedHost(host string) bool {
	h := normalizeHostForMatch(host)
	if h == "" || h == "localhost" || h == "localhost.localdomain" || h == "::1" || h == "0.0.0.0" || h == "::" {
		return true
	}
	s.mu.RLock()
	wslIP := s.wslBridgeIP
	s.mu.RUnlock()
	if wslIP != "" && h == wslIP {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return s.isWSLRestrictedIP(ip)
	}
	return false
}

func (s *LocalProxyServer) isWSLRestrictedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	s.mu.RLock()
	wslIP := s.wslBridgeIP
	s.mu.RUnlock()
	if wslIP != "" && ip.String() == wslIP {
		return true
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || IsPrivateOrReservedIP(ip)
}

func (s *LocalProxyServer) serveLoopbackHTTP(w http.ResponseWriter, r *http.Request, isWSL bool) {
	if r.Method == http.MethodConnect {
		chost, cportStr, err := net.SplitHostPort(r.Host)
		cport := 443
		if err != nil {
			chost = r.Host
		} else {
			cport, _ = strconv.Atoi(cportStr)
		}
		if s.isSelfTarget(chost, cport) || (isWSL && s.isWSLRestrictedHost(chost)) {
			http.Error(w, "Forbidden proxy target", http.StatusForbidden)
			return
		}
		s.handleHTTPConnect(w, r, isWSL)
		return
	}
	if r.URL.IsAbs() {
		ahost := r.URL.Hostname()
		aport := 80
		if p := r.URL.Port(); p != "" {
			aport, _ = strconv.Atoi(p)
		} else if strings.EqualFold(r.URL.Scheme, "https") {
			aport = 443
		}
		if s.isSelfTarget(ahost, aport) || (isWSL && s.isWSLRestrictedHost(ahost)) {
			http.Error(w, "Forbidden proxy target", http.StatusForbidden)
			return
		}
		if isWSL && strings.HasPrefix(r.URL.Path, "/__pixelcore") {
			http.Error(w, "Forbidden on WSL bridge", http.StatusForbidden)
			return
		}
		s.handleHTTPForward(w, r, isWSL)
		return
	}

	path := r.URL.Path

	// WSL2 bridge MUST NOT access /__pixelcore/* or /ui local control endpoints.
	if isWSL {
		if path == "/proxy.pac" {
			w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.WriteString(w, GenerateSmartPACJS(s.getConfig(), s.wslBridgeIP))
			return
		}
		http.Error(w, "Forbidden on WSL bridge", http.StatusForbidden)
		return
	}

	switch {
	case path == "/proxy.pac":
		if !s.isValidLoopbackHost(r) {
			http.Error(w, "Invalid Host", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, GenerateSmartPACJS(s.getConfig(), "127.0.0.1"))

	case path == "/__pixelcore/telemetry":
		if !s.isValidLoopbackHost(r) {
			http.Error(w, "Invalid Host", http.StatusForbidden)
			return
		}
		s.handleLegacyTelemetry(w)

	case path == "/ui" || strings.HasPrefix(path, "/ui/"):
		if !s.isValidLoopbackHost(r) {
			http.Error(w, "Invalid Host (DNS rebinding rejected)", http.StatusForbidden)
			return
		}
		if s.headless {
			http.Error(w, "Web-UI disabled in headless mode", http.StatusNotFound)
			return
		}
		s.uiHandler.ServeHTTP(w, r)

	case strings.HasPrefix(path, "/__pixelcore/v4/"):
		if !s.isValidLoopbackHost(r) {
			http.Error(w, "Invalid Host (DNS rebinding rejected)", http.StatusForbidden)
			return
		}
		if !s.isAuthorizedLocalAPI(r) {
			http.Error(w, "Unauthorized local API request", http.StatusUnauthorized)
			return
		}
		s.handleV4API(w, r)

	default:
		http.NotFound(w, r)
	}
}

func (s *LocalProxyServer) isValidLoopbackHost(r *http.Request) bool {
	// Require exact Host: 127.0.0.1:<port> to block DNS-rebinding attacks
	expectedHost := fmt.Sprintf("127.0.0.1:%d", s.HTTPPort())
	if r.Host != expectedHost {
		return false
	}
	// Verify peer TCP IP is also loopback when coming over real socket
	if r.RemoteAddr != "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				return false
			}
		}
	}
	return true
}

func (s *LocalProxyServer) isAuthorizedLocalAPI(r *http.Request) bool {
	tok := r.Header.Get("X-Pixel-Local-Token")
	if tok != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.localToken)) == 1 {
		return true
	}
	// Or authenticated Web-UI HttpOnly SameSite=Strict session cookie + matching X-Pixel-CSRF header
	return s.uiCSRFStore.ValidateRequest(r)
}

func (s *LocalProxyServer) handleLegacyTelemetry(w http.ResponseWriter) {
	cfg := s.getConfig()
	var snap MuxManagerSnapshot
	if s.mux != nil {
		snap = s.mux.Snapshot()
	}
	tier := "FREE"
	if snap.License.Tier != "" {
		tier = strings.ToUpper(snap.License.Tier)
	} else if !IsTrialOrFreeKey(cfg.ClientUUID) {
		tier = "PRO"
	}
	totalUp := s.bytesUp.Load() + snap.BytesUp
	totalDown := s.bytesDown.Load() + snap.BytesDown
	manifestVer, manifestSrc := s.manifestInfo()

	payload := map[string]any{
		"engine":                EngineName,
		"engine_version":        EngineVersion,
		"protocol":              snap.Protocol,
		"region":                cfg.PreferredRegion,
		"manifest_ver":          manifestVer,
		"manifest_src":          manifestSrc,
		"mux_streams":           snap.MuxStreams,
		"udp_assocs":            0,
		"dpi_clienthello_split": cfg.ActiveNode.Frag || cfg.ActiveNode.EnableDpiSplit,
		"dpi_profile":           cfg.V2.DPIProfile,
		"anti_freeze_ok":        true,
		"dpi_escalations":       0,
		"clock_offset_sec":      snap.ClockOffsetSec,
		"license_tier":          tier,
		"days_left":             snap.License.DaysLeft,
		"devices_used":          snap.License.DevicesUsed,
		"devices_max":           snap.License.DevicesMax,
		"speed_mbps":            0.0,
		"latest_version":        EngineVersion,
		"license_error":         "",
		"uptime_sec":            int64(time.Since(s.startedAt).Seconds()),
		"active_connections":    s.activeConns.Load(),
		"bytes_up":              totalUp,
		"bytes_down":            totalDown,
		"nodes":                 snap.Nodes,
		// v4 additions
		"utls_profile":       snap.UTLSProfile,
		"standby_node":       snap.StandbyNode,
		"standby_ready":      snap.StandbyReady,
		"failover_count":     snap.FailoverCount,
		"instant_wake_count": snap.InstantWakeCount,
		"pac_rev":            s.pacRev.Load(),
		"wsl_bridge_ip":      s.wslBridgeIP,
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *LocalProxyServer) handleV4API(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/__pixelcore/v4/status":
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.writeV4Status(w)

	case "/__pixelcore/v4/live-routes":
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		limit := 100
		if q := r.URL.Query().Get("limit"); q != "" {
			if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 100 {
				limit = n
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"pac_rev": s.pacRev.Load(),
			"entries": s.radar.List(limit),
		})

	case "/__pixelcore/v4/ai-pulse":
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		writeJSON(w, http.StatusOK, s.xray.QueryAIPulse(ctx))

	case "/__pixelcore/v4/reload-rules":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleReloadRules(w, r)

	case "/__pixelcore/v4/instant-wake":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleInstantWake(w, r)

	case "/__pixelcore/v4/run-xray":
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		writeJSON(w, http.StatusOK, s.xray.RunXRay(ctx))

	case "/__pixelcore/v4/activate":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleActivateKeyAPI(w, r)

	default:
		http.NotFound(w, r)
	}
}

func (s *LocalProxyServer) writeV4Status(w http.ResponseWriter) {
	cfg := s.getConfig()
	var snap MuxManagerSnapshot
	if s.mux != nil {
		snap = s.mux.Snapshot()
	}
	tier := "FREE"
	if snap.License.Tier != "" {
		tier = strings.ToUpper(snap.License.Tier)
	} else if !IsTrialOrFreeKey(cfg.ClientUUID) {
		tier = "PRO"
	}
	manifestVer, manifestSrc := s.manifestInfo()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                    true,
		"engine":                EngineName,
		"engine_version":        EngineVersion,
		"connected":             snap.Connected,
		"protocol":              snap.Protocol,
		"utls_profile":          snap.UTLSProfile,
		"dpi_profile":           cfg.V2.DPIProfile,
		"active_node":           snap.ActiveNode,
		"active_role":           "ai",
		"standby_node":          snap.StandbyNode,
		"standby_ready":         snap.StandbyReady,
		"failover_count":        snap.FailoverCount,
		"instant_wake_count":    snap.InstantWakeCount,
		"last_wake_reason":      snap.LastWakeReason,
		"last_wake_unix":        snap.LastWakeUnix,
		"pac_rev":               s.pacRev.Load(),
		"http_port":             s.HTTPPort(),
		"socks_port":            s.SOCKSPort(),
		"wsl_bridge_ip":         s.wslBridgeIP,
		"license_tier":          tier,
		"days_left":             snap.License.DaysLeft,
		"manifest_ver":          manifestVer,
		"manifest_src":          manifestSrc,
		"uptime_sec":            int64(time.Since(s.startedAt).Seconds()),
		"bytes_up":              s.bytesUp.Load() + snap.BytesUp,
		"bytes_down":            s.bytesDown.Load() + snap.BytesDown,
		"active_connections":    s.activeConns.Load(),
		"categories":            cfg.Categories,
		"custom_proxy_domains":  cfg.CustomProxy,
		"custom_direct_domains": cfg.CustomDirect,
		"proxy_all":             cfg.ProxyAll,
	})
}

func (s *LocalProxyServer) handleReloadRules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Categories   map[string]bool `json:"categories"`
		CustomProxy  []string        `json:"custom_proxy_domains"`
		CustomDirect []string        `json:"custom_direct_domains"`
		ProxyAll     *bool           `json:"proxy_all"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 512*1024))

	s.mu.Lock()
	cfg := s.cfg.Clone()
	if cfg == nil {
		cfg = DefaultEngineConfig()
	}
	if cfg.Categories == nil {
		cfg.Categories = make(map[string]bool)
	}
	if len(strings.TrimSpace(string(raw))) == 0 && cfg.ConfigPath != "" {
		if reloaded, err := LoadConfig(cfg.ConfigPath); err == nil {
			if reloaded.Categories == nil {
				reloaded.Categories = make(map[string]bool)
			}
			cfg = reloaded
		}
	} else if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			s.mu.Unlock()
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Categories != nil {
			for k, v := range body.Categories {
				cfg.Categories[strings.ToLower(k)] = v
			}
		}
		if body.CustomProxy != nil {
			cfg.CustomProxy = append([]string(nil), body.CustomProxy...)
		}
		if body.CustomDirect != nil {
			cfg.CustomDirect = append([]string(nil), body.CustomDirect...)
		}
		if body.ProxyAll != nil {
			cfg.ProxyAll = *body.ProxyAll
		}
		cfg.RebuildEffectiveRules()
		if cfg.ConfigPath != "" && !s.headless {
			_ = SaveConfig(cfg.ConfigPath, cfg)
		}
	}
	s.cfg = cfg
	if s.mux != nil {
		s.mux.UpdateConfig(cfg)
	}
	s.matcher.UpdateFromConfig(cfg)
	newRev := s.pacRev.Add(1)
	cb := s.onRulesReloaded
	s.mu.Unlock()

	if cb != nil {
		cb(cfg, newRev)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"pac_rev":        newRev,
		"proxy_domains":  len(cfg.ProxyDomains),
		"direct_domains": len(cfg.DirectDomains),
	})
}

func (s *LocalProxyServer) handleInstantWake(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	if body.Reason == "" {
		body.Reason = "manual"
	}

	var failoverMs int64
	var err error
	if s.mux != nil {
		failoverMs, err = s.mux.TriggerInstantWake(body.Reason)
	}
	newRev := s.pacRev.Add(1)
	var snap MuxManagerSnapshot
	if s.mux != nil {
		snap = s.mux.Snapshot()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 err == nil,
		"reason":             body.Reason,
		"pac_rev":            newRev,
		"standby_ready":      snap.StandbyReady,
		"active_node":        snap.ActiveNode,
		"failover_ms":        failoverMs,
		"instant_wake_count": snap.InstantWakeCount,
	})
}

func (s *LocalProxyServer) handleActivateKeyAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	pk, err := ParseKeyInput(body.Key)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	s.mu.Lock()
	cfg := s.cfg.Clone()
	if cfg == nil {
		cfg = DefaultEngineConfig()
	}
	if cfg.Categories == nil {
		cfg.Categories = make(map[string]bool)
	}
	cfg.ApplyParsedKey(pk)
	if cfg.ConfigPath != "" && !s.headless {
		_ = SaveConfig(cfg.ConfigPath, cfg)
	}
	s.cfg = cfg
	if s.mux != nil {
		s.mux.UpdateConfig(cfg)
	}
	s.matcher.UpdateFromConfig(cfg)
	s.pacRev.Add(1)
	s.mu.Unlock()

	if s.mux != nil {
		_, _ = s.mux.TriggerInstantWake("key_activated")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"format": pk.Format,
		"uuid":   pk.UUID,
	})
}

func (s *LocalProxyServer) handleHTTPConnect(w http.ResponseWriter, r *http.Request, isWSL bool) {
	host, portStr, err := net.SplitHostPort(r.Host)
	port := 443
	if err != nil {
		host = r.Host
	} else {
		port, _ = strconv.Atoi(portStr)
	}
	if port <= 0 || port > 65535 {
		http.Error(w, "Invalid port", http.StatusBadRequest)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking unavailable", http.StatusInternalServerError)
		return
	}
	clientConn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = rw.Flush()

	var wrapped net.Conn = clientConn
	if rw.Reader.Buffered() > 0 {
		wrapped = &prefixedConn{Conn: clientConn, r: rw.Reader}
	}
	s.bridgeTCPConnection(r.Context(), wrapped, host, port, "CONNECT", isWSL)
}

var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func stripHopByHopHeaders(h http.Header) {
	if h == nil {
		return
	}
	// First delete headers named inside any Connection header values.
	for _, connVal := range h.Values("Connection") {
		for _, tok := range strings.Split(connVal, ",") {
			if name := strings.TrimSpace(tok); name != "" {
				h.Del(name)
			}
		}
	}
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
}

func (s *LocalProxyServer) handleHTTPForward(w http.ResponseWriter, r *http.Request, isWSL bool) {
	host := r.URL.Hostname()
	port := 80
	if p := r.URL.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	} else if strings.EqualFold(r.URL.Scheme, "https") {
		port = 443
	}
	if host == "" || port <= 0 || port > 65535 {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	decision := s.matcher.Classify(host)
	var pid int
	var proc string
	if ra, rerr := net.ResolveTCPAddr("tcp", r.RemoteAddr); rerr == nil {
		pid, proc = LookupProcessForConnection(ra, s.HTTPPort(), s.SOCKSPort())
	}

	dialCtx, dialCancel := context.WithTimeout(r.Context(), 10*time.Second)
	t0 := time.Now()
	upstream, nodeUsed, err := s.dialUpstreamTCP(dialCtx, decision, host, port, isWSL)
	dialCancel()
	pingMs := time.Since(t0).Milliseconds()
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	s.radar.Record(RouteRadarEntry{
		PID:     pid,
		Process: proc,
		Domain:  host,
		Port:    port,
		Proto:   "HTTP",
		Action:  decision.Action,
		Rule:    decision.Rule,
		Node:    nodeUsed,
		Role:    decision.Role,
		PingMs:  pingMs,
		Error:   errStr,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	_ = upstream.SetWriteDeadline(time.Now().Add(20 * time.Second))
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	stripHopByHopHeaders(outReq.Header)
	if err := outReq.Write(upstream); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = upstream.SetWriteDeadline(time.Time{})

	_ = upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(upstream), outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	stripHopByHopHeaders(resp.Header)
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_ = upstream.SetReadDeadline(time.Now().Add(60 * time.Second))
	_, _ = io.Copy(w, resp.Body)
}

func (s *LocalProxyServer) acceptSOCKSLoop(ln net.Listener, isWSL bool) {
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				continue
			}
		}
		go s.handleSOCKS5Conn(c, isWSL)
	}
}

func (s *LocalProxyServer) handleSOCKS5Conn(c net.Conn, isWSL bool) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))

	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	_, _ = c.Write([]byte{0x05, 0x00}) // No auth required on loopback / WSL

	var reqHdr [4]byte
	if _, err := io.ReadFull(c, reqHdr[:]); err != nil || reqHdr[0] != 0x05 {
		return
	}
	cmd := reqHdr[1]
	atyp := reqHdr[3]
	targetHost, err := readSOCKSAddr(c, atyp)
	if err != nil {
		return
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(c, portBuf[:]); err != nil {
		return
	}
	targetPort := int(binary.BigEndian.Uint16(portBuf[:]))
	_ = c.SetDeadline(time.Time{})

	switch cmd {
	case 0x01: // CONNECT
		if targetPort <= 0 || targetPort > 65535 || s.isSelfTarget(targetHost, targetPort) || (isWSL && s.isWSLRestrictedHost(targetHost)) {
			_, _ = c.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		decision := s.matcher.Classify(targetHost)
		pid, proc := LookupProcessForConnection(c.RemoteAddr(), s.HTTPPort(), s.SOCKSPort())
		t0 := time.Now()
		upstream, nodeUsed, uerr := s.dialUpstreamTCP(context.Background(), decision, targetHost, targetPort, isWSL)
		lat := time.Since(t0).Milliseconds()
		errStr := ""
		if uerr != nil {
			errStr = uerr.Error()
		}
		seq := s.radar.Record(RouteRadarEntry{
			PID:     pid,
			Process: proc,
			Domain:  targetHost,
			Port:    targetPort,
			Proto:   "SOCKS5",
			Action:  decision.Action,
			Rule:    decision.Rule,
			Node:    nodeUsed,
			Role:    decision.Role,
			PingMs:  lat,
			Error:   errStr,
		})
		if uerr != nil {
			_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer upstream.Close()
		_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		up, down := s.relayBidirectional(c, upstream)
		s.radar.UpdateTraffic(seq, up, down, "")

	case 0x03: // UDP ASSOCIATE
		s.handleSOCKS5UDPAssociate(c, isWSL)

	default:
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func (s *LocalProxyServer) handleSOCKS5UDPAssociate(tcpCtrl net.Conn, isWSL bool) {
	if s.mux == nil {
		_, _ = tcpCtrl.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var tcpCtrlIP net.IP
	if ta, ok := tcpCtrl.RemoteAddr().(*net.TCPAddr); ok && ta.IP != nil {
		tcpCtrlIP = ta.IP
	} else if tcpCtrl.RemoteAddr() != nil {
		if h, _, err := net.SplitHostPort(tcpCtrl.RemoteAddr().String()); err == nil {
			tcpCtrlIP = net.ParseIP(h)
		}
	}
	if tcpCtrlIP == nil {
		_, _ = tcpCtrl.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	sess, err := s.mux.GetOrConnectSession(context.Background(), "ai")
	if err != nil {
		_, _ = tcpCtrl.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	bindIP := net.IPv4(127, 0, 0, 1)
	if la, ok := tcpCtrl.LocalAddr().(*net.TCPAddr); ok && la.IP != nil {
		if v4 := la.IP.To4(); v4 != nil {
			bindIP = v4
		}
	}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: bindIP, Port: 0})
	if err != nil {
		_, _ = tcpCtrl.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpConn.Close()

	uaddr := udpConn.LocalAddr().(*net.UDPAddr)
	reply := []byte{0x05, 0x00, 0x00, 0x01, bindIP[0], bindIP[1], bindIP[2], bindIP[3], byte(uaddr.Port >> 8), byte(uaddr.Port)}
	if _, err := tcpCtrl.Write(reply); err != nil {
		return
	}

	var clientUDPAddr atomic.Pointer[net.UDPAddr]
	assocID := sess.RegisterUDPHandler(func(srcHost string, srcPort int, payload []byte) {
		cli := clientUDPAddr.Load()
		if cli == nil {
			return
		}
		var hdr []byte
		if ip := net.ParseIP(srcHost); ip != nil && ip.To4() != nil {
			v4 := ip.To4()
			hdr = []byte{0, 0, 0, 0x01, v4[0], v4[1], v4[2], v4[3], byte(srcPort >> 8), byte(srcPort)}
		} else {
			hdr = make([]byte, 4+1+len(srcHost)+2)
			hdr[3] = 0x03
			hdr[4] = byte(len(srcHost))
			copy(hdr[5:], srcHost)
			binary.BigEndian.PutUint16(hdr[5+len(srcHost):], uint16(srcPort))
		}
		pkt := append(hdr, payload...)
		_, _ = udpConn.WriteToUDP(pkt, cli)
	})
	defer sess.UnregisterUDPHandler(assocID)

	go func() {
		buf := make([]byte, 16384)
		for {
			n, from, rerr := udpConn.ReadFromUDP(buf)
			if rerr != nil || n < 8 {
				return
			}
			// Reject packets from any source IP other than the authenticated TCP control client
			// BEFORE parsing or storing the peer UDP endpoint to prevent session hijacking.
			if from == nil || !from.IP.Equal(tcpCtrlIP) {
				continue
			}
			host, port, off, perr := parseSOCKS5UDPHeader(buf[:n])
			if perr != nil || off >= n || port <= 0 || port > 65535 {
				continue
			}
			if s.isSelfTarget(host, port) || (isWSL && s.isWSLRestrictedHost(host)) {
				continue
			}
			clientUDPAddr.Store(from)
			_ = sess.SendUDP(assocID, host, port, buf[off:n])
		}
	}()

	// Hold association until TCP control socket closes
	var tmp [1]byte
	_, _ = tcpCtrl.Read(tmp[:])
}

func (s *LocalProxyServer) bridgeTCPConnection(ctx context.Context, client net.Conn, host string, port int, protoLabel string, isWSL bool) {
	decision := s.matcher.Classify(host)
	pid, proc := LookupProcessForConnection(client.RemoteAddr(), s.HTTPPort(), s.SOCKSPort())
	t0 := time.Now()
	upstream, nodeUsed, err := s.dialUpstreamTCP(ctx, decision, host, port, isWSL)
	lat := time.Since(t0).Milliseconds()
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	seq := s.radar.Record(RouteRadarEntry{
		PID:     pid,
		Process: proc,
		Domain:  host,
		Port:    port,
		Proto:   protoLabel,
		Action:  decision.Action,
		Rule:    decision.Rule,
		Node:    nodeUsed,
		Role:    decision.Role,
		PingMs:  lat,
		Error:   errStr,
	})
	if err != nil {
		return
	}
	defer upstream.Close()
	up, down := s.relayBidirectional(client, upstream)
	s.radar.UpdateTraffic(seq, up, down, "")
}

func (s *LocalProxyServer) dialUpstreamTCP(ctx context.Context, decision RuleAction, host string, port int, isWSL bool) (net.Conn, string, error) {
	if port <= 0 || port > 65535 {
		return nil, decision.Action, fmt.Errorf("invalid port %d", port)
	}
	if s.isSelfTarget(host, port) || (isWSL && s.isWSLRestrictedHost(host)) {
		return nil, decision.Action, fmt.Errorf("blocked proxy target %s:%d", host, port)
	}
	if decision.Action == "PROXY" && s.mux != nil {
		return s.mux.OpenStream(ctx, decision.Role, host, port)
	}

	// Direct outbound: strictly resolve hostnames via DoH without falling back to OS DNS,
	// and block DNS rebinding into local proxy ports or restricted WSL targets.
	dialHost := host
	if ip := net.ParseIP(host); ip != nil {
		if s.isSelfTarget(ip.String(), port) || (isWSL && s.isWSLRestrictedIP(ip)) {
			return nil, "DIRECT", fmt.Errorf("blocked direct IP target %s:%d", ip.String(), port)
		}
	} else {
		if s.resolver == nil {
			return nil, "DIRECT", errors.New("doh resolver unavailable for direct hostname")
		}
		ips, err := s.resolver.LookupHost(ctx, host)
		if err != nil || len(ips) == 0 {
			if err == nil {
				err = errors.New("doh returned no addresses")
			}
			return nil, "DIRECT", fmt.Errorf("doh resolve failed: %w", err)
		}
		var chosen net.IP
		for _, ip := range ips {
			if s.isSelfTarget(ip.String(), port) {
				return nil, "DIRECT", fmt.Errorf("doh resolved to blocked self target %s:%d", ip.String(), port)
			}
			if isWSL && s.isWSLRestrictedIP(ip) {
				return nil, "DIRECT", fmt.Errorf("doh resolved to restricted wsl ip %s", ip.String())
			}
			if chosen == nil {
				chosen = ip
			}
		}
		dialHost = chosen.String()
	}
	conn, err := (&net.Dialer{Timeout: 6 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(dialHost, strconv.Itoa(port)))
	return conn, "DIRECT", err
}

func (s *LocalProxyServer) relayBidirectional(a, b net.Conn) (up int64, down int64) {
	s.activeConns.Add(1)
	defer s.activeConns.Add(-1)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(b, a)
		up = n
		s.bytesUp.Add(n)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(a, b)
		down = n
		s.bytesDown.Add(n)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
	return up, down
}

func readSOCKSAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		dom := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, dom); err != nil {
			return "", err
		}
		return string(dom), nil
	case 0x04:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	default:
		return "", errors.New("unsupported SOCKS5 ATYP")
	}
}

func parseSOCKS5UDPHeader(pkt []byte) (host string, port int, off int, err error) {
	if len(pkt) < 8 || pkt[2] != 0x00 {
		return "", 0, 0, errors.New("fragmented or invalid SOCKS5 UDP")
	}
	switch pkt[3] {
	case 0x01:
		if len(pkt) < 10 {
			return "", 0, 0, errors.New("short ipv4 udp header")
		}
		return net.IP(pkt[4:8]).String(), int(binary.BigEndian.Uint16(pkt[8:10])), 10, nil
	case 0x03:
		hl := int(pkt[4])
		if len(pkt) < 5+hl+2 {
			return "", 0, 0, errors.New("short domain udp header")
		}
		return string(pkt[5 : 5+hl]), int(binary.BigEndian.Uint16(pkt[5+hl : 7+hl])), 7 + hl, nil
	case 0x04:
		if len(pkt) < 22 {
			return "", 0, 0, errors.New("short ipv6 udp header")
		}
		return net.IP(pkt[4:20]).String(), int(binary.BigEndian.Uint16(pkt[20:22])), 22, nil
	default:
		return "", 0, 0, errors.New("bad udp atyp")
	}
}

type prefixedConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *prefixedConn) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
