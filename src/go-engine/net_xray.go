package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RouteRadarEntry records one routed TCP/UDP/HTTP connection in the 100-entry ring buffer.
type RouteRadarEntry struct {
	Seq       uint64 `json:"seq"`
	TS        int64  `json:"ts"`
	Time      string `json:"time"`
	PID       int    `json:"pid"`
	Process   string `json:"process"`
	Domain    string `json:"domain"`
	Port      int    `json:"port"`
	Proto     string `json:"proto"`
	Action    string `json:"action"` // "PROXY" or "DIRECT"
	Rule      string `json:"rule"`
	Node      string `json:"node"`
	Role      string `json:"role"`
	PingMs    int64  `json:"ping_ms"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
	Error     string `json:"error,omitempty"`
}

// RouteRadar is a fixed-capacity lock-safe ring buffer of live routing events.
type RouteRadar struct {
	mu      sync.RWMutex
	capSize int
	ring    []RouteRadarEntry
	head    int
	count   int
	seq     atomic.Uint64
}

// NewRouteRadar constructs a RouteRadar ring buffer (default capacity 100).
func NewRouteRadar(capacity int) *RouteRadar {
	if capacity <= 0 {
		capacity = 100
	}
	return &RouteRadar{
		capSize: capacity,
		ring:    make([]RouteRadarEntry, capacity),
	}
}

// Record appends an entry into the ring buffer, overwriting the oldest when full.
func (r *RouteRadar) Record(ent RouteRadarEntry) uint64 {
	seq := r.seq.Add(1)
	now := time.Now()
	if ent.TS == 0 {
		ent.TS = now.Unix()
	}
	if ent.Time == "" {
		ent.Time = now.Format("15:04:05")
	}
	ent.Seq = seq

	r.mu.Lock()
	r.ring[r.head] = ent
	r.head = (r.head + 1) % r.capSize
	if r.count < r.capSize {
		r.count++
	}
	r.mu.Unlock()
	return seq
}

// UpdateTraffic adds bytes transferred to an existing entry matching seq if still present.
func (r *RouteRadar) UpdateTraffic(seq uint64, bytesUp, bytesDown int64, errStr string) {
	if seq == 0 {
		return
	}
	r.mu.Lock()
	for i := 0; i < r.count; i++ {
		idx := (r.head - 1 - i + r.capSize) % r.capSize
		if r.ring[idx].Seq == seq {
			r.ring[idx].BytesUp += bytesUp
			r.ring[idx].BytesDown += bytesDown
			if errStr != "" {
				r.ring[idx].Error = errStr
			}
			break
		}
	}
	r.mu.Unlock()
}

// List returns up to limit entries ordered newest-first.
func (r *RouteRadar) List(limit int) []RouteRadarEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 || limit > r.count {
		limit = r.count
	}
	out := make([]RouteRadarEntry, 0, limit)
	for i := 0; i < limit; i++ {
		idx := (r.head - 1 - i + r.capSize) % r.capSize
		out = append(out, r.ring[idx])
	}
	return out
}

// AIProviderPulse mirrors PixelCore_v3_Server /api/v4/ai-pulse provider status.
type AIProviderPulse struct {
	Status    string `json:"status"` // "ok", "degraded", "down"
	HTTPCode  int    `json:"http_code"`
	LatencyMs int64  `json:"latency_ms"`
	Host      string `json:"host"`
}

// AIPulseResponse matches server /api/v4/ai-pulse JSON schema 100%.
type AIPulseResponse struct {
	OK        bool                       `json:"ok"`
	Node      string                     `json:"node"`
	CheckedAt int64                      `json:"checked_at"`
	TTLSec    int                        `json:"ttl_sec"`
	Cached    bool                       `json:"cached"`
	Providers map[string]AIProviderPulse `json:"providers"`
}

// XRayCard represents one diagnostic card in Diagnostics 4.0.
type XRayCard struct {
	ID        string         `json:"id"`
	Title     string         `json:"title"`
	Status    string         `json:"status"` // "ok", "warn", "fail"
	Summary   string         `json:"summary"`
	LatencyMs int64          `json:"latency_ms"`
	Metrics   map[string]any `json:"metrics,omitempty"`
}

// XRayReport is the complete 6-card Diagnostics 4.0 payload with local report text only (NO #PT codes).
type XRayReport struct {
	OK         bool       `json:"ok"`
	CheckedAt  int64      `json:"checked_at"`
	DurationMs int64      `json:"duration_ms"`
	Overall    string     `json:"overall"` // "ok", "warn", "fail"
	Cards      []XRayCard `json:"cards"`
	ReportText string     `json:"report_text"`
}

type aiPulseCall struct {
	done chan struct{}
	resp *AIPulseResponse
}

// XRayRunner executes non-destructive Diagnostics 4.0 and AI Pulse checks.
type XRayRunner struct {
	cfgFn       func() *EngineConfig
	mux         *MuxManager
	resolver    *DohResolver
	radar       *RouteRadar
	pulseMu     sync.Mutex
	cachedPulse *AIPulseResponse
	pulseExp    time.Time
	pulseFlight *aiPulseCall
}

// NewXRayRunner creates an XRayRunner tied to MuxManager and DohResolver.
func NewXRayRunner(cfgFn func() *EngineConfig, mux *MuxManager, resolver *DohResolver, radar *RouteRadar) *XRayRunner {
	return &XRayRunner{
		cfgFn:    cfgFn,
		mux:      mux,
		resolver: resolver,
		radar:    radar,
	}
}

// QueryAIPulse fetches AI provider reachability over the authenticated mux session
// (`diag.internal.pixel:443` AI_PULSE), falling back to signed /api/v4/ai-pulse and
// finally direct mux TLS probes for v1.9.0 nodes. Concurrent callers share a single flight
// so replay nonces on /api/v4/ai-pulse are never collided.
func (x *XRayRunner) QueryAIPulse(ctx context.Context) *AIPulseResponse {
	x.pulseMu.Lock()
	if x.cachedPulse != nil && time.Now().Before(x.pulseExp) {
		cp := *x.cachedPulse
		cp.Cached = true
		x.pulseMu.Unlock()
		return &cp
	}
	if call := x.pulseFlight; call != nil {
		x.pulseMu.Unlock()
		select {
		case <-call.done:
			if call.resp != nil {
				cp := *call.resp
				cp.Cached = true
				return &cp
			}
			return &AIPulseResponse{
				OK:        false,
				CheckedAt: time.Now().Unix(),
				Providers: map[string]AIProviderPulse{},
			}
		case <-ctx.Done():
			return &AIPulseResponse{
				OK:        false,
				CheckedAt: time.Now().Unix(),
				Providers: map[string]AIProviderPulse{},
			}
		}
	}
	call := &aiPulseCall{done: make(chan struct{})}
	x.pulseFlight = call
	x.pulseMu.Unlock()

	resp := x.queryAIPulseUncached(ctx)
	if resp != nil {
		x.storeCachedPulse(resp)
	}

	x.pulseMu.Lock()
	call.resp = resp
	if x.pulseFlight == call {
		x.pulseFlight = nil
	}
	close(call.done)
	x.pulseMu.Unlock()
	return resp
}

func (x *XRayRunner) queryAIPulseUncached(ctx context.Context) *AIPulseResponse {
	var cfg *EngineConfig
	if x.cfgFn != nil {
		cfg = x.cfgFn()
	}
	nodeName := ""
	if cfg != nil {
		nodeName = cfg.ActiveNode.Name
	}
	if x.mux != nil {
		snap := x.mux.Snapshot()
		if snap.ActiveNode != "" {
			nodeName = snap.ActiveNode
		}
	}

	if resp, ok := x.fetchMuxDiagAIPulse(ctx, nodeName); ok {
		return resp
	}

	if resp, ok := x.fetchNodeAIPulse(ctx, cfg); ok {
		if resp.Node == "" {
			resp.Node = nodeName
		}
		return resp
	}

	// Fallback: probe Gemini / Claude / OpenAI over active mux session
	providers := make(map[string]AIProviderPulse, 3)
	targets := []struct {
		key  string
		host string
	}{
		{"gemini", "daily-cloudcode-pa.googleapis.com"},
		{"claude", "api.anthropic.com"},
		{"openai", "api.openai.com"},
	}
	var wg sync.WaitGroup
	var pMu sync.Mutex
	for _, t := range targets {
		wg.Add(1)
		go func(key, host string) {
			defer wg.Done()
			p := x.probeSingleAIHost(ctx, host)
			pMu.Lock()
			providers[key] = p
			pMu.Unlock()
		}(t.key, t.host)
	}
	wg.Wait()

	return &AIPulseResponse{
		OK:        true,
		Node:      nodeName,
		CheckedAt: time.Now().Unix(),
		TTLSec:    60,
		Cached:    false,
		Providers: providers,
	}
}

func (x *XRayRunner) fetchMuxDiagAIPulse(ctx context.Context, nodeName string) (*AIPulseResponse, bool) {
	if x.mux == nil || ctx.Err() != nil {
		return nil, false
	}
	sess := x.mux.ActiveSession("ai")
	if sess == nil || sess.IsClosed() {
		return nil, false
	}
	st, err := sess.OpenTCPStream("diag.internal.pixel", 443, 3*time.Second)
	if err != nil {
		return nil, false
	}
	defer st.Close()

	_ = st.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := st.Write([]byte("AI_PULSE\n")); err != nil {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(st, 64*1024))
	if err != nil && len(body) == 0 {
		return nil, false
	}
	var parsed AIPulseResponse
	if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Providers) == 0 {
		return nil, false
	}
	if parsed.Node == "" {
		parsed.Node = nodeName
	}
	return &parsed, true
}

func (x *XRayRunner) storeCachedPulse(resp *AIPulseResponse) {
	x.pulseMu.Lock()
	x.cachedPulse = resp
	ttl := time.Duration(resp.TTLSec) * time.Second
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	x.pulseExp = time.Now().Add(ttl)
	x.pulseMu.Unlock()
}

func (x *XRayRunner) fetchNodeAIPulse(ctx context.Context, cfg *EngineConfig) (*AIPulseResponse, bool) {
	if cfg == nil || cfg.ActiveNode.Host == "" {
		return nil, false
	}
	dialHost := cfg.ActiveNode.Host
	if net.ParseIP(dialHost) == nil {
		if x.resolver == nil {
			return nil, false
		}
		ips, err := x.resolver.LookupHost(ctx, dialHost)
		if err != nil || len(ips) == 0 {
			return nil, false
		}
		dialHost = ips[0].String()
	}
	port := cfg.ActiveNode.Port
	if port <= 0 {
		port = 443
	}
	sni := cfg.ActiveNode.SNI
	if sni == "" {
		sni = DefaultSNI
	}
	rootCAs := getRootCAsFromMux(x.mux)
	insecure := isInsecureTestFromMux(x.mux)
	res, err := DialUTLS(ctx, UTLSDialOptions{
		Address:          net.JoinHostPort(dialHost, strconv.Itoa(port)),
		SNI:              sni,
		Profile:          cfg.V2.UTLSProfile,
		Pins:             cfg.PinnedSPKI,
		RequirePin:       len(cfg.PinnedSPKI) > 0 && rootCAs == nil && !insecure,
		RootCAs:          rootCAs,
		ForceHTTP1ALPN:   true,
		InsecureTestOnly: insecure,
		ConnectTimeout:   4 * time.Second,
	})
	if err != nil {
		return nil, false
	}
	defer res.Conn.Close()

	var nonceRaw [8]byte
	_, _ = rand.Read(nonceRaw[:])
	nonceHex := hex.EncodeToString(nonceRaw[:])

	tsOffset := int64(0)
	if x.mux != nil {
		tsOffset = x.mux.Snapshot().ClockOffsetSec
	}
	tsStr := strconv.FormatInt(time.Now().Unix()+tsOffset, 10)
	mac := hmac.New(sha256.New, []byte(cfg.ActiveNode.Secret))
	_, _ = mac.Write([]byte("ai-pulse:" + tsStr + ":" + nonceHex))
	sigHex32 := hex.EncodeToString(mac.Sum(nil)[:16])

	req := fmt.Sprintf(
		"GET /api/v4/ai-pulse HTTP/1.1\r\nHost: %s\r\nX-Pixel-Ts: %s\r\nX-Pixel-Nonce: %s\r\nX-Pixel-Sig: %s\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
		sni, tsStr, nonceHex, sigHex32,
	)
	_ = res.Conn.SetDeadline(time.Now().Add(4 * time.Second))
	if err := writeFull(res.Conn, []byte(req)); err != nil {
		return nil, false
	}
	br := bufio.NewReader(res.Conn)
	statusLine, hdrs, err := readHTTPResponseHeaders(br)
	if err != nil || !strings.Contains(statusLine, " 200 ") {
		return nil, false
	}
	if !strings.Contains(strings.ToLower(hdrs.Get("Content-Type")), "application/json") {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(br, 64*1024))
	if err != nil {
		return nil, false
	}
	var parsed AIPulseResponse
	if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Providers) == 0 {
		return nil, false
	}
	return &parsed, true
}

func (x *XRayRunner) probeSingleAIHost(ctx context.Context, host string) AIProviderPulse {
	out := AIProviderPulse{Host: host, Status: "down"}
	if x.mux == nil {
		return out
	}
	t0 := time.Now()
	st, _, err := x.mux.OpenStream(ctx, "ai", host, 443)
	if err != nil {
		return out
	}
	defer st.Close()

	tlsRes, err := DialUTLSOverConn(ctx, st, host)
	if err != nil {
		out.LatencyMs = time.Since(t0).Milliseconds()
		return out
	}
	defer tlsRes.Close()

	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	_ = tlsRes.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := tlsRes.Write([]byte(req)); err != nil {
		out.LatencyMs = time.Since(t0).Milliseconds()
		return out
	}
	br := bufio.NewReader(tlsRes)
	line, err := br.ReadString('\n')
	out.LatencyMs = time.Since(t0).Milliseconds()
	if err != nil {
		return out
	}
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		code, _ := strconv.Atoi(parts[1])
		out.HTTPCode = code
		switch {
		case code >= 100 && code <= 499 && code != 429:
			out.Status = "ok"
		case code == 429 || code == 503 || code == 529:
			out.Status = "degraded"
		default:
			out.Status = "down"
		}
	}
	return out
}

// RunXRay runs all 6 non-destructive Diagnostics 4.0 cards and returns a copyable/downloadable report.
func (x *XRayRunner) RunXRay(ctx context.Context) *XRayReport {
	started := time.Now()
	cfg := x.cfgFn()

	cards := make([]XRayCard, 6)
	var wg sync.WaitGroup
	wg.Add(6)
	go func() { defer wg.Done(); cards[0] = x.cardISPHosts(ctx) }()
	go func() { defer wg.Done(); cards[1] = x.cardTSPU(ctx) }()
	go func() { defer wg.Done(); cards[2] = x.cardUTLSMITM(ctx, cfg) }()
	go func() { defer wg.Done(); cards[3] = x.cardNodeMatrix(ctx, cfg) }()
	go func() { defer wg.Done(); cards[4] = x.cardIDESockets(cfg) }()
	go func() { defer wg.Done(); cards[5] = x.cardAIPulse(ctx) }()
	wg.Wait()

	overall := "ok"
	for _, c := range cards {
		if c.Status == "fail" {
			overall = "fail"
			break
		}
		if c.Status == "warn" && overall == "ok" {
			overall = "warn"
		}
	}

	rep := &XRayReport{
		OK:         overall != "fail",
		CheckedAt:  time.Now().Unix(),
		DurationMs: time.Since(started).Milliseconds(),
		Overall:    overall,
		Cards:      cards,
	}
	rep.ReportText = FormatLocalDiagnosticReport(rep, cfg, x.mux, x.radar)
	return rep
}

func (x *XRayRunner) cardISPHosts(ctx context.Context) XRayCard {
	card := XRayCard{
		ID:     "isp_hosts",
		Title:  "ISP & Hosts",
		Status: "ok",
	}
	blockedHosts := inspectSystemHostsFile()
	t0 := time.Now()
	dohOK := false
	sinkhole := false
	var resolvedIP string
	if x.resolver != nil {
		ips, err := x.resolver.LookupHost(ctx, DefaultSNI)
		if err == nil && len(ips) > 0 {
			dohOK = true
			resolvedIP = ips[0].String()
		} else if err != nil && strings.Contains(err.Error(), ErrSinkholeIP.Error()) {
			sinkhole = true
		}
	}
	lat := time.Since(t0).Milliseconds()
	card.LatencyMs = lat
	card.Metrics = map[string]any{
		"hosts_blocked": len(blockedHosts) > 0,
		"hosts_entries": blockedHosts,
		"doh_ok":        dohOK,
		"doh_ms":        lat,
		"dns_sinkhole":  sinkhole,
		"resolved_ip":   resolvedIP,
	}
	switch {
	case len(blockedHosts) > 0 || sinkhole:
		card.Status = "warn"
		card.Summary = fmt.Sprintf("Hosts hijacks=%d, DoH sinkhole=%v (%dms)", len(blockedHosts), sinkhole, lat)
	case !dohOK:
		card.Status = "warn"
		card.Summary = fmt.Sprintf("Hosts clean; DoH lookup unreachable (%dms)", lat)
	default:
		card.Summary = fmt.Sprintf("Hosts clean; DoH %s OK (%dms)", resolvedIP, lat)
	}
	return card
}

func (x *XRayRunner) cardTSPU(ctx context.Context) XRayCard {
	card := XRayCard{
		ID:     "tspu_mtu",
		Title:  "TSPU & MTU (64KB DL / 32KB UL)",
		Status: "ok",
	}
	if x.mux == nil {
		card.Status = "fail"
		card.Summary = "Mux engine offline"
		return card
	}
	sess, err := x.mux.GetOrConnectSession(ctx, "ai")
	if err != nil {
		card.Status = "fail"
		card.Summary = fmt.Sprintf("Tunnel connect failed: %v", err)
		return card
	}

	t0 := time.Now()
	echoOK, echoProto, echoErr := runDiagEchoMeta(sess)
	dlOK, dlMs, dlErr := runDiagDownload64K(sess)
	ulOK, ulMs, ulErr := runDiagUpload32K(sess)

	// If server is v1.9.0 and lacks diag.internal.pixel:443, fall back to probe.internal.pixel:36
	fallback36OK := false
	if !dlOK && !ulOK {
		if fOK, fMs := runLegacyProbe36K(sess); fOK {
			fallback36OK = true
			dlOK = true
			dlMs = fMs
		}
	}

	lat := time.Since(t0).Milliseconds()
	card.LatencyMs = lat
	card.Metrics = map[string]any{
		"echo_ok":      echoOK,
		"echo_proto":   echoProto,
		"dl_64k_ok":    dlOK,
		"dl_ms":        dlMs,
		"ul_32k_ok":    ulOK,
		"ul_ms":        ulMs,
		"fallback_36k": fallback36OK,
	}

	if dlOK && ulOK {
		card.Summary = fmt.Sprintf("DL 64KB OK (%dms), UL 32KB OK (%dms) [%s]", dlMs, ulMs, echoProto)
	} else if fallback36OK {
		card.Status = "warn"
		card.Summary = fmt.Sprintf("v1.9 node: 36KB anti-freeze OK (%dms); PWP-4 diag unavailable", dlMs)
	} else {
		card.Status = "fail"
		card.Summary = fmt.Sprintf("TSPU test partial/failed (echo=%v, dl=%v, ul=%v)", echoErr, dlErr, ulErr)
	}
	return card
}

func (x *XRayRunner) cardUTLSMITM(ctx context.Context, cfg *EngineConfig) XRayCard {
	card := XRayCard{
		ID:     "utls_mitm",
		Title:  "Chrome uTLS & SSL MITM",
		Status: "ok",
	}
	prof := "HelloChrome_Auto"
	if x.mux != nil {
		snap := x.mux.Snapshot()
		if snap.UTLSProfile != "" {
			prof = snap.UTLSProfile
		}
	}
	if cfg == nil || cfg.ActiveNode.Host == "" {
		card.Status = "warn"
		card.Summary = "No upstream node configured for SSL pin probe"
		return card
	}
	t0 := time.Now()
	dialHost := cfg.ActiveNode.Host
	if net.ParseIP(dialHost) == nil {
		if x.resolver == nil {
			card.Status = "fail"
			card.Summary = "DoH resolver unavailable for TLS pin probe"
			return card
		}
		ips, err := x.resolver.LookupHost(ctx, dialHost)
		if err != nil || len(ips) == 0 {
			card.Status = "fail"
			card.Summary = fmt.Sprintf("DoH lookup failed for TLS pin probe: %v", err)
			return card
		}
		dialHost = ips[0].String()
	}
	port := cfg.ActiveNode.Port
	if port <= 0 {
		port = 443
	}
	sni := cfg.ActiveNode.SNI
	if sni == "" {
		sni = DefaultSNI
	}
	rootCAs := getRootCAsFromMux(x.mux)
	insecure := isInsecureTestFromMux(x.mux)
	res, err := DialUTLS(ctx, UTLSDialOptions{
		Address:          net.JoinHostPort(dialHost, strconv.Itoa(port)),
		SNI:              sni,
		Profile:          cfg.V2.UTLSProfile,
		DPIProfile:       DPIProfile(cfg.V2.DPIProfile),
		EnableSplit:      true,
		Pins:             cfg.PinnedSPKI,
		RequirePin:       len(cfg.PinnedSPKI) > 0 && rootCAs == nil && !insecure,
		RootCAs:          rootCAs,
		ForceHTTP1ALPN:   true,
		InsecureTestOnly: insecure,
		ConnectTimeout:   4 * time.Second,
	})
	lat := time.Since(t0).Milliseconds()
	card.LatencyMs = lat
	if err != nil {
		mitm := strings.Contains(err.Error(), ErrCertPinMismatch.Error()) || strings.Contains(err.Error(), ErrMitmDetected.Error())
		card.Status = "fail"
		card.Metrics = map[string]any{
			"utls_profile":  prof,
			"spki_pin_ok":   false,
			"mitm_detected": mitm,
			"error":         err.Error(),
		}
		if mitm {
			card.Summary = fmt.Sprintf("Possible SSL MITM or SPKI mismatch: %v", err)
		} else {
			card.Summary = fmt.Sprintf("uTLS handshake error: %v", err)
		}
		return card
	}
	_ = res.Conn.Close()
	avMitm := looksLikeAVMitmIssuer(res.Issuer)
	card.Metrics = map[string]any{
		"utls_profile":  res.Profile,
		"spki_pin_ok":   res.PinMatched,
		"mitm_detected": avMitm,
		"issuer":        res.Issuer,
		"spki_sha256":   res.SPKISHA256,
	}
	if avMitm {
		card.Status = "warn"
		card.Summary = fmt.Sprintf("%s; AV SSL scanner issuer detected (%s)", res.Profile, res.Issuer)
	} else {
		card.Summary = fmt.Sprintf("%s, SPKI pin valid=%v (%dms)", res.Profile, res.PinMatched, lat)
	}
	return card
}

func (x *XRayRunner) cardNodeMatrix(ctx context.Context, cfg *EngineConfig) XRayCard {
	card := XRayCard{
		ID:     "node_matrix",
		Title:  "Node Matrix & Warm Standby",
		Status: "ok",
	}
	if x.mux == nil {
		card.Status = "fail"
		card.Summary = "Mux manager offline"
		return card
	}
	t0 := time.Now()
	snap := x.mux.Snapshot()
	if !snap.Connected {
		if _, err := x.mux.GetOrConnectSession(ctx, "ai"); err == nil {
			snap = x.mux.Snapshot()
		}
	}
	lat := time.Since(t0).Milliseconds()
	onlineCount := 0
	for _, n := range snap.Nodes {
		if n.Online {
			onlineCount++
		}
	}
	if onlineCount == 0 && snap.Connected {
		onlineCount = 1
	}
	card.LatencyMs = lat
	card.Metrics = map[string]any{
		"active_node":    snap.ActiveNode,
		"protocol":       snap.Protocol,
		"standby_node":   snap.StandbyNode,
		"standby_ready":  snap.StandbyReady,
		"failover_count": snap.FailoverCount,
		"online_nodes":   onlineCount,
		"nodes":          snap.Nodes,
	}
	if !snap.Connected {
		card.Status = "fail"
		card.Summary = "No active tunnel node connected"
	} else if !snap.StandbyReady {
		card.Status = "warn"
		card.Summary = fmt.Sprintf("Active: %s (%s); standby warming", snap.ActiveNode, snap.Protocol)
	} else {
		card.Summary = fmt.Sprintf("Active: %s (%s), Standby ready: %s", snap.ActiveNode, snap.Protocol, snap.StandbyNode)
	}
	return card
}

func (x *XRayRunner) cardIDESockets(cfg *EngineConfig) XRayCard {
	card := XRayCard{
		ID:     "ide_sockets",
		Title:  "IDE Sockets & PAC Bypass",
		Status: "ok",
	}
	httpPort, socksPort := DefaultHTTPPort, DefaultSOCKSPort
	if cfg != nil {
		if cfg.HTTPPort > 0 {
			httpPort = cfg.HTTPPort
		}
		if cfg.SOCKSPort > 0 {
			socksPort = cfg.SOCKSPort
		}
	}
	t0 := time.Now()
	leaks := FindIDELeakedSockets(httpPort, socksPort)
	card.LatencyMs = time.Since(t0).Milliseconds()
	card.Metrics = map[string]any{
		"leaked_sockets": len(leaks),
		"leaks":          leaks,
	}
	if len(leaks) > 0 {
		card.Status = "warn"
		card.Summary = fmt.Sprintf("%d direct 80/443 IDE sockets bypassing proxy (first: %s -> %s:%d)", len(leaks), leaks[0].Process, leaks[0].RemoteIP, leaks[0].RemotePort)
	} else {
		card.Summary = "0 bypassed AI IDE sockets detected"
	}
	return card
}

func (x *XRayRunner) cardAIPulse(ctx context.Context) XRayCard {
	card := XRayCard{
		ID:     "ai_pulse",
		Title:  "AI Endpoints Probe",
		Status: "ok",
	}
	t0 := time.Now()
	pulse := x.QueryAIPulse(ctx)
	card.LatencyMs = time.Since(t0).Milliseconds()
	card.Metrics = map[string]any{
		"node":      pulse.Node,
		"providers": pulse.Providers,
	}
	downCount := 0
	var parts []string
	for _, k := range []string{"gemini", "claude", "openai"} {
		if p, ok := pulse.Providers[k]; ok {
			parts = append(parts, fmt.Sprintf("%s=%s(%dms)", k, strings.ToUpper(p.Status), p.LatencyMs))
			if p.Status == "down" {
				downCount++
			}
		}
	}
	if downCount == len(pulse.Providers) && downCount > 0 {
		card.Status = "fail"
	} else if downCount > 0 {
		card.Status = "warn"
	}
	if len(parts) > 0 {
		card.Summary = strings.Join(parts, ", ")
	} else {
		card.Summary = "No AI provider probe data"
	}
	return card
}

// FormatLocalDiagnosticReport formats a pure local clipboard/download report (STRICTLY NO #PT-XXXX ticket code).
func FormatLocalDiagnosticReport(rep *XRayReport, cfg *EngineConfig, mux *MuxManager, radar *RouteRadar) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("PixelTunnel Diagnostics 4.0 Report (%s)\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("OS: %s/%s | Engine: %s %s\n", runtime.GOOS, runtime.GOARCH, EngineName, EngineVersion))
	if mux != nil {
		snap := mux.Snapshot()
		b.WriteString(fmt.Sprintf("Node: %s | Protocol: %s | uTLS: %s | Standby: %v (%s) | Failovers: %d | Wakes: %d\n",
			snap.ActiveNode, snap.Protocol, snap.UTLSProfile, snap.StandbyReady, snap.StandbyNode, snap.FailoverCount, snap.InstantWakeCount))
	}
	if cfg != nil {
		b.WriteString(fmt.Sprintf("Ports: HTTP 127.0.0.1:%d | SOCKS5 127.0.0.1:%d\n\n", cfg.HTTPPort, cfg.SOCKSPort))
	}
	if rep != nil {
		b.WriteString(fmt.Sprintf("Overall: %s (%dms)\n", strings.ToUpper(rep.Overall), rep.DurationMs))
		for _, c := range rep.Cards {
			b.WriteString(fmt.Sprintf("- [%s] %s: %s (%dms)\n", strings.ToUpper(c.Status), c.Title, c.Summary, c.LatencyMs))
		}
	}
	if radar != nil {
		entries := radar.List(15)
		if len(entries) > 0 {
			b.WriteString("\nRecent Live Route Radar (latest 15):\n")
			for _, e := range entries {
				b.WriteString(fmt.Sprintf("  %s [%s:%s] %s (%d) -> %s:%d (%s, %dms)\n",
					e.Time, e.Action, e.Rule, e.Process, e.PID, e.Domain, e.Port, e.Node, e.PingMs))
			}
		}
	}
	return b.String()
}

func runDiagEchoMeta(sess *ClientMuxSession) (bool, string, error) {
	st, err := sess.OpenTCPStream("diag.internal.pixel", 443, 3*time.Second)
	if err != nil {
		return false, "", err
	}
	defer st.Close()
	if _, err := st.Write([]byte("ECHO_META\n")); err != nil {
		return false, "", err
	}
	br := bufio.NewReader(st)
	line, err := br.ReadString('\n')
	if err != nil {
		return false, "", err
	}
	var res struct {
		OK    bool   `json:"ok"`
		Proto string `json:"proto"`
	}
	if jErr := json.Unmarshal([]byte(line), &res); jErr != nil {
		return false, "", jErr
	}
	return res.OK, res.Proto, nil
}

func runDiagDownload64K(sess *ClientMuxSession) (bool, int64, error) {
	t0 := time.Now()
	st, err := sess.OpenTCPStream("diag.internal.pixel", 443, 3*time.Second)
	if err != nil {
		return false, 0, err
	}
	defer st.Close()
	if _, err := st.Write([]byte("DL_64K\n")); err != nil {
		return false, 0, err
	}
	br := bufio.NewReader(st)
	hdr, err := br.ReadString('\n')
	if err != nil {
		return false, 0, err
	}
	hdr = strings.TrimSpace(hdr)
	if !strings.HasPrefix(hdr, "PWP4_DL_OK:") {
		return false, 0, fmt.Errorf("unexpected diag DL header %q", hdr)
	}
	expectedHex := strings.TrimPrefix(hdr, "PWP4_DL_OK:")
	buf := make([]byte, 65536)
	if _, err := io.ReadFull(br, buf); err != nil {
		return false, 0, err
	}
	sum := sha256.Sum256(buf)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), expectedHex) {
		return false, 0, fmt.Errorf("DL_64K SHA-256 mismatch")
	}
	return true, time.Since(t0).Milliseconds(), nil
}

func runDiagUpload32K(sess *ClientMuxSession) (bool, int64, error) {
	t0 := time.Now()
	st, err := sess.OpenTCPStream("diag.internal.pixel", 443, 3*time.Second)
	if err != nil {
		return false, 0, err
	}
	defer st.Close()
	ulBuf := make([]byte, 32768)
	for i := range ulBuf {
		ulBuf[i] = byte((i*37 + 11) & 0xFF)
	}
	sum := sha256.Sum256(ulBuf)
	expectedHex := hex.EncodeToString(sum[:])

	if _, err := st.Write([]byte("UL_32K\n")); err != nil {
		return false, 0, err
	}
	if _, err := st.Write(ulBuf); err != nil {
		return false, 0, err
	}
	br := bufio.NewReader(st)
	resp, err := br.ReadString('\n')
	if err != nil {
		return false, 0, err
	}
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "PWP4_UL_OK:") {
		return false, 0, fmt.Errorf("unexpected diag UL response %q", resp)
	}
	parts := strings.Split(strings.TrimPrefix(resp, "PWP4_UL_OK:"), ":")
	if len(parts) == 0 || !strings.EqualFold(parts[0], expectedHex) {
		return false, 0, fmt.Errorf("UL_32K SHA-256 mismatch")
	}
	return true, time.Since(t0).Milliseconds(), nil
}

func runLegacyProbe36K(sess *ClientMuxSession) (bool, int64) {
	t0 := time.Now()
	st, err := sess.OpenTCPStream("probe.internal.pixel", 36, 3*time.Second)
	if err != nil {
		return false, 0
	}
	defer st.Close()
	n, err := io.CopyN(io.Discard, st, 36*1024)
	return n >= 32*1024 && (err == nil || err == io.EOF), time.Since(t0).Milliseconds()
}

func inspectSystemHostsFile() []string {
	hostsPath := "/etc/hosts"
	if runtime.GOOS == "windows" {
		sysRoot := os.Getenv("SystemRoot")
		if sysRoot == "" {
			sysRoot = `C:\Windows`
		}
		hostsPath = sysRoot + `\System32\drivers\etc\hosts`
	}
	raw, err := os.ReadFile(hostsPath)
	if err != nil {
		return nil
	}
	watched := []string{"googleapis.com", "anthropic.com", "openai.com", "claude.ai", "cursor.sh", "github.com", "pixelstore.space"}
	var hits []string
	for _, line := range strings.Split(string(raw), "\n") {
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, dom := range fields[1:] {
			low := strings.ToLower(dom)
			for _, w := range watched {
				if low == w || strings.HasSuffix(low, "."+w) {
					hits = append(hits, fields[0]+" -> "+dom)
					break
				}
			}
		}
	}
	return hits
}

func looksLikeAVMitmIssuer(issuer string) bool {
	low := strings.ToLower(issuer)
	for _, kw := range []string{"kaspersky", "eset", "avast", "avg", "bitdefender", "dr.web", "fiddler", "charles", "mitmproxy", "zscaler"} {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

func getRootCAsFromMux(mux *MuxManager) (pool *x509.CertPool) {
	if mux == nil {
		return nil
	}
	mux.mu.Lock()
	pool = mux.rootCAs
	mux.mu.Unlock()
	return pool
}

func isInsecureTestFromMux(mux *MuxManager) bool {
	if mux == nil {
		return false
	}
	mux.mu.Lock()
	v := mux.insecureTest
	mux.mu.Unlock()
	return v
}
