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
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type nodeTelemetry struct {
	ewmaRTTMs   int64
	probedRTT   bool
	probeKnown  bool
	online      bool
	aiDegraded  bool
	lastChecked time.Time
}

// SmartNodeSelector ranks upstream nodes using per-endpoint EWMA RTT, AI provider pulse
// health, preferred-region affinity, and sticky AI pinning to prevent cross-country jitter
// flapping while migrating immediately when AI providers report blocks or outages.
type SmartNodeSelector struct {
	mu           sync.RWMutex
	stats        map[string]*nodeTelemetry
	stickyAIKey  string
	stickyAIName string
	aiMigrations atomic.Int64

	resolver       *DohResolver
	rootCAs        *x509.CertPool
	insecureTest   bool
	clockOffset    *atomic.Int64
	localClockSkew atomic.Int64
}

// NewSmartNodeSelector creates a thread-safe SmartNodeSelector.
func NewSmartNodeSelector() *SmartNodeSelector {
	return &SmartNodeSelector{
		stats: make(map[string]*nodeTelemetry),
	}
}

// SetTransportDeps attaches optional DoH, TLS verification, and clock-offset state used
// when probing /api/v4/ai-pulse directly over uTLS.
func (s *SmartNodeSelector) SetTransportDeps(resolver *DohResolver, rootCAs *x509.CertPool, insecureTest bool, clockOffset *atomic.Int64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.resolver = resolver
	s.rootCAs = rootCAs
	s.insecureTest = insecureTest
	s.clockOffset = clockOffset
	s.mu.Unlock()
}

func nodeEndpointKey(node NodeConfig) string {
	host := strings.ToLower(strings.TrimSpace(node.Host))
	if host == "" {
		return ""
	}
	port := node.Port
	if port <= 0 {
		port = 443
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func cloneNodeConfig(n NodeConfig) NodeConfig {
	if len(n.Roles) > 0 {
		n.Roles = append([]string(nil), n.Roles...)
	}
	return n
}

func isMediaRole(role string) bool {
	return strings.EqualFold(strings.TrimSpace(role), "media")
}

func isAIPulseDegraded(pulse AIPulseResponse) bool {
	for k, p := range pulse.Providers {
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "claude", "openai", "gemini":
			if strings.EqualFold(strings.TrimSpace(p.Status), "down") || p.HTTPCode == 403 || p.HTTPCode == 429 {
				return true
			}
		}
	}
	return false
}

// RecordProbe records reachability and RTT telemetry for a node endpoint, updating its
// integer EWMA latency as (old*3 + new)/4 when online and rttMs > 0.
func (s *SmartNodeSelector) RecordProbe(node NodeConfig, online bool, rttMs int64) {
	if s == nil {
		return
	}
	key := nodeEndpointKey(node)
	if key == "" {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stats == nil {
		s.stats = make(map[string]*nodeTelemetry)
	}
	st := s.stats[key]
	if st == nil {
		st = &nodeTelemetry{}
		s.stats[key] = st
	}
	st.probeKnown = true
	st.online = online
	st.lastChecked = now
	if online && rttMs > 0 {
		if !st.probedRTT || st.ewmaRTTMs <= 0 {
			st.ewmaRTTMs = rttMs
		} else {
			st.ewmaRTTMs = (st.ewmaRTTMs*3 + rttMs) / 4
		}
		st.probedRTT = true
	}
}

// RecordAIPulse updates AI provider degradation state from an /api/v4/ai-pulse response.
func (s *SmartNodeSelector) RecordAIPulse(node NodeConfig, pulse AIPulseResponse) {
	if s == nil {
		return
	}
	key := nodeEndpointKey(node)
	if key == "" {
		return
	}
	degraded := isAIPulseDegraded(pulse)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stats == nil {
		s.stats = make(map[string]*nodeTelemetry)
	}
	st := s.stats[key]
	if st == nil {
		st = &nodeTelemetry{}
		s.stats[key] = st
	}
	st.aiDegraded = degraded
	st.lastChecked = now
}

// NodeEWMA returns the smoothed EWMA RTT in milliseconds for node if probed, or 0 if unknown.
func (s *SmartNodeSelector) NodeEWMA(node NodeConfig) int64 {
	if s == nil {
		return 0
	}
	key := nodeEndpointKey(node)
	if key == "" {
		return 0
	}
	s.mu.RLock()
	st := s.stats[key]
	var rtt int64
	if st != nil && st.probedRTT && st.ewmaRTTMs > 0 {
		rtt = st.ewmaRTTMs
	}
	s.mu.RUnlock()
	return rtt
}

// RankCandidates returns a newly allocated, ranked copy of candidates for role and preferredRegion.
// The input slice is never mutated.
func (s *SmartNodeSelector) RankCandidates(role, preferredRegion string, candidates []NodeConfig) []NodeConfig {
	if len(candidates) == 0 {
		return nil
	}
	out := make([]NodeConfig, len(candidates))
	for i, c := range candidates {
		out[i] = cloneNodeConfig(c)
	}
	if s == nil {
		return out
	}

	media := isMediaRole(role)
	pref := strings.TrimSpace(preferredRegion)
	useRegion := pref != "" && !strings.EqualFold(pref, "auto")

	type rankEntry struct {
		node          NodeConfig
		key           string
		origIdx       int
		regionHit     bool
		knownOffline  bool
		aiDegraded    bool
		ewmaRTTMs     int64
		primaryBucket int
		healthTier    int
		stickyBoost   int
		rttGroup      int
	}

	s.mu.RLock()
	stickyKey := s.stickyAIKey
	entries := make([]rankEntry, len(out))
	for i, c := range out {
		key := nodeEndpointKey(c)
		st := s.stats[key]
		knownOff := st != nil && st.probeKnown && !st.online
		aiDeg := st != nil && st.aiDegraded
		probedRTT := st != nil && st.probedRTT && st.ewmaRTTMs > 0
		ewma := int64(0)
		if probedRTT {
			ewma = st.ewmaRTTMs
		}
		regHit := useRegion && (strings.EqualFold(strings.TrimSpace(c.Region), pref) || strings.EqualFold(strings.TrimSpace(c.Name), pref))

		healthTier := 0
		if media {
			if knownOff {
				healthTier = 1
			}
		} else {
			if knownOff {
				healthTier = 2
			} else if aiDeg {
				healthTier = 1
			}
		}

		rttGroup := 1
		if probedRTT {
			rttGroup = 0
		}

		entries[i] = rankEntry{
			node:         c,
			key:          key,
			origIdx:      i,
			regionHit:    regHit,
			knownOffline: knownOff,
			aiDegraded:   aiDeg,
			ewmaRTTMs:    ewma,
			healthTier:   healthTier,
			stickyBoost:  1,
			rttGroup:     rttGroup,
		}
	}
	s.mu.RUnlock()

	hasCleanRegion := false
	hasCleanOverall := false
	for i := range entries {
		if entries[i].healthTier == 0 {
			hasCleanOverall = true
			if entries[i].regionHit {
				hasCleanRegion = true
			}
		}
	}

	for i := range entries {
		e := &entries[i]
		if useRegion {
			if media {
				if e.regionHit {
					e.primaryBucket = 0
				} else {
					e.primaryBucket = 1
				}
			} else if hasCleanRegion {
				switch {
				case e.regionHit && e.healthTier == 0:
					e.primaryBucket = 0
				case !e.regionHit && e.healthTier == 0:
					e.primaryBucket = 1
				case e.regionHit && e.healthTier == 1:
					e.primaryBucket = 2
				case !e.regionHit && e.healthTier == 1:
					e.primaryBucket = 3
				case e.regionHit:
					e.primaryBucket = 4
				default:
					e.primaryBucket = 5
				}
			} else {
				if e.regionHit {
					e.primaryBucket = 0
				} else {
					e.primaryBucket = 1
				}
			}
		}

		if !media && stickyKey != "" && e.key == stickyKey && !e.knownOffline {
			if useRegion {
				if e.regionHit && (!e.aiDegraded || !hasCleanRegion) {
					e.stickyBoost = 0
				} else if !e.regionHit && !hasCleanRegion && (!e.aiDegraded || !hasCleanOverall) {
					e.stickyBoost = 0
				}
			} else if !e.aiDegraded || !hasCleanOverall {
				e.stickyBoost = 0
			}
		}
	}

	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.primaryBucket != b.primaryBucket {
			return a.primaryBucket < b.primaryBucket
		}
		if a.healthTier != b.healthTier {
			return a.healthTier < b.healthTier
		}
		if a.stickyBoost != b.stickyBoost {
			return a.stickyBoost < b.stickyBoost
		}
		if a.rttGroup != b.rttGroup {
			return a.rttGroup < b.rttGroup
		}
		if a.rttGroup == 0 && a.ewmaRTTMs != b.ewmaRTTMs {
			return a.ewmaRTTMs < b.ewmaRTTMs
		}
		return a.origIdx < b.origIdx
	})

	for i := range entries {
		out[i] = entries[i].node
	}
	return out
}

// NotifyConnected records an active session connection for role. For "ai" (or "auto"/""),
// it updates the sticky AI endpoint and increments AIMigrations when switching from a
// different previously pinned AI endpoint.
func (s *SmartNodeSelector) NotifyConnected(role string, node NodeConfig) {
	if s == nil || isMediaRole(role) {
		return
	}
	norm := strings.ToLower(strings.TrimSpace(role))
	if norm != "" && norm != "ai" && norm != "auto" {
		return
	}
	key := nodeEndpointKey(node)
	if key == "" {
		return
	}
	name := strings.TrimSpace(node.Name)
	if name == "" {
		name = key
	}

	s.mu.Lock()
	if s.stickyAIKey != "" && s.stickyAIKey != key {
		s.aiMigrations.Add(1)
	}
	s.stickyAIKey = key
	s.stickyAIName = name
	s.mu.Unlock()
}

// ShouldMigrateAI returns true when the current sticky AI endpoint is known aiDegraded or
// offline AND at least one alternate candidate in candidates is healthy and non-degraded.
func (s *SmartNodeSelector) ShouldMigrateAI(candidates []NodeConfig) bool {
	if s == nil || len(candidates) == 0 {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.stickyAIKey == "" {
		return false
	}
	stickyStat := s.stats[s.stickyAIKey]
	if stickyStat == nil {
		return false
	}
	if !stickyStat.aiDegraded && (!stickyStat.probeKnown || stickyStat.online) {
		return false
	}
	for _, c := range candidates {
		key := nodeEndpointKey(c)
		if key == "" || key == s.stickyAIKey {
			continue
		}
		st := s.stats[key]
		if st == nil {
			return true
		}
		knownOffline := st.probeKnown && !st.online
		if !knownOffline && !st.aiDegraded {
			return true
		}
	}
	return false
}

// StickyAINode returns the display name (or endpoint key if unnamed) of the pinned AI node.
func (s *SmartNodeSelector) StickyAINode() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.stickyAIName != "" {
		return s.stickyAIName
	}
	return s.stickyAIKey
}

// AIMigrations returns the number of times the active AI node changed after initial pin.
func (s *SmartNodeSelector) AIMigrations() int64 {
	if s == nil {
		return 0
	}
	return s.aiMigrations.Load()
}

// ProbeSessionAIPulse probes AI provider health for node using the same protocol as
// XRayRunner.QueryAIPulse (in-band diag.internal.pixel:443 AI_PULSE over sess when available,
// falling back to signed HTTP/HMAC GET /api/v4/ai-pulse over uTLS), then records the result.
func (s *SmartNodeSelector) ProbeSessionAIPulse(ctx context.Context, sess *ClientMuxSession, node NodeConfig, cfg *EngineConfig) (AIPulseResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return AIPulseResponse{}, err
	}
	origHostEmpty := strings.TrimSpace(node.Host) == ""
	if origHostEmpty && sess != nil {
		node = sess.Node()
	}
	if strings.TrimSpace(node.Host) == "" {
		return AIPulseResponse{}, errors.New("ai-pulse: missing node host")
	}

	if sess != nil && !sess.IsClosed() && (origHostEmpty || sameEndpoint(node, sess.Node())) {
		if resp, ok := probeMuxDiagAIPulse(ctx, sess, node); ok {
			if resp.Node == "" {
				resp.Node = node.Name
			}
			s.RecordAIPulse(node, resp)
			return resp, nil
		}
		if err := ctx.Err(); err != nil {
			return AIPulseResponse{}, err
		}
	}

	resp, err := s.probeHTTPNodeAIPulse(ctx, node, cfg)
	if err != nil {
		return AIPulseResponse{}, err
	}
	if resp.Node == "" {
		resp.Node = node.Name
	}
	s.RecordAIPulse(node, resp)
	return resp, nil
}

func probeMuxDiagAIPulse(ctx context.Context, sess *ClientMuxSession, node NodeConfig) (AIPulseResponse, bool) {
	if sess == nil || sess.IsClosed() || ctx.Err() != nil {
		return AIPulseResponse{}, false
	}
	synTimeout := 3 * time.Second
	ioDeadline := time.Now().Add(4 * time.Second)
	if dl, ok := ctx.Deadline(); ok {
		rem := time.Until(dl)
		if rem <= 0 {
			return AIPulseResponse{}, false
		}
		if rem < synTimeout {
			synTimeout = rem
		}
		if dl.Before(ioDeadline) {
			ioDeadline = dl
		}
	}

	st, err := sess.OpenTCPStream("diag.internal.pixel", 443, synTimeout)
	if err != nil {
		return AIPulseResponse{}, false
	}
	defer st.Close()

	_ = st.SetDeadline(ioDeadline)
	if _, err := st.Write([]byte("AI_PULSE\n")); err != nil {
		return AIPulseResponse{}, false
	}
	body, err := io.ReadAll(io.LimitReader(st, 64*1024))
	if err != nil && len(body) == 0 {
		return AIPulseResponse{}, false
	}
	var parsed AIPulseResponse
	if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.Providers) == 0 {
		return AIPulseResponse{}, false
	}
	if parsed.Node == "" {
		parsed.Node = node.Name
	}
	return parsed, true
}

func (s *SmartNodeSelector) probeHTTPNodeAIPulse(ctx context.Context, node NodeConfig, cfg *EngineConfig) (AIPulseResponse, error) {
	var resolver *DohResolver
	var rootCAs *x509.CertPool
	var insecure bool
	var clockPtr *atomic.Int64

	if s != nil {
		s.mu.RLock()
		resolver = s.resolver
		rootCAs = s.rootCAs
		insecure = s.insecureTest
		clockPtr = s.clockOffset
		s.mu.RUnlock()
		if clockPtr == nil {
			clockPtr = &s.localClockSkew
		}
	}

	dialHost := strings.TrimSpace(node.Host)
	if net.ParseIP(dialHost) == nil && resolver != nil {
		ips, err := resolver.LookupHost(ctx, dialHost)
		if err != nil || len(ips) == 0 {
			if err == nil {
				err = errors.New("no DNS records")
			}
			return AIPulseResponse{}, fmt.Errorf("ai-pulse resolve %s: %w", dialHost, err)
		}
		dialHost = ips[0].String()
	}

	port := node.Port
	if port <= 0 {
		port = 443
	}
	sni := strings.TrimSpace(node.SNI)
	if sni == "" {
		sni = DefaultSNI
	}

	utlsProfile := ""
	var pins []string
	if cfg != nil {
		utlsProfile = cfg.V2.UTLSProfile
		pins = cfg.PinnedSPKI
	}
	secret := node.Secret
	if secret == "" && cfg != nil {
		for _, n := range cfg.Nodes {
			if sameEndpoint(n, node) && n.Secret != "" {
				secret = n.Secret
				break
			}
		}
		if secret == "" {
			secret = cfg.ActiveNode.Secret
		}
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		resp, resynced, err := probeHTTPNodeAIPulseOnce(ctx, dialHost, port, sni, utlsProfile, pins, rootCAs, insecure, secret, clockPtr)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !resynced || attempt > 0 {
			break
		}
	}
	return AIPulseResponse{}, lastErr
}

func probeHTTPNodeAIPulseOnce(
	ctx context.Context,
	dialHost string,
	port int,
	sni, utlsProfile string,
	pins []string,
	rootCAs *x509.CertPool,
	insecure bool,
	secret string,
	clockPtr *atomic.Int64,
) (AIPulseResponse, bool, error) {
	res, err := DialUTLS(ctx, UTLSDialOptions{
		Address:          net.JoinHostPort(dialHost, strconv.Itoa(port)),
		SNI:              sni,
		Profile:          utlsProfile,
		Pins:             pins,
		RequirePin:       len(pins) > 0 && rootCAs == nil && !insecure,
		RootCAs:          rootCAs,
		ForceHTTP1ALPN:   true,
		InsecureTestOnly: insecure,
		ConnectTimeout:   4 * time.Second,
	})
	if err != nil {
		return AIPulseResponse{}, false, fmt.Errorf("ai-pulse dial: %w", err)
	}
	defer res.Conn.Close()

	var nonceRaw [8]byte
	if _, err := rand.Read(nonceRaw[:]); err != nil {
		return AIPulseResponse{}, false, fmt.Errorf("ai-pulse nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonceRaw[:])

	tsOffset := int64(0)
	if clockPtr != nil {
		tsOffset = clockPtr.Load()
	}
	tsStr := strconv.FormatInt(time.Now().Unix()+tsOffset, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("ai-pulse:" + tsStr + ":" + nonceHex))
	sigHex32 := hex.EncodeToString(mac.Sum(nil)[:16])

	req := fmt.Sprintf(
		"GET /api/v4/ai-pulse HTTP/1.1\r\nHost: %s\r\nX-Pixel-Ts: %s\r\nX-Pixel-Nonce: %s\r\nX-Pixel-Sig: %s\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
		sni, tsStr, nonceHex, sigHex32,
	)

	deadline := time.Now().Add(4 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = res.Conn.SetDeadline(deadline)
	if err := writeFull(res.Conn, []byte(req)); err != nil {
		return AIPulseResponse{}, false, fmt.Errorf("ai-pulse write: %w", err)
	}

	br := bufio.NewReader(res.Conn)
	statusLine, hdrs, err := readHTTPResponseHeaders(br)
	if err != nil {
		return AIPulseResponse{}, false, fmt.Errorf("ai-pulse read headers: %w", err)
	}

	resynced := syncClockFromHTTPDate(hdrs.Get("Date"), tsOffset, clockPtr)
	if !strings.Contains(statusLine, " 200 ") {
		return AIPulseResponse{}, resynced && strings.Contains(statusLine, " 403 "), fmt.Errorf("ai-pulse http status %q", statusLine)
	}
	if !strings.Contains(strings.ToLower(hdrs.Get("Content-Type")), "application/json") {
		return AIPulseResponse{}, false, fmt.Errorf("ai-pulse unexpected content-type %q", hdrs.Get("Content-Type"))
	}

	body, err := io.ReadAll(io.LimitReader(br, 64*1024))
	if err != nil {
		return AIPulseResponse{}, false, fmt.Errorf("ai-pulse read body: %w", err)
	}
	var parsed AIPulseResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return AIPulseResponse{}, false, fmt.Errorf("ai-pulse decode json: %w", err)
	}
	if len(parsed.Providers) == 0 {
		return AIPulseResponse{}, false, errors.New("ai-pulse empty providers map")
	}
	return parsed, false, nil
}
