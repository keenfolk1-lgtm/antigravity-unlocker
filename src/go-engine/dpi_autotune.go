package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/fnv"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	maxAutoTuneCacheEntries    = 64
	autoTuneCacheTTL           = 7 * 24 * time.Hour
	defaultAdaptiveStepTimeout = 1600 * time.Millisecond
)

// DPIStrategy identifies one TLS ClientHello fragmentation + uTLS + optional Decoy-SNI combination.
type DPIStrategy struct {
	DPIProfile  DPIProfile `json:"dpi_profile"`
	UTLSProfile string     `json:"utls_profile"`
	UseDecoySNI bool       `json:"use_decoy_sni"`
	DecoySNI    string     `json:"decoy_sni,omitempty"`
}

// Label formats the strategy into a concise human/telemetry string.
func (s DPIStrategy) Label() string {
	prof := strings.ToLower(strings.TrimSpace(s.UTLSProfile))
	if prof == "" {
		prof = "chrome"
	}
	base := s.DPIProfile.String() + "/" + prof
	if s.UseDecoySNI && strings.TrimSpace(s.DecoySNI) != "" {
		return "decoy:" + strings.ToLower(strings.TrimSpace(s.DecoySNI)) + "+" + base
	}
	return base
}

func (s DPIStrategy) canonicalKey() string {
	return s.Label()
}

type cachedDPIStrategy struct {
	Strategy    DPIStrategy `json:"strategy"`
	UpdatedUnix int64       `json:"updated_unix"`
}

type persistedDPICache struct {
	Version int                          `json:"version"`
	Entries map[string]cachedDPIStrategy `json:"entries"`
}

// DPIAutoTuner learns, applies, and persists per-network DPI bypass strategies.
type DPIAutoTuner struct {
	mu             sync.RWMutex
	ioMu           sync.Mutex
	cachePath      string
	entries        map[string]cachedDPIStrategy
	promotions     atomic.Int64
	activeStrategy atomic.Value
	clockNow       func() time.Time
}

// NewDPIAutoTuner constructs a DPIAutoTuner backed by cachePath (or default state path outside sandbox tests).
func NewDPIAutoTuner(cachePath string) *DPIAutoTuner {
	if cachePath == "" && os.Getenv("PIXEL_TEST_LOCAL_SANDBOX") != "1" {
		cachePath = filepath.Join(DefaultStateDir(), "dpi_autotune_v1.json")
	}
	t := &DPIAutoTuner{
		cachePath: cachePath,
		entries:   make(map[string]cachedDPIStrategy),
		clockNow:  time.Now,
	}
	t.activeStrategy.Store("")
	if cachePath != "" {
		t.loadFromDisk()
	}
	return t
}

func (t *DPIAutoTuner) now() time.Time {
	if t != nil && t.clockNow != nil {
		return t.clockNow()
	}
	return time.Now()
}

func autoTuneKey(netFP, addr string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(netFP)))
	return hex.EncodeToString(sum[:8]) + "|" + strings.ToLower(strings.TrimSpace(addr))
}

// ActiveStrategy returns the most recently successful strategy label.
func (t *DPIAutoTuner) ActiveStrategy() string {
	if t == nil {
		return ""
	}
	if v, ok := t.activeStrategy.Load().(string); ok {
		return v
	}
	return ""
}

// Promotions returns how many connections succeeded via fallback escalation.
func (t *DPIAutoTuner) Promotions() int64 {
	if t == nil {
		return 0
	}
	return t.promotions.Load()
}

// Lookup returns a fresh cached strategy for (netFP, addr) if present and unexpired.
func (t *DPIAutoTuner) Lookup(netFP, addr string) (DPIStrategy, bool) {
	if t == nil || strings.TrimSpace(addr) == "" {
		return DPIStrategy{}, false
	}
	key := autoTuneKey(netFP, addr)
	now := t.now()

	t.mu.RLock()
	ent, ok := t.entries[key]
	t.mu.RUnlock()
	if !ok {
		return DPIStrategy{}, false
	}
	if ent.UpdatedUnix <= 0 || now.Sub(time.Unix(ent.UpdatedUnix, 0)) > autoTuneCacheTTL {
		t.Invalidate(netFP, addr)
		return DPIStrategy{}, false
	}
	return ent.Strategy, true
}

// RecordSuccess updates the active strategy label, promotion counter, and network-keyed cache.
func (t *DPIAutoTuner) RecordSuccess(netFP, addr string, s DPIStrategy, promoted bool) {
	if t == nil {
		return
	}
	t.activeStrategy.Store(s.Label())
	if promoted {
		t.promotions.Add(1)
	}
	if strings.TrimSpace(addr) == "" {
		return
	}
	key := autoTuneKey(netFP, addr)
	now := t.now()

	t.mu.Lock()
	if t.entries == nil {
		t.entries = make(map[string]cachedDPIStrategy)
	}
	t.pruneExpiredLocked(now)
	if _, exists := t.entries[key]; !exists {
		t.evictOverflowLocked(maxAutoTuneCacheEntries - 1)
	}
	t.entries[key] = cachedDPIStrategy{
		Strategy:    s,
		UpdatedUnix: now.Unix(),
	}
	snap := t.copyEntriesLocked()
	t.mu.Unlock()

	t.saveSnapshotToDisk(snap)
}

// Invalidate removes a cached strategy for (netFP, addr) so the ladder re-probes cleanly.
func (t *DPIAutoTuner) Invalidate(netFP, addr string) {
	if t == nil || strings.TrimSpace(addr) == "" {
		return
	}
	key := autoTuneKey(netFP, addr)
	t.mu.Lock()
	if _, exists := t.entries[key]; !exists {
		t.mu.Unlock()
		return
	}
	delete(t.entries, key)
	snap := t.copyEntriesLocked()
	t.mu.Unlock()

	t.saveSnapshotToDisk(snap)
}

func (t *DPIAutoTuner) pruneExpiredLocked(now time.Time) {
	for k, ent := range t.entries {
		if ent.UpdatedUnix <= 0 || now.Sub(time.Unix(ent.UpdatedUnix, 0)) > autoTuneCacheTTL {
			delete(t.entries, k)
		}
	}
}

func (t *DPIAutoTuner) evictOverflowLocked(targetMax int) {
	if targetMax < 0 {
		targetMax = 0
	}
	for len(t.entries) > targetMax {
		var oldestKey string
		var oldestTS int64
		first := true
		for k, ent := range t.entries {
			if first || ent.UpdatedUnix < oldestTS {
				oldestKey = k
				oldestTS = ent.UpdatedUnix
				first = false
			}
		}
		if oldestKey == "" {
			break
		}
		delete(t.entries, oldestKey)
	}
}

func (t *DPIAutoTuner) copyEntriesLocked() map[string]cachedDPIStrategy {
	out := make(map[string]cachedDPIStrategy, len(t.entries))
	for k, v := range t.entries {
		out[k] = v
	}
	return out
}

func (t *DPIAutoTuner) loadFromDisk() {
	if t.cachePath == "" {
		return
	}
	raw, err := os.ReadFile(t.cachePath)
	if err != nil {
		return
	}
	var doc persistedDPICache
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Entries) == 0 {
		return
	}
	now := t.now()
	t.mu.Lock()
	if t.entries == nil {
		t.entries = make(map[string]cachedDPIStrategy)
	}
	for k, ent := range doc.Entries {
		if ent.UpdatedUnix > 0 && now.Sub(time.Unix(ent.UpdatedUnix, 0)) <= autoTuneCacheTTL {
			t.entries[k] = ent
		}
	}
	t.evictOverflowLocked(maxAutoTuneCacheEntries)
	t.mu.Unlock()
}

func (t *DPIAutoTuner) saveSnapshotToDisk(entries map[string]cachedDPIStrategy) {
	if t.cachePath == "" {
		return
	}
	t.ioMu.Lock()
	defer t.ioMu.Unlock()

	if err := os.MkdirAll(filepath.Dir(t.cachePath), 0700); err != nil {
		return
	}
	payload, err := json.MarshalIndent(persistedDPICache{
		Version: 1,
		Entries: entries,
	}, "", "  ")
	if err != nil {
		return
	}
	tmp := t.cachePath + ".tmp"
	if err := os.WriteFile(tmp, payload, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, t.cachePath)
}

// AdaptiveDialOptions configures the adaptive TLS/DPI escalation ladder.
type AdaptiveDialOptions struct {
	Address          string
	SNI              string
	BaseUTLSProfile  string
	BaseDPIProfile   DPIProfile
	EnableSplit      bool
	DecoySNIs        []string
	AllowDecoySNI    bool
	Pins             []string
	RequirePin       bool
	RootCAs          *x509.CertPool
	ForceHTTP1ALPN   bool
	InsecureTestOnly bool
	StepTimeout      time.Duration
	NetFingerprint   string
	DialControl      func(network, address string, c syscall.RawConn) error
}

// BuildAdaptiveLadder returns deduplicated bypass strategies ordered from cached/fast to Auto Decoy-SNI.
func (t *DPIAutoTuner) BuildAdaptiveLadder(opts AdaptiveDialOptions) ([]DPIStrategy, bool) {
	primaryUTLS := "chrome"
	altUTLS := "firefox"
	if strings.EqualFold(strings.TrimSpace(opts.BaseUTLSProfile), "firefox") {
		primaryUTLS = "firefox"
		altUTLS = "chrome"
	}

	if !opts.EnableSplit && !opts.AllowDecoySNI {
		return []DPIStrategy{
			{DPIProfile: opts.BaseDPIProfile, UTLSProfile: primaryUTLS},
			{DPIProfile: opts.BaseDPIProfile, UTLSProfile: altUTLS},
		}, false
	}

	var ladder []DPIStrategy
	seen := make(map[string]struct{})
	appendUnique := func(s DPIStrategy) {
		k := s.canonicalKey()
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		ladder = append(ladder, s)
	}

	hadCached := false
	if cached, ok := t.Lookup(opts.NetFingerprint, opts.Address); ok {
		if !cached.UseDecoySNI || (opts.AllowDecoySNI && len(opts.Pins) > 0 && !opts.InsecureTestOnly && strings.TrimSpace(cached.DecoySNI) != "") {
			appendUnique(cached)
			hadCached = true
		}
	}

	// Step 1: Configured / fast profile on native SNI.
	appendUnique(DPIStrategy{
		DPIProfile:  opts.BaseDPIProfile,
		UTLSProfile: primaryUTLS,
	})

	// Step 2: Escalated TLS record + multi-record + micro-chunk splits on native SNI.
	appendUnique(DPIStrategy{
		DPIProfile:  DPIProfileTlsRecordSplit,
		UTLSProfile: primaryUTLS,
	})
	appendUnique(DPIStrategy{
		DPIProfile:  DPIProfileComboMultiRecord,
		UTLSProfile: primaryUTLS,
	})
	appendUnique(DPIStrategy{
		DPIProfile:  DPIProfileSniMicroChunk,
		UTLSProfile: altUTLS,
	})

	// Step 3: Auto Decoy-SNI with SPKI pin verification.
	if opts.AllowDecoySNI && len(opts.Pins) > 0 && !opts.InsecureTestOnly {
		decoys := selectDecoyCandidates(opts.DecoySNIs, opts.SNI, opts.Address)
		if len(decoys) > 0 {
			d1 := decoys[0]
			d2 := d1
			if len(decoys) > 1 {
				d2 = decoys[1]
			}
			appendUnique(DPIStrategy{
				DPIProfile:  DPIProfileComboMultiRecord,
				UTLSProfile: primaryUTLS,
				UseDecoySNI: true,
				DecoySNI:    d1,
			})
			appendUnique(DPIStrategy{
				DPIProfile:  DPIProfileTlsRecordSplit,
				UTLSProfile: altUTLS,
				UseDecoySNI: true,
				DecoySNI:    d2,
			})
		}
	}

	return ladder, hadCached
}

func selectDecoyCandidates(configured []string, nativeSNI, addr string) []string {
	pool := configured
	if len(pool) == 0 {
		pool = DefaultDecoySNIs
	}
	nativeLower := strings.ToLower(strings.TrimSpace(nativeSNI))
	defaultLower := strings.ToLower(DefaultSNI)

	var filtered []string
	seen := make(map[string]struct{})
	for _, raw := range pool {
		d := strings.ToLower(strings.TrimSpace(raw))
		if d == "" || d == nativeLower || d == defaultLower || strings.HasSuffix(d, ".pixelstore.space") {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		filtered = append(filtered, d)
	}
	if len(filtered) == 0 {
		for _, raw := range DefaultDecoySNIs {
			d := strings.ToLower(strings.TrimSpace(raw))
			if d != "" && d != nativeLower && d != defaultLower && !strings.HasSuffix(d, ".pixelstore.space") {
				if _, ok := seen[d]; !ok {
					seen[d] = struct{}{}
					filtered = append(filtered, d)
				}
			}
		}
	}
	if len(filtered) <= 1 {
		return filtered
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(strings.TrimSpace(addr))))
	start := int(h.Sum32()) % len(filtered)
	ordered := make([]string, 0, 2)
	ordered = append(ordered, filtered[start])
	second := filtered[(start+1)%len(filtered)]
	if second != ordered[0] {
		ordered = append(ordered, second)
	}
	return ordered
}

// DialAdaptiveTLS executes the adaptive DPI ladder against opts.Address, caching the winner per network fingerprint.
func (t *DPIAutoTuner) DialAdaptiveTLS(ctx context.Context, opts AdaptiveDialOptions) (*UTLSDialResult, DPIStrategy, error) {
	if ctx.Err() != nil {
		return nil, DPIStrategy{}, ctx.Err()
	}
	ladder, hadCached := t.BuildAdaptiveLadder(opts)
	stepTimeout := opts.StepTimeout
	if stepTimeout <= 0 {
		stepTimeout = defaultAdaptiveStepTimeout
	}

	addrHost := hostFromAddr(opts.Address)
	addrIsIP := net.ParseIP(addrHost) != nil

	var firstSubstantiveErr error
	var lastErr error
	skipRemainingDecoys := false

	for idx, cand := range ladder {
		if ctx.Err() != nil {
			return nil, DPIStrategy{}, ctx.Err()
		}
		if cand.UseDecoySNI && skipRemainingDecoys {
			continue
		}

		targetSNI := opts.SNI
		maskedDecoy := false
		if cand.UseDecoySNI {
			targetSNI = cand.DecoySNI
			maskedDecoy = true
		} else if addrIsIP && targetSNI != "" && !strings.EqualFold(targetSNI, DefaultSNI) && !strings.HasSuffix(strings.ToLower(targetSNI), ".pixelstore.space") {
			maskedDecoy = true
		}

		enableSplit := opts.EnableSplit || idx > 0 || cand.UseDecoySNI

		stepCtx, stepCancel := context.WithTimeout(ctx, stepTimeout)
		res, err := dialUTLSOnce(stepCtx, UTLSDialOptions{
			Address:          opts.Address,
			SNI:              targetSNI,
			Profile:          cand.UTLSProfile,
			DPIProfile:       cand.DPIProfile,
			EnableSplit:      enableSplit,
			MaskedDecoySNI:   maskedDecoy,
			Pins:             opts.Pins,
			RequirePin:       opts.RequirePin,
			RootCAs:          opts.RootCAs,
			ForceHTTP1ALPN:   opts.ForceHTTP1ALPN,
			InsecureTestOnly: opts.InsecureTestOnly,
			ConnectTimeout:   stepTimeout,
			DialControl:      opts.DialControl,
		}, cand.UTLSProfile, stepTimeout)
		stepCancel()

		if err == nil {
			if t != nil {
				t.RecordSuccess(opts.NetFingerprint, opts.Address, cand, idx > 0)
			}
			return res, cand, nil
		}

		if ctx.Err() != nil {
			return nil, DPIStrategy{}, ctx.Err()
		}

		var tcpErr *tcpConnectError
		isTCPErr := errors.As(err, &tcpErr)

		if idx == 0 && hadCached && !isTCPErr && t != nil {
			t.Invalidate(opts.NetFingerprint, opts.Address)
		}

		if isTCPErr {
			return nil, DPIStrategy{}, err
		}

		if !cand.UseDecoySNI && (errors.Is(err, ErrCertPinMismatch) || errors.Is(err, ErrMitmDetected)) {
			return nil, DPIStrategy{}, err
		}

		if cand.UseDecoySNI && errors.Is(err, ErrCertPinMismatch) {
			skipRemainingDecoys = true
			continue
		}

		if firstSubstantiveErr == nil {
			firstSubstantiveErr = err
		}
		lastErr = err
	}

	if firstSubstantiveErr != nil {
		return nil, DPIStrategy{}, firstSubstantiveErr
	}
	if lastErr != nil {
		return nil, DPIStrategy{}, lastErr
	}
	return nil, DPIStrategy{}, errors.New("adaptive TLS dial attempts exhausted")
}

func hostFromAddr(addr string) string {
	h, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err == nil {
		return h
	}
	return strings.TrimSpace(addr)
}
