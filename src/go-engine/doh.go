package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	ErrSinkholeIP     = errors.New("doh resolved loopback/private/sinkhole IP")
	ErrDohUnavailable = errors.New("all DoH upstream endpoints failed")
)

const (
	dnsTypeA           uint16 = 1
	dnsTypeTXT         uint16 = 16
	dnsTypeAAAA        uint16 = 28
	maxDohCacheEntries        = 512
	dohStaleGrace             = 30 * time.Minute
	dohStaggerDelay           = 350 * time.Millisecond
	dohCooldownWindow         = 15 * time.Second
)

// DohEndpoint represents a direct-IP DoH resolver so system/ISP DNS is never consulted.
type DohEndpoint struct {
	URL        string
	ServerName string
}

var defaultDohEndpoints = []DohEndpoint{
	{URL: "https://8.8.8.8/dns-query", ServerName: "dns.google"},
	{URL: "https://9.9.9.9/dns-query", ServerName: "dns.quad9.net"},
	{URL: "https://1.1.1.1/dns-query", ServerName: "cloudflare-dns.com"},
	{URL: "https://1.0.0.1/dns-query", ServerName: "cloudflare-dns.com"},
	{URL: "https://8.8.4.4/dns-query", ServerName: "dns.google"},
	{URL: "https://149.112.112.112/dns-query", ServerName: "dns.quad9.net"},
}

type cachedDNS struct {
	ips        []net.IP
	txts       []string
	expiresAt  time.Time
	staleUntil time.Time
}

type dohCall struct {
	done chan struct{}
	ips  []net.IP
	err  error
}

// DohResolver resolves A/AAAA/TXT records strictly via direct-IP DNS-over-HTTPS (RFC 8484)
// using uTLS + DPI record splitting, 350ms staggered failover racing, SWR cache, and singleflight.
type DohResolver struct {
	endpoints       []DohEndpoint
	httpClient      *http.Client
	mu              sync.RWMutex
	cache           map[string]cachedDNS
	inflight        map[string]*dohCall
	cooldownMu      sync.Mutex
	cooldownUntil   []int64
	preferredIdx    atomic.Int32
	activeUpstream  atomic.Value
	dialCtrlMu      sync.RWMutex
	dialControlFn   func(network, address string, c syscall.RawConn) error
	dialControlProv func() func(network, address string, c syscall.RawConn) error
}

// SetDialControl sets a static socket Control callback for DoH dials (nil resets to default).
func (r *DohResolver) SetDialControl(fn func(network, address string, c syscall.RawConn) error) {
	if r == nil {
		return
	}
	r.dialCtrlMu.Lock()
	r.dialControlFn = fn
	r.dialCtrlMu.Unlock()
}

// SetDialControlProvider registers a dynamic provider returning a socket Control callback only while TUN is active.
func (r *DohResolver) SetDialControlProvider(fn func() func(network, address string, c syscall.RawConn) error) {
	if r == nil {
		return
	}
	r.dialCtrlMu.Lock()
	r.dialControlProv = fn
	r.dialCtrlMu.Unlock()
}

func (r *DohResolver) currentDialControl() func(network, address string, c syscall.RawConn) error {
	if r == nil {
		return nil
	}
	r.dialCtrlMu.RLock()
	prov := r.dialControlProv
	fn := r.dialControlFn
	r.dialCtrlMu.RUnlock()
	if prov != nil {
		return prov()
	}
	return fn
}

// CloseIdleConnections drops pooled DoH transport sockets (e.g. after TUN toggle).
func (r *DohResolver) CloseIdleConnections() {
	if r != nil && r.httpClient != nil {
		r.httpClient.CloseIdleConnections()
	}
}

// NewDohResolver constructs an IP-direct DoH resolver with optional custom endpoints for testing.
func NewDohResolver(endpoints []DohEndpoint, tlsConfig *tls.Config) *DohResolver {
	eps := defaultDohEndpoints
	if len(endpoints) > 0 {
		eps = append([]DohEndpoint(nil), endpoints...)
	}

	sniByHost := make(map[string]string, len(eps))
	for _, ep := range eps {
		if u, err := url.Parse(ep.URL); err == nil && u.Hostname() != "" && ep.ServerName != "" {
			sniByHost[strings.ToLower(u.Hostname())] = ep.ServerName
		}
	}

	r := &DohResolver{
		endpoints:     eps,
		cache:         make(map[string]cachedDNS),
		inflight:      make(map[string]*dohCall),
		cooldownUntil: make([]int64, len(eps)),
	}
	r.activeUpstream.Store("")

	tr := &http.Transport{
		DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{
				Timeout:   4 * time.Second,
				KeepAlive: 30 * time.Second,
				Control:   r.currentDialControl(),
			}).DialContext(dctx, network, addr)
		},
		TLSHandshakeTimeout: 4 * time.Second,
		DisableKeepAlives:   false,
	}
	if tlsConfig != nil {
		tr.TLSClientConfig = tlsConfig.Clone()
	} else {
		tr.ForceAttemptHTTP2 = false
		tr.DialTLSContext = func(dctx context.Context, network, addr string) (net.Conn, error) {
			host, _, serr := net.SplitHostPort(addr)
			if serr != nil {
				host = addr
			}
			sni := sniByHost[strings.ToLower(host)]
			if sni == "" {
				sni = host
			}
			ctrl := r.currentDialControl()
			if isLoopbackHostOrIP(host) {
				d := &tls.Dialer{
					NetDialer: &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second, Control: ctrl},
					Config:    &tls.Config{ServerName: sni},
				}
				return d.DialContext(dctx, network, addr)
			}
			res, err := DialUTLS(dctx, UTLSDialOptions{
				Address:        addr,
				SNI:            sni,
				Profile:        "chrome",
				DPIProfile:     DPIProfileTlsRecordSplit,
				EnableSplit:    true,
				ForceHTTP1ALPN: true,
				ConnectTimeout: 2000 * time.Millisecond,
				DialControl:    ctrl,
			})
			if err == nil {
				return res.Conn, nil
			}
			var tcpErr *tcpConnectError
			if !errors.As(err, &tcpErr) && dctx.Err() == nil {
				res2, err2 := DialUTLS(dctx, UTLSDialOptions{
					Address:        addr,
					SNI:            sni,
					Profile:        "chrome",
					DPIProfile:     DPIProfileComboMultiRecord,
					EnableSplit:    true,
					ForceHTTP1ALPN: true,
					ConnectTimeout: 2000 * time.Millisecond,
					DialControl:    ctrl,
				})
				if err2 == nil {
					return res2.Conn, nil
				}
				return nil, err2
			}
			return nil, err
		}
	}
	r.httpClient = &http.Client{Timeout: 5 * time.Second, Transport: tr}
	return r
}

func isLoopbackHostOrIP(host string) bool {
	h := strings.TrimSpace(host)
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// ActiveUpstream returns the label of the last healthy DoH upstream endpoint.
func (r *DohResolver) ActiveUpstream() string {
	if r == nil {
		return ""
	}
	if v, ok := r.activeUpstream.Load().(string); ok {
		return v
	}
	return ""
}

// LookupHost resolves IPv4/IPv6 addresses over DoH (with SWR and singleflight) and rejects sinkhole IPs.
func (r *DohResolver) LookupHost(ctx context.Context, host string) ([]net.IP, error) {
	h := normalizeHostForMatch(host)
	if h == "" {
		return nil, errors.New("empty host")
	}
	if ip := net.ParseIP(h); ip != nil {
		if IsSinkholeIP(ip) {
			return nil, fmt.Errorf("%w: %s", ErrSinkholeIP, ip.String())
		}
		return []net.IP{ip}, nil
	}

	cacheKey := "A:" + h
	now := time.Now()

	r.mu.Lock()
	if r.cache == nil {
		r.cache = make(map[string]cachedDNS)
	}
	if r.inflight == nil {
		r.inflight = make(map[string]*dohCall)
	}
	ent, ok := r.cache[cacheKey]
	if ok && len(ent.ips) > 0 && now.Before(ent.expiresAt) {
		out := append([]net.IP(nil), ent.ips...)
		r.mu.Unlock()
		return out, nil
	}
	if ok && len(ent.ips) > 0 && now.Before(ent.staleUntil) {
		out := append([]net.IP(nil), ent.ips...)
		if _, pending := r.inflight[cacheKey]; !pending {
			r.startSingleflightLocked(h, cacheKey, 4*time.Second)
		}
		r.mu.Unlock()
		return out, nil
	}
	var lastResortIPs []net.IP
	if ok && len(ent.ips) > 0 {
		lastResortIPs = append([]net.IP(nil), ent.ips...)
	}
	call, pending := r.inflight[cacheKey]
	if !pending {
		call = r.startSingleflightLocked(h, cacheKey, 8*time.Second)
	}
	r.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.done:
		if call.err == nil && len(call.ips) > 0 {
			return append([]net.IP(nil), call.ips...), nil
		}
		if len(lastResortIPs) > 0 {
			return lastResortIPs, nil
		}
		return nil, call.err
	}
}

func (r *DohResolver) startSingleflightLocked(host, cacheKey string, budget time.Duration) *dohCall {
	call := &dohCall{done: make(chan struct{})}
	r.inflight[cacheKey] = call
	go func() {
		qctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		ips, ttl, err := r.queryA(qctx, host)
		if err == nil && len(ips) > 0 {
			if ttl < 15*time.Second {
				ttl = 15 * time.Second
			}
			if ttl > 10*time.Minute {
				ttl = 10 * time.Minute
			}
			now := time.Now()
			r.mu.Lock()
			r.setCachedLocked(cacheKey, cachedDNS{
				ips:        append([]net.IP(nil), ips...),
				expiresAt:  now.Add(ttl),
				staleUntil: now.Add(ttl + dohStaleGrace),
			})
			delete(r.inflight, cacheKey)
			r.mu.Unlock()
			call.ips = append([]net.IP(nil), ips...)
		} else {
			r.mu.Lock()
			delete(r.inflight, cacheKey)
			r.mu.Unlock()
			call.err = err
		}
		close(call.done)
	}()
	return call
}

// LookupTXT queries TXT records over DoH (used for PTM3 signed manifest fallback).
func (r *DohResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	h := normalizeHostForMatch(domain)
	if h == "" {
		return nil, errors.New("empty domain")
	}
	cacheKey := "TXT:" + h
	r.mu.RLock()
	if ent, ok := r.cache[cacheKey]; ok && time.Now().Before(ent.expiresAt) && len(ent.txts) > 0 {
		out := append([]string(nil), ent.txts...)
		r.mu.RUnlock()
		return out, nil
	}
	r.mu.RUnlock()

	recs, ttl, err := r.queryWire(ctx, h, dnsTypeTXT)
	if err != nil {
		return nil, err
	}
	if len(recs.txts) == 0 {
		return nil, errors.New("no TXT records returned")
	}
	if ttl < 30*time.Second {
		ttl = 30 * time.Second
	}
	r.mu.Lock()
	r.setCachedLocked(cacheKey, cachedDNS{txts: recs.txts, expiresAt: time.Now().Add(ttl)})
	r.mu.Unlock()
	return append([]string(nil), recs.txts...), nil
}

func (r *DohResolver) setCachedLocked(cacheKey string, entry cachedDNS) {
	now := time.Now()
	for k, v := range r.cache {
		evictAt := v.staleUntil
		if evictAt.IsZero() {
			evictAt = v.expiresAt
		}
		if !now.Before(evictAt) {
			delete(r.cache, k)
		}
	}
	if _, exists := r.cache[cacheKey]; !exists {
		for len(r.cache) >= maxDohCacheEntries {
			var oldestKey string
			var oldestExp time.Time
			first := true
			for k, v := range r.cache {
				if first || v.expiresAt.Before(oldestExp) {
					oldestKey = k
					oldestExp = v.expiresAt
					first = false
				}
			}
			if oldestKey == "" {
				break
			}
			delete(r.cache, oldestKey)
		}
	}
	r.cache[cacheKey] = entry
}

// IsSinkholeIP returns true if ip is loopback, unspecified, private RFC1918/ULA, CGNAT, or link-local.
func IsSinkholeIP(ip net.IP) bool {
	return IsPrivateOrReservedIP(ip)
}

func (r *DohResolver) queryA(ctx context.Context, host string) ([]net.IP, time.Duration, error) {
	recs, ttl, err := r.queryWire(ctx, host, dnsTypeA)
	if err == nil && len(recs.ips) > 0 {
		return filterCleanIPs(recs.ips, ttl)
	}
	recs6, ttl6, err6 := r.queryWire(ctx, host, dnsTypeAAAA)
	if err6 == nil && len(recs6.ips) > 0 {
		return filterCleanIPs(recs6.ips, ttl6)
	}
	if err != nil {
		return nil, 0, err
	}
	if err6 != nil {
		return nil, ttl6, err6
	}
	return nil, 0, fmt.Errorf("%w: no records for %s", ErrDohUnavailable, host)
}

func filterCleanIPs(in []net.IP, ttl time.Duration) ([]net.IP, time.Duration, error) {
	var clean []net.IP
	var sinkholed []net.IP
	for _, ip := range in {
		if IsSinkholeIP(ip) {
			sinkholed = append(sinkholed, ip)
			continue
		}
		clean = append(clean, ip)
	}
	if len(clean) == 0 && len(sinkholed) > 0 {
		return nil, 0, fmt.Errorf("%w: %s", ErrSinkholeIP, sinkholed[0].String())
	}
	if len(clean) == 0 {
		return nil, 0, errors.New("no valid public IPs returned")
	}
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return clean, ttl, nil
}

type parsedDNSResp struct {
	ips  []net.IP
	txts []string
}

type dohRaceOutcome struct {
	epIdx int
	res   parsedDNSResp
	ttl   time.Duration
	err   error
}

func (r *DohResolver) orderedEndpointIndices() []int {
	n := len(r.endpoints)
	if n == 0 {
		return nil
	}
	pref := int(r.preferredIdx.Load())
	nowMs := time.Now().UnixMilli()

	r.cooldownMu.Lock()
	defer r.cooldownMu.Unlock()

	var healthy, cooled []int
	usedPref := false
	if pref >= 0 && pref < n {
		if len(r.cooldownUntil) > pref && r.cooldownUntil[pref] > nowMs {
			cooled = append(cooled, pref)
		} else {
			healthy = append(healthy, pref)
		}
		usedPref = true
	}
	for i := 0; i < n; i++ {
		if usedPref && i == pref {
			continue
		}
		if len(r.cooldownUntil) > i && r.cooldownUntil[i] > nowMs {
			cooled = append(cooled, i)
		} else {
			healthy = append(healthy, i)
		}
	}
	return append(healthy, cooled...)
}

func (r *DohResolver) markEndpointCooldown(epIdx int, d time.Duration) {
	if epIdx < 0 || epIdx >= len(r.endpoints) {
		return
	}
	until := time.Now().Add(d).UnixMilli()
	r.cooldownMu.Lock()
	if epIdx < len(r.cooldownUntil) {
		r.cooldownUntil[epIdx] = until
	}
	r.cooldownMu.Unlock()
}

func (r *DohResolver) markEndpointSuccess(epIdx int) {
	if epIdx < 0 || epIdx >= len(r.endpoints) {
		return
	}
	r.cooldownMu.Lock()
	if epIdx < len(r.cooldownUntil) {
		r.cooldownUntil[epIdx] = 0
	}
	r.cooldownMu.Unlock()
	r.preferredIdx.Store(int32(epIdx))
	r.activeUpstream.Store(formatDohUpstreamLabel(r.endpoints[epIdx]))
}

func formatDohUpstreamLabel(ep DohEndpoint) string {
	u, err := url.Parse(ep.URL)
	host := ep.URL
	if err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	if ep.ServerName != "" && !strings.EqualFold(ep.ServerName, host) {
		return ep.ServerName + " (" + host + ")"
	}
	return host
}

func (r *DohResolver) querySingleEndpoint(ctx context.Context, epIdx int, pkt []byte, id uint16, qtype uint16) (parsedDNSResp, time.Duration, error) {
	respPkt, err := r.postDohWire(ctx, r.endpoints[epIdx], pkt)
	if err != nil {
		return parsedDNSResp{}, 0, err
	}
	return parseDNSResponseWire(respPkt, id, qtype)
}

func (r *DohResolver) queryWire(ctx context.Context, name string, qtype uint16) (parsedDNSResp, time.Duration, error) {
	pkt, id, err := buildDNSQueryWire(name, qtype)
	if err != nil {
		return parsedDNSResp{}, 0, err
	}
	ordered := r.orderedEndpointIndices()
	if len(ordered) == 0 {
		return parsedDNSResp{}, 0, ErrDohUnavailable
	}
	if len(ordered) == 1 {
		res, ttl, qerr := r.querySingleEndpoint(ctx, ordered[0], pkt, id, qtype)
		if qerr != nil {
			if ctx.Err() == nil {
				r.markEndpointCooldown(ordered[0], dohCooldownWindow)
			}
			return parsedDNSResp{}, 0, qerr
		}
		r.markEndpointSuccess(ordered[0])
		return res, ttl, nil
	}

	raceCtx, raceCancel := context.WithCancel(ctx)
	resCh := make(chan dohRaceOutcome, 2)
	inflight := 0
	launch := func(epIdx int) {
		inflight++
		go func() {
			res, ttl, qerr := r.querySingleEndpoint(raceCtx, epIdx, pkt, id, qtype)
			resCh <- dohRaceOutcome{epIdx: epIdx, res: res, ttl: ttl, err: qerr}
		}()
	}

	drainRes := func(pending int) {
		if pending <= 0 {
			return
		}
		go func() {
			for i := 0; i < pending; i++ {
				<-resCh
			}
		}()
	}

	launch(ordered[0])
	staggerTimer := time.NewTimer(dohStaggerDelay)
	launchedSecond := false
	var lastErr error

	for inflight > 0 || !launchedSecond {
		var timerCh <-chan time.Time
		if !launchedSecond {
			timerCh = staggerTimer.C
		}
		select {
		case <-ctx.Done():
			staggerTimer.Stop()
			raceCancel()
			drainRes(inflight)
			return parsedDNSResp{}, 0, ctx.Err()

		case <-timerCh:
			launchedSecond = true
			launch(ordered[1])

		case out := <-resCh:
			inflight--
			if out.err == nil {
				staggerTimer.Stop()
				raceCancel()
				drainRes(inflight)
				r.markEndpointSuccess(out.epIdx)
				return out.res, out.ttl, nil
			}
			lastErr = out.err
			if ctx.Err() == nil {
				r.markEndpointCooldown(out.epIdx, dohCooldownWindow)
			}
			if !launchedSecond {
				staggerTimer.Stop()
				launchedSecond = true
				launch(ordered[1])
			}
		}
	}
	raceCancel()

	for _, epIdx := range ordered[2:] {
		if ctx.Err() != nil {
			return parsedDNSResp{}, 0, ctx.Err()
		}
		aCtx, aCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		res, ttl, qerr := r.querySingleEndpoint(aCtx, epIdx, pkt, id, qtype)
		aCancel()
		if qerr == nil {
			r.markEndpointSuccess(epIdx)
			return res, ttl, nil
		}
		lastErr = qerr
		if ctx.Err() == nil {
			r.markEndpointCooldown(epIdx, dohCooldownWindow)
		}
	}

	if lastErr == nil {
		lastErr = ErrDohUnavailable
	}
	return parsedDNSResp{}, 0, lastErr
}

func (r *DohResolver) postDohWire(ctx context.Context, ep DohEndpoint, wire []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	if ep.ServerName != "" {
		req.Host = ep.ServerName
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh %s returned HTTP %d", ep.URL, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}

func buildDNSQueryWire(domain string, qtype uint16) ([]byte, uint16, error) {
	var idBuf [2]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idBuf[:])
	var buf bytes.Buffer
	// Header: ID, Flags=0x0100 (RD), QDCOUNT=1, AN=0, NS=0, AR=0
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	buf.Write(hdr[:])

	labels := strings.Split(strings.Trim(domain, "."), ".")
	for _, lbl := range labels {
		if len(lbl) == 0 || len(lbl) > 63 {
			return nil, 0, fmt.Errorf("invalid DNS label %q", lbl)
		}
		buf.WriteByte(byte(len(lbl)))
		buf.WriteString(lbl)
	}
	buf.WriteByte(0)

	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], 1) // IN class
	buf.Write(tail[:])
	return buf.Bytes(), id, nil
}

func parseDNSResponseWire(pkt []byte, expectedID uint16, wantType uint16) (parsedDNSResp, time.Duration, error) {
	if len(pkt) < 12 {
		return parsedDNSResp{}, 0, errors.New("dns response too short")
	}
	id := binary.BigEndian.Uint16(pkt[0:2])
	if id != expectedID {
		return parsedDNSResp{}, 0, errors.New("dns response id mismatch")
	}
	rcode := pkt[3] & 0x0F
	if rcode != 0 {
		return parsedDNSResp{}, 0, fmt.Errorf("dns rcode %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(pkt[4:6]))
	an := int(binary.BigEndian.Uint16(pkt[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		next, err := skipDNSName(pkt, off)
		if err != nil {
			return parsedDNSResp{}, 0, err
		}
		if next+4 > len(pkt) {
			return parsedDNSResp{}, 0, errors.New("truncated dns question")
		}
		off = next + 4
	}

	var out parsedDNSResp
	minTTL := uint32(300)
	for i := 0; i < an && off < len(pkt); i++ {
		next, err := skipDNSName(pkt, off)
		if err != nil {
			return out, 0, err
		}
		if next+10 > len(pkt) {
			return out, 0, errors.New("truncated dns answer")
		}
		rtype := binary.BigEndian.Uint16(pkt[next : next+2])
		ttl := binary.BigEndian.Uint32(pkt[next+4 : next+8])
		rdlen := int(binary.BigEndian.Uint16(pkt[next+8 : next+10]))
		rdataOff := next + 10
		if rdataOff+rdlen > len(pkt) {
			return out, 0, errors.New("truncated dns rdata")
		}
		rdata := pkt[rdataOff : rdataOff+rdlen]
		off = rdataOff + rdlen

		if ttl > 0 && ttl < minTTL {
			minTTL = ttl
		}
		if rtype != wantType {
			continue
		}
		switch rtype {
		case dnsTypeA:
			if rdlen == 4 {
				out.ips = append(out.ips, net.IPv4(rdata[0], rdata[1], rdata[2], rdata[3]))
			}
		case dnsTypeAAAA:
			if rdlen == 16 {
				ip := make(net.IP, 16)
				copy(ip, rdata)
				out.ips = append(out.ips, ip)
			}
		case dnsTypeTXT:
			var joined strings.Builder
			for p := 0; p < len(rdata); {
				segLen := int(rdata[p])
				p++
				if p+segLen > len(rdata) {
					break
				}
				joined.Write(rdata[p : p+segLen])
				p += segLen
			}
			if joined.Len() > 0 {
				out.txts = append(out.txts, joined.String())
			}
		}
	}
	return out, time.Duration(minTTL) * time.Second, nil
}

func skipDNSName(pkt []byte, off int) (int, error) {
	seen := 0
	for off < len(pkt) {
		b := pkt[off]
		if b == 0 {
			return off + 1, nil
		}
		if b&0xC0 == 0xC0 {
			if off+1 >= len(pkt) {
				return 0, errors.New("bad dns pointer")
			}
			return off + 2, nil
		}
		off += int(b) + 1
		seen++
		if seen > 128 {
			return 0, errors.New("dns name loop")
		}
	}
	return 0, errors.New("unterminated dns name")
}
