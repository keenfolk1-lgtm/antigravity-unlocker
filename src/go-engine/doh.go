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
	"strings"
	"sync"
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
)

// DohEndpoint represents a direct-IP DoH resolver so system/ISP DNS is never consulted.
type DohEndpoint struct {
	URL        string
	ServerName string
}

var defaultDohEndpoints = []DohEndpoint{
	{URL: "https://1.1.1.1/dns-query", ServerName: "cloudflare-dns.com"},
	{URL: "https://8.8.8.8/dns-query", ServerName: "dns.google"},
}

type cachedDNS struct {
	ips       []net.IP
	txts      []string
	expiresAt time.Time
}

// DohResolver resolves A/AAAA/TXT records strictly via direct-IP DNS-over-HTTPS (RFC 8484).
type DohResolver struct {
	endpoints  []DohEndpoint
	httpClient *http.Client
	mu         sync.RWMutex
	cache      map[string]cachedDNS
}

// NewDohResolver constructs an IP-direct DoH resolver with optional custom endpoints for testing.
func NewDohResolver(endpoints []DohEndpoint, tlsConfig *tls.Config) *DohResolver {
	eps := defaultDohEndpoints
	if len(endpoints) > 0 {
		eps = endpoints
	}
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   4 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 4 * time.Second,
		DisableKeepAlives:   false,
	}
	if tlsConfig != nil {
		tr.TLSClientConfig = tlsConfig.Clone()
	}
	return &DohResolver{
		endpoints: eps,
		httpClient: &http.Client{
			Timeout:   5 * time.Second,
			Transport: tr,
		},
		cache: make(map[string]cachedDNS),
	}
}

// LookupHost resolves IPv4/IPv6 addresses over DoH and rejects loopback/sinkhole IPs.
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
	r.mu.RLock()
	if ent, ok := r.cache[cacheKey]; ok && time.Now().Before(ent.expiresAt) && len(ent.ips) > 0 {
		out := append([]net.IP(nil), ent.ips...)
		r.mu.RUnlock()
		return out, nil
	}
	r.mu.RUnlock()

	ips, ttl, err := r.queryA(ctx, h)
	if err != nil {
		return nil, err
	}
	if ttl < 15*time.Second {
		ttl = 15 * time.Second
	}
	if ttl > 10*time.Minute {
		ttl = 10 * time.Minute
	}
	r.mu.Lock()
	r.setCachedLocked(cacheKey, cachedDNS{ips: ips, expiresAt: time.Now().Add(ttl)})
	r.mu.Unlock()
	return append([]net.IP(nil), ips...), nil
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
		if !now.Before(v.expiresAt) {
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

func (r *DohResolver) queryWire(ctx context.Context, name string, qtype uint16) (parsedDNSResp, time.Duration, error) {
	pkt, id, err := buildDNSQueryWire(name, qtype)
	if err != nil {
		return parsedDNSResp{}, 0, err
	}
	var lastErr error
	for _, ep := range r.endpoints {
		respPkt, err := r.postDohWire(ctx, ep, pkt)
		if err != nil {
			lastErr = err
			continue
		}
		res, ttl, err := parseDNSResponseWire(respPkt, id, qtype)
		if err != nil {
			lastErr = err
			continue
		}
		return res, ttl, nil
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
