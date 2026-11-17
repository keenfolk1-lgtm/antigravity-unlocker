package main

import (
	"container/list"
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	TUNAdapterName           = "PixelTunnel"
	TUNAdapterIPStr          = "198.18.0.1"
	TUNDNSIPStr              = "198.18.0.2"
	TUNPrefixLen             = 15
	DefaultFakeIPPoolSize    = 16384
	DefaultTUNNATMaxEntries  = 8192
	DefaultTUNUDPIdleTimeout = 60 * time.Second
	MaxTUNUDPFlows           = 56

	fakeIPRangeStart uint32 = (198 << 24) | (18 << 16) | (0 << 8) | 10
	fakeIPRangeEnd   uint32 = (198 << 24) | (19 << 16) | (255 << 8) | 250

	tcpFlagFIN byte = 0x01
	tcpFlagSYN byte = 0x02
	tcpFlagRST byte = 0x04
	tcpFlagACK byte = 0x10
)

// TUNOptions configures the L3 Wintun controller and packet processor.
type TUNOptions struct {
	ClassifyFn         func(host string) RuleAction
	Resolver           *DohResolver
	Mux                *MuxManager
	IsDirectIPFn       func(ip net.IP) bool
	BypassNodeIPsFn    func() []net.IP
	AllowRawVoiceUDPFn func() bool
	CanProxyUDPFn      func() bool
}

// TUNStatusSnapshot describes current TUN runtime state for telemetry and status APIs.
type TUNStatusSnapshot struct {
	Enabled       bool   `json:"enabled"`
	Active        bool   `json:"active"`
	Status        string `json:"status"`
	AdapterName   string `json:"adapter_name"`
	FakeIPEntries int    `json:"fakeip_entries"`
	UDPFlows      int    `json:"udp_flows"`
	TCPFlows      int    `json:"tcp_flows"`
	LastError     string `json:"last_error,omitempty"`
}

type fakeIPEntry struct {
	domain string
	ip     uint32
	elem   *list.Element
}

// FakeIPPool manages a thread-safe bidirectional LRU mapping between domains and
// synthetic IPv4 addresses in 198.18.0.10 - 198.19.255.250 (inside 198.18.0.0/15).
type FakeIPPool struct {
	mu         sync.Mutex
	maxEntries int
	nextIP     uint32
	byDomain   map[string]*fakeIPEntry
	byIP       map[uint32]*fakeIPEntry
	lru        *list.List
}

// NewFakeIPPool constructs a bounded FakeIPPool. Zero/negative maxEntries uses DefaultFakeIPPoolSize.
func NewFakeIPPool(maxEntries int) *FakeIPPool {
	maxCap := int(fakeIPRangeEnd - fakeIPRangeStart + 1)
	if maxEntries <= 0 {
		maxEntries = DefaultFakeIPPoolSize
	}
	if maxEntries > maxCap {
		maxEntries = maxCap
	}
	return &FakeIPPool{
		maxEntries: maxEntries,
		nextIP:     fakeIPRangeStart,
		byDomain:   make(map[string]*fakeIPEntry),
		byIP:       make(map[uint32]*fakeIPEntry),
		lru:        list.New(),
	}
}

func ipv4ToUint32(ip net.IP) (uint32, bool) {
	if ip == nil {
		return 0, false
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(v4), true
}

func uint32ToIPv4(u uint32) net.IP {
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}

// Assign returns the existing FakeIP for domain (promoting it in LRU) or allocates a new one.
func (p *FakeIPPool) Assign(domain string) net.IP {
	d := normalizeHostForMatch(domain)
	if d == "" {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if ent, ok := p.byDomain[d]; ok {
		p.lru.MoveToFront(ent.elem)
		return uint32ToIPv4(ent.ip)
	}

	var allocIP uint32
	found := false

	if len(p.byDomain) < p.maxEntries {
		total := fakeIPRangeEnd - fakeIPRangeStart + 1
		for tries := uint32(0); tries < total; tries++ {
			cand := p.nextIP
			if p.nextIP >= fakeIPRangeEnd {
				p.nextIP = fakeIPRangeStart
			} else {
				p.nextIP++
			}
			if _, used := p.byIP[cand]; !used {
				allocIP = cand
				found = true
				break
			}
		}
	}

	if !found {
		back := p.lru.Back()
		if back == nil {
			return nil
		}
		evicted := back.Value.(*fakeIPEntry)
		p.lru.Remove(back)
		delete(p.byDomain, evicted.domain)
		delete(p.byIP, evicted.ip)
		allocIP = evicted.ip
	}

	ent := &fakeIPEntry{
		domain: d,
		ip:     allocIP,
	}
	ent.elem = p.lru.PushFront(ent)
	p.byDomain[d] = ent
	p.byIP[allocIP] = ent
	return uint32ToIPv4(allocIP)
}

// LookupDomain resolves an active FakeIP back to its domain name and promotes it in LRU.
func (p *FakeIPPool) LookupDomain(ip net.IP) (string, bool) {
	u, ok := ipv4ToUint32(ip)
	if !ok {
		return "", false
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	ent, exists := p.byIP[u]
	if !exists {
		return "", false
	}
	p.lru.MoveToFront(ent.elem)
	return ent.domain, true
}

// Contains reports whether ip falls inside the FakeIP pool address range (198.18.0.10 - 198.19.255.250).
func (p *FakeIPPool) Contains(ip net.IP) bool {
	u, ok := ipv4ToUint32(ip)
	if !ok {
		return false
	}
	return u >= fakeIPRangeStart && u <= fakeIPRangeEnd
}

// Count returns the number of active domain <-> FakeIP mappings.
func (p *FakeIPPool) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byDomain)
}

func onesComplementSumRange(b []byte, sum uint32) uint32 {
	n := len(b)
	i := 0
	for i+1 < n {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
		i += 2
	}
	if i < n {
		sum += uint32(b[i]) << 8
	}
	return sum
}

func foldOnesComplement(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ComputeIPv4Checksum calculates the RFC 1071 IPv4 header checksum, treating hdr[10:12] as zero.
// Returns 0 on truncated or non-IPv4 input without panicking.
func ComputeIPv4Checksum(hdr []byte) uint16 {
	if len(hdr) < 20 || hdr[0]>>4 != 4 {
		return 0
	}
	ihl := int(hdr[0]&0x0F) * 4
	if ihl < 20 || ihl > len(hdr) {
		return 0
	}
	sum := onesComplementSumRange(hdr[0:10], 0)
	sum = onesComplementSumRange(hdr[12:ihl], sum)
	return foldOnesComplement(sum)
}

// ComputeTCPChecksum calculates the RFC 1071 TCP checksum over the IPv4 pseudo-header and TCP segment,
// treating the TCP checksum field [ihl+16:ihl+18] as zero. Returns 0 on malformed/truncated input.
func ComputeTCPChecksum(pkt []byte) uint16 {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return 0
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || ihl+20 > len(pkt) {
		return 0
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl+20 || totalLen > len(pkt) {
		return 0
	}
	tcpLen := totalLen - ihl
	var sum uint32
	sum = onesComplementSumRange(pkt[12:20], sum)
	sum += 6 // IPPROTO_TCP
	sum += uint32(tcpLen)
	sum = onesComplementSumRange(pkt[ihl:ihl+16], sum)
	sum = onesComplementSumRange(pkt[ihl+18:totalLen], sum)
	return foldOnesComplement(sum)
}

// ComputeUDPChecksum calculates the RFC 1071 UDP checksum over the IPv4 pseudo-header and UDP datagram,
// treating the UDP checksum field [ihl+6:ihl+8] as zero. Per RFC 768, a zero result is returned as 0xFFFF.
// Returns 0 on malformed/truncated input without panicking.
func ComputeUDPChecksum(pkt []byte) uint16 {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 17 {
		return 0
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || ihl+8 > len(pkt) {
		return 0
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	udpLen := int(binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6]))
	if totalLen < ihl+8 || totalLen > len(pkt) || udpLen < 8 || ihl+udpLen > totalLen {
		return 0
	}
	var sum uint32
	sum = onesComplementSumRange(pkt[12:20], sum)
	sum += 17 // IPPROTO_UDP
	sum += uint32(udpLen)
	sum = onesComplementSumRange(pkt[ihl:ihl+6], sum)
	sum = onesComplementSumRange(pkt[ihl+8:ihl+udpLen], sum)
	csum := foldOnesComplement(sum)
	if csum == 0 {
		return 0xFFFF
	}
	return csum
}

// SetIPv4Checksum writes the computed RFC 1071 IPv4 header checksum into pkt[10:12].
func SetIPv4Checksum(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || ihl > len(pkt) {
		return false
	}
	binary.BigEndian.PutUint16(pkt[10:12], ComputeIPv4Checksum(pkt[:ihl]))
	return true
}

// SetTCPChecksum writes the computed RFC 1071 TCP checksum into pkt[ihl+16:ihl+18].
func SetTCPChecksum(pkt []byte) bool {
	if len(pkt) < 40 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || ihl+20 > len(pkt) {
		return false
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl+20 || totalLen > len(pkt) {
		return false
	}
	binary.BigEndian.PutUint16(pkt[ihl+16:ihl+18], ComputeTCPChecksum(pkt))
	return true
}

// SetUDPChecksum writes the computed RFC 1071 UDP checksum into pkt[ihl+6:ihl+8].
func SetUDPChecksum(pkt []byte) bool {
	if len(pkt) < 28 || pkt[0]>>4 != 4 || pkt[9] != 17 {
		return false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || ihl+8 > len(pkt) {
		return false
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	udpLen := int(binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6]))
	if totalLen < ihl+8 || totalLen > len(pkt) || udpLen < 8 || ihl+udpLen > totalLen {
		return false
	}
	binary.BigEndian.PutUint16(pkt[ihl+6:ihl+8], ComputeUDPChecksum(pkt))
	return true
}

// UpdateIPv4TCPChecksums recomputes both IPv4 and TCP checksums in place.
func UpdateIPv4TCPChecksums(pkt []byte) bool {
	return SetIPv4Checksum(pkt) && SetTCPChecksum(pkt)
}

// UpdateIPv4UDPChecksums recomputes both IPv4 and UDP checksums in place.
func UpdateIPv4UDPChecksums(pkt []byte) bool {
	return SetIPv4Checksum(pkt) && SetUDPChecksum(pkt)
}

// TUNNATEntry records the original destination for an active kernel-assisted TCP NAT port.
type TUNNATEntry struct {
	ClientIP    net.IP
	ClientPort  int
	OrigDstIP   net.IP
	OrigDstPort int
	LastSeen    time.Time
	elem        *list.Element
}

// TUNNATTable performs bounded-LRU IPv4+TCP NAT translation between application sockets
// and the local TUN TCP relay listener (e.g. 198.18.0.1:<relayPort>).
type TUNNATTable struct {
	mu           sync.Mutex
	relayIP      [4]byte
	relayPort    int
	fakeIPs      *FakeIPPool
	maxEntries   int
	byClientPort map[int]*TUNNATEntry
	lru          *list.List
}

// NewTUNNATTable constructs a thread-safe TCP NAT table.
func NewTUNNATTable(relayIP net.IP, relayPort int, fakeIPs *FakeIPPool, maxEntries int) *TUNNATTable {
	if maxEntries <= 0 {
		maxEntries = DefaultTUNNATMaxEntries
	}
	t := &TUNNATTable{
		relayPort:    relayPort,
		fakeIPs:      fakeIPs,
		maxEntries:   maxEntries,
		byClientPort: make(map[int]*TUNNATEntry),
		lru:          list.New(),
	}
	t.SetRelayEndpoint(relayIP, relayPort)
	return t
}

// SetRelayEndpoint updates the local TCP relay IP and port.
func (t *TUNNATTable) SetRelayEndpoint(relayIP net.IP, relayPort int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if v4 := relayIP.To4(); v4 != nil {
		copy(t.relayIP[:], v4)
	}
	t.relayPort = relayPort
}

// Count returns the number of active tracked TCP NAT entries.
func (t *TUNNATTable) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byClientPort)
}

// TranslateOutbound translates an outbound IPv4+TCP packet (srcIP -> dstIP:dstPort)
// to (origDstIP:clientPort -> relayIP:relayPort) and recomputes IPv4+TCP checksums.
func (t *TUNNATTable) TranslateOutbound(pkt []byte) ([]byte, bool) {
	if len(pkt) < 40 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return nil, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || ihl+20 > len(pkt) {
		return nil, false
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl+20 || totalLen > len(pkt) {
		return nil, false
	}
	frag := binary.BigEndian.Uint16(pkt[6:8])
	if frag&0x1FFF != 0 {
		return nil, false
	}

	srcPort := int(binary.BigEndian.Uint16(pkt[ihl : ihl+2]))
	dstPort := int(binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4]))
	if srcPort <= 0 || dstPort <= 0 {
		return nil, false
	}
	flags := pkt[ihl+13]

	srcIP := net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])
	dstIP := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
	if dstIP.IsLoopback() || dstIP.IsMulticast() || dstIP.IsUnspecified() || isBroadcastIPv4(dstIP) {
		return nil, false
	}

	t.mu.Lock()
	relayIP := t.relayIP
	relayPort := t.relayPort
	if relayPort <= 0 || relayIP == ([4]byte{}) {
		t.mu.Unlock()
		return nil, false
	}
	relayNetIP := net.IPv4(relayIP[0], relayIP[1], relayIP[2], relayIP[3])
	// Do not NAT packets coming from or directly targeting the relay endpoint itself.
	if (srcIP.Equal(relayNetIP) && srcPort == relayPort) || (dstIP.Equal(relayNetIP) && dstPort == relayPort) {
		t.mu.Unlock()
		return nil, false
	}

	now := time.Now()
	if ent, exists := t.byClientPort[srcPort]; exists {
		isPureSYN := (flags&tcpFlagSYN) != 0 && (flags&tcpFlagACK) == 0
		if isPureSYN {
			ent.ClientIP = append(net.IP(nil), srcIP.To4()...)
			ent.OrigDstIP = append(net.IP(nil), dstIP.To4()...)
			ent.OrigDstPort = dstPort
		}
		ent.LastSeen = now
		t.lru.MoveToFront(ent.elem)
	} else {
		if len(t.byClientPort) >= t.maxEntries {
			if back := t.lru.Back(); back != nil {
				old := back.Value.(*TUNNATEntry)
				t.lru.Remove(back)
				delete(t.byClientPort, old.ClientPort)
			}
		}
		ent := &TUNNATEntry{
			ClientIP:    append(net.IP(nil), srcIP.To4()...),
			ClientPort:  srcPort,
			OrigDstIP:   append(net.IP(nil), dstIP.To4()...),
			OrigDstPort: dstPort,
			LastSeen:    now,
		}
		ent.elem = t.lru.PushFront(ent)
		t.byClientPort[srcPort] = ent
	}
	t.mu.Unlock()

	out := make([]byte, totalLen)
	copy(out, pkt[:totalLen])
	copy(out[12:16], dstIP.To4())
	copy(out[16:20], relayIP[:])
	binary.BigEndian.PutUint16(out[ihl+2:ihl+4], uint16(relayPort))
	if !UpdateIPv4TCPChecksums(out) {
		return nil, false
	}
	return out, true
}

// TranslateInbound translates a return IPv4+TCP packet from relayIP:relayPort back to
// (origDstIP:origDstPort -> clientIP:clientPort) and recomputes IPv4+TCP checksums.
func (t *TUNNATTable) TranslateInbound(pkt []byte) ([]byte, bool) {
	if len(pkt) < 40 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return nil, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || ihl+20 > len(pkt) {
		return nil, false
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl+20 || totalLen > len(pkt) {
		return nil, false
	}
	frag := binary.BigEndian.Uint16(pkt[6:8])
	if frag&0x1FFF != 0 {
		return nil, false
	}

	srcPort := int(binary.BigEndian.Uint16(pkt[ihl : ihl+2]))
	dstPort := int(binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4]))
	if srcPort <= 0 || dstPort <= 0 {
		return nil, false
	}
	srcIP := net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])

	t.mu.Lock()
	relayNetIP := net.IPv4(t.relayIP[0], t.relayIP[1], t.relayIP[2], t.relayIP[3])
	if t.relayPort <= 0 || !srcIP.Equal(relayNetIP) || srcPort != t.relayPort {
		t.mu.Unlock()
		return nil, false
	}
	ent, ok := t.byClientPort[dstPort]
	if !ok {
		t.mu.Unlock()
		return nil, false
	}
	ent.LastSeen = time.Now()
	t.lru.MoveToFront(ent.elem)
	clientIP := append(net.IP(nil), ent.ClientIP...)
	origDstIP := append(net.IP(nil), ent.OrigDstIP...)
	origDstPort := ent.OrigDstPort
	t.mu.Unlock()

	if len(clientIP) != 4 || len(origDstIP) != 4 {
		return nil, false
	}

	out := make([]byte, totalLen)
	copy(out, pkt[:totalLen])
	copy(out[12:16], origDstIP)
	binary.BigEndian.PutUint16(out[ihl:ihl+2], uint16(origDstPort))
	copy(out[16:20], clientIP)
	binary.BigEndian.PutUint16(out[ihl+2:ihl+4], uint16(dstPort))
	if !UpdateIPv4TCPChecksums(out) {
		return nil, false
	}
	return out, true
}

// LookupOriginalTarget resolves the original domain (via FakeIPPool) or IPv4 target and port for clientPort.
func (t *TUNNATTable) LookupOriginalTarget(clientPort int) (host string, port int, isFakeIP bool, ok bool) {
	t.mu.Lock()
	ent, exists := t.byClientPort[clientPort]
	if !exists {
		t.mu.Unlock()
		return "", 0, false, false
	}
	origIP := append(net.IP(nil), ent.OrigDstIP...)
	origPort := ent.OrigDstPort
	t.mu.Unlock()

	if t.fakeIPs != nil {
		if domain, found := t.fakeIPs.LookupDomain(origIP); found {
			return domain, origPort, true, true
		}
		if t.fakeIPs.Contains(origIP) {
			// Stale/evicted FakeIP: never dial 198.18.x.y directly as a real IP.
			return "", origPort, true, false
		}
	}
	return origIP.String(), origPort, false, true
}

type udpFlowKey struct {
	clientIP   [4]byte
	clientPort uint16
}

type tunUDPFlow struct {
	key        udpFlowKey
	elem       *list.Element
	lastActive atomic.Int64
	isProxy    bool
	role       string

	mu            sync.Mutex
	closed        bool
	sess          *ClientMuxSession
	assocID       uint32
	directConn    net.PacketConn
	fakeByPort    map[uint16]net.IP
	directTargets map[string]bool
	proxyTargets  map[string]bool
}

func (f *tunUDPFlow) close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	sess := f.sess
	assocID := f.assocID
	f.sess = nil
	f.assocID = 0
	dc := f.directConn
	f.directConn = nil
	f.mu.Unlock()

	if sess != nil && assocID != 0 {
		sess.UnregisterUDPHandler(assocID)
	}
	if dc != nil {
		_ = dc.Close()
	}
}

// TUNPacketProcessor handles L3 IPv4 packets from Wintun or offline tests:
// DNS (:53) interception + FakeIP, kernel-assisted TCP NAT, and native PWP-4 UDP relay.
type TUNPacketProcessor struct {
	FakeIP *FakeIPPool
	NAT    *TUNNATTable

	classifyFn         func(host string) RuleAction
	isDirectIPFn       func(ip net.IP) bool
	allowRawVoiceUDPFn func() bool
	canProxyUDPFn      func() bool
	resolver           *DohResolver
	mux                *MuxManager
	writePkt           func([]byte) error

	dialCtrlMu        sync.RWMutex
	directDialControl func(network, address string, c syscall.RawConn) error

	udpMu    sync.Mutex
	udpFlows map[udpFlowKey]*tunUDPFlow
	udpLRU   *list.List

	dnsSem    chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closed    atomic.Bool
}

// NewTUNPacketProcessor creates an L3 packet processor and launches the 60s UDP idle GC loop.
func NewTUNPacketProcessor(opts TUNOptions, relayIP net.IP, relayPort int, writePkt func([]byte) error) *TUNPacketProcessor {
	fakePool := NewFakeIPPool(DefaultFakeIPPoolSize)
	ctx, cancel := context.WithCancel(context.Background())
	p := &TUNPacketProcessor{
		FakeIP:             fakePool,
		NAT:                NewTUNNATTable(relayIP, relayPort, fakePool, DefaultTUNNATMaxEntries),
		classifyFn:         opts.ClassifyFn,
		isDirectIPFn:       opts.IsDirectIPFn,
		allowRawVoiceUDPFn: opts.AllowRawVoiceUDPFn,
		canProxyUDPFn:      opts.CanProxyUDPFn,
		resolver:           opts.Resolver,
		mux:                opts.Mux,
		writePkt:           writePkt,
		udpFlows:     make(map[udpFlowKey]*tunUDPFlow),
		udpLRU:       list.New(),
		dnsSem:       make(chan struct{}, 64),
		ctx:          ctx,
		cancel:       cancel,
	}
	go p.udpIdleGCLoop()
	return p
}

// SetDirectDialControl sets the socket Control callback used for DIRECT UDP sockets.
func (p *TUNPacketProcessor) SetDirectDialControl(fn func(network, address string, c syscall.RawConn) error) {
	p.dialCtrlMu.Lock()
	p.directDialControl = fn
	p.dialCtrlMu.Unlock()
}

func (p *TUNPacketProcessor) getDirectDialControl() func(network, address string, c syscall.RawConn) error {
	p.dialCtrlMu.RLock()
	fn := p.directDialControl
	p.dialCtrlMu.RUnlock()
	return fn
}

// UDPFlowCount returns the number of active tracked UDP flows.
func (p *TUNPacketProcessor) UDPFlowCount() int {
	p.udpMu.Lock()
	defer p.udpMu.Unlock()
	return len(p.udpFlows)
}

// TCPFlowCount returns the number of active tracked TCP NAT entries.
func (p *TUNPacketProcessor) TCPFlowCount() int {
	if p.NAT == nil {
		return 0
	}
	return p.NAT.Count()
}

// FakeIPCount returns the number of active FakeIP entries.
func (p *TUNPacketProcessor) FakeIPCount() int {
	if p.FakeIP == nil {
		return 0
	}
	return p.FakeIP.Count()
}

// Close shuts down background DNS/UDP workers and unregisters all active UDP associations.
func (p *TUNPacketProcessor) Close() {
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		p.cancel()

		p.udpMu.Lock()
		flows := make([]*tunUDPFlow, 0, len(p.udpFlows))
		for k, f := range p.udpFlows {
			flows = append(flows, f)
			delete(p.udpFlows, k)
		}
		p.udpLRU.Init()
		p.udpMu.Unlock()

		for _, f := range flows {
			f.close()
		}
	})
}

func (p *TUNPacketProcessor) udpIdleGCLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case now := <-ticker.C:
			p.gcIdleUDPFlows(now, DefaultTUNUDPIdleTimeout)
		}
	}
}

func (p *TUNPacketProcessor) gcIdleUDPFlows(now time.Time, maxIdle time.Duration) int {
	p.udpMu.Lock()
	var expired []*tunUDPFlow
	for k, f := range p.udpFlows {
		last := time.Unix(0, f.lastActive.Load())
		if now.Sub(last) >= maxIdle {
			expired = append(expired, f)
			delete(p.udpFlows, k)
			if f.elem != nil {
				p.udpLRU.Remove(f.elem)
				f.elem = nil
			}
		}
	}
	p.udpMu.Unlock()

	for _, f := range expired {
		f.close()
	}
	return len(expired)
}

func (p *TUNPacketProcessor) emitPacket(pkt []byte) {
	if len(pkt) == 0 || p.closed.Load() || p.writePkt == nil {
		return
	}
	_ = p.writePkt(pkt)
}

// ProcessPacket parses and dispatches one raw L3 IPv4 packet safely (zero panics on malformed input).
func (p *TUNPacketProcessor) ProcessPacket(pkt []byte) {
	if p == nil || p.closed.Load() || len(pkt) < 20 {
		return
	}
	if pkt[0]>>4 != 4 {
		return
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || ihl > len(pkt) {
		return
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl || totalLen > len(pkt) {
		return
	}
	frag := binary.BigEndian.Uint16(pkt[6:8])
	if frag&0x1FFF != 0 {
		return
	}

	proto := pkt[9]
	switch proto {
	case 6: // TCP
		if totalLen < ihl+20 {
			return
		}
		if out, ok := p.NAT.TranslateInbound(pkt[:totalLen]); ok {
			p.emitPacket(out)
			return
		}
		if out, ok := p.NAT.TranslateOutbound(pkt[:totalLen]); ok {
			p.emitPacket(out)
		}

	case 17: // UDP
		if totalLen < ihl+8 {
			return
		}
		udpLen := int(binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6]))
		if udpLen < 8 || ihl+udpLen > totalLen {
			return
		}
		srcPort := int(binary.BigEndian.Uint16(pkt[ihl : ihl+2]))
		dstPort := int(binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4]))
		if srcPort <= 0 || dstPort <= 0 {
			return
		}
		srcIP := net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])
		dstIP := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
		payload := pkt[ihl+8 : ihl+udpLen]

		if dstPort == 53 {
			p.handleDNSQuery(srcIP, dstIP, srcPort, dstPort, payload)
			return
		}
		p.handleUDPPacket(pkt[:totalLen], srcIP, dstIP, srcPort, dstPort, payload)
	}
}

func (p *TUNPacketProcessor) classifyHost(host string) RuleAction {
	if p.classifyFn != nil {
		return p.classifyFn(host)
	}
	return RuleAction{Action: "PROXY", Rule: "default", Role: "ai"}
}

func (p *TUNPacketProcessor) handleDNSQuery(srcIP, dstIP net.IP, srcPort, dstPort int, dns []byte) {
	_, qname, qtype, qclass, qEnd, ok := parseDNSQuery(dns)
	if !ok {
		return
	}
	if qclass != 1 {
		resp := buildDNSResponsePacket(dstIP, srcIP, dstPort, srcPort, dns, qEnd, 0, nil, 5)
		p.emitPacket(resp)
		return
	}

	if qtype == dnsTypeAAAA {
		// Suppress IPv6 AAAA over IPv4 TUN so clients cleanly connect via IPv4 A records.
		resp := buildDNSResponsePacket(dstIP, srcIP, dstPort, srcPort, dns, qEnd, 0, nil, 5)
		p.emitPacket(resp)
		return
	}

	if qtype != dnsTypeA {
		resp := buildDNSResponsePacket(dstIP, srcIP, dstPort, srcPort, dns, qEnd, 0, nil, 5)
		p.emitPacket(resp)
		return
	}

	decision := p.classifyHost(qname)
	if strings.EqualFold(decision.Action, "PROXY") {
		fakeIP := p.FakeIP.Assign(qname)
		if fakeIP == nil {
			resp := buildDNSResponsePacket(dstIP, srcIP, dstPort, srcPort, dns, qEnd, 2, nil, 0)
			p.emitPacket(resp)
			return
		}
		resp := buildDNSResponsePacket(dstIP, srcIP, dstPort, srcPort, dns, qEnd, 0, []net.IP{fakeIP}, 5)
		p.emitPacket(resp)
		return
	}

	// DIRECT domain: resolve strictly over DoH asynchronously without stalling the Wintun RX ring.
	if p.resolver == nil {
		resp := buildDNSResponsePacket(dstIP, srcIP, dstPort, srcPort, dns, qEnd, 2, nil, 0)
		p.emitPacket(resp)
		return
	}

	select {
	case p.dnsSem <- struct{}{}:
	default:
		resp := buildDNSResponsePacket(dstIP, srcIP, dstPort, srcPort, dns, qEnd, 2, nil, 0)
		p.emitPacket(resp)
		return
	}

	dnsCopy := append([]byte(nil), dns[:qEnd]...)
	srcIPCopy := append(net.IP(nil), srcIP...)
	dstIPCopy := append(net.IP(nil), dstIP...)

	go func() {
		defer func() { <-p.dnsSem }()
		qctx, cancel := context.WithTimeout(p.ctx, 4*time.Second)
		defer cancel()

		ips, err := p.resolver.LookupHost(qctx, qname)
		if p.closed.Load() {
			return
		}
		if err != nil {
			resp := buildDNSResponsePacket(dstIPCopy, srcIPCopy, dstPort, srcPort, dnsCopy, qEnd, 2, nil, 0)
			p.emitPacket(resp)
			return
		}
		var v4s []net.IP
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				v4s = append(v4s, v4)
				if len(v4s) >= 4 {
					break
				}
			}
		}
		resp := buildDNSResponsePacket(dstIPCopy, srcIPCopy, dstPort, srcPort, dnsCopy, qEnd, 0, v4s, 60)
		p.emitPacket(resp)
	}()
}

func (p *TUNPacketProcessor) handleUDPPacket(origPkt []byte, srcIP, dstIP net.IP, srcPort, dstPort int, payload []byte) {
	if len(payload) == 0 || len(payload) > 16384 {
		return
	}
	if dstIP.IsUnspecified() || dstIP.IsLoopback() || dstIP.IsMulticast() ||
		dstIP.IsLinkLocalMulticast() || dstIP.IsLinkLocalUnicast() || isBroadcastIPv4(dstIP) {
		return
	}

	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return
	}

	targetHost := ""
	isFakeIP := false
	if p.FakeIP.Contains(dst4) {
		domain, ok := p.FakeIP.LookupDomain(dst4)
		if !ok {
			return
		}
		targetHost = domain
		isFakeIP = true
	} else {
		if IsPrivateOrReservedIP(dst4) {
			return
		}
		targetHost = dst4.String()
	}

	decision := p.classifyHost(targetHost)
	isDirectIP := !isFakeIP && p.isDirectIPFn != nil && p.isDirectIPFn(dst4)
	if isDirectIP {
		decision.Action = "DIRECT"
	}

	if dstPort == 443 && !isDirectIP && (strings.EqualFold(decision.Action, "PROXY") || !isFakeIP) {
		if icmp := buildICMPv4PortUnreachable(origPkt); icmp != nil {
			p.emitPacket(icmp)
		}
		return
	}

	var key udpFlowKey
	copy(key.clientIP[:], src4)
	key.clientPort = uint16(srcPort)

	if !isFakeIP && !isDirectIP && !strings.EqualFold(decision.Action, "PROXY") &&
		p.allowRawVoiceUDPFn != nil && p.allowRawVoiceUDPFn() {
		if IsDiscordOrRTCVoiceUDP(dstPort, payload) || p.isEstablishedProxyUDPTarget(key, dst4, dstPort) {
			decision = RuleAction{Action: "PROXY", Rule: "voice_rtc_udp", Role: "media"}
		}
	}

	canUDP := p.canProxyUDPFn == nil || p.canProxyUDPFn()
	if strings.EqualFold(decision.Action, "PROXY") && !canUDP {
		if isFakeIP {
			if icmp := buildICMPv4PortUnreachable(origPkt); icmp != nil {
				p.emitPacket(icmp)
			}
			return
		}
		decision.Action = "DIRECT"
	}

	isProxy := strings.EqualFold(decision.Action, "PROXY") && p.mux != nil && canUDP
	role := decision.Role
	if role == "" {
		role = "media"
	}

	flow := p.getOrCreateUDPFlow(key, isProxy, role)
	if flow == nil {
		return
	}
	flow.lastActive.Store(time.Now().UnixNano())

	flow.mu.Lock()
	if flow.closed {
		flow.mu.Unlock()
		return
	}
	if isFakeIP {
		flow.fakeByPort[uint16(dstPort)] = append(net.IP(nil), dst4...)
	} else if isProxy {
		flow.proxyTargets[dst4.String()+":"+strconv.Itoa(dstPort)] = true
	} else {
		flow.directTargets[dst4.String()+":"+strconv.Itoa(dstPort)] = true
	}
	flow.mu.Unlock()

	if isProxy {
		p.sendProxyUDP(flow, targetHost, dstPort, payload)
		return
	}
	p.sendDirectUDP(flow, dst4, targetHost, dstPort, isFakeIP, payload)
}

func (p *TUNPacketProcessor) isEstablishedProxyUDPTarget(key udpFlowKey, dstIP net.IP, dstPort int) bool {
	if p == nil || dstIP == nil || dstPort <= 0 {
		return false
	}
	p.udpMu.Lock()
	existing := p.udpFlows[key]
	p.udpMu.Unlock()
	if existing == nil || !existing.isProxy {
		return false
	}
	targetKey := dstIP.String() + ":" + strconv.Itoa(dstPort)
	existing.mu.Lock()
	ok := !existing.closed && existing.proxyTargets[targetKey]
	existing.mu.Unlock()
	return ok
}

// IsDiscordOrRTCVoiceUDP identifies Discord IP Discovery, STUN, DTLS, and RTP/RTCP
// WebRTC voice/video media datagrams targeting raw server IPs (including non-Discord-owned relays).
func IsDiscordOrRTCVoiceUDP(dstPort int, payload []byte) bool {
	if dstPort <= 0 || dstPort == 53 || dstPort == 80 || dstPort == 123 || dstPort == 443 || dstPort == 1900 || dstPort == 5353 {
		return false
	}
	n := len(payload)
	if (n == 74 || n == 70) && payload[0] == 0x00 && payload[1] == 0x01 {
		msgLen := binary.BigEndian.Uint16(payload[2:4])
		if msgLen == 70 || msgLen == 66 {
			return true
		}
	}
	if n >= 20 && (payload[0]&0xC0) == 0x00 && binary.BigEndian.Uint32(payload[4:8]) == 0x2112A442 {
		return true
	}
	if n >= 13 && payload[0] >= 20 && payload[0] <= 25 && payload[1] == 0xFE {
		return true
	}
	isMediaPort := (dstPort >= 50000 && dstPort <= 65535) || (dstPort >= 19294 && dstPort <= 19344)
	if isMediaPort && n >= 12 && (payload[0]&0xC0) == 0x80 {
		return true
	}
	return false
}

func (p *TUNPacketProcessor) getOrCreateUDPFlow(key udpFlowKey, isProxy bool, role string) *tunUDPFlow {
	now := time.Now().UnixNano()
	var toClose []*tunUDPFlow

	p.udpMu.Lock()
	if existing, ok := p.udpFlows[key]; ok {
		if existing.isProxy == isProxy {
			existing.lastActive.Store(now)
			p.udpLRU.MoveToFront(existing.elem)
			p.udpMu.Unlock()
			return existing
		}
		delete(p.udpFlows, key)
		if existing.elem != nil {
			p.udpLRU.Remove(existing.elem)
			existing.elem = nil
		}
		toClose = append(toClose, existing)
	}

	for len(p.udpFlows) >= MaxTUNUDPFlows {
		back := p.udpLRU.Back()
		if back == nil {
			break
		}
		evicted := back.Value.(*tunUDPFlow)
		p.udpLRU.Remove(back)
		evicted.elem = nil
		delete(p.udpFlows, evicted.key)
		toClose = append(toClose, evicted)
	}

	flow := &tunUDPFlow{
		key:           key,
		isProxy:       isProxy,
		role:          role,
		fakeByPort:    make(map[uint16]net.IP),
		directTargets: make(map[string]bool),
		proxyTargets:  make(map[string]bool),
	}
	flow.lastActive.Store(now)
	flow.elem = p.udpLRU.PushFront(flow)
	p.udpFlows[key] = flow
	p.udpMu.Unlock()

	for _, old := range toClose {
		old.close()
	}
	return flow
}

func (p *TUNPacketProcessor) sendProxyUDP(flow *tunUDPFlow, targetHost string, dstPort int, payload []byte) {
	flow.mu.Lock()
	if flow.closed {
		flow.mu.Unlock()
		return
	}
	sess := flow.sess
	assocID := flow.assocID
	if sess == nil || sess.IsClosed() || assocID == 0 {
		sctx, cancel := context.WithTimeout(p.ctx, 8*time.Second)
		newSess, err := p.mux.GetOrConnectSession(sctx, flow.role)
		cancel()
		if err != nil || newSess == nil || flow.closed {
			flow.mu.Unlock()
			return
		}
		clientIP := net.IPv4(flow.key.clientIP[0], flow.key.clientIP[1], flow.key.clientIP[2], flow.key.clientIP[3])
		clientPort := int(flow.key.clientPort)
		newAssoc := newSess.RegisterUDPHandler(func(repHost string, repPort int, repPayload []byte) {
			if len(repPayload) == 0 || repPort <= 0 || repPort > 65535 || p.closed.Load() {
				return
			}
			flow.lastActive.Store(time.Now().UnixNano())
			pktSrcIP := p.resolveUDPReplySourceIP(flow, repHost, repPort)
			if pktSrcIP == nil {
				return
			}
			out := buildIPv4UDPPacket(pktSrcIP, clientIP, repPort, clientPort, repPayload)
			if out != nil {
				p.emitPacket(out)
			}
		})
		flow.sess = newSess
		flow.assocID = newAssoc
		sess = newSess
		assocID = newAssoc
	}
	flow.mu.Unlock()

	if err := sess.SendUDP(assocID, targetHost, dstPort, payload); err != nil {
		flow.mu.Lock()
		if flow.sess == sess {
			flow.sess = nil
			flow.assocID = 0
		}
		flow.mu.Unlock()
	}
}

func (p *TUNPacketProcessor) resolveUDPReplySourceIP(flow *tunUDPFlow, repHost string, repPort int) net.IP {
	ip := net.ParseIP(strings.TrimSpace(repHost))
	var v4 net.IP
	if ip != nil {
		v4 = ip.To4()
	}

	flow.mu.Lock()
	defer flow.mu.Unlock()

	if v4 != nil {
		if flow.directTargets[v4.String()+":"+strconv.Itoa(repPort)] {
			return v4
		}
		if fakeIP, ok := flow.fakeByPort[uint16(repPort)]; ok {
			return append(net.IP(nil), fakeIP...)
		}
		return v4
	}
	if fakeIP, ok := flow.fakeByPort[uint16(repPort)]; ok {
		return append(net.IP(nil), fakeIP...)
	}
	if repHost != "" && p.FakeIP != nil {
		return p.FakeIP.Assign(repHost)
	}
	return nil
}

func (p *TUNPacketProcessor) sendDirectUDP(flow *tunUDPFlow, dstIP net.IP, targetHost string, dstPort int, isFakeIP bool, payload []byte) {
	sendIP := dstIP
	if isFakeIP {
		if p.resolver == nil {
			return
		}
		qctx, cancel := context.WithTimeout(p.ctx, 4*time.Second)
		ips, err := p.resolver.LookupHost(qctx, targetHost)
		cancel()
		if err != nil {
			return
		}
		var resolved net.IP
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				resolved = v4
				break
			}
		}
		if resolved == nil {
			return
		}
		sendIP = resolved
	}

	flow.mu.Lock()
	if flow.closed {
		flow.mu.Unlock()
		return
	}
	dc := flow.directConn
	if dc == nil {
		lc := net.ListenConfig{Control: p.getDirectDialControl()}
		pc, err := lc.ListenPacket(p.ctx, "udp4", ":0")
		if err != nil {
			flow.mu.Unlock()
			return
		}
		flow.directConn = pc
		dc = pc
		go p.directUDPReadLoop(flow, pc)
	}
	flow.mu.Unlock()

	_, _ = dc.WriteTo(payload, &net.UDPAddr{IP: sendIP, Port: dstPort})
}

func (p *TUNPacketProcessor) directUDPReadLoop(flow *tunUDPFlow, pc net.PacketConn) {
	buf := make([]byte, 16384)
	clientIP := net.IPv4(flow.key.clientIP[0], flow.key.clientIP[1], flow.key.clientIP[2], flow.key.clientIP[3])
	clientPort := int(flow.key.clientPort)

	for !p.closed.Load() {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if n <= 0 || addr == nil {
			continue
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok || ua.IP == nil || ua.Port <= 0 || ua.Port > 65535 {
			continue
		}
		flow.lastActive.Store(time.Now().UnixNano())
		pktSrcIP := p.resolveUDPReplySourceIP(flow, ua.IP.String(), ua.Port)
		if pktSrcIP == nil {
			continue
		}
		out := buildIPv4UDPPacket(pktSrcIP, clientIP, ua.Port, clientPort, buf[:n])
		if out != nil {
			p.emitPacket(out)
		}
	}
}

func isBroadcastIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if v4[0] == 255 && v4[1] == 255 && v4[2] == 255 && v4[3] == 255 {
		return true
	}
	// Subnet broadcast for 198.18.0.0/15 is 198.19.255.255.
	return v4[0] == 198 && v4[1] == 19 && v4[2] == 255 && v4[3] == 255
}

func parseDNSQuery(dns []byte) (id uint16, qname string, qtype uint16, qclass uint16, qEnd int, ok bool) {
	if len(dns) < 12 {
		return 0, "", 0, 0, 0, false
	}
	id = binary.BigEndian.Uint16(dns[0:2])
	flags := binary.BigEndian.Uint16(dns[2:4])
	if flags&0x8000 != 0 {
		return 0, "", 0, 0, 0, false
	}
	qdCount := binary.BigEndian.Uint16(dns[4:6])
	if qdCount == 0 {
		return 0, "", 0, 0, 0, false
	}

	off := 12
	var sb strings.Builder
	for off < len(dns) {
		lblLen := int(dns[off])
		if lblLen == 0 {
			off++
			break
		}
		if lblLen&0xC0 != 0 || lblLen > 63 {
			return 0, "", 0, 0, 0, false
		}
		off++
		if off+lblLen > len(dns) {
			return 0, "", 0, 0, 0, false
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for i := 0; i < lblLen; i++ {
			c := dns[off+i]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			sb.WriteByte(c)
		}
		if sb.Len() > 253 {
			return 0, "", 0, 0, 0, false
		}
		off += lblLen
	}
	if off == 12 || off+4 > len(dns) {
		return 0, "", 0, 0, 0, false
	}
	name := sb.String()
	if name == "" {
		return 0, "", 0, 0, 0, false
	}
	qtype = binary.BigEndian.Uint16(dns[off : off+2])
	qclass = binary.BigEndian.Uint16(dns[off+2 : off+4])
	return id, name, qtype, qclass, off + 4, true
}

func buildDNSResponsePacket(srcIP, dstIP net.IP, srcPort, dstPort int, dnsQuery []byte, qEnd int, rcode uint8, ips []net.IP, ttl uint32) []byte {
	if len(dnsQuery) < 12 || qEnd < 12 || qEnd > len(dnsQuery) {
		return nil
	}
	var validV4 [][4]byte
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			var b [4]byte
			copy(b[:], v4)
			validV4 = append(validV4, b)
			if len(validV4) >= 4 {
				break
			}
		}
	}

	qSection := dnsQuery[12:qEnd]
	dnsResp := make([]byte, 12+len(qSection)+len(validV4)*16)
	binary.BigEndian.PutUint16(dnsResp[0:2], binary.BigEndian.Uint16(dnsQuery[0:2]))
	dnsResp[2] = 0x80 | (dnsQuery[2] & 0x01) // QR=1, preserve RD
	dnsResp[3] = 0x80 | (rcode & 0x0F)       // RA=1, RCODE
	binary.BigEndian.PutUint16(dnsResp[4:6], 1)
	binary.BigEndian.PutUint16(dnsResp[6:8], uint16(len(validV4)))
	copy(dnsResp[12:], qSection)

	off := 12 + len(qSection)
	for _, v4 := range validV4 {
		dnsResp[off] = 0xC0
		dnsResp[off+1] = 0x0C
		binary.BigEndian.PutUint16(dnsResp[off+2:off+4], dnsTypeA)
		binary.BigEndian.PutUint16(dnsResp[off+4:off+6], 1) // IN class
		binary.BigEndian.PutUint32(dnsResp[off+6:off+10], ttl)
		binary.BigEndian.PutUint16(dnsResp[off+10:off+12], 4)
		copy(dnsResp[off+12:off+16], v4[:])
		off += 16
	}
	return buildIPv4UDPPacket(srcIP, dstIP, srcPort, dstPort, dnsResp)
}

func buildIPv4UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort int, payload []byte) []byte {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil || srcPort <= 0 || srcPort > 65535 || dstPort <= 0 || dstPort > 65535 {
		return nil
	}
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	if totalLen > 65535 {
		return nil
	}
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // Don't Fragment
	pkt[8] = 64                                  // TTL
	pkt[9] = 17                                  // UDP
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)

	binary.BigEndian.PutUint16(pkt[20:22], uint16(srcPort))
	binary.BigEndian.PutUint16(pkt[22:24], uint16(dstPort))
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	if len(payload) > 0 {
		copy(pkt[28:], payload)
	}
	if !UpdateIPv4UDPChecksums(pkt) {
		return nil
	}
	return pkt
}

func buildIPv4TCPPacket(srcIP, dstIP net.IP, srcPort, dstPort int, seq, ack uint32, flags byte, payload []byte) []byte {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil || srcPort <= 0 || srcPort > 65535 || dstPort <= 0 || dstPort > 65535 {
		return nil
	}
	totalLen := 40 + len(payload)
	if totalLen > 65535 {
		return nil
	}
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)

	binary.BigEndian.PutUint16(pkt[20:22], uint16(srcPort))
	binary.BigEndian.PutUint16(pkt[22:24], uint16(dstPort))
	binary.BigEndian.PutUint32(pkt[24:28], seq)
	binary.BigEndian.PutUint32(pkt[28:32], ack)
	pkt[32] = 0x50 // 5 * 4 = 20-byte TCP header
	pkt[33] = flags
	binary.BigEndian.PutUint16(pkt[34:36], 65535)
	if len(payload) > 0 {
		copy(pkt[40:], payload)
	}
	if !UpdateIPv4TCPChecksums(pkt) {
		return nil
	}
	return pkt
}

func buildICMPv4PortUnreachable(origIPv4Pkt []byte) []byte {
	if len(origIPv4Pkt) < 20 || origIPv4Pkt[0]>>4 != 4 {
		return nil
	}
	ihl := int(origIPv4Pkt[0]&0x0F) * 4
	if ihl < 20 || ihl > len(origIPv4Pkt) {
		return nil
	}
	quoteLen := ihl + 8
	if quoteLen > len(origIPv4Pkt) {
		quoteLen = len(origIPv4Pkt)
	}
	icmpLen := 8 + quoteLen
	totalLen := 20 + icmpLen
	if totalLen > 65535 {
		return nil
	}

	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // Don't Fragment
	pkt[8] = 64                                  // TTL
	pkt[9] = 1                                   // ICMP
	copy(pkt[12:16], origIPv4Pkt[16:20])         // src = original dst
	copy(pkt[16:20], origIPv4Pkt[12:16])         // dst = original src
	if !SetIPv4Checksum(pkt) {
		return nil
	}

	pkt[20] = 3 // Destination Unreachable
	pkt[21] = 3 // Port Unreachable
	copy(pkt[28:], origIPv4Pkt[:quoteLen])
	icmpCsum := foldOnesComplement(onesComplementSumRange(pkt[20:], 0))
	binary.BigEndian.PutUint16(pkt[22:24], icmpCsum)
	return pkt
}

// IsECHCoverDomain returns true if sni is a public Cloudflare ECH outer cover name.
func IsECHCoverDomain(sni string) bool {
	h := normalizeHostForMatch(sni)
	return h == "cloudflare-ech.com" || strings.HasSuffix(h, ".cloudflare-ech.com")
}

// ExtractTLSClientHelloSNI safely extracts the lowercase SNI hostname from raw TLS
// record bytes containing a ClientHello without panicking on truncated/malformed input.
func ExtractTLSClientHelloSNI(buf []byte) string {
	if len(buf) < 43 || buf[0] != 0x16 || buf[1] != 0x03 || buf[2] > 0x04 {
		return ""
	}
	firstRecLen := int(binary.BigEndian.Uint16(buf[3:5]))
	if firstRecLen <= 0 {
		return ""
	}

	var hs []byte
	if 5+firstRecLen >= len(buf) {
		end := len(buf)
		if 5+firstRecLen < end {
			end = 5 + firstRecLen
		}
		hs = buf[5:end]
	} else {
		hs = make([]byte, 0, minInt(len(buf), 8192))
		off := 0
		for off+5 <= len(buf) && len(hs) < 8192 {
			if buf[off] != 0x16 || buf[off+1] != 0x03 || buf[off+2] > 0x04 {
				break
			}
			rlen := int(binary.BigEndian.Uint16(buf[off+3 : off+5]))
			if rlen <= 0 || rlen > 16384+256 {
				break
			}
			end := off + 5 + rlen
			if end > len(buf) {
				end = len(buf)
			}
			remain := 8192 - len(hs)
			chunk := buf[off+5 : end]
			if len(chunk) > remain {
				chunk = chunk[:remain]
			}
			hs = append(hs, chunk...)
			if off+5+rlen > len(buf) {
				break
			}
			off = end
		}
	}

	if len(hs) < 39 || hs[0] != 0x01 {
		return ""
	}
	hsBodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	hsLimit := len(hs)
	if 4+hsBodyLen < hsLimit {
		hsLimit = 4 + hsBodyLen
	}
	// Handshake header (4) + ClientVersion (2) + Random (32) = 38.
	pos := 38
	if pos >= hsLimit {
		return ""
	}
	sidLen := int(hs[pos])
	pos += 1 + sidLen
	if pos+2 > hsLimit {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(hs[pos : pos+2]))
	pos += 2 + csLen
	if pos+1 > hsLimit {
		return ""
	}
	compLen := int(hs[pos])
	pos += 1 + compLen
	if pos+2 > hsLimit {
		return ""
	}
	extTotal := int(binary.BigEndian.Uint16(hs[pos : pos+2]))
	pos += 2
	extEnd := pos + extTotal
	if extEnd > hsLimit {
		extEnd = hsLimit
	}
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(hs[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(hs[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > extEnd {
			return ""
		}
		if extType == 0x0000 {
			if extLen < 5 {
				return ""
			}
			listLen := int(binary.BigEndian.Uint16(hs[pos : pos+2]))
			if 2+listLen > extLen {
				listLen = extLen - 2
			}
			sniPos := pos + 2
			sniEnd := sniPos + listLen
			for sniPos+3 <= sniEnd {
				nameType := hs[sniPos]
				nameLen := int(binary.BigEndian.Uint16(hs[sniPos+1 : sniPos+3]))
				sniPos += 3
				if sniPos+nameLen > sniEnd {
					return ""
				}
				if nameType == 0x00 && nameLen > 0 && nameLen <= 253 {
					candidate := normalizeHostForMatch(string(hs[sniPos : sniPos+nameLen]))
					if candidate != "" && net.ParseIP(candidate) == nil && strings.Contains(candidate, ".") {
						return candidate
					}
					return ""
				}
				sniPos += nameLen
			}
			return ""
		}
		pos += extLen
	}
	return ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type replayConn struct {
	net.Conn
	prefix []byte
}

func (rc *replayConn) Read(b []byte) (int, error) {
	if len(rc.prefix) > 0 {
		n := copy(b, rc.prefix)
		rc.prefix = rc.prefix[n:]
		return n, nil
	}
	return rc.Conn.Read(b)
}

func (rc *replayConn) CloseWrite() error {
	if cw, ok := rc.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// PeekConnTLSClientHelloSNI peeks the initial TLS ClientHello on conn within timeout,
// returning the lowercase SNI (if present) and a wrapped net.Conn that replays all
// peeked bytes verbatim.
func PeekConnTLSClientHelloSNI(conn net.Conn, timeout time.Duration) (string, net.Conn) {
	if conn == nil {
		return "", nil
	}
	if timeout <= 0 {
		timeout = 250 * time.Millisecond
	}
	const maxPeek = 8192
	buf := make([]byte, maxPeek)
	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)
	total := 0
	n, err := conn.Read(buf)
	if n > 0 {
		total = n
	}
	// If this looks like a TLS Handshake record fragmented across multiple TCP segments
	// (e.g., Chrome X25519MLKEM768 ClientHello > 1500B MTU), read until the first record
	// completes or timeout/buffer cap is reached.
	if err == nil && total >= 5 && buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x04 {
		target := 5 + int(binary.BigEndian.Uint16(buf[3:5]))
		if target > maxPeek {
			target = maxPeek
		}
		for total < target {
			if sni := ExtractTLSClientHelloSNI(buf[:total]); sni != "" {
				break
			}
			if time.Now().After(deadline) {
				break
			}
			m, rErr := conn.Read(buf[total:target])
			if m > 0 {
				total += m
			}
			if rErr != nil {
				break
			}
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	if total == 0 {
		return "", conn
	}
	wrapped := &replayConn{
		Conn:   conn,
		prefix: buf[:total],
	}
	return ExtractTLSClientHelloSNI(buf[:total]), wrapped
}
