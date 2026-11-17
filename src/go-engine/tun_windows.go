//go:build windows

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed wintun_amd64.dll.gz
var embeddedWintunDLLGz []byte

const (
	wintunRingCapacity uint32 = 0x400000
	ipUnicastIf        int    = 31
	ipv6UnicastIf      int    = 31
	createNoWindowFlag uint32 = 0x08000000
)

var pixelTunnelAdapterGUID = windows.GUID{
	Data1: 0x7E9A3B12,
	Data2: 0x4F51,
	Data3: 0x4C8A,
	Data4: [8]byte{0x9B, 0x0D, 0x2E, 0x1A, 0x4C, 0x8D, 0x6F, 0x01},
}

var (
	modKernel32TUN                  = windows.NewLazySystemDLL("kernel32.dll")
	procRtlMoveMemory               = modKernel32TUN.NewProc("RtlMoveMemory")
	modIphlpapiTUN                  = windows.NewLazySystemDLL("iphlpapi.dll")
	procInitializeUnicastIpAddress  = modIphlpapiTUN.NewProc("InitializeUnicastIpAddressEntry")
	procCreateUnicastIpAddress      = modIphlpapiTUN.NewProc("CreateUnicastIpAddressEntry")
	procSetIpInterfaceEntry         = modIphlpapiTUN.NewProc("SetIpInterfaceEntry")
	procInitializeIpForwardEntry    = modIphlpapiTUN.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2       = modIphlpapiTUN.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2       = modIphlpapiTUN.NewProc("DeleteIpForwardEntry2")
	procConvertInterfaceLuidToIndex = modIphlpapiTUN.NewProc("ConvertInterfaceLuidToIndex")
	procConvertInterfaceLuidToAlias = modIphlpapiTUN.NewProc("ConvertInterfaceLuidToAlias")
)

type wintunBindings struct {
	dll                *windows.LazyDLL
	createAdapter      *windows.LazyProc
	openAdapter        *windows.LazyProc
	closeAdapter       *windows.LazyProc
	getAdapterLUID     *windows.LazyProc
	startSession       *windows.LazyProc
	endSession         *windows.LazyProc
	getReadWaitEvent   *windows.LazyProc
	receivePacket      *windows.LazyProc
	releaseReceivePkt  *windows.LazyProc
	allocateSendPacket *windows.LazyProc
	sendPacket         *windows.LazyProc
}

// TUNController manages the Windows Wintun L3 TUN adapter, routes, physical NIC
// binding, internal TCP relay listener, and TUNPacketProcessor lifecycle.
type TUNController struct {
	opts TUNOptions

	opMu        sync.Mutex
	txMu        sync.Mutex
	statusMu    sync.RWMutex
	statusText  string
	lastErrText string
	enabled     atomic.Bool
	active      atomic.Bool
	physIfIndex atomic.Uint32

	wintun     *wintunBindings
	adapter    uintptr
	session    uintptr
	stopEvent  windows.Handle
	tunLuid    uint64
	tunIfIndex uint32
	tunAlias   string

	tcpRelayLn net.Listener
	processor  *TUNPacketProcessor
	routes     []windows.MibIpForwardRow2

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewTUNController constructs a TUNController in disabled/stopped state.
func NewTUNController(opts TUNOptions) *TUNController {
	return &TUNController{
		opts:       opts,
		statusText: "stopped",
	}
}

func (c *TUNController) setStatus(enabled, active bool, status, lastErr string) {
	c.enabled.Store(enabled)
	c.active.Store(active)
	c.statusMu.Lock()
	c.statusText = status
	c.lastErrText = lastErr
	c.statusMu.Unlock()
}

// Status returns the current TUN status snapshot.
func (c *TUNController) Status() TUNStatusSnapshot {
	c.statusMu.RLock()
	st := c.statusText
	lastErr := c.lastErrText
	c.statusMu.RUnlock()

	snap := TUNStatusSnapshot{
		Enabled:     c.enabled.Load(),
		Active:      c.active.Load(),
		Status:      st,
		AdapterName: TUNAdapterName,
		LastError:   lastErr,
	}
	if c.tunAlias != "" {
		snap.AdapterName = c.tunAlias
	}
	if c.processor != nil {
		snap.FakeIPEntries = c.processor.FakeIPCount()
		snap.UDPFlows = c.processor.UDPFlowCount()
		snap.TCPFlows = c.processor.TCPFlowCount()
	}
	return snap
}

// PhysicalDialControl returns a net.Dialer Control callback binding outbound sockets
// via IP_UNICAST_IF (31) to the primary physical NIC when TUN is active, or nil when inactive.
func (c *TUNController) PhysicalDialControl() func(network, address string, rawConn syscall.RawConn) error {
	if c == nil || !c.active.Load() {
		return nil
	}
	ifIdx := c.physIfIndex.Load()
	if ifIdx == 0 {
		return nil
	}
	return func(network, address string, rawConn syscall.RawConn) error {
		if !c.active.Load() {
			return nil
		}
		curIdx := c.physIfIndex.Load()
		if curIdx == 0 {
			return nil
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		host = strings.Trim(strings.TrimSpace(host), "[]")
		if strings.EqualFold(host, "localhost") {
			return nil
		}
		ip := net.ParseIP(host)
		if ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
			return nil
		}
		var sockErr error
		ctrlErr := rawConn.Control(func(fd uintptr) {
			isV6 := strings.HasSuffix(network, "6") || (ip != nil && ip.To4() == nil)
			if isV6 {
				sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, ipv6UnicastIf, int(curIdx))
				return
			}
			var be [4]byte
			binary.BigEndian.PutUint32(be[:], curIdx)
			sockErr = windows.SetsockoptInet4Addr(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, be)
		})
		if ctrlErr != nil {
			return ctrlErr
		}
		return sockErr
	}
}

func isWindowsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// Start elevates-checks, extracts wintun.dll, opens Wintun, configures IP/DNS/routes,
// binds the internal TCP relay listener, and starts packet processing loops.
func (c *TUNController) Start() error {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if c.active.Load() {
		return nil
	}

	if !isWindowsElevated() {
		err := errors.New("administrator privileges required for Wintun TUN mode")
		c.setStatus(false, false, "admin_required", err.Error())
		return err
	}

	if runtime.GOARCH != "amd64" {
		err := fmt.Errorf("embedded wintun_amd64.dll only supports amd64 (current arch: %s)", runtime.GOARCH)
		c.setStatus(false, false, "error", err.Error())
		return err
	}

	c.setStatus(true, false, "starting", "")

	dllPath, err := extractEmbeddedWintunDLL()
	if err != nil {
		c.setStatus(false, false, "error", err.Error())
		return err
	}
	wt, err := loadWintunBindings(dllPath)
	if err != nil {
		c.setStatus(false, false, "error", err.Error())
		return err
	}
	c.wintun = wt

	// Detect physical NIC index and default gateway BEFORE adding TUN routes.
	physIdx, physLuid, physGW, err := detectPrimaryPhysicalNIC()
	if err != nil {
		c.setStatus(false, false, "error", err.Error())
		return err
	}
	c.physIfIndex.Store(physIdx)

	adapter, err := wt.createOrOpenAdapter(TUNAdapterName)
	if err != nil {
		c.physIfIndex.Store(0)
		c.setStatus(false, false, "error", err.Error())
		return err
	}
	c.adapter = adapter

	var luid uint64
	_, _, _ = wt.getAdapterLUID.Call(adapter, uintptr(unsafe.Pointer(&luid)))
	if luid == 0 {
		c.cleanupFailedStartLocked()
		err := errors.New("failed to obtain Wintun adapter LUID")
		c.setStatus(false, false, "error", err.Error())
		return err
	}
	c.tunLuid = luid

	tunIdx, err := luidToInterfaceIndex(luid)
	if err != nil {
		c.cleanupFailedStartLocked()
		c.setStatus(false, false, "error", err.Error())
		return err
	}
	c.tunIfIndex = tunIdx
	if alias, aErr := luidToInterfaceAlias(luid); aErr == nil && alias != "" {
		c.tunAlias = alias
	} else {
		c.tunAlias = TUNAdapterName
	}

	sess, _, lastErr := wt.startSession.Call(adapter, uintptr(wintunRingCapacity))
	if sess == 0 {
		c.cleanupFailedStartLocked()
		err := fmt.Errorf("WintunStartSession failed: %w", lastErr)
		c.setStatus(false, false, "error", err.Error())
		return err
	}
	c.session = sess

	stopEv, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		c.cleanupFailedStartLocked()
		err = fmt.Errorf("CreateEvent stop handle: %w", err)
		c.setStatus(false, false, "error", err.Error())
		return err
	}
	c.stopEvent = stopEv

	if err := configureWintunInterface(luid, tunIdx, c.tunAlias); err != nil {
		c.cleanupFailedStartLocked()
		c.setStatus(false, false, "error", err.Error())
		return err
	}

	relayLn, relayPort, err := listenTUNRelayWithRetry(net.JoinHostPort(TUNAdapterIPStr, "0"))
	if err != nil {
		c.cleanupFailedStartLocked()
		c.setStatus(false, false, "error", err.Error())
		return err
	}
	c.tcpRelayLn = relayLn

	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.processor = NewTUNPacketProcessor(c.opts, net.ParseIP(TUNAdapterIPStr), relayPort, c.writeWintunPacket)
	// Active must be true when PhysicalDialControl is called for direct sockets.
	c.active.Store(true)
	c.processor.SetDirectDialControl(c.PhysicalDialControl())

	// Install /32 bypass routes via physical NIC BEFORE adding 0.0.0.0/1 + 128.0.0.0/1 TUN routes.
	bypassIPs := c.collectBypassIPv4s()
	for _, bip := range bypassIPs {
		row, rErr := addIPv4Route(physLuid, physIdx, bip, 32, physGW, 1)
		if rErr == nil {
			c.routes = append(c.routes, row)
		}
	}

	// Add split default routes covering 0.0.0.0/0 via PixelTunnel Wintun adapter.
	splitPrefixes := []struct {
		ip  net.IP
		len uint8
	}{
		{net.IPv4(0, 0, 0, 0), 1},
		{net.IPv4(128, 0, 0, 0), 1},
	}
	for _, sp := range splitPrefixes {
		row, rErr := addIPv4Route(luid, tunIdx, sp.ip, sp.len, net.IPv4zero, 2)
		if rErr != nil {
			c.active.Store(false)
			c.cleanupFailedStartLocked()
			c.setStatus(false, false, "error", rErr.Error())
			return rErr
		}
		c.routes = append(c.routes, row)
	}

	readWaitRaw, _, _ := wt.getReadWaitEvent.Call(sess)
	readWait := windows.Handle(readWaitRaw)

	c.wg.Add(2)
	go c.wintunRXLoop(sess, readWait)
	go c.relayAcceptLoop(relayLn)

	c.setStatus(true, true, "active", "")
	return nil
}

// Stop tears down routes, Wintun session/adapter, relay listener, and packet processor cleanly.
func (c *TUNController) Stop() error {
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.teardownLocked()
	c.setStatus(false, false, "stopped", "")
	return nil
}

func (c *TUNController) cleanupFailedStartLocked() {
	c.teardownLocked()
}

func (c *TUNController) teardownLocked() {
	c.active.Store(false)
	c.enabled.Store(false)
	c.physIfIndex.Store(0)

	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.tcpRelayLn != nil {
		_ = c.tcpRelayLn.Close()
		c.tcpRelayLn = nil
	}
	if c.stopEvent != 0 {
		_ = windows.SetEvent(c.stopEvent)
	}

	c.wg.Wait()

	for i := len(c.routes) - 1; i >= 0; i-- {
		row := c.routes[i]
		_, _, _ = procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	}
	c.routes = nil

	c.txMu.Lock()
	sess := c.session
	c.session = 0
	c.txMu.Unlock()
	if sess != 0 && c.wintun != nil {
		_, _, _ = c.wintun.endSession.Call(sess)
	}

	if c.adapter != 0 && c.wintun != nil {
		_, _, _ = c.wintun.closeAdapter.Call(c.adapter)
		c.adapter = 0
	}
	if c.stopEvent != 0 {
		_ = windows.CloseHandle(c.stopEvent)
		c.stopEvent = 0
	}
	if c.processor != nil {
		c.processor.Close()
		c.processor = nil
	}
	c.tunLuid = 0
	c.tunIfIndex = 0
}

func (c *TUNController) collectBypassIPv4s() []net.IP {
	seen := make(map[string]struct{})
	var out []net.IP
	addIP := func(ip net.IP) {
		if ip == nil {
			return
		}
		v4 := ip.To4()
		if v4 == nil || v4.IsLoopback() || v4.IsUnspecified() || v4.IsMulticast() || IsPrivateOrReservedIP(v4) {
			return
		}
		if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			return
		}
		s := v4.String()
		if _, exists := seen[s]; exists {
			return
		}
		seen[s] = struct{}{}
		out = append(out, append(net.IP(nil), v4...))
	}

	if c.opts.BypassNodeIPsFn != nil {
		for _, ip := range c.opts.BypassNodeIPsFn() {
			addIP(ip)
		}
	}
	if c.opts.Resolver != nil {
		for _, ep := range c.opts.Resolver.endpoints {
			if u, err := url.Parse(ep.URL); err == nil {
				if ip := net.ParseIP(u.Hostname()); ip != nil {
					addIP(ip)
				}
			}
		}
	}
	for _, ep := range defaultDohEndpoints {
		if u, err := url.Parse(ep.URL); err == nil {
			if ip := net.ParseIP(u.Hostname()); ip != nil {
				addIP(ip)
			}
		}
	}
	return out
}

func (c *TUNController) writeWintunPacket(pkt []byte) error {
	if len(pkt) == 0 || !c.active.Load() {
		return nil
	}
	c.txMu.Lock()
	defer c.txMu.Unlock()

	if c.session == 0 || c.wintun == nil || !c.active.Load() {
		return errors.New("wintun session closed")
	}
	ptr, _, err := c.wintun.allocateSendPacket.Call(c.session, uintptr(len(pkt)))
	if ptr == 0 {
		return fmt.Errorf("WintunAllocateSendPacket: %w", err)
	}
	_, _, _ = procRtlMoveMemory.Call(ptr, uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)))
	_, _, _ = c.wintun.sendPacket.Call(c.session, ptr)
	return nil
}

func (c *TUNController) wintunRXLoop(sess uintptr, readWait windows.Handle) {
	defer c.wg.Done()
	handles := []windows.Handle{readWait, c.stopEvent}

	for c.active.Load() {
		var pktSize uint32
		ptr, _, err := c.wintun.receivePacket.Call(sess, uintptr(unsafe.Pointer(&pktSize)))
		if ptr == 0 {
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
				ev, wErr := windows.WaitForMultipleObjects(handles, false, windows.INFINITE)
				if wErr != nil || ev != windows.WAIT_OBJECT_0 {
					return
				}
				continue
			}
			return
		}

		var pkt []byte
		if pktSize > 0 && pktSize <= 65536 {
			pkt = make([]byte, pktSize)
			_, _, _ = procRtlMoveMemory.Call(uintptr(unsafe.Pointer(&pkt[0])), ptr, uintptr(pktSize))
		}
		_, _, _ = c.wintun.releaseReceivePkt.Call(sess, ptr)

		if len(pkt) > 0 && c.processor != nil {
			c.processor.ProcessPacket(pkt)
		}
	}
}

func (c *TUNController) relayAcceptLoop(ln net.Listener) {
	defer c.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		c.wg.Add(1)
		go func(cl net.Conn) {
			defer c.wg.Done()
			c.handleRelayTCPConn(cl)
		}(conn)
	}
}

func (c *TUNController) handleRelayTCPConn(clientConn net.Conn) {
	defer clientConn.Close()

	tcpAddr, ok := clientConn.RemoteAddr().(*net.TCPAddr)
	if !ok || tcpAddr == nil || tcpAddr.Port <= 0 || c.processor == nil {
		return
	}

	host, port, isFakeIP, found := c.processor.NAT.LookupOriginalTarget(tcpAddr.Port)
	if !found || host == "" || port <= 0 || port > 65535 {
		return
	}

	decision := RuleAction{Action: "PROXY", Rule: "default", Role: "ai"}
	if c.opts.ClassifyFn != nil {
		decision = c.opts.ClassifyFn(host)
	}
	isDirectIP := false
	if !isFakeIP && c.opts.IsDirectIPFn != nil {
		if ip := net.ParseIP(host); ip != nil && c.opts.IsDirectIPFn(ip) {
			isDirectIP = true
			decision.Action = "DIRECT"
		}
	}
	if !isFakeIP && !isDirectIP && !strings.EqualFold(decision.Action, "PROXY") &&
		(port == 443 || port == 8443 || port == 2053 || port == 2083 || port == 2087 || port == 2096) &&
		c.opts.ClassifyFn != nil {
		sni, wrappedConn := PeekConnTLSClientHelloSNI(clientConn, 250*time.Millisecond)
		clientConn = wrappedConn
		if sni != "" && !IsECHCoverDomain(sni) {
			sniDecision := c.opts.ClassifyFn(sni)
			if strings.EqualFold(sniDecision.Action, "PROXY") {
				decision = sniDecision
				host = sni
			}
		}
	}

	dialCtx, cancel := context.WithTimeout(c.ctx, 15*time.Second)
	defer cancel()

	var upstream net.Conn
	var err error
	if strings.EqualFold(decision.Action, "PROXY") && c.opts.Mux != nil {
		upstream, _, err = c.opts.Mux.OpenStream(dialCtx, decision.Role, host, port)
	} else {
		dialHost := host
		if isFakeIP {
			if c.opts.Resolver == nil {
				return
			}
			ips, rErr := c.opts.Resolver.LookupHost(dialCtx, host)
			if rErr != nil {
				return
			}
			var chosen net.IP
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					chosen = v4
					break
				}
			}
			if chosen == nil {
				return
			}
			dialHost = chosen.String()
		}
		d := &net.Dialer{
			Timeout:   6 * time.Second,
			KeepAlive: 30 * time.Second,
			Control:   c.PhysicalDialControl(),
		}
		upstream, err = d.DialContext(dialCtx, "tcp4", net.JoinHostPort(dialHost, strconv.Itoa(port)))
	}
	if err != nil || upstream == nil {
		return
	}
	defer upstream.Close()

	var copyWg sync.WaitGroup
	copyWg.Add(2)
	go func() {
		defer copyWg.Done()
		_, _ = io.Copy(upstream, clientConn)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer copyWg.Done()
		_, _ = io.Copy(clientConn, upstream)
		if cw, ok := clientConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	copyWg.Wait()
}

func extractEmbeddedWintunDLL() (string, error) {
	if len(embeddedWintunDLLGz) == 0 {
		return "", errors.New("embedded wintun_amd64.dll.gz is empty")
	}
	gz, err := gzip.NewReader(bytes.NewReader(embeddedWintunDLLGz))
	if err != nil {
		return "", fmt.Errorf("decompress wintun.dll: %w", err)
	}
	dllBytes, err := io.ReadAll(io.LimitReader(gz, 8*1024*1024))
	_ = gz.Close()
	if err != nil || len(dllBytes) < 4096 {
		return "", fmt.Errorf("invalid decompressed wintun.dll (len=%d): %w", len(dllBytes), err)
	}

	baseDir := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
	if baseDir == "" {
		if uc, uErr := os.UserCacheDir(); uErr == nil && uc != "" {
			baseDir = uc
		} else {
			home, _ := os.UserHomeDir()
			baseDir = filepath.Join(home, "AppData", "Local")
		}
	}
	binDir := filepath.Join(baseDir, "PixelTunnel", "bin")
	if err := os.MkdirAll(binDir, 0700); err != nil {
		return "", fmt.Errorf("create wintun bin dir: %w", err)
	}
	dstPath := filepath.Join(binDir, "wintun.dll")

	wantSum := sha256.Sum256(dllBytes)
	if existing, rErr := os.ReadFile(dstPath); rErr == nil && sha256.Sum256(existing) == wantSum {
		return dstPath, nil
	}

	tmpPath := dstPath + ".tmp"
	if err := os.WriteFile(tmpPath, dllBytes, 0700); err != nil {
		return "", fmt.Errorf("write temp wintun.dll: %w", err)
	}
	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Remove(tmpPath)
		if existing, rErr := os.ReadFile(dstPath); rErr == nil && sha256.Sum256(existing) == wantSum {
			return dstPath, nil
		}
		if wErr := os.WriteFile(dstPath, dllBytes, 0700); wErr != nil {
			return "", fmt.Errorf("install wintun.dll: %w", wErr)
		}
	}
	return dstPath, nil
}

func loadWintunBindings(dllPath string) (*wintunBindings, error) {
	dll := windows.NewLazyDLL(dllPath)
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("load %s: %w", dllPath, err)
	}
	b := &wintunBindings{
		dll:                dll,
		createAdapter:      dll.NewProc("WintunCreateAdapter"),
		openAdapter:        dll.NewProc("WintunOpenAdapter"),
		closeAdapter:       dll.NewProc("WintunCloseAdapter"),
		getAdapterLUID:     dll.NewProc("WintunGetAdapterLUID"),
		startSession:       dll.NewProc("WintunStartSession"),
		endSession:         dll.NewProc("WintunEndSession"),
		getReadWaitEvent:   dll.NewProc("WintunGetReadWaitEvent"),
		receivePacket:      dll.NewProc("WintunReceivePacket"),
		releaseReceivePkt:  dll.NewProc("WintunReleaseReceivePacket"),
		allocateSendPacket: dll.NewProc("WintunAllocateSendPacket"),
		sendPacket:         dll.NewProc("WintunSendPacket"),
	}
	for _, p := range []*windows.LazyProc{
		b.createAdapter, b.openAdapter, b.closeAdapter, b.getAdapterLUID,
		b.startSession, b.endSession, b.getReadWaitEvent,
		b.receivePacket, b.releaseReceivePkt, b.allocateSendPacket, b.sendPacket,
	} {
		if err := p.Find(); err != nil {
			return nil, fmt.Errorf("wintun export %s missing: %w", p.Name, err)
		}
	}
	return b, nil
}

func (b *wintunBindings) createOrOpenAdapter(name string) (uintptr, error) {
	nameUTF16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	typeUTF16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	guid := pixelTunnelAdapterGUID
	h, _, callErr := b.createAdapter.Call(
		uintptr(unsafe.Pointer(nameUTF16)),
		uintptr(unsafe.Pointer(typeUTF16)),
		uintptr(unsafe.Pointer(&guid)),
	)
	if h != 0 {
		return h, nil
	}
	h2, _, openErr := b.openAdapter.Call(uintptr(unsafe.Pointer(nameUTF16)))
	if h2 != 0 {
		return h2, nil
	}
	return 0, fmt.Errorf("WintunCreateAdapter(%s): %w (open fallback: %v)", name, callErr, openErr)
}

func isVirtualTunnelAlias(alias string) bool {
	al := strings.ToLower(strings.TrimSpace(alias))
	if al == "" {
		return false
	}
	for _, marker := range []string{
		"pixeltunnel", "pixeltun", "wintun", "sing-tun", "singbox", "sing-box",
		"wireguard", "nekoray", "nekobox", "hiddify", "amnezia", "outline",
		"clash", "mihomo", "tailscale", "zerotier", "nordlynx", "tap-windows",
	} {
		if strings.Contains(al, marker) {
			return true
		}
	}
	return false
}

func detectPrimaryPhysicalNIC() (uint32, uint64, net.IP, error) {
	var bestIdx uint32
	sa := &windows.SockaddrInet4{Addr: [4]byte{8, 8, 8, 8}}
	_ = windows.GetBestInterfaceEx(sa, &bestIdx)

	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return 0, 0, nil, fmt.Errorf("GetIpForwardTable2: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	var bestRow *windows.MibIpForwardRow2
	for _, row := range table.Rows() {
		if row.DestinationPrefix.PrefixLength != 0 || row.Loopback != 0 || row.InterfaceIndex <= 1 {
			continue
		}
		prefix4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.DestinationPrefix.Prefix))
		if prefix4.Family != windows.AF_INET || prefix4.Addr != ([4]byte{}) {
			continue
		}
		if alias, err := luidToInterfaceAlias(row.InterfaceLuid); err == nil {
			if isVirtualTunnelAlias(alias) {
				continue
			}
		}
		if bestRow == nil {
			r := row
			bestRow = &r
			continue
		}
		if bestIdx != 0 && row.InterfaceIndex == bestIdx && bestRow.InterfaceIndex != bestIdx {
			r := row
			bestRow = &r
			continue
		}
		if bestIdx != 0 && bestRow.InterfaceIndex == bestIdx && row.InterfaceIndex != bestIdx {
			continue
		}
		if row.Metric < bestRow.Metric {
			r := row
			bestRow = &r
		}
	}

	if bestRow == nil {
		return 0, 0, nil, errors.New("no active physical IPv4 default gateway found")
	}
	nh := (*windows.RawSockaddrInet4)(unsafe.Pointer(&bestRow.NextHop))
	gw := net.IPv4(nh.Addr[0], nh.Addr[1], nh.Addr[2], nh.Addr[3])
	return bestRow.InterfaceIndex, bestRow.InterfaceLuid, gw, nil
}

func luidToInterfaceIndex(luid uint64) (uint32, error) {
	var idx uint32
	r1, _, _ := procConvertInterfaceLuidToIndex.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&idx)))
	if r1 != 0 {
		return 0, fmt.Errorf("ConvertInterfaceLuidToIndex: %w", syscall.Errno(r1))
	}
	return idx, nil
}

func luidToInterfaceAlias(luid uint64) (string, error) {
	var buf [260]uint16
	r1, _, _ := procConvertInterfaceLuidToAlias.Call(
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 != 0 {
		return "", fmt.Errorf("ConvertInterfaceLuidToAlias: %w", syscall.Errno(r1))
	}
	return windows.UTF16ToString(buf[:]), nil
}

func configureWintunInterface(luid uint64, ifIdx uint32, alias string) error {
	var ifRow windows.MibIpInterfaceRow
	ifRow.Family = windows.AF_INET
	ifRow.InterfaceLuid = luid
	if err := windows.GetIpInterfaceEntry(&ifRow); err == nil {
		ifRow.SitePrefixLength = 0 // Must be 0 for IPv4 SetIpInterfaceEntry.
		ifRow.DadTransmits = 0
		ifRow.UseAutomaticMetric = 0
		ifRow.Metric = 2
		ifRow.NlMtu = 1500
		_, _, _ = procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&ifRow)))
	}

	var addrRow windows.MibUnicastIpAddressRow
	_, _, _ = procInitializeUnicastIpAddress.Call(uintptr(unsafe.Pointer(&addrRow)))
	addrRow.InterfaceLuid = luid
	addrRow.InterfaceIndex = ifIdx
	addrRow.OnLinkPrefixLength = TUNPrefixLen
	addrRow.DadState = 4 // IpDadStatePreferred
	addr4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&addrRow.Address))
	addr4.Family = windows.AF_INET
	addr4.Addr = [4]byte{198, 18, 0, 1}

	r1, _, _ := procCreateUnicastIpAddress.Call(uintptr(unsafe.Pointer(&addrRow)))
	if r1 != 0 && syscall.Errno(r1) != windows.ERROR_OBJECT_ALREADY_EXISTS {
		return fmt.Errorf("CreateUnicastIpAddressEntry: %w", syscall.Errno(r1))
	}

	netshPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe")
	if _, err := os.Stat(netshPath); err != nil {
		netshPath = "netsh.exe"
	}
	cmd := exec.Command(netshPath, "interface", "ipv4", "set", "dnsservers", "name="+alias, "source=static", "address="+TUNDNSIPStr, "register=none", "validate=no")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindowFlag,
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set TUN DNS via netsh (%s): %w (%s)", alias, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func listenTUNRelayWithRetry(addr string) (net.Listener, int, error) {
	deadline := time.Now().Add(2500 * time.Millisecond)
	var lastErr error
	for {
		ln, err := net.Listen("tcp4", addr)
		if err == nil {
			ta, _ := ln.Addr().(*net.TCPAddr)
			if ta == nil || ta.Port <= 0 {
				_ = ln.Close()
				return nil, 0, errors.New("TUN relay listener returned invalid port")
			}
			return ln, ta.Port, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return nil, 0, fmt.Errorf("bind TUN relay %s: %w", addr, lastErr)
		}
		time.Sleep(30 * time.Millisecond)
	}
}

func addIPv4Route(luid uint64, ifIdx uint32, dst net.IP, prefixLen uint8, nextHop net.IP, metric uint32) (windows.MibIpForwardRow2, error) {
	var row windows.MibIpForwardRow2
	_, _, _ = procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.InterfaceLuid = luid
	row.InterfaceIndex = ifIdx
	row.DestinationPrefix.PrefixLength = prefixLen

	dst4 := dst.To4()
	if dst4 == nil {
		dst4 = net.IPv4zero.To4()
	}
	dstSa := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.DestinationPrefix.Prefix))
	dstSa.Family = windows.AF_INET
	copy(dstSa.Addr[:], dst4)

	nh4 := nextHop.To4()
	if nh4 == nil {
		nh4 = net.IPv4zero.To4()
	}
	nhSa := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.NextHop))
	nhSa.Family = windows.AF_INET
	copy(nhSa.Addr[:], nh4)

	row.Metric = metric
	r1, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if r1 != 0 && syscall.Errno(r1) != windows.ERROR_OBJECT_ALREADY_EXISTS {
		return row, fmt.Errorf("CreateIpForwardEntry2(%s/%d): %w", dst4.String(), prefixLen, syscall.Errno(r1))
	}
	return row, nil
}
