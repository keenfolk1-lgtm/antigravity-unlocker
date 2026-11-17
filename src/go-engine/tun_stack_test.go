package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func rawOnesComplementSum(data []byte) uint16 {
	var sum uint32
	n := len(data)
	i := 0
	for i+1 < n {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
		i += 2
	}
	if i < n {
		sum += uint32(data[i]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(sum)
}

func verifyIPv4PacketChecksums(t *testing.T, pkt []byte) {
	t.Helper()
	if len(pkt) < 20 {
		t.Fatalf("packet too short: %d", len(pkt))
	}
	ihl := int(pkt[0]&0x0F) * 4
	if rawOnesComplementSum(pkt[:ihl]) != 0xFFFF {
		t.Fatalf("invalid IPv4 header checksum: sum=0x%04x hdr=%x", rawOnesComplementSum(pkt[:ihl]), pkt[:ihl])
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen != len(pkt) {
		t.Fatalf("totalLen=%d != len(pkt)=%d", totalLen, len(pkt))
	}
	switch pkt[9] {
	case 6:
		got := binary.BigEndian.Uint16(pkt[ihl+16 : ihl+18])
		want := ComputeTCPChecksum(pkt)
		if got != want {
			t.Fatalf("TCP checksum mismatch: got=0x%04x want=0x%04x", got, want)
		}
	case 17:
		got := binary.BigEndian.Uint16(pkt[ihl+6 : ihl+8])
		want := ComputeUDPChecksum(pkt)
		if got != want {
			t.Fatalf("UDP checksum mismatch: got=0x%04x want=0x%04x", got, want)
		}
	}
}

func TestFakeIPPoolBidirectionalAndLRU(t *testing.T) {
	pool := NewFakeIPPool(3)

	ip1 := pool.Assign("Claude.AI.")
	if ip1 == nil {
		t.Fatal("expected non-nil FakeIP")
	}
	if ip1.String() != "198.18.0.10" {
		t.Fatalf("expected first FakeIP 198.18.0.10, got %s", ip1.String())
	}
	if !pool.Contains(ip1) {
		t.Fatalf("expected Contains(%s) == true", ip1.String())
	}
	if got := pool.Assign("claude.ai"); !got.Equal(ip1) {
		t.Fatalf("expected idempotent FakeIP %s, got %s", ip1.String(), got.String())
	}
	if dom, ok := pool.LookupDomain(ip1); !ok || dom != "claude.ai" {
		t.Fatalf("LookupDomain(%s) = (%q, %v), want (claude.ai, true)", ip1.String(), dom, ok)
	}

	if pool.Contains(net.ParseIP("198.18.0.1")) {
		t.Fatal("TUN gateway IP 198.18.0.1 must not be inside FakeIP range")
	}
	if pool.Contains(net.ParseIP("198.18.0.2")) {
		t.Fatal("TUN DNS IP 198.18.0.2 must not be inside FakeIP range")
	}
	if pool.Contains(net.ParseIP("8.8.8.8")) {
		t.Fatal("8.8.8.8 must not be inside FakeIP range")
	}
	if pool.Contains(nil) || pool.Contains(net.ParseIP("::1")) {
		t.Fatal("nil and IPv6 must not be inside FakeIP range")
	}

	ip2 := pool.Assign("openai.com")
	ip3 := pool.Assign("discord.com")
	if pool.Count() != 3 {
		t.Fatalf("Count = %d, want 3", pool.Count())
	}

	// Touch ip1 so ip2 becomes LRU and gets evicted when assigning a 4th domain.
	if _, ok := pool.LookupDomain(ip1); !ok {
		t.Fatal("expected ip1 lookup to succeed")
	}
	ip4 := pool.Assign("anthropic.com")
	if pool.Count() != 3 {
		t.Fatalf("Count after eviction = %d, want 3", pool.Count())
	}
	if dom, ok := pool.LookupDomain(ip1); !ok || dom != "claude.ai" {
		t.Fatalf("expected claude.ai retained after touch, got (%q, %v)", dom, ok)
	}
	if !ip4.Equal(ip2) {
		t.Fatalf("expected evicted ip2 (%s) reused for ip4, got %s", ip2.String(), ip4.String())
	}
	if dom, ok := pool.LookupDomain(ip4); !ok || dom != "anthropic.com" {
		t.Fatalf("expected recycled IP mapped to anthropic.com, got (%q, %v)", dom, ok)
	}
	if dom, ok := pool.LookupDomain(ip3); !ok || dom != "discord.com" {
		t.Fatalf("expected discord.com retained, got (%q, %v)", dom, ok)
	}

	// Concurrent stress test for data-race freedom.
	concPool := NewFakeIPPool(64)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				ip := concPool.Assign(string(rune('a'+gid)) + ".example.com")
				if ip != nil {
					_, _ = concPool.LookupDomain(ip)
					_ = concPool.Contains(ip)
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestTUNDNSInterceptionProxyAndDirect(t *testing.T) {
	dohSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		resp := buildFakeADNSResponse(q, [4]byte{77, 88, 55, 80})
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	}))
	defer dohSrv.Close()

	resolver := NewDohResolver([]DohEndpoint{{URL: dohSrv.URL, ServerName: "dns.google"}}, &tls.Config{InsecureSkipVerify: true})
	cfg := DefaultEngineConfig()
	cfg.Categories["media"] = true
	cfg.RebuildEffectiveRules()
	matcher := NewDomainRuleMatcher(cfg)

	outCh := make(chan []byte, 8)
	proc := NewTUNPacketProcessor(TUNOptions{
		ClassifyFn: func(host string) RuleAction {
			return matcher.Classify(host)
		},
		Resolver: resolver,
	}, net.IPv4(198, 18, 0, 1), 40001, func(pkt []byte) error {
		outCh <- append([]byte(nil), pkt...)
		return nil
	})
	defer proc.Close()

	// 1) PROXY domain A query -> FakeIP 198.18.0.10, TTL 5s
	qClaudeA, _, err := buildDNSQueryWire("claude.ai", dnsTypeA)
	if err != nil {
		t.Fatalf("buildDNSQueryWire: %v", err)
	}
	pktClaudeA := buildIPv4UDPPacket(net.IPv4(198, 18, 0, 1), net.IPv4(198, 18, 0, 2), 51001, 53, qClaudeA)
	proc.ProcessPacket(pktClaudeA)

	select {
	case respPkt := <-outCh:
		verifyIPv4PacketChecksums(t, respPkt)
		dnsPayload := respPkt[28:]
		id := binary.BigEndian.Uint16(qClaudeA[0:2])
		parsed, ttl, perr := parseDNSResponseWire(dnsPayload, id, dnsTypeA)
		if perr != nil || len(parsed.ips) != 1 {
			t.Fatalf("parseDNSResponseWire failed: err=%v ips=%v", perr, parsed.ips)
		}
		if !proc.FakeIP.Contains(parsed.ips[0]) {
			t.Fatalf("expected FakeIP in 198.18.0.10-198.19.255.250, got %s", parsed.ips[0])
		}
		if ttl != 5*time.Second {
			t.Fatalf("expected FakeIP TTL 5s, got %v", ttl)
		}
		if dom, ok := proc.FakeIP.LookupDomain(parsed.ips[0]); !ok || dom != "claude.ai" {
			t.Fatalf("expected FakeIP mapped to claude.ai, got (%q, %v)", dom, ok)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for PROXY DNS A response")
	}

	// 2) PROXY domain AAAA query -> empty NOERROR
	qClaudeAAAA, _, err := buildDNSQueryWire("claude.ai", dnsTypeAAAA)
	if err != nil {
		t.Fatalf("buildDNSQueryWire AAAA: %v", err)
	}
	pktClaudeAAAA := buildIPv4UDPPacket(net.IPv4(198, 18, 0, 1), net.IPv4(198, 18, 0, 2), 51002, 53, qClaudeAAAA)
	proc.ProcessPacket(pktClaudeAAAA)

	select {
	case respPkt := <-outCh:
		verifyIPv4PacketChecksums(t, respPkt)
		dnsPayload := respPkt[28:]
		if rcode := dnsPayload[3] & 0x0F; rcode != 0 {
			t.Fatalf("expected NOERROR (0) for AAAA, got rcode=%d", rcode)
		}
		if anCount := binary.BigEndian.Uint16(dnsPayload[6:8]); anCount != 0 {
			t.Fatalf("expected 0 answers for suppressed AAAA, got %d", anCount)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for AAAA NOERROR response")
	}

	// 3) DIRECT domain (.ru) A query -> resolved via DoH mock to 77.88.55.80
	qYandexA, _, err := buildDNSQueryWire("yandex.ru", dnsTypeA)
	if err != nil {
		t.Fatalf("buildDNSQueryWire yandex.ru: %v", err)
	}
	pktYandexA := buildIPv4UDPPacket(net.IPv4(198, 18, 0, 1), net.IPv4(198, 18, 0, 2), 51003, 53, qYandexA)
	proc.ProcessPacket(pktYandexA)

	select {
	case respPkt := <-outCh:
		verifyIPv4PacketChecksums(t, respPkt)
		dnsPayload := respPkt[28:]
		id := binary.BigEndian.Uint16(qYandexA[0:2])
		parsed, _, perr := parseDNSResponseWire(dnsPayload, id, dnsTypeA)
		if perr != nil || len(parsed.ips) != 1 {
			t.Fatalf("parseDNSResponseWire DIRECT failed: err=%v ips=%v", perr, parsed.ips)
		}
		if parsed.ips[0].String() != "77.88.55.80" {
			t.Fatalf("expected DoH resolved IP 77.88.55.80, got %s", parsed.ips[0].String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for DIRECT DNS A response")
	}
}

func TestTUNNATTableOutboundInboundAndChecksums(t *testing.T) {
	fakePool := NewFakeIPPool(16)
	fakeIP := fakePool.Assign("api.anthropic.com")
	relayIP := net.IPv4(198, 18, 0, 1)
	const relayPort = 45678

	nat := NewTUNNATTable(relayIP, relayPort, fakePool, 32)
	clientIP := net.IPv4(198, 18, 0, 1)

	// Outbound SYN with odd-length payload to exercise RFC 1071 odd byte padding.
	synPkt := buildIPv4TCPPacket(clientIP, fakeIP, 54321, 443, 1000, 0, tcpFlagSYN, []byte("ABC"))
	verifyIPv4PacketChecksums(t, synPkt)

	natOut, ok := nat.TranslateOutbound(synPkt)
	if !ok {
		t.Fatal("expected TranslateOutbound to succeed")
	}
	verifyIPv4PacketChecksums(t, natOut)
	if gotSrc := net.IP(natOut[12:16]).String(); gotSrc != fakeIP.String() {
		t.Fatalf("outbound NAT srcIP = %s, want %s", gotSrc, fakeIP.String())
	}
	if gotDst := net.IP(natOut[16:20]).String(); gotDst != relayIP.String() {
		t.Fatalf("outbound NAT dstIP = %s, want %s", gotDst, relayIP.String())
	}
	if gotDPort := int(binary.BigEndian.Uint16(natOut[22:24])); gotDPort != relayPort {
		t.Fatalf("outbound NAT dstPort = %d, want %d", gotDPort, relayPort)
	}

	host, port, isFake, found := nat.LookupOriginalTarget(54321)
	if !found || !isFake || host != "api.anthropic.com" || port != 443 {
		t.Fatalf("LookupOriginalTarget(54321) = (%q, %d, %v, %v), want (api.anthropic.com, 443, true, true)", host, port, isFake, found)
	}

	// Return SYN-ACK from relay listener back through NAT.
	retPkt := buildIPv4TCPPacket(relayIP, fakeIP, relayPort, 54321, 2000, 1004, tcpFlagSYN|tcpFlagACK, []byte("12345"))
	natIn, ok := nat.TranslateInbound(retPkt)
	if !ok {
		t.Fatal("expected TranslateInbound to succeed")
	}
	verifyIPv4PacketChecksums(t, natIn)
	if gotSrc := net.IP(natIn[12:16]).String(); gotSrc != fakeIP.String() {
		t.Fatalf("inbound NAT srcIP = %s, want %s", gotSrc, fakeIP.String())
	}
	if gotSPort := int(binary.BigEndian.Uint16(natIn[20:22])); gotSPort != 443 {
		t.Fatalf("inbound NAT srcPort = %d, want 443", gotSPort)
	}
	if gotDst := net.IP(natIn[16:20]).String(); gotDst != clientIP.String() {
		t.Fatalf("inbound NAT dstIP = %s, want %s", gotDst, clientIP.String())
	}
	if gotDPort := int(binary.BigEndian.Uint16(natIn[22:24])); gotDPort != 54321 {
		t.Fatalf("inbound NAT dstPort = %d, want 54321", gotDPort)
	}

	// Real non-FakeIP target tracking.
	realIP := net.IPv4(104, 18, 10, 1)
	realSyn := buildIPv4TCPPacket(clientIP, realIP, 54322, 8443, 1, 0, tcpFlagSYN, nil)
	if _, ok := nat.TranslateOutbound(realSyn); !ok {
		t.Fatal("expected real IP TranslateOutbound to succeed")
	}
	host2, port2, isFake2, found2 := nat.LookupOriginalTarget(54322)
	if !found2 || isFake2 || host2 != "104.18.10.1" || port2 != 8443 {
		t.Fatalf("LookupOriginalTarget(54322) = (%q, %d, %v, %v), want (104.18.10.1, 8443, false, true)", host2, port2, isFake2, found2)
	}
}

func TestTUNUDPRelayDiscordVoicePWP4EchoAndIdleGC(t *testing.T) {
	pCli, pSrv := net.Pipe()
	defer pSrv.Close()

	mat, err := DerivePWP4KeyMaterial("tun-udp-secret", "cli", "srv")
	if err != nil {
		t.Fatalf("DerivePWP4KeyMaterial: %v", err)
	}
	cTx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	cRx, _ := newPWP4Cipher(mat[32:64], mat[80:96])
	sRx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	sTx, _ := newPWP4Cipher(mat[32:64], mat[80:96])

	type srvUDP struct {
		host string
		port int
		data string
	}
	srvGotCh := make(chan srvUDP, 4)
	srvRstCh := make(chan uint32, 4)

	go func() {
		br := bufio.NewReader(pSrv)
		for {
			ft, sid, payload, _, rerr := sRx.OpenFrame(br, nil)
			if rerr != nil {
				return
			}
			switch ft {
			case FrameUDPData:
				if len(payload) > 3 {
					hl := int(payload[0])
					if len(payload) >= 1+hl+2 {
						h := string(payload[1 : 1+hl])
						p := int(binary.BigEndian.Uint16(payload[1+hl : 3+hl]))
						d := string(payload[3+hl:])
						srvGotCh <- srvUDP{host: h, port: p, data: d}

						// Simulate remote Discord media server IP echoing back RTP packet.
						replyHost := "162.159.130.233"
						ack := "echo:" + d
						reply := make([]byte, 1+len(replyHost)+2+len(ack))
						reply[0] = byte(len(replyHost))
						copy(reply[1:], replyHost)
						binary.BigEndian.PutUint16(reply[1+len(replyHost):], uint16(p))
						copy(reply[3+len(replyHost):], ack)
						if sealed, serr := sTx.SealFrame(FrameUDPData, sid, reply); serr == nil {
							_, _ = pSrv.Write(sealed)
						}
					}
				}
			case FrameRst:
				srvRstCh <- sid
			}
		}
	}()

	cfg := DefaultEngineConfig()
	cfg.ProxyAll = true
	cfg.Categories["media"] = true
	cfg.RebuildEffectiveRules()
	matcher := NewDomainRuleMatcher(cfg)
	mux := NewMuxManager(cfg, nil)
	defer mux.Close()

	sess := NewClientMuxSession(pCli, bufio.NewReader(pCli), &pwp4ClientCodec{rx: cRx, tx: cTx}, NodeConfig{Name: "VoiceEdge", Host: "10.0.0.2", Port: 443}, LicenseMetadata{})
	mux.mu.Lock()
	mux.sessions["ai"] = sess
	mux.mu.Unlock()

	tunOutCh := make(chan []byte, 8)
	proc := NewTUNPacketProcessor(TUNOptions{
		ClassifyFn: func(host string) RuleAction {
			return matcher.Classify(host)
		},
		Mux: mux,
		IsDirectIPFn: func(ip net.IP) bool {
			return ip != nil && ip.String() == "77.88.55.80"
		},
	}, net.IPv4(198, 18, 0, 1), 40002, func(pkt []byte) error {
		tunOutCh <- append([]byte(nil), pkt...)
		return nil
	})
	defer proc.Close()

	// Assign FakeIP to a Discord Voice domain and send raw IPv4/UDP voice datagram.
	voiceFakeIP := proc.FakeIP.Assign("bucharest1234.discord.media")
	clientIP := net.IPv4(198, 18, 0, 1)
	voicePkt := buildIPv4UDPPacket(clientIP, voiceFakeIP, 50123, 50001, []byte("opus-rtp-frame"))
	proc.ProcessPacket(voicePkt)

	select {
	case got := <-srvGotCh:
		if got.host != "bucharest1234.discord.media" || got.port != 50001 || got.data != "opus-rtp-frame" {
			t.Fatalf("server received unexpected FrameUDPData: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for FrameUDPData on mock server")
	}

	select {
	case replyPkt := <-tunOutCh:
		verifyIPv4PacketChecksums(t, replyPkt)
		if gotSrc := net.IP(replyPkt[12:16]).String(); gotSrc != voiceFakeIP.String() {
			t.Fatalf("reply srcIP = %s, want FakeIP %s", gotSrc, voiceFakeIP.String())
		}
		if gotDst := net.IP(replyPkt[16:20]).String(); gotDst != clientIP.String() {
			t.Fatalf("reply dstIP = %s, want %s", gotDst, clientIP.String())
		}
		if gotSPort := int(binary.BigEndian.Uint16(replyPkt[20:22])); gotSPort != 50001 {
			t.Fatalf("reply srcPort = %d, want 50001", gotSPort)
		}
		if gotDPort := int(binary.BigEndian.Uint16(replyPkt[22:24])); gotDPort != 50123 {
			t.Fatalf("reply dstPort = %d, want 50123", gotDPort)
		}
		if gotBody := string(replyPkt[28:]); gotBody != "echo:opus-rtp-frame" {
			t.Fatalf("reply UDP payload = %q, want %q", gotBody, "echo:opus-rtp-frame")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for injected TUN IPv4/UDP reply packet")
	}

	// Also verify raw-IP UDP flow (e.g., Discord signaling IP) + IsDirectIPFn bypass.
	rawVoiceIP := net.IPv4(66, 22, 196, 10)
	rawPkt := buildIPv4UDPPacket(clientIP, rawVoiceIP, 50222, 50002, []byte("voice-raw-ip"))
	proc.ProcessPacket(rawPkt)
	select {
	case got := <-srvGotCh:
		if got.host != "66.22.196.10" || got.port != 50002 || got.data != "voice-raw-ip" {
			t.Fatalf("unexpected raw-IP FrameUDPData: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for raw-IP FrameUDPData")
	}
	select {
	case <-tunOutCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for raw-IP UDP reply")
	}

	if proc.UDPFlowCount() != 2 {
		t.Fatalf("expected 2 active UDP flows, got %d", proc.UDPFlowCount())
	}

	// Trigger 60s idle GC deterministically and verify UnregisterUDPHandler sends FrameRst.
	evicted := proc.gcIdleUDPFlows(time.Now().Add(61*time.Second), DefaultTUNUDPIdleTimeout)
	if evicted != 2 || proc.UDPFlowCount() != 0 {
		t.Fatalf("expected 2 evicted flows and 0 remaining, got evicted=%d remaining=%d", evicted, proc.UDPFlowCount())
	}
	for i := 0; i < 2; i++ {
		select {
		case <-srvRstCh:
		case <-time.After(2 * time.Second):
			t.Fatalf("expected FrameRst #%d sent to mux server after UDP idle GC", i+1)
		}
	}
}

func TestTUNMalformedPacketCorpusZeroPanics(t *testing.T) {
	proc := NewTUNPacketProcessor(TUNOptions{
		ClassifyFn: func(host string) RuleAction {
			return RuleAction{Action: "PROXY", Rule: "test", Role: "ai"}
		},
	}, net.IPv4(198, 18, 0, 1), 40003, func(pkt []byte) error {
		return nil
	})
	defer proc.Close()

	corpus := [][]byte{
		nil,
		{},
		{0x45},
		{0x60, 0, 0, 0}, // IPv6 prefix
		make([]byte, 19),
		make([]byte, 20),
		make([]byte, 40),
		// IHL=15 (60 bytes) in a 24-byte slice
		func() []byte {
			b := make([]byte, 24)
			b[0] = 0x4F
			binary.BigEndian.PutUint16(b[2:4], 24)
			b[9] = 6
			return b
		}(),
		// TotalLen > len(pkt)
		func() []byte {
			b := make([]byte, 28)
			b[0] = 0x45
			binary.BigEndian.PutUint16(b[2:4], 1500)
			b[9] = 17
			return b
		}(),
		// UDP Length < 8 and > TotalLen
		func() []byte {
			b := make([]byte, 32)
			b[0] = 0x45
			binary.BigEndian.PutUint16(b[2:4], 32)
			b[9] = 17
			binary.BigEndian.PutUint16(b[24:26], 4)
			return b
		}(),
		// Truncated DNS query to :53 with bad compression loop pointer 0xC0 0x0C
		func() []byte {
			dns := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1}
			return buildIPv4UDPPacket(net.IPv4(198, 18, 0, 1), net.IPv4(198, 18, 0, 2), 55555, 53, dns)
		}(),
	}

	for l := 0; l <= 40; l++ {
		b := make([]byte, l)
		for i := range b {
			b[i] = byte((i*37 + l) & 0xFF)
		}
		corpus = append(corpus, b)
	}

	for idx, pkt := range corpus {
		_ = ComputeIPv4Checksum(pkt)
		_ = ComputeTCPChecksum(pkt)
		_ = ComputeUDPChecksum(pkt)
		_ = SetIPv4Checksum(append([]byte(nil), pkt...))
		_ = SetTCPChecksum(append([]byte(nil), pkt...))
		_ = SetUDPChecksum(append([]byte(nil), pkt...))
		_, _ = proc.NAT.TranslateOutbound(pkt)
		_, _ = proc.NAT.TranslateInbound(pkt)
		proc.ProcessPacket(pkt)
		if idx == 0 && proc.UDPFlowCount() != 0 {
			t.Fatal("nil packet should not create UDP flow")
		}
	}
}

func TestTUNControllerOfflineLifecycle(t *testing.T) {
	ctrl := NewTUNController(TUNOptions{})
	if ctrl.PhysicalDialControl() != nil {
		t.Fatal("PhysicalDialControl must be nil when TUN is inactive")
	}
	st := ctrl.Status()
	if st.Active || st.Enabled || st.AdapterName != TUNAdapterName {
		t.Fatalf("unexpected initial TUNStatusSnapshot: %+v", st)
	}
	if err := ctrl.Stop(); err != nil {
		t.Fatalf("Stop on stopped controller returned error: %v", err)
	}
	if st := ctrl.Status(); st.Status != "stopped" {
		t.Fatalf("expected stopped status, got %q", st.Status)
	}
	// On unprivileged test runs (or non-Windows), Start must fail cleanly without panicking.
	if err := ctrl.Start(); err != nil {
		stAfter := ctrl.Status()
		if stAfter.Active || (stAfter.Status != "admin_required" && stAfter.Status != "unsupported" && !strings.Contains(stAfter.Status, "error")) {
			t.Fatalf("unexpected status after failed Start: %+v (err=%v)", stAfter, err)
		}
		if ctrl.PhysicalDialControl() != nil {
			t.Fatal("PhysicalDialControl must remain nil after failed Start")
		}
	} else {
		_ = ctrl.Stop()
	}
}

func TestTUNUDP443QUICEmitsICMPPortUnreachableWithoutUDPFlow(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.Categories["media"] = true
	cfg.RebuildEffectiveRules()
	matcher := NewDomainRuleMatcher(cfg)

	outCh := make(chan []byte, 4)
	proc := NewTUNPacketProcessor(TUNOptions{
		ClassifyFn: func(host string) RuleAction {
			return matcher.Classify(host)
		},
	}, net.IPv4(198, 18, 0, 1), 40004, func(pkt []byte) error {
		outCh <- append([]byte(nil), pkt...)
		return nil
	})
	defer proc.Close()

	ytFakeIP := proc.FakeIP.Assign("rr1---sn-4g5ednsd.googlevideo.com")
	clientIP := net.IPv4(198, 18, 0, 1)
	quicPkt := buildIPv4UDPPacket(clientIP, ytFakeIP, 55001, 443, []byte("quic-initial-chlo"))
	proc.ProcessPacket(quicPkt)

	if proc.UDPFlowCount() != 0 {
		t.Fatalf("expected QUIC UDP :443 to NOT allocate UDP flow, got %d", proc.UDPFlowCount())
	}

	select {
	case icmpPkt := <-outCh:
		if len(icmpPkt) < 28 {
			t.Fatalf("ICMP packet too short: %d", len(icmpPkt))
		}
		if icmpPkt[0]>>4 != 4 || icmpPkt[9] != 1 {
			t.Fatalf("expected IPv4 ICMP protocol=1, got ver=%d proto=%d", icmpPkt[0]>>4, icmpPkt[9])
		}
		if rawOnesComplementSum(icmpPkt[:20]) != 0xFFFF {
			t.Fatalf("invalid IPv4 header checksum on ICMP packet")
		}
		if icmpPkt[20] != 3 || icmpPkt[21] != 3 {
			t.Fatalf("expected ICMP Type 3 Code 3 (Port Unreachable), got Type=%d Code=%d", icmpPkt[20], icmpPkt[21])
		}
		if rawOnesComplementSum(icmpPkt[20:]) != 0xFFFF {
			t.Fatalf("invalid ICMP checksum on Port Unreachable packet")
		}
		if gotSrc := net.IP(icmpPkt[12:16]).String(); gotSrc != ytFakeIP.String() {
			t.Fatalf("ICMP srcIP = %s, want %s", gotSrc, ytFakeIP.String())
		}
		if gotDst := net.IP(icmpPkt[16:20]).String(); gotDst != clientIP.String() {
			t.Fatalf("ICMP dstIP = %s, want %s", gotDst, clientIP.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ICMPv4 Port Unreachable packet on UDP :443 QUIC")
	}
}

func TestTUNRawIPDiscordVoiceAndBrowserDoHQUICAndSNI(t *testing.T) {
	pCli, pSrv := net.Pipe()
	defer pSrv.Close()

	mat, err := DerivePWP4KeyMaterial("tun-voice-secret", "cli", "srv")
	if err != nil {
		t.Fatalf("DerivePWP4KeyMaterial: %v", err)
	}
	cTx, _ := newPWP4Cipher(mat[0:32], mat[64:80])
	cRx, _ := newPWP4Cipher(mat[32:64], mat[80:96])
	sRx, _ := newPWP4Cipher(mat[0:32], mat[64:80])

	type srvUDP struct {
		host    string
		port    int
		payload []byte
	}
	srvGotCh := make(chan srvUDP, 8)
	go func() {
		br := bufio.NewReader(pSrv)
		for {
			ft, _, payload, _, rerr := sRx.OpenFrame(br, nil)
			if rerr != nil {
				return
			}
			if ft == FrameUDPData && len(payload) > 3 {
				hl := int(payload[0])
				if len(payload) >= 1+hl+2 {
					h := string(payload[1 : 1+hl])
					p := int(binary.BigEndian.Uint16(payload[1+hl : 3+hl]))
					d := append([]byte(nil), payload[3+hl:]...)
					srvGotCh <- srvUDP{host: h, port: p, payload: d}
				}
			}
		}
	}()

	cfg := DefaultEngineConfig()
	cfg.ProxyAll = false
	cfg.Categories = map[string]bool{"antigravity": true, "media": true}
	cfg.RebuildEffectiveRules()
	matcher := NewDomainRuleMatcher(cfg)
	mux := NewMuxManager(cfg, nil)
	defer mux.Close()

	sess := NewClientMuxSession(pCli, bufio.NewReader(pCli), &pwp4ClientCodec{rx: cRx, tx: cTx}, NodeConfig{Name: "VoiceEdge", Host: "10.0.0.2", Port: 443}, LicenseMetadata{})
	mux.mu.Lock()
	mux.sessions["media"] = sess
	mux.mu.Unlock()

	outCh := make(chan []byte, 8)
	proc := NewTUNPacketProcessor(TUNOptions{
		ClassifyFn: func(host string) RuleAction {
			return matcher.Classify(host)
		},
		IsDirectIPFn: func(ip net.IP) bool {
			return ip != nil && ip.String() == "77.88.55.80"
		},
		AllowRawVoiceUDPFn: matcher.AllowsRawVoiceUDP,
		Mux:                mux,
	}, net.IPv4(198, 18, 0, 1), 40005, func(pkt []byte) error {
		outCh <- append([]byte(nil), pkt...)
		return nil
	})
	defer proc.Close()

	clientIP := net.IPv4(198, 18, 0, 1)
	relayIP := net.IPv4(138, 199, 36, 10)

	// 1) Discord IP Discovery (74 bytes: type 0x0001, len 0x0046) + subsequent raw SRTP/keepalive to non-CIDR relay IP
	disc := make([]byte, 74)
	disc[0] = 0x00
	disc[1] = 0x01
	binary.BigEndian.PutUint16(disc[2:4], 70)
	binary.BigEndian.PutUint32(disc[4:8], 0x11223344)
	proc.ProcessPacket(buildIPv4UDPPacket(clientIP, relayIP, 55111, 50018, disc))

	srtpKeepalive := []byte("keepalive-after-discovery")
	proc.ProcessPacket(buildIPv4UDPPacket(clientIP, relayIP, 55111, 50018, srtpKeepalive))

	for i := 0; i < 2; i++ {
		select {
		case got := <-srvGotCh:
			if got.host != "138.199.36.10" || got.port != 50018 {
				t.Fatalf("packet #%d routed to unexpected target %+v", i+1, got)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for Discord voice FrameUDPData #%d", i+1)
		}
	}

	// 2) Random BitTorrent DHT UDP must NOT trigger raw voice promotion
	dht := []byte("d1:ad2:id20:01234567890123456789e1:q4:ping1:t2:aa1:y1:qe")
	if IsDiscordOrRTCVoiceUDP(51413, dht) {
		t.Fatal("expected BitTorrent DHT UDP payload not to match IsDiscordOrRTCVoiceUDP")
	}

	// 3) Browser DoH QUIC UDP :443 to real foreign IP emits ICMP Port Unreachable, while RU IP does not
	ruQUIC := buildIPv4UDPPacket(clientIP, net.IPv4(77, 88, 55, 80), 55112, 443, []byte("ru-quic"))
	proc.ProcessPacket(ruQUIC)

	dohQUIC := buildIPv4UDPPacket(clientIP, net.IPv4(142, 250, 74, 110), 55113, 443, []byte("yt-doh-quic"))
	proc.ProcessPacket(dohQUIC)

	select {
	case icmpPkt := <-outCh:
		if icmpPkt[9] != 1 || icmpPkt[20] != 3 || icmpPkt[21] != 3 {
			t.Fatalf("expected ICMP Port Unreachable, got proto=%d type=%d code=%d", icmpPkt[9], icmpPkt[20], icmpPkt[21])
		}
		if gotSrc := net.IP(icmpPkt[12:16]).String(); gotSrc != "142.250.74.110" {
			t.Fatalf("expected ICMP srcIP=142.250.74.110 (DoH foreign IP, not RU), got %s", gotSrc)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ICMP Port Unreachable on Browser DoH UDP :443")
	}

	// 4) TLS ClientHello SNI peek + lossless byte replay + ECH cover check
	if !IsECHCoverDomain("cloudflare-ech.com") || !IsECHCoverDomain("sub.cloudflare-ech.com") {
		t.Fatal("expected IsECHCoverDomain true for cloudflare-ech.com")
	}
	if IsECHCoverDomain("rr3---sn-4g5e.googlevideo.com") {
		t.Fatal("expected IsECHCoverDomain false for googlevideo.com")
	}

	cert, pool, _, _ := generateTestCert(t, "rr3---sn-4g5e.googlevideo.com")
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	srvDone := make(chan string, 1)
	go func() {
		peekedSNI, replay := PeekConnTLSClientHelloSNI(c2, 2*time.Second)
		tlsSrv := tls.Server(replay, &tls.Config{Certificates: []tls.Certificate{cert}})
		if herr := tlsSrv.Handshake(); herr != nil {
			srvDone <- "handshake_err:" + herr.Error()
			return
		}
		_ = tlsSrv.Close()
		srvDone <- peekedSNI
	}()

	tlsCli := tls.Client(c1, &tls.Config{
		ServerName: "rr3---sn-4g5e.googlevideo.com",
		RootCAs:    pool,
	})
	_ = tlsCli.Handshake()
	_ = tlsCli.Close()

	select {
	case gotSNI := <-srvDone:
		if gotSNI != "rr3---sn-4g5e.googlevideo.com" {
			t.Fatalf("PeekConnTLSClientHelloSNI = %q, want rr3---sn-4g5e.googlevideo.com", gotSNI)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for TLS handshake via PeekConnTLSClientHelloSNI replayConn")
	}
}
