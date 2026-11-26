package main

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"
)

func TestV222VirtualInterfaceFilterAndDeterministicFingerprint(t *testing.T) {
	t.Parallel()

	volatileNames := []string{
		"vEthernet (WSL)",
		"vEthernet (Default Switch)",
		"docker0",
		"br-abc123",
		"veth0a1b2c",
		"Hyper-V Virtual Ethernet Adapter",
		"PixelTUN",
		"wintun",
		"utun4",
		"tailscale0",
		"wg0",
		"Teredo Tunneling Pseudo-Interface",
	}
	for _, name := range volatileNames {
		if !isVirtualOrVolatileInterfaceName(name) {
			t.Fatalf("expected %q to be filtered as virtual/volatile interface", name)
		}
	}

	realNames := []string{"Ethernet", "Wi-Fi", "en0", "eth0", "wlan0"}
	for _, name := range realNames {
		if isVirtualOrVolatileInterfaceName(name) {
			t.Fatalf("expected physical interface %q not to be filtered", name)
		}
	}

	fp1 := formatInterfaceFingerprint([]string{"Wi-Fi=192.168.1.50", "Ethernet=10.0.0.12"})
	fp2 := formatInterfaceFingerprint([]string{"Ethernet=10.0.0.12", "Wi-Fi=192.168.1.50"})
	if fp1 != "Ethernet=10.0.0.12;Wi-Fi=192.168.1.50;" || fp1 != fp2 {
		t.Fatalf("unexpected/non-deterministic fingerprint: fp1=%q fp2=%q", fp1, fp2)
	}
	if empty := formatInterfaceFingerprint(nil); empty != "" {
		t.Fatalf("expected empty fingerprint for nil slice, got %q", empty)
	}
}

func TestV222ActiveRxPreventsFalsePrimaryFailover(t *testing.T) {
	t.Parallel()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	codec := &pwp3Codec{tx: NewPixelStreamCipher("sec", "salt1"), rx: NewPixelStreamCipher("sec", "salt2")}
	sess := NewClientMuxSession(c1, bufio.NewReader(c1), codec, NodeConfig{Name: "Auto-Edge-443"}, LicenseMetadata{})
	defer sess.Close()

	// Fresh RX within 3s grace window must protect active streaming session from ping-timeout teardown.
	sess.lastRxTs.Store(time.Now().Add(-500 * time.Millisecond).UnixNano())
	if shouldClosePrimaryAfterPingFailure(sess, 3*time.Second) {
		t.Fatalf("expected recent RX (<3s) to prevent closing primary session")
	}

	// Stale RX older than 3s grace allows closing stalled session.
	sess.lastRxTs.Store(time.Now().Add(-5 * time.Second).UnixNano())
	if !shouldClosePrimaryAfterPingFailure(sess, 3*time.Second) {
		t.Fatalf("expected stale RX (>=3s) to allow closing primary session")
	}

	// Closed session must always return true.
	_ = sess.Close()
	if !shouldClosePrimaryAfterPingFailure(sess, 3*time.Second) {
		t.Fatalf("expected closed session to return true")
	}
	if !shouldClosePrimaryAfterPingFailure(nil, 3*time.Second) {
		t.Fatalf("expected nil session to return true")
	}
}

func TestV222PingSessionWithRetryBailsOnClosedSession(t *testing.T) {
	t.Parallel()

	cfg := DefaultEngineConfig()
	mgr := NewMuxManager(cfg, nil)
	defer mgr.Close()

	if _, err := mgr.pingSessionWithRetry(nil, 2, 100*time.Millisecond); err != io.ErrClosedPipe {
		t.Fatalf("expected io.ErrClosedPipe for nil session, got %v", err)
	}

	c1, c2 := net.Pipe()
	defer c2.Close()
	codec := &pwp3Codec{tx: NewPixelStreamCipher("sec", "salt1"), rx: NewPixelStreamCipher("sec", "salt2")}
	sess := NewClientMuxSession(c1, bufio.NewReader(c1), codec, NodeConfig{Name: "Auto-Edge-443"}, LicenseMetadata{})
	_ = sess.Close()

	start := time.Now()
	if _, err := mgr.pingSessionWithRetry(sess, 3, 2*time.Second); err != io.ErrClosedPipe {
		t.Fatalf("expected io.ErrClosedPipe for closed session, got %v", err)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatalf("pingSessionWithRetry waited unnecessarily on closed session (%v)", time.Since(start))
	}
}
