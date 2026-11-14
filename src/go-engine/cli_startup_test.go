package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHeadlessFastStartupAndAsyncManifestUpdate(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.HTTPPort = 0
	cfg.SOCKSPort = 0
	cfg.EnableWSLBridge = false

	verFile := filepath.Join(t.TempDir(), "manifest_ver.dat")
	manifestRelease := make(chan struct{})
	startedCh := make(chan int, 1)
	stopCh := make(chan struct{})
	doneCh := make(chan int, 1)

	startTime := time.Now()
	go func() {
		code := runStartEngine(startEngineOptions{
			Config:          cfg,
			Headless:        true,
			NoSysProxy:      true,
			WatchStdin:      false, // Bug A fix: detached -H=windowsgui stdin EOF must NOT exit
			Stdin:           bytes.NewReader(nil),
			LocalToken:      "fast-boot-token",
			ManifestVerPath: verFile,
			SkipWarmConnect: true,
			StopCh:          stopCh,
			ManifestFetcher: func(ctx context.Context, _ *DohResolver, _ ManifestVerifierOptions) (*ManifestDocument, string, error) {
				select {
				case <-manifestRelease:
				case <-ctx.Done():
					return nil, "", ctx.Err()
				}
				return &ManifestDocument{
					Ver: 99,
					Nodes: []NodeConfig{
						{
							Name:     "Async-Edge-1",
							Region:   "NL",
							Host:     "198.51.100.10",
							Port:     443,
							SNI:      "ai.pixelstore.space",
							Path:     DefaultPWP3Path,
							PWP4Path: DefaultPWP4Path,
							TLS:      true,
							Mux:      true,
						},
					},
				}, "mock_async", nil
			},
			OnStarted: func(srv *LocalProxyServer) {
				startedCh <- srv.HTTPPort()
			},
		})
		doneCh <- code
	}()

	var httpPort int
	select {
	case httpPort = <-startedCh:
	case code := <-doneCh:
		t.Fatalf("engine exited unexpectedly on EOF stdin with code=%d", code)
	case <-time.After(2 * time.Second):
		close(stopCh)
		t.Fatal("timed out waiting for OnStarted")
	}

	// Bug B fix: HTTP status endpoint must be ready well under 250ms while manifest fetch is stalled.
	client := &http.Client{Timeout: 500 * time.Millisecond}
	var statusBody map[string]any
	ready := false
	var readyAt time.Duration
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(httpPort)+"/__pixelcore/v4/status", nil)
		req.Header.Set("X-Pixel-Local-Token", "fast-boot-token")
		resp, err := client.Do(req)
		if err == nil {
			_ = json.NewDecoder(resp.Body).Decode(&statusBody)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && statusBody["ok"] == true {
				ready = true
				readyAt = time.Since(startTime)
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready || readyAt >= 250*time.Millisecond {
		close(stopCh)
		t.Fatalf("expected /__pixelcore/v4/status HTTP 200 within <250ms while manifest blocks, got ready=%v readyAt=%v body=%v", ready, readyAt, statusBody)
	}

	// Bug A check: confirm engine stays alive even though Stdin was at immediate EOF.
	select {
	case code := <-doneCh:
		t.Fatalf("headless engine must NOT exit on closed stdin when --watch-stdin=false (exited with %d)", code)
	case <-time.After(120 * time.Millisecond):
	}

	// Unblock async manifest fetch and verify /__pixelcore/v4/status reflects manifest_ver=99.
	close(manifestRelease)
	updated := false
	updateDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(updateDeadline) {
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(httpPort)+"/__pixelcore/v4/status", nil)
		req.Header.Set("X-Pixel-Local-Token", "fast-boot-token")
		resp, err := client.Do(req)
		if err == nil {
			var body map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&body)
			_ = resp.Body.Close()
			if v, ok := body["manifest_ver"].(float64); ok && int64(v) == 99 && body["manifest_src"] == "mock_async" {
				updated = true
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !updated {
		close(stopCh)
		t.Fatalf("timed out waiting for async manifest_ver=99 update on /__pixelcore/v4/status")
	}

	close(stopCh)
	select {
	case code := <-doneCh:
		if code != 0 {
			t.Fatalf("expected clean exit code 0, got %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for clean stop")
	}
}

func TestHeadlessWatchStdinOptInExitsOnEOF(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.HTTPPort = 0
	cfg.SOCKSPort = 0
	cfg.EnableWSLBridge = false

	pr, pw := io.Pipe()
	startedCh := make(chan int, 1)
	stopCh := make(chan struct{})
	doneCh := make(chan int, 1)

	go func() {
		code := runStartEngine(startEngineOptions{
			Config:          cfg,
			Headless:        true,
			NoSysProxy:      true,
			WatchStdin:      true,
			Stdin:           pr,
			LocalToken:      "watch-stdin-token",
			ManifestVerPath: filepath.Join(t.TempDir(), "manifest_ver.dat"),
			SkipWarmConnect: true,
			StopCh:          stopCh,
			OnStarted: func(srv *LocalProxyServer) {
				startedCh <- srv.HTTPPort()
			},
		})
		doneCh <- code
	}()

	var httpPort int
	select {
	case httpPort = <-startedCh:
	case <-time.After(2 * time.Second):
		close(stopCh)
		_ = pw.Close()
		t.Fatal("timed out waiting for OnStarted")
	}

	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(httpPort)+"/__pixelcore/v4/status", nil)
	req.Header.Set("X-Pixel-Local-Token", "watch-stdin-token")
	resp, err := (&http.Client{Timeout: time.Second}).Do(req)
	if err != nil {
		close(stopCh)
		_ = pw.Close()
		t.Fatalf("status request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		close(stopCh)
		_ = pw.Close()
		t.Fatalf("expected 200 status before pipe close, got %d", resp.StatusCode)
	}

	// Closing pipe writer must trigger exit when --watch-stdin=true.
	_ = pw.Close()
	select {
	case code := <-doneCh:
		if code != 0 {
			t.Fatalf("expected clean exit code 0 after stdin EOF, got %d", code)
		}
	case <-time.After(2 * time.Second):
		close(stopCh)
		t.Fatal("expected process exit when --watch-stdin=true and stdin pipe closes")
	}
}

func TestLoadConfigBytesStripsUTF8BOM(t *testing.T) {
	rawWithBOM := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"http_port":28890,"socks_port":28891,"preferredRegion":"DE"}`)...)
	cfg, err := LoadConfigBytes(rawWithBOM)
	if err != nil {
		t.Fatalf("expected UTF-8 BOM JSON to parse cleanly, got %v", err)
	}
	if cfg.HTTPPort != 28890 || cfg.SOCKSPort != 28891 || cfg.PreferredRegion != "DE" {
		t.Fatalf("unexpected parsed config from BOM JSON: %+v", cfg)
	}
}

func TestRound2CLIFlagsHelpVersionAndJSONCSettings(t *testing.T) {
	for _, flag := range []string{"--help", "-h", "help", "--version", "-v", "version"} {
		if code := runCLI([]string{flag}); code != 0 {
			t.Fatalf("runCLI(%q) expected exit 0, got %d", flag, code)
		}
	}

	settingsPath := filepath.Join(t.TempDir(), "Antigravity", "User", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0755); err != nil {
		t.Fatal(err)
	}
	jsonc := "// User IDE config\n{\n  /* Keep URL with // intact */\n  \"custom.url\": \"https://example.com/a//b\",\n  \"editor.tabSize\": 4,\n}\n"
	if err := os.WriteFile(settingsPath, []byte(jsonc), 0644); err != nil {
		t.Fatal(err)
	}
	if err := patchIDESettingsFile(settingsPath, 17890, true); err != nil {
		t.Fatalf("patchIDESettingsFile JSONC: %v", err)
	}
	updated, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(updated, &parsed); err != nil {
		t.Fatalf("patched JSON invalid: %v (%s)", err, string(updated))
	}
	if parsed["http.proxy"] != "http://127.0.0.1:17890" || parsed["custom.url"] != "https://example.com/a//b" || !strings.Contains(string(updated), "17890") {
		t.Fatalf("unexpected patched settings: %+v", parsed)
	}
}

func TestLoadConfigBytesNodePixelstoreAndMissingSecretFallback(t *testing.T) {
	// 1. C# active_config.json with node.pixelstore.space:8443 Reality key, no pwpSecret, no nodes.
	rawCluster := []byte(`{
		"http-in": {"port": 17890},
		"socks-in": {"port": 17891},
		"outbounds": [{
			"tag": "proxy",
			"protocol": "vless",
			"settings": {
				"vnext": [{
					"address": "node.pixelstore.space",
					"port": 8443,
					"users": [{"id": "11111111-2222-4333-8444-555555555555"}]
				}]
			},
			"streamSettings": {
				"network": "tcp",
				"security": "reality",
				"tlsSettings": {"serverName": "www.amd.com"}
			}
		}]
	}`)
	cfg, err := LoadConfigBytes(rawCluster)
	if err != nil {
		t.Fatalf("LoadConfigBytes(node.pixelstore.space) failed: %v", err)
	}
	if cfg.ClientUUID != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("expected ClientUUID preserved, got %q", cfg.ClientUUID)
	}
	if cfg.ActiveNode.Port != 443 {
		t.Fatalf("expected legacy Reality port 8443 normalized to 443, got %d", cfg.ActiveNode.Port)
	}
	if cfg.ActiveNode.SNI != DefaultSNI {
		t.Fatalf("expected SNI normalized to %q, got %q", DefaultSNI, cfg.ActiveNode.SNI)
	}
	if cfg.ActiveNode.Secret == "" {
		t.Fatal("expected ActiveNode.Secret populated from cached/embedded manifest, got empty")
	}
	if len(cfg.Nodes) < 2 {
		t.Fatalf("expected fallback cluster Nodes populated, got %d", len(cfg.Nodes))
	}
	hasStandbySE := false
	for i, n := range cfg.Nodes {
		if n.Secret == "" {
			t.Fatalf("fallback node[%d] (%s) has empty Secret", i, n.Name)
		}
		if n.UUID != cfg.ClientUUID {
			t.Fatalf("fallback node[%d] UUID mismatch: got %q want %q", i, n.UUID, cfg.ClientUUID)
		}
		if n.Host == "185.103.103.162" {
			hasStandbySE = true
		}
	}
	if !hasStandbySE {
		t.Fatalf("expected standby SE node 185.103.103.162 in fallback Nodes: %+v", cfg.Nodes)
	}

	// 2. Top-level node.pixelstore.space without pwp_secret or nodes.
	rawTop := []byte(`{"address":"node.pixelstore.space","client_uuid":"22222222-2222-4333-8444-555555555555"}`)
	cfgTop, err := LoadConfigBytes(rawTop)
	if err != nil {
		t.Fatalf("LoadConfigBytes(top-level node.pixelstore.space) failed: %v", err)
	}
	if cfgTop.ActiveNode.Secret == "" || cfgTop.ActiveNode.Port != 443 || len(cfgTop.Nodes) < 2 {
		t.Fatalf("expected valid fallback on top-level node.pixelstore.space, got ActiveNode=%+v nodes=%d", cfgTop.ActiveNode, len(cfgTop.Nodes))
	}

	// 3. Explicit nodes array missing per-node secret on cluster host inherits fallback secret.
	rawNodesNoSecret := []byte(`{
		"address": "node.pixelstore.space",
		"pwp_port": 443,
		"nodes": [
			{"name": "SE-443", "host": "185.103.103.162", "port": 443, "sni": "ai.pixelstore.space", "tls": true, "mux": true}
		]
	}`)
	cfgNodes, err := LoadConfigBytes(rawNodesNoSecret)
	if err != nil {
		t.Fatalf("LoadConfigBytes(nodes missing secret) failed: %v", err)
	}
	if cfgNodes.ActiveNode.Secret == "" || cfgNodes.Nodes[0].Secret == "" {
		t.Fatalf("expected cluster nodes missing secret to inherit fallback secret, got Active=%q Node0=%q", cfgNodes.ActiveNode.Secret, cfgNodes.Nodes[0].Secret)
	}

	// 4. Non-cluster custom endpoint preserves explicit host/port/secret without injecting cluster nodes.
	rawCustom := []byte(`{"address":"10.99.88.77","pwp_port":9443,"pwp_secret":"custom-only"}`)
	cfgCustom, err := LoadConfigBytes(rawCustom)
	if err != nil {
		t.Fatalf("LoadConfigBytes(custom endpoint) failed: %v", err)
	}
	if cfgCustom.ActiveNode.Host != "10.99.88.77" || cfgCustom.ActiveNode.Port != 9443 || cfgCustom.ActiveNode.Secret != "custom-only" || len(cfgCustom.Nodes) != 0 {
		t.Fatalf("expected custom non-cluster endpoint preserved untouched, got Active=%+v nodes=%d", cfgCustom.ActiveNode, len(cfgCustom.Nodes))
	}
}

func TestHeadlessStartupToleratesManifestFetchFailure(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.HTTPPort = 0
	cfg.SOCKSPort = 0
	cfg.EnableWSLBridge = false
	cfg.ApplyFallbackManifestIfNeeded()

	startedCh := make(chan int, 1)
	stopCh := make(chan struct{})
	doneCh := make(chan int, 1)

	go func() {
		doneCh <- runStartEngine(startEngineOptions{
			Config:          cfg,
			Headless:        true,
			NoSysProxy:      true,
			LocalToken:      "fail-tolerant-tok",
			ManifestVerPath: filepath.Join(t.TempDir(), "manifest_ver.dat"),
			SkipWarmConnect: true,
			StopCh:          stopCh,
			ManifestFetcher: func(ctx context.Context, _ *DohResolver, _ ManifestVerifierOptions) (*ManifestDocument, string, error) {
				return nil, "", io.EOF
			},
			OnStarted: func(srv *LocalProxyServer) {
				startedCh <- srv.HTTPPort()
			},
		})
	}()

	var httpPort int
	select {
	case httpPort = <-startedCh:
	case <-time.After(2 * time.Second):
		close(stopCh)
		t.Fatal("timed out waiting for OnStarted")
	}

	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(httpPort)+"/__pixelcore/v4/status", nil)
	req.Header.Set("X-Pixel-Local-Token", "fail-tolerant-tok")
	resp, err := (&http.Client{Timeout: time.Second}).Do(req)
	if err != nil {
		close(stopCh)
		t.Fatalf("status request failed after manifest error: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		close(stopCh)
		t.Fatalf("expected HTTP 200 after manifest fetch failure, got %d", resp.StatusCode)
	}

	close(stopCh)
	select {
	case code := <-doneCh:
		if code != 0 {
			t.Fatalf("expected clean exit 0, got %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for clean stop")
	}
}
