package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPatchLanguageServerTiersAndProxyVariants(t *testing.T) {
	t.Run("TiersAndP1", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "language_server_linux_x64")
		orig := []byte("hdr\x00ineligible_tiers\x00ineligibleTiers\x00HTTPS_PROXYhttps_proxy\x00ftr")
		if err := os.WriteFile(p, orig, 0755); err != nil {
			t.Fatal(err)
		}

		res := PatchSingleLanguageServerBinary(p, AntigravityPatchOptions{})
		if res.Err != "" || !res.PatchedNow || !res.TiersVerified || !res.ProxyVerified || res.ProxyPatchTag != "P1" {
			t.Fatalf("unexpected patch result: %+v", res)
		}
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(orig) {
			t.Fatalf("file length changed: got %d want %d", len(got), len(orig))
		}
		want := []byte("hdr\x00inexigible_tiers\x00inexigibleTiers\x00AG_LS_PROXYag_ls_proxy\x00ftr")
		if !bytes.Equal(got, want) {
			t.Fatalf("patched bytes mismatch:\n got: %q\nwant: %q", got, want)
		}

		// Idempotency check
		res2 := PatchSingleLanguageServerBinary(p, AntigravityPatchOptions{})
		if !res2.AlreadyPatched || res2.PatchedNow || !res2.TiersVerified || !res2.ProxyVerified {
			t.Fatalf("expected idempotent second run, got %+v", res2)
		}
	})

	t.Run("P2RetryAfter", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "language_server")
		orig := []byte("xx\x00ineligible_tiers\x00retry-afterHTTPS_PROXY\x00retry-afterhttps_proxy\x00yy")
		if err := os.WriteFile(p, orig, 0755); err != nil {
			t.Fatal(err)
		}
		res := PatchSingleLanguageServerBinary(p, AntigravityPatchOptions{})
		if res.Err != "" || !res.PatchedNow || !res.TiersVerified || !res.ProxyVerified || res.ProxyPatchTag != "P2" {
			t.Fatalf("unexpected P2 patch result: %+v", res)
		}
		got, _ := os.ReadFile(p)
		want := []byte("xx\x00inexigible_tiers\x00retry-afterAG_LS_PROXY\x00retry-afterag_ls_proxy\x00yy")
		if !bytes.Equal(got, want) {
			t.Fatalf("P2 mismatch:\n got: %q\nwant: %q", got, want)
		}
	})

	t.Run("P3ContextAndNegativeCases", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "language_server")
		var buf bytes.Buffer
		// Isolated HTTPS_PROXY far (>512B) from any anchor -> must NOT be patched
		buf.WriteString("ISOLATED_START\x00HTTPS_PROXY\x00")
		buf.Write(bytes.Repeat([]byte{'Z'}, 700))
		// Near NO_PROXY anchor: valid standalone HTTPS_PROXY / https_proxy + disallowed MY_HTTPS_PROXY / HTTPS_PROXY=1
		buf.WriteString("ineligible_tiers\x00NO_PROXY\x00HTTPS_PROXY\x00https_proxy\x00MY_HTTPS_PROXY\x00HTTPS_PROXY=1\x00")
		orig := buf.Bytes()
		if err := os.WriteFile(p, orig, 0755); err != nil {
			t.Fatal(err)
		}

		res := PatchSingleLanguageServerBinary(p, AntigravityPatchOptions{})
		if res.Err != "" || !res.PatchedNow || !res.TiersVerified || !res.ProxyVerified || res.ProxyPatchTag != "P3" {
			t.Fatalf("unexpected P3 result: %+v", res)
		}
		got, _ := os.ReadFile(p)
		if !bytes.Contains(got, []byte("ISOLATED_START\x00HTTPS_PROXY\x00")) {
			t.Fatal("isolated HTTPS_PROXY >512B away from anchors must NOT be modified")
		}
		if !bytes.Contains(got, []byte("MY_HTTPS_PROXY")) {
			t.Fatal("MY_HTTPS_PROXY must NOT be modified")
		}
		if !bytes.Contains(got, []byte("HTTPS_PROXY=1")) {
			t.Fatal("HTTPS_PROXY=1 must NOT be modified")
		}
		if !bytes.Contains(got, []byte("NO_PROXY\x00AG_LS_PROXY\x00ag_ls_proxy\x00")) {
			t.Fatalf("expected context-anchored P3 proxy tokens patched, got %q", got)
		}
	})
}

func TestPatchChunkBoundaryScanning(t *testing.T) {
	origChunk := lsScanChunkSize
	lsScanChunkSize = 64
	defer func() { lsScanChunkSize = origChunk }()

	p := filepath.Join(t.TempDir(), "language_server_boundary")
	var buf bytes.Buffer
	// Put "ineligible_tiers" straddling offset 64 (starts at 56)
	buf.Write(bytes.Repeat([]byte{'A'}, 56))
	buf.WriteString("ineligible_tiers") // [56:72]
	// Put "HTTPS_PROXYhttps_proxy" straddling offset 128 (starts at 118)
	buf.Write(bytes.Repeat([]byte{'B'}, 118-buf.Len()))
	buf.WriteString("HTTPS_PROXYhttps_proxy") // [118:140]
	buf.Write(bytes.Repeat([]byte{'C'}, 32))
	orig := buf.Bytes()
	if err := os.WriteFile(p, orig, 0755); err != nil {
		t.Fatal(err)
	}

	res := PatchSingleLanguageServerBinary(p, AntigravityPatchOptions{})
	if res.Err != "" || !res.PatchedNow || !res.TiersVerified || !res.ProxyVerified {
		t.Fatalf("boundary patch failed: %+v", res)
	}
	got, _ := os.ReadFile(p)
	if len(got) != len(orig) {
		t.Fatalf("length changed: %d vs %d", len(got), len(orig))
	}
	if !bytes.Contains(got, []byte("inexigible_tiers")) || bytes.Contains(got, []byte("ineligible_tiers")) {
		t.Fatal("boundary-spanning ineligible_tiers not patched cleanly")
	}
	if !bytes.Contains(got, []byte("AG_LS_PROXYag_ls_proxy")) || bytes.Contains(got, []byte("HTTPS_PROXYhttps_proxy")) {
		t.Fatal("boundary-spanning HTTPS_PROXYhttps_proxy not patched cleanly")
	}
}

func TestPatchCheckOnlyTiersOnlyAndResignRollback(t *testing.T) {
	t.Run("CheckOnlyLeavesFileUntouched", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "language_server")
		orig := []byte("data\x00ineligible_tiers\x00HTTPS_PROXYhttps_proxy\x00end")
		if err := os.WriteFile(p, orig, 0644); err != nil {
			t.Fatal(err)
		}
		res := PatchSingleLanguageServerBinary(p, AntigravityPatchOptions{CheckOnly: true})
		if !res.NeedsPatch || res.PatchedNow || res.TiersVerified || res.ProxyVerified {
			t.Fatalf("unexpected CheckOnly result: %+v", res)
		}
		after, _ := os.ReadFile(p)
		if !bytes.Equal(after, orig) {
			t.Fatal("CheckOnly must not modify file bytes")
		}
	})

	t.Run("TiersOnlyPreservesHTTPSProxy", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "language_server")
		orig := []byte("data\x00ineligibleTiers\x00HTTPS_PROXYhttps_proxy\x00end")
		if err := os.WriteFile(p, orig, 0644); err != nil {
			t.Fatal(err)
		}
		res := PatchSingleLanguageServerBinary(p, AntigravityPatchOptions{TiersOnly: true})
		if res.Err != "" || !res.PatchedNow || !res.TiersVerified || res.ProxyVerified {
			t.Fatalf("unexpected TiersOnly result: %+v", res)
		}
		after, _ := os.ReadFile(p)
		if !bytes.Contains(after, []byte("inexigibleTiers")) || !bytes.Contains(after, []byte("HTTPS_PROXYhttps_proxy")) {
			t.Fatalf("TiersOnly should patch tiers only and leave HTTPS_PROXY intact, got %q", after)
		}
	})

	t.Run("ResignFailureRollsBackCleanly", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "language_server")
		orig := []byte("data\x00ineligible_tiers\x00HTTPS_PROXYhttps_proxy\x00end")
		if err := os.WriteFile(p, orig, 0755); err != nil {
			t.Fatal(err)
		}
		res := PatchSingleLanguageServerBinary(p, AntigravityPatchOptions{
			ResignFunc: func(string) error {
				return errors.New("simulated codesign failure")
			},
		})
		if res.Err == "" || res.PatchedNow {
			t.Fatalf("expected resign error without PatchedNow, got %+v", res)
		}
		after, _ := os.ReadFile(p)
		if !bytes.Equal(after, orig) {
			t.Fatal("resign failure must preserve original binary bytes")
		}
		entries, _ := os.ReadDir(dir)
		for _, ent := range entries {
			if strings.HasPrefix(ent.Name(), ".pixeltunnel-patch-") {
				t.Fatalf("leftover temp file found after resign failure: %s", ent.Name())
			}
		}
	})
}

func captureStdout(fn func()) string {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		fn()
		return ""
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = origStdout
	b, _ := io.ReadAll(r)
	_ = r.Close()
	return string(b)
}

func TestCmdPatchCLIFlagsAndCmdEnvAGLSProxy(t *testing.T) {
	p := filepath.Join(t.TempDir(), "language_server_linux_x64")
	orig := []byte("bin\x00ineligible_tiers\x00HTTPS_PROXYhttps_proxy\x00")
	if err := os.WriteFile(p, orig, 0755); err != nil {
		t.Fatal(err)
	}

	var checkCode int
	checkOut := captureStdout(func() {
		checkCode = runCLI([]string{"patch", "--check", "--path", p})
	})
	if checkCode != 1 || !strings.Contains(checkOut, "NEEDS PATCH") {
		t.Fatalf("expected exit 1 and NEEDS PATCH from --check, got code=%d out=%q", checkCode, checkOut)
	}

	var tiersCode int
	tiersOut := captureStdout(func() {
		tiersCode = runCLI([]string{"patch", "--tiers-only", "--path", p})
	})
	if tiersCode != 0 || !strings.Contains(tiersOut, "PATCHED") {
		t.Fatalf("expected exit 0 and PATCHED from --tiers-only, got code=%d out=%q", tiersCode, tiersOut)
	}
	afterTiers, _ := os.ReadFile(p)
	if !bytes.Contains(afterTiers, []byte("inexigible_tiers")) || !bytes.Contains(afterTiers, []byte("HTTPS_PROXYhttps_proxy")) {
		t.Fatalf("expected --tiers-only to leave proxy unpatched, got %q", afterTiers)
	}

	var fullCode int
	fullOut := captureStdout(func() {
		fullCode = runCLI([]string{"patch", "--path", p})
	})
	if fullCode != 0 || !strings.Contains(fullOut, "PATCHED") {
		t.Fatalf("expected exit 0 and PATCHED from full patch, got code=%d out=%q", fullCode, fullOut)
	}

	var cleanCheckCode int
	cleanOut := captureStdout(func() {
		cleanCheckCode = runCLI([]string{"patch", "--check", "--path", p})
	})
	if cleanCheckCode != 0 || !strings.Contains(cleanOut, "OK") {
		t.Fatalf("expected exit 0 and OK after full patch, got code=%d out=%q", cleanCheckCode, cleanOut)
	}

	var envCode int
	envOut := captureStdout(func() {
		envCode = runCLI([]string{"env"})
	})
	if envCode != 0 || !strings.Contains(envOut, "AG_LS_PROXY") || !strings.Contains(envOut, "HTTPS_PROXY") {
		t.Fatalf("expected AG_LS_PROXY and HTTPS_PROXY in cmdEnv output, got code=%d out=%q", envCode, envOut)
	}
}
