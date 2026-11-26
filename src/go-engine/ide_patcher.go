package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var lsScanChunkSize = 4 * 1024 * 1024

var (
	patTiers1 = []byte("ineligible_tiers")
	repTiers1 = []byte("inexigible_tiers")
	patTiers2 = []byte("ineligibleTiers")
	repTiers2 = []byte("inexigibleTiers")

	patAgLsProxy    = []byte("AG_LS_PROXY")
	patProxyP1      = []byte("HTTPS_PROXYhttps_proxy")
	repProxyP1      = []byte("AG_LS_PROXYag_ls_proxy")
	patProxyP2a     = []byte("retry-afterHTTPS_PROXY")
	repProxyP2a     = []byte("retry-afterAG_LS_PROXY")
	patProxyP2b     = []byte("retry-afterhttps_proxy")
	repProxyP2b     = []byte("retry-afterag_ls_proxy")
	patProxyP3Upper = []byte("HTTPS_PROXY")
	repProxyP3Upper = []byte("AG_LS_PROXY")
	patProxyP3Lower = []byte("https_proxy")
	repProxyP3Lower = []byte("ag_ls_proxy")

	p3ContextAnchors = [][]byte{
		[]byte("HTTP_PROXY"),
		[]byte("http_proxy"),
		[]byte("NO_PROXY"),
		[]byte("no_proxy"),
	}
)

// AntigravityPatchOptions controls discovery, check-only inspection, and binary patching.
type AntigravityPatchOptions struct {
	CheckOnly        bool
	TiersOnly        bool
	RestartProcesses bool
	ExplicitPaths    []string
	ResignFunc       func(string) error
}

// AntigravityBinaryPatchResult describes the inspection or patch outcome for one language_server binary.
type AntigravityBinaryPatchResult struct {
	Path             string `json:"path"`
	TiersVerified    bool   `json:"tiers_verified"`
	ProxyVerified    bool   `json:"proxy_verified"`
	PatchedNow       bool   `json:"patched_now"`
	AlreadyPatched   bool   `json:"already_patched"`
	NeedsPatch       bool   `json:"needs_patch"`
	PermissionDenied bool   `json:"permission_denied"`
	ProxyPatchTag    string `json:"proxy_patch_tag,omitempty"`
	Err              string `json:"error,omitempty"`
}

// AntigravityPatchSummary aggregates patch outcomes across all discovered Antigravity binaries.
type AntigravityPatchSummary struct {
	Found            int                            `json:"found"`
	PatchedNow       int                            `json:"patched_now"`
	Verified         int                            `json:"verified"`
	PermissionDenied int                            `json:"permission_denied"`
	Results          []AntigravityBinaryPatchResult `json:"results,omitempty"`
}

type binaryOffsetPatch struct {
	offsets     []int64
	replacement []byte
}

func scanBinaryForPatternOffsets(filePath string, pattern []byte) ([]int64, error) {
	if len(pattern) == 0 {
		return nil, nil
	}
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	chunkSize := lsScanChunkSize
	if chunkSize <= 0 {
		chunkSize = 4 * 1024 * 1024
	}
	overlap := len(pattern) + 8
	buf := make([]byte, chunkSize+overlap)
	var filePos int64
	carry := 0
	seen := make(map[int64]struct{})
	var results []int64

	for {
		n, rerr := f.Read(buf[carry : carry+chunkSize])
		if n > 0 {
			total := carry + n
			idx := 0
			for idx < total {
				rel := bytes.Index(buf[idx:total], pattern)
				if rel < 0 {
					break
				}
				absOffset := filePos - int64(carry) + int64(idx+rel)
				if _, ok := seen[absOffset]; !ok {
					seen[absOffset] = struct{}{}
					results = append(results, absOffset)
				}
				idx += rel + len(pattern)
			}

			filePos += int64(n)
			if total > overlap {
				copy(buf[:overlap], buf[total-overlap:total])
				carry = overlap
			} else {
				carry = total
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
		if n == 0 {
			break
		}
	}

	return results, nil
}

func isDisallowedProxyAdjacentByte(b byte) bool {
	return b == '_' || b == '=' ||
		(b >= '0' && b <= '9') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z')
}

func filterP3ContextProxyOffsets(filePath string, rawOffsets []int64, patternLen int) []int64 {
	if len(rawOffsets) == 0 || patternLen <= 0 {
		return nil
	}
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil
	}
	fileLen := st.Size()
	winBuf := make([]byte, 1024+patternLen+4)
	seen := make(map[int64]struct{})
	var accepted []int64

	for _, pos := range rawOffsets {
		if pos < 0 || pos+int64(patternLen) > fileLen {
			continue
		}
		if pos > 0 {
			var bPrev [1]byte
			if _, rerr := f.ReadAt(bPrev[:], pos-1); rerr != nil {
				continue
			}
			if isDisallowedProxyAdjacentByte(bPrev[0]) {
				continue
			}
		}
		if pos+int64(patternLen) < fileLen {
			var bNext [1]byte
			if _, rerr := f.ReadAt(bNext[:], pos+int64(patternLen)); rerr != nil {
				continue
			}
			if isDisallowedProxyAdjacentByte(bNext[0]) {
				continue
			}
		}

		winStart := pos - 512
		if winStart < 0 {
			winStart = 0
		}
		winEnd := pos + int64(patternLen) + 512
		if winEnd > fileLen {
			winEnd = fileLen
		}
		winLen := int(winEnd - winStart)
		if winLen <= 0 || winLen > len(winBuf) {
			continue
		}
		n, rerr := f.ReadAt(winBuf[:winLen], winStart)
		if rerr != nil && rerr != io.EOF {
			continue
		}
		slice := winBuf[:n]
		hasAnchor := false
		for _, anchor := range p3ContextAnchors {
			if bytes.Contains(slice, anchor) {
				hasAnchor = true
				break
			}
		}
		if hasAnchor {
			if _, ok := seen[pos]; !ok {
				seen[pos] = struct{}{}
				accepted = append(accepted, pos)
			}
		}
	}
	return accepted
}

func isIgnoredLanguageServerCandidate(path string) bool {
	lower := strings.ToLower(path)
	for _, suf := range []string{".bak", ".old", ".tmp", ".log", ".json", ".js", ".map", ".txt", ".sh", ".so"} {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	return false
}

func resolveAndDedupeBinaryPaths(candidates []string) []string {
	seen := make(map[string]struct{}, len(candidates))
	var out []string
	for _, raw := range candidates {
		p := strings.TrimSpace(raw)
		if p == "" || isIgnoredLanguageServerCandidate(p) {
			continue
		}
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			resolved = filepath.Clean(p)
		}
		if isIgnoredLanguageServerCandidate(resolved) {
			continue
		}
		st, err := os.Stat(resolved)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if _, ok := seen[resolved]; ok {
			continue
		}
		seen[resolved] = struct{}{}
		out = append(out, resolved)
	}
	return out
}

func hasAnyOffsets(filePath string, pattern []byte) (bool, error) {
	offs, err := scanBinaryForPatternOffsets(filePath, pattern)
	if err != nil {
		return false, err
	}
	return len(offs) > 0, nil
}

// PatchSingleLanguageServerBinary inspects and atomically patches a single Antigravity language_server binary.
func PatchSingleLanguageServerBinary(binPath string, opts AntigravityPatchOptions) AntigravityBinaryPatchResult {
	res := AntigravityBinaryPatchResult{Path: binPath}
	if strings.TrimSpace(binPath) == "" {
		res.Err = "empty binary path"
		return res
	}
	st, err := os.Stat(binPath)
	if err != nil {
		res.Err = err.Error()
		if errors.Is(err, os.ErrPermission) {
			res.PermissionDenied = true
		}
		return res
	}
	if st.IsDir() {
		res.Err = "target path is a directory"
		return res
	}

	offTiers1, err := scanBinaryForPatternOffsets(binPath, patTiers1)
	if err != nil {
		res.Err = err.Error()
		if errors.Is(err, os.ErrPermission) {
			res.PermissionDenied = true
		}
		return res
	}
	offTiers2, err := scanBinaryForPatternOffsets(binPath, patTiers2)
	if err != nil {
		res.Err = err.Error()
		if errors.Is(err, os.ErrPermission) {
			res.PermissionDenied = true
		}
		return res
	}
	hasRepTiers1, _ := hasAnyOffsets(binPath, repTiers1)
	hasRepTiers2, _ := hasAnyOffsets(binPath, repTiers2)
	hasAgLsProxyBefore, _ := hasAnyOffsets(binPath, patAgLsProxy)

	var patches []binaryOffsetPatch
	if len(offTiers1) > 0 {
		patches = append(patches, binaryOffsetPatch{offsets: offTiers1, replacement: repTiers1})
	}
	if len(offTiers2) > 0 {
		patches = append(patches, binaryOffsetPatch{offsets: offTiers2, replacement: repTiers2})
	}

	if !opts.TiersOnly && !hasAgLsProxyBefore {
		offP1, _ := scanBinaryForPatternOffsets(binPath, patProxyP1)
		if len(offP1) > 0 {
			patches = append(patches, binaryOffsetPatch{offsets: offP1, replacement: repProxyP1})
			res.ProxyPatchTag = "P1"
		} else {
			offP2a, _ := scanBinaryForPatternOffsets(binPath, patProxyP2a)
			offP2b, _ := scanBinaryForPatternOffsets(binPath, patProxyP2b)
			if len(offP2a) > 0 {
				patches = append(patches, binaryOffsetPatch{offsets: offP2a, replacement: repProxyP2a})
			}
			if len(offP2b) > 0 {
				patches = append(patches, binaryOffsetPatch{offsets: offP2b, replacement: repProxyP2b})
			}
			if len(offP2a) > 0 || len(offP2b) > 0 {
				res.ProxyPatchTag = "P2"
			} else {
				rawP3Upper, _ := scanBinaryForPatternOffsets(binPath, patProxyP3Upper)
				offP3Upper := filterP3ContextProxyOffsets(binPath, rawP3Upper, len(patProxyP3Upper))
				if len(offP3Upper) > 0 {
					patches = append(patches, binaryOffsetPatch{offsets: offP3Upper, replacement: repProxyP3Upper})
				}
				rawP3Lower, _ := scanBinaryForPatternOffsets(binPath, patProxyP3Lower)
				offP3Lower := filterP3ContextProxyOffsets(binPath, rawP3Lower, len(patProxyP3Lower))
				if len(offP3Lower) > 0 {
					patches = append(patches, binaryOffsetPatch{offsets: offP3Lower, replacement: repProxyP3Lower})
				}
				if len(offP3Upper) > 0 || len(offP3Lower) > 0 {
					res.ProxyPatchTag = "P3"
				}
			}
		}
	}

	tiersClean := (hasRepTiers1 || hasRepTiers2) && len(offTiers1) == 0 && len(offTiers2) == 0
	if len(patches) == 0 {
		res.TiersVerified = tiersClean
		res.ProxyVerified = hasAgLsProxyBefore
		res.AlreadyPatched = tiersClean && (hasAgLsProxyBefore || opts.TiersOnly)
		return res
	}

	if opts.CheckOnly {
		res.NeedsPatch = true
		res.TiersVerified = tiersClean
		res.ProxyVerified = hasAgLsProxyBefore
		return res
	}

	dir := filepath.Dir(binPath)
	tmpFile, err := os.CreateTemp(dir, ".pixeltunnel-patch-*")
	if err != nil {
		res.Err = err.Error()
		if errors.Is(err, os.ErrPermission) {
			res.PermissionDenied = true
		}
		return res
	}
	tmpPath := tmpFile.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	srcFile, err := os.Open(binPath)
	if err != nil {
		_ = tmpFile.Close()
		res.Err = err.Error()
		if errors.Is(err, os.ErrPermission) {
			res.PermissionDenied = true
		}
		return res
	}
	copyBuf := make([]byte, 1024*1024)
	_, copyErr := io.CopyBuffer(tmpFile, srcFile, copyBuf)
	_ = srcFile.Close()
	if copyErr != nil {
		_ = tmpFile.Close()
		res.Err = copyErr.Error()
		return res
	}

	for _, p := range patches {
		for _, off := range p.offsets {
			if _, serr := tmpFile.Seek(off, io.SeekStart); serr != nil {
				_ = tmpFile.Close()
				res.Err = serr.Error()
				return res
			}
			if _, werr := tmpFile.Write(p.replacement); werr != nil {
				_ = tmpFile.Close()
				res.Err = werr.Error()
				return res
			}
		}
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		res.Err = err.Error()
		return res
	}
	if err := tmpFile.Chmod(st.Mode().Perm()); err != nil {
		_ = tmpFile.Close()
		res.Err = err.Error()
		return res
	}
	if err := tmpFile.Close(); err != nil {
		res.Err = err.Error()
		return res
	}

	resignFn := opts.ResignFunc
	if resignFn == nil {
		resignFn = ResignPatchedBinary
	}
	if err := resignFn(tmpPath); err != nil {
		res.Err = err.Error()
		return res
	}

	if err := os.Rename(tmpPath, binPath); err != nil {
		res.Err = err.Error()
		if errors.Is(err, os.ErrPermission) {
			res.PermissionDenied = true
		}
		return res
	}
	cleanupTmp = false
	res.PatchedNow = true

	// Independently verify patched bytes on disk
	hasRep1After, _ := hasAnyOffsets(binPath, repTiers1)
	hasRep2After, _ := hasAnyOffsets(binPath, repTiers2)
	hasRem1After, _ := hasAnyOffsets(binPath, patTiers1)
	hasRem2After, _ := hasAnyOffsets(binPath, patTiers2)
	res.TiersVerified = hasRep1After || hasRep2After || (res.PatchedNow && !hasRem1After && !hasRem2After)
	res.ProxyVerified, _ = hasAnyOffsets(binPath, patAgLsProxy)

	if res.PatchedNow && opts.RestartProcesses {
		StopLanguageServerProcessesForPath(binPath)
	}
	return res
}

// PatchAntigravityLanguageServers discovers (or uses ExplicitPaths) and processes all Antigravity language_server binaries.
func PatchAntigravityLanguageServers(opts AntigravityPatchOptions) AntigravityPatchSummary {
	var candidates []string
	if len(opts.ExplicitPaths) > 0 {
		candidates = resolveAndDedupeBinaryPaths(opts.ExplicitPaths)
		if len(candidates) == 0 {
			candidates = opts.ExplicitPaths
		}
	} else {
		candidates = DiscoverAntigravityLanguageServerBinaries()
	}

	summary := AntigravityPatchSummary{
		Found:   len(candidates),
		Results: make([]AntigravityBinaryPatchResult, 0, len(candidates)),
	}

	for _, p := range candidates {
		r := PatchSingleLanguageServerBinary(p, opts)
		summary.Results = append(summary.Results, r)
		if r.PatchedNow {
			summary.PatchedNow++
		}
		if r.TiersVerified && (r.ProxyVerified || opts.TiersOnly) {
			summary.Verified++
		}
		if r.PermissionDenied {
			summary.PermissionDenied++
		}
	}
	return summary
}

// FormatAntigravityPatchHint returns concise operator-facing log lines for startEngine output.
func FormatAntigravityPatchHint(summary AntigravityPatchSummary) string {
	if summary.Found == 0 {
		return ""
	}
	var lines []string
	for _, r := range summary.Results {
		base := filepath.Base(r.Path)
		switch {
		case r.PatchedNow:
			lines = append(lines, fmt.Sprintf("  Antigravity patch : %s patched (%s)", base, r.Path))
		case r.PermissionDenied:
			lines = append(lines, fmt.Sprintf("  Antigravity patch : permission denied for %s", r.Path))
		case r.Err != "":
			lines = append(lines, fmt.Sprintf("  Antigravity patch : error for %s (%s)", base, r.Err))
		case r.AlreadyPatched:
			lines = append(lines, fmt.Sprintf("  Antigravity patch : %s verified OK", base))
		}
	}
	if summary.PermissionDenied > 0 {
		exe := "pixeltunnel"
		if ex, err := os.Executable(); err == nil && strings.TrimSpace(ex) != "" {
			exe = ex
		}
		lines = append(lines, fmt.Sprintf("  Run once with sudo to unlock Antigravity location bypass: sudo %s patch", exe))
	}
	return strings.Join(lines, "\n")
}
