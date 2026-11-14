package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// SocketProcessInfo represents an active TCP socket owned by a local process.
type SocketProcessInfo struct {
	PID        int    `json:"pid"`
	Process    string `json:"process"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
}

// ProxyRollbackState tracks OS proxy changes so stop/SIGINT/crash always restores clean settings.
type ProxyRollbackState struct {
	Managed         bool              `json:"managed"`
	OS              string            `json:"os"`
	PACURL          string            `json:"pac_url"`
	DesktopEnv      string            `json:"desktop_env,omitempty"`
	Services        []string          `json:"services,omitempty"`
	PrevAutoProxyOn map[string]bool   `json:"prev_autoproxy_on,omitempty"`
	PrevAutoURL     map[string]string `json:"prev_autourl,omitempty"`
	PrevMode        string            `json:"prev_mode,omitempty"`
	PrevKdeMode     string            `json:"prev_kde_mode,omitempty"`
}

func proxyStateFilePath() string {
	return filepath.Join(DefaultStateDir(), "proxy_state.json")
}

func readProxyRollbackState() (*ProxyRollbackState, error) {
	raw, err := os.ReadFile(proxyStateFilePath())
	if err != nil {
		return nil, err
	}
	var st ProxyRollbackState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func writeProxyRollbackState(st *ProxyRollbackState) error {
	p := proxyStateFilePath()
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0600)
}

func isIPIn17216Range(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31
}

// LookupProcessForConnection matches a local TCP client address (e.g. 127.0.0.1:54321) to its owning PID/process.
func LookupProcessForConnection(localAddr net.Addr, targetHTTPPort, targetSOCKSPort int) (int, string) {
	tcpAddr, ok := localAddr.(*net.TCPAddr)
	if !ok || tcpAddr == nil || tcpAddr.Port <= 0 {
		return 0, ""
	}
	socks := ListActiveTCPSockets()
	for _, s := range socks {
		if s.LocalPort == tcpAddr.Port && (s.RemotePort == targetHTTPPort || s.RemotePort == targetSOCKSPort || s.RemotePort == 0) {
			return s.PID, s.Process
		}
	}
	for _, s := range socks {
		if s.LocalPort == tcpAddr.Port {
			return s.PID, s.Process
		}
	}
	return 0, ""
}

// FindIDELeakedSockets scans active non-loopback 443/80 sockets owned by AI IDEs / CLIs
// that are bypassing the local proxy ports.
func FindIDELeakedSockets(httpPort, socksPort int) []SocketProcessInfo {
	ideKeywords := []string{"antigravity", "cursor", "language_server", "claude", "codex", "gemini", "code", "node"}
	all := ListActiveTCPSockets()
	var leaks []SocketProcessInfo
	for _, s := range all {
		procLower := strings.ToLower(s.Process)
		isIDE := false
		for _, kw := range ideKeywords {
			if strings.Contains(procLower, kw) {
				isIDE = true
				break
			}
		}
		if !isIDE {
			continue
		}
		if s.RemotePort != 443 && s.RemotePort != 80 && s.RemotePort != 8443 {
			continue
		}
		ip := net.ParseIP(s.RemoteIP)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		if s.RemotePort == httpPort || s.RemotePort == socksPort {
			continue
		}
		leaks = append(leaks, s)
	}
	return leaks
}

// stripJSONCommentsAndTrailingCommas strips // line comments, /* block */ comments,
// and trailing commas outside string literals so VS Code / Antigravity / Cursor JSONC
// settings.json files can be parsed safely without corrupting URLs inside strings.
func stripJSONCommentsAndTrailingCommas(src []byte) []byte {
	noComments := make([]byte, 0, len(src))
	inStr := false
	escaped := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		if inStr {
			noComments = append(noComments, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			noComments = append(noComments, c)
			continue
		}
		if c == '/' && i+1 < len(src) && src[i+1] == '/' {
			i += 2
			for i < len(src) && src[i] != '\n' {
				i++
			}
			if i < len(src) {
				noComments = append(noComments, '\n')
			}
			continue
		}
		if c == '/' && i+1 < len(src) && src[i+1] == '*' {
			i += 2
			for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			i++
			continue
		}
		noComments = append(noComments, c)
	}

	out := make([]byte, 0, len(noComments))
	inStr = false
	escaped = false
	for i := 0; i < len(noComments); i++ {
		c := noComments[i]
		if inStr {
			out = append(out, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(noComments) && (noComments[j] == ' ' || noComments[j] == '\t' || noComments[j] == '\r' || noComments[j] == '\n') {
				j++
			}
			if j < len(noComments) && (noComments[j] == '}' || noComments[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// patchIDESettingsFile updates Antigravity/Cursor User/settings.json cleanly (supporting JSONC).
func patchIDESettingsFile(settingsPath string, httpPort int, enable bool) error {
	if settingsPath == "" {
		return nil
	}
	var obj map[string]any
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		if !enable {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(settingsPath), 0700); err != nil {
			return err
		}
		obj = make(map[string]any)
	} else {
		if err := json.Unmarshal(raw, &obj); err != nil {
			cleaned := stripJSONCommentsAndTrailingCommas(raw)
			if len(strings.TrimSpace(string(cleaned))) == 0 {
				obj = make(map[string]any)
			} else if err2 := json.Unmarshal(cleaned, &obj); err2 != nil {
				// Avoid overwriting corrupted/unparseable user settings
				return nil
			}
		}
	}
	if obj == nil {
		obj = make(map[string]any)
	}

	isCursor := strings.Contains(strings.ToLower(settingsPath), "cursor")
	if enable {
		obj["http.proxy"] = fmt.Sprintf("http://127.0.0.1:%d", httpPort)
		obj["http.proxySupport"] = "on"
		obj["http.proxyStrictSSL"] = false
		if isCursor {
			obj["cursor.general.disableHttp2"] = true
		}
	} else {
		delete(obj, "http.proxy")
		delete(obj, "http.proxySupport")
		delete(obj, "http.proxyStrictSSL")
		if isCursor {
			delete(obj, "cursor.general.disableHttp2")
		}
	}

	out, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(settingsPath, append(out, '\n'), 0600)
}

func resolveKDERollbackSettings(prevType, prevScript string) (restoredType, restoredScript string, deleteScript bool) {
	t := strings.TrimSpace(prevType)
	s := strings.TrimSpace(prevScript)
	hasExternalPAC := s != "" && !strings.Contains(s, "127.0.0.1")
	if t == "" || (t == "2" && !hasExternalPAC) {
		return "0", "", true
	}
	if hasExternalPAC {
		return t, s, false
	}
	return t, "", true
}
