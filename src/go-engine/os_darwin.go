//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// FindWSLBridgeIP returns empty on macOS (WSL2 bridge is Windows-only).
func FindWSLBridgeIP() (string, error) {
	return "", nil
}

// ListActiveTCPSockets parses lsof -nP -iTCP -F pcn on macOS.
func ListActiveTCPSockets() []SocketProcessInfo {
	cmd := exec.Command("lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pcn")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var res []SocketProcessInfo
	curPID := 0
	curProc := ""
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		tag, val := line[0], line[1:]
		switch tag {
		case 'p':
			curPID, _ = strconv.Atoi(strings.TrimSpace(val))
			curProc = ""
		case 'c':
			curProc = strings.TrimSpace(val)
		case 'n':
			parts := strings.SplitN(val, "->", 2)
			if len(parts) != 2 {
				continue
			}
			lip, lport := splitHostPortLenient(parts[0])
			rip, rport := splitHostPortLenient(parts[1])
			if lport > 0 {
				res = append(res, SocketProcessInfo{
					PID:        curPID,
					Process:    curProc,
					LocalAddr:  lip,
					LocalPort:  lport,
					RemoteIP:   rip,
					RemotePort: rport,
					State:      "ESTABLISHED",
				})
			}
		}
	}
	return res
}

func splitHostPortLenient(s string) (string, int) {
	idx := strings.LastIndexByte(s, ':')
	if idx <= 0 {
		return s, 0
	}
	p, err := strconv.Atoi(strings.TrimSpace(s[idx+1:]))
	if err != nil {
		return s[:idx], 0
	}
	return strings.Trim(s[:idx], "[]"), p
}

// ConfigureSystemProxy configures macOS Auto Proxy URL across active network services
// and persists rollback state in ~/.config/pixeltunnel/proxy_state.json.
func ConfigureSystemProxy(pacURL string, httpPort int, headless bool) error {
	if headless {
		return nil
	}
	// Rollback any leftover crashed session first
	if st, err := readProxyRollbackState(); err == nil && st.Managed {
		_ = RollbackSystemProxy(false)
	}

	svcs, err := listMacNetworkServices()
	if err != nil {
		return err
	}

	st := &ProxyRollbackState{
		Managed:         true,
		OS:              "darwin",
		PACURL:          pacURL,
		Services:        svcs,
		PrevAutoProxyOn: make(map[string]bool),
		PrevAutoURL:     make(map[string]string),
	}

	for _, svc := range svcs {
		out, gErr := exec.Command("networksetup", "-getautoproxyurl", svc).Output()
		if gErr == nil {
			for _, ln := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(ln, "URL:") {
					u := strings.TrimSpace(strings.TrimPrefix(ln, "URL:"))
					if u != "(null)" {
						st.PrevAutoURL[svc] = u
					}
				} else if strings.HasPrefix(ln, "Enabled:") {
					v := strings.TrimSpace(strings.TrimPrefix(ln, "Enabled:"))
					st.PrevAutoProxyOn[svc] = strings.EqualFold(v, "Yes")
				}
			}
		}
	}
	_ = writeProxyRollbackState(st)

	for _, svc := range svcs {
		_ = exec.Command("networksetup", "-setautoproxyurl", svc, pacURL).Run()
		_ = exec.Command("networksetup", "-setautoproxystate", svc, "on").Run()
	}
	_ = exec.Command("launchctl", "setenv", "AG_LS_PROXY", fmt.Sprintf("http://127.0.0.1:%d", httpPort)).Run()
	return nil
}

// RollbackSystemProxy restores macOS networksetup auto proxy state from proxy_state.json.
func RollbackSystemProxy(headless bool) error {
	if headless {
		return nil
	}
	st, err := readProxyRollbackState()
	if err != nil || !st.Managed {
		_ = exec.Command("launchctl", "unsetenv", "AG_LS_PROXY").Run()
		return nil
	}
	for _, svc := range st.Services {
		if prevURL := st.PrevAutoURL[svc]; prevURL != "" && !strings.Contains(prevURL, "127.0.0.1") {
			_ = exec.Command("networksetup", "-setautoproxyurl", svc, prevURL).Run()
		}
		if st.PrevAutoProxyOn[svc] && !strings.Contains(st.PrevAutoURL[svc], "127.0.0.1") {
			_ = exec.Command("networksetup", "-setautoproxystate", svc, "on").Run()
		} else {
			_ = exec.Command("networksetup", "-setautoproxystate", svc, "off").Run()
		}
	}
	_ = exec.Command("launchctl", "unsetenv", "AG_LS_PROXY").Run()
	st.Managed = false
	return writeProxyRollbackState(st)
}

// HealIDEConfigurations updates Antigravity and Cursor User/settings.json on macOS.
func HealIDEConfigurations(httpPort int, enable bool, headless bool) {
	if headless {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	appSupport := filepath.Join(home, "Library", "Application Support")
	for _, ide := range []string{"Antigravity", "Cursor"} {
		_ = patchIDESettingsFile(filepath.Join(appSupport, ide, "User", "settings.json"), httpPort, enable)
	}
}

func listMacNetworkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, err
	}
	var svcs []string
	for i, ln := range strings.Split(string(out), "\n") {
		ln = strings.TrimSpace(ln)
		if i == 0 || ln == "" || strings.HasPrefix(ln, "*") || strings.HasPrefix(ln, "An asterisk") {
			continue
		}
		svcs = append(svcs, ln)
	}
	return svcs, nil
}
