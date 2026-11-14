//go:build linux

package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// FindWSLBridgeIP returns empty on Linux host OS (WSL2 bridge listener runs on Windows host).
func FindWSLBridgeIP() (string, error) {
	return "", nil
}

// ListActiveTCPSockets reads /proc/net/tcp and maps socket inodes via /proc/<pid>/fd -> comm.
func ListActiveTCPSockets() []SocketProcessInfo {
	inodeToPID := make(map[string]int)
	pidToName := make(map[int]string)

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	for _, ent := range procEntries {
		if !ent.IsDir() {
			continue
		}
		pid, perr := strconv.Atoi(ent.Name())
		if perr != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join("/proc", ent.Name(), "fd")
		fds, ferr := os.ReadDir(fdDir)
		if ferr != nil {
			continue
		}
		for _, fd := range fds {
			link, lerr := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if lerr != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			inodeToPID[inode] = pid
			if _, ok := pidToName[pid]; !ok {
				if comm, cerr := os.ReadFile(filepath.Join("/proc", ent.Name(), "comm")); cerr == nil {
					pidToName[pid] = strings.TrimSpace(string(comm))
				}
			}
		}
	}

	raw, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil
	}
	var res []SocketProcessInfo
	for i, line := range strings.Split(string(raw), "\n") {
		if i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		// st == "01" is TCP_ESTABLISHED
		if fields[3] != "01" {
			continue
		}
		lip, lport := parseProcHexIPPort(fields[1])
		rip, rport := parseProcHexIPPort(fields[2])
		inode := fields[9]
		pid := inodeToPID[inode]
		res = append(res, SocketProcessInfo{
			PID:        pid,
			Process:    pidToName[pid],
			LocalAddr:  lip,
			LocalPort:  lport,
			RemoteIP:   rip,
			RemotePort: rport,
			State:      "ESTABLISHED",
		})
	}
	return res
}

func parseProcHexIPPort(hexPair string) (string, int) {
	parts := strings.SplitN(hexPair, ":", 2)
	if len(parts) != 2 {
		return "", 0
	}
	ipBytes, err := hex.DecodeString(parts[0])
	if err != nil || len(ipBytes) != 4 {
		return "", 0
	}
	// /proc/net/tcp IPv4 hex is little-endian uint32 on x86_64/arm64
	ip := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0]).String()
	portVal, _ := strconv.ParseInt(parts[1], 16, 32)
	return ip, int(portVal)
}

func hasLinuxDesktopSession() bool {
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" || os.Getenv("DBUS_SESSION_BUS_ADDRESS") != ""
}

func isKDESessionEnv() bool {
	de := strings.ToUpper(os.Getenv("XDG_CURRENT_DESKTOP"))
	sess := strings.ToUpper(os.Getenv("DESKTOP_SESSION"))
	return strings.Contains(de, "KDE") || strings.Contains(de, "PLASMA") ||
		strings.Contains(sess, "KDE") || strings.Contains(sess, "PLASMA") ||
		strings.EqualFold(os.Getenv("KDE_FULL_SESSION"), "true")
}

func isGNOMESessionEnv() bool {
	de := strings.ToUpper(os.Getenv("XDG_CURRENT_DESKTOP"))
	sess := strings.ToUpper(os.Getenv("DESKTOP_SESSION"))
	for _, tok := range []string{"GNOME", "UBUNTU", "CINNAMON", "MATE", "BUDGIE"} {
		if strings.Contains(de, tok) || strings.Contains(sess, tok) {
			return true
		}
	}
	return false
}

func configureGNOMEProxy(pacURL string, st *ProxyRollbackState) bool {
	if _, gErr := exec.LookPath("gsettings"); gErr != nil {
		return false
	}
	prevModeOut, err := exec.Command("gsettings", "get", "org.gnome.system.proxy", "mode").Output()
	if err != nil {
		return false
	}
	prevURLOut, _ := exec.Command("gsettings", "get", "org.gnome.system.proxy", "autoconfig-url").Output()
	st.DesktopEnv = "gnome"
	st.PrevMode = strings.Trim(strings.TrimSpace(string(prevModeOut)), "'")
	st.PrevAutoURL = map[string]string{"gnome": strings.Trim(strings.TrimSpace(string(prevURLOut)), "'")}
	_ = writeProxyRollbackState(st)

	_ = exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "auto").Run()
	_ = exec.Command("gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", pacURL).Run()
	return true
}

func configureKDEProxy(pacURL string, st *ProxyRollbackState) bool {
	for _, ktool := range []string{"kwriteconfig6", "kwriteconfig5"} {
		if _, kErr := exec.LookPath(ktool); kErr != nil {
			continue
		}
		kread := "kreadconfig" + strings.TrimPrefix(ktool, "kwriteconfig")
		prevType := "0"
		prevScript := ""
		if _, rErr := exec.LookPath(kread); rErr == nil {
			if out, err := exec.Command(kread, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType").Output(); err == nil {
				if v := strings.TrimSpace(string(out)); v != "" {
					prevType = v
				}
			}
			if out, err := exec.Command(kread, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "Proxy Config Script").Output(); err == nil {
				prevScript = strings.TrimSpace(string(out))
			}
		}
		st.DesktopEnv = ktool
		st.PrevKdeMode = prevType
		st.PrevAutoURL = map[string]string{"kde": prevScript}
		_ = writeProxyRollbackState(st)

		_ = exec.Command(ktool, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "2").Run()
		_ = exec.Command(ktool, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "Proxy Config Script", pacURL).Run()
		notifyKDEReparse()
		return true
	}
	return false
}

func notifyKDEReparse() {
	if _, err := exec.LookPath("dbus-send"); err == nil {
		_ = exec.Command("dbus-send", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseConfiguration", "string:").Run()
	}
	for _, qb := range []string{"qdbus6", "qdbus"} {
		if _, err := exec.LookPath(qb); err == nil {
			_ = exec.Command(qb, "org.kde.kded6", "/modules/proxyscout", "org.kde.KPAC.reparseConfiguration").Run()
			_ = exec.Command(qb, "org.kde.kded5", "/modules/proxyscout", "org.kde.KPAC.reparseConfiguration").Run()
			break
		}
	}
}

// ConfigureSystemProxy configures GNOME gsettings or KDE kioslaverc when a desktop session exists.
// Safely becomes a no-op on headless Linux servers.
func ConfigureSystemProxy(pacURL string, httpPort int, headless bool) error {
	if headless || !hasLinuxDesktopSession() {
		return nil
	}
	if st, err := readProxyRollbackState(); err == nil && st.Managed {
		_ = RollbackSystemProxy(false)
	}

	if _, err := exec.LookPath("systemctl"); err == nil {
		_ = exec.Command("systemctl", "--user", "set-environment", fmt.Sprintf("AG_LS_PROXY=http://127.0.0.1:%d", httpPort)).Run()
	}

	st := &ProxyRollbackState{
		Managed: true,
		OS:      "linux",
		PACURL:  pacURL,
	}

	if isKDESessionEnv() {
		if configureKDEProxy(pacURL, st) {
			return nil
		}
		_ = configureGNOMEProxy(pacURL, st)
		return nil
	}
	if isGNOMESessionEnv() || strings.TrimSpace(os.Getenv("XDG_CURRENT_DESKTOP")) == "" {
		if configureGNOMEProxy(pacURL, st) {
			return nil
		}
	}
	_ = configureKDEProxy(pacURL, st)
	return nil
}

// RollbackSystemProxy restores GNOME/KDE proxy configuration cleanly.
func RollbackSystemProxy(headless bool) error {
	if headless {
		return nil
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		_ = exec.Command("systemctl", "--user", "unset-environment", "AG_LS_PROXY").Run()
	}
	st, err := readProxyRollbackState()
	if err != nil || !st.Managed {
		return nil
	}
	if st.DesktopEnv == "gnome" {
		if prevURL := st.PrevAutoURL["gnome"]; prevURL != "" && !strings.Contains(prevURL, "127.0.0.1") {
			_ = exec.Command("gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", prevURL).Run()
		} else {
			_ = exec.Command("gsettings", "reset", "org.gnome.system.proxy", "autoconfig-url").Run()
		}
		if st.PrevMode != "" && st.PrevMode != "auto" {
			_ = exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", st.PrevMode).Run()
		} else {
			_ = exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run()
		}
	} else if st.DesktopEnv == "kwriteconfig6" || st.DesktopEnv == "kwriteconfig5" {
		restoredType, restoredScript, deleteScript := resolveKDERollbackSettings(st.PrevKdeMode, st.PrevAutoURL["kde"])
		_ = exec.Command(st.DesktopEnv, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", restoredType).Run()
		if !deleteScript {
			_ = exec.Command(st.DesktopEnv, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "Proxy Config Script", restoredScript).Run()
		} else {
			_ = exec.Command(st.DesktopEnv, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "Proxy Config Script", "--delete").Run()
		}
		notifyKDEReparse()
	}
	st.Managed = false
	return writeProxyRollbackState(st)
}

// HealIDEConfigurations updates ~/.config/{Antigravity,Cursor}/User/settings.json on Linux.
func HealIDEConfigurations(httpPort int, enable bool, headless bool) {
	if headless {
		return
	}
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return
	}
	for _, ide := range []string{"Antigravity", "Cursor"} {
		_ = patchIDESettingsFile(filepath.Join(cfgDir, ide, "User", "settings.json"), httpPort, enable)
	}
}
