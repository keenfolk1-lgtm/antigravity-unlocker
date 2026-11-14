//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modIphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable    = modIphlpapi.NewProc("GetExtendedTcpTable")
	modKernel32                = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess            = modKernel32.NewProc("OpenProcess")
	procQueryFullProcessImageW = modKernel32.NewProc("QueryFullProcessImageNameW")
)

const (
	afInet                  = 2
	tcpTableOwnerPidAll     = 5
	processQueryLimitedInfo = 0x1000
	mibTcpStateEstablished  = 5
)

// FindWSLBridgeIP locates ONLY a vEthernet (WSL) interface IPv4 address in 172.16.0.0/12.
// Never returns 0.0.0.0 or LAN adapter IPs.
func FindWSLBridgeIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if (iface.Flags & net.FlagUp) == 0 {
			continue
		}
		nameLower := strings.ToLower(iface.Name)
		if !strings.Contains(nameLower, "wsl") {
			continue
		}
		addrs, aErr := iface.Addrs()
		if aErr != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil {
				continue
			}
			v4 := ipNet.IP.To4()
			if v4 != nil && isIPIn17216Range(v4) {
				return v4.String(), nil
			}
		}
	}
	return "", errors.New("vEthernet (WSL) 172.16.0.0/12 adapter not found")
}

// ListActiveTCPSockets uses iphlpapi.dll GetExtendedTcpTable (TCP_TABLE_OWNER_PID_ALL)
// to enumerate IPv4 sockets and resolve each PID to its executable basename.
func ListActiveTCPSockets() []SocketProcessInfo {
	var size uint32 = 32 * 1024
	buf := make([]byte, size)
	for attempt := 0; attempt < 3; attempt++ {
		r1, _, _ := procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			uintptr(afInet),
			uintptr(tcpTableOwnerPidAll),
			0,
		)
		if r1 == 0 {
			break
		}
		if r1 == 122 { // ERROR_INSUFFICIENT_BUFFER
			if size > 16*1024*1024 {
				return nil
			}
			buf = make([]byte, size+4096)
			continue
		}
		return nil
	}

	if len(buf) < 4 {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(buf[0:4]))
	const rowSize = 24
	if 4+count*rowSize > len(buf) {
		count = (len(buf) - 4) / rowSize
	}

	pidNameCache := make(map[int]string)
	out := make([]SocketProcessInfo, 0, count)
	for i := 0; i < count; i++ {
		row := buf[4+i*rowSize : 4+(i+1)*rowSize]
		state := binary.LittleEndian.Uint32(row[0:4])
		if state != mibTcpStateEstablished {
			continue
		}
		localIP := net.IPv4(row[4], row[5], row[6], row[7]).String()
		localPort := int(binary.BigEndian.Uint16(row[8:10]))
		remoteIP := net.IPv4(row[12], row[13], row[14], row[15]).String()
		remotePort := int(binary.BigEndian.Uint16(row[16:18]))
		pid := int(binary.LittleEndian.Uint32(row[20:24]))

		procName, cached := pidNameCache[pid]
		if !cached {
			procName = lookupWindowsProcessName(uint32(pid))
			pidNameCache[pid] = procName
		}

		out = append(out, SocketProcessInfo{
			PID:        pid,
			Process:    procName,
			LocalAddr:  localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			State:      "ESTABLISHED",
		})
	}
	return out
}

func lookupWindowsProcessName(pid uint32) string {
	if pid == 0 {
		return "SystemIdle"
	}
	if pid == 4 {
		return "System"
	}
	h, _, _ := procOpenProcess.Call(uintptr(processQueryLimitedInfo), 0, uintptr(pid))
	if h == 0 {
		return ""
	}
	defer syscall.CloseHandle(syscall.Handle(h))

	var utf16Buf [520]uint16
	size := uint32(len(utf16Buf))
	r1, _, _ := procQueryFullProcessImageW.Call(
		h,
		0,
		uintptr(unsafe.Pointer(&utf16Buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r1 == 0 || size == 0 {
		return ""
	}
	fullPath := syscall.UTF16ToString(utf16Buf[:size])
	return filepath.Base(fullPath)
}

// ConfigureSystemProxy is a no-op on Windows: in headless mode C# WPF owns WinInet/UI,
// and standalone Windows CLI users consume explicit HTTP/SOCKS5 ports or `pixeltunnel env`
// without mutating Windows Internet Settings registry keys outside WPF's rollback guard.
func ConfigureSystemProxy(pacURL string, httpPort int, headless bool) error {
	_ = pacURL
	_ = httpPort
	if headless {
		return nil
	}
	return nil
}

// RollbackSystemProxy is a no-op on Windows because ConfigureSystemProxy leaves WinInet
// under C# WPF / NativeUtlsEngineHost lifecycle management.
func RollbackSystemProxy(headless bool) error {
	if headless {
		return nil
	}
	return nil
}

// HealIDEConfigurations is skipped on Windows because PixelTunnelNext.cs manages IDE
// proxy config integration directly when WPF launches the engine.
func HealIDEConfigurations(httpPort int, enable bool, headless bool) {
	_ = httpPort
	_ = enable
	if headless {
		return
	}
}
