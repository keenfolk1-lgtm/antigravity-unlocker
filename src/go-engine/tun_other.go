//go:build !windows

package main

import (
	"errors"
	"sync"
	"syscall"
)

// TUNController provides cross-platform parity for TUN lifecycle APIs on non-Windows hosts.
type TUNController struct {
	mu     sync.RWMutex
	opts   TUNOptions
	status TUNStatusSnapshot
}

// NewTUNController constructs a TUNController in stopped state.
func NewTUNController(opts TUNOptions) *TUNController {
	return &TUNController{
		opts: opts,
		status: TUNStatusSnapshot{
			Enabled:     false,
			Active:      false,
			Status:      "stopped",
			AdapterName: TUNAdapterName,
		},
	}
}

// Start reports that Wintun L3 TUN is supported on Windows only.
func (c *TUNController) Start() error {
	err := errors.New("TUN mode is supported on Windows only")
	c.mu.Lock()
	c.status.Enabled = false
	c.status.Active = false
	c.status.Status = "unsupported"
	c.status.LastError = err.Error()
	c.mu.Unlock()
	return err
}

// Stop transitions the controller cleanly to stopped state.
func (c *TUNController) Stop() error {
	c.mu.Lock()
	c.status.Enabled = false
	c.status.Active = false
	c.status.Status = "stopped"
	c.status.LastError = ""
	c.mu.Unlock()
	return nil
}

// Status returns the current TUN status snapshot.
func (c *TUNController) Status() TUNStatusSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

// PhysicalDialControl returns nil on non-Windows platforms where TUN is inactive.
func (c *TUNController) PhysicalDialControl() func(network, address string, c syscall.RawConn) error {
	return nil
}
