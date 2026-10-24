//go:build linux

// Package runner supplies platform-specific child process settings.
package runner

import (
	"os/exec"
	"syscall"
)

// ParentDeathSignal requests an engine safe stop if enigma-web dies.
func ParentDeathSignal(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
