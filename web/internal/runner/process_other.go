//go:build !linux

package runner

import "os/exec"

// ParentDeathSignal is unavailable on this platform.
func ParentDeathSignal(cmd *exec.Cmd) {}
