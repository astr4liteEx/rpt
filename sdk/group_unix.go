//go:build unix

package sdk

import (
	"os/exec"
	"syscall"
)

// inGroup starts cmd in a process group of its own, which a canceled
// context kills whole.
func inGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		killGroup(cmd.Process.Pid)
		return nil
	}
}

// killGroup kills the process group whose leader was pid.
func killGroup(pid int) { _ = syscall.Kill(-pid, syscall.SIGKILL) }
