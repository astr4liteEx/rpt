//go:build unix

package plugin

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// Exec runs the plugin in place of rpt, its arguments passed on byte for
// byte. It returns only when it couldn't start it.
var Exec = func(p Plugin, args, env []string) (int, error) {
	return 0, syscall.Exec(p.Path, append([]string{p.Path}, args...), env)
}

// relayed are the signals rpt catches while a plugin runs as its child.
var relayed = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}

// exitCode is the exit code a finished child's Wait error gives.
func exitCode(err error) (int, error) {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return 0, err
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), nil
	}
	return ee.ExitCode(), nil
}
