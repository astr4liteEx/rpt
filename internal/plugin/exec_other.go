//go:build !unix

package plugin

import (
	"errors"
	"os"
	"os/exec"
)

// Exec runs the plugin with rpt's standard streams and returns its exit
// code: off unix, rpt can't hand its process over.
var Exec = func(p Plugin, args, env []string) (int, error) {
	cmd := exec.Command(p.Path, args...)
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, os.Stdin, os.Stdout, os.Stderr
	return exitCode(cmd.Run())
}

// relayed are the signals rpt catches while a plugin runs as its child.
var relayed = []os.Signal{os.Interrupt}

// exitCode is the exit code a finished child's Wait error gives.
func exitCode(err error) (int, error) {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return 0, err
}
