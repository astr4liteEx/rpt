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
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return 0, err
}
