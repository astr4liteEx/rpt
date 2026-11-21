//go:build unix

package main

import "syscall"

// execPlugin replaces the rpt process with the plugin, so the plugin owns
// stdin, stdout, stderr, signals and the exit code. It returns only when
// the exec fails. It is a variable so the tests, which run rpt in their
// own process, can refuse it: an exec there would replace the test binary
// and end the run early, reporting it passed.
var execPlugin = func(bin string, args, env []string) error {
	if err := syscall.Exec(bin, append([]string{bin}, args...), env); err != nil {
		return err
	}
	return errExecReturned
}
