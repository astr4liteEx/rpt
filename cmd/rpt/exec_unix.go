//go:build unix

package main

import "syscall"

// execPlugin replaces the rpt process with the plugin, so the plugin owns
// stdin, stdout, stderr, signals and the exit code. It returns only when
// the exec fails.
func execPlugin(bin string, args, env []string) error {
	if err := syscall.Exec(bin, append([]string{bin}, args...), env); err != nil {
		return err
	}
	return errExecReturned
}
