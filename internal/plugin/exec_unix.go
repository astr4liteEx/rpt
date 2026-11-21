//go:build unix

package plugin

import "syscall"

// Exec runs the plugin in place of rpt, its arguments passed on byte for
// byte. It returns only when it couldn't start it.
var Exec = func(p Plugin, args, env []string) (int, error) {
	return 0, syscall.Exec(p.Path, append([]string{p.Path}, args...), env)
}
