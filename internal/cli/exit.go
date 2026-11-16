package cli

import "os"

// Exit codes every rpt verb uses.
const (
	ExitOK           = 0   // clean
	ExitProblems     = 1   // problems in the report
	ExitUsage        = 2   // usage or config error
	ExitPluginFailed = 126 // a plugin failed to start
)

// IsTerminal reports whether f is a terminal, which decides between a
// table and JSON Lines.
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
