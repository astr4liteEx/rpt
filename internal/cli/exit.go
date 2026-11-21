package cli

import "os"

// Exit codes every rpt command uses. Exit 2 is for usage only: wrong
// flags or arguments. Anything that goes wrong after that is exit 1.
const (
	ExitOK           = 0   // clean
	ExitProblems     = 1   // problems in the report or its input, or a failure
	ExitUsage        = 2   // usage error
	ExitPluginFailed = 126 // a plugin failed to start
)

// IsTerminal reports whether f is a terminal, which decides between a
// table and JSON Lines.
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
