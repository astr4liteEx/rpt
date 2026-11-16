package sdk

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"os"
)

// Description is what a plugin prints for --describe: one JSON object on
// one line. rpt plugins shows it; the plugin's name comes from its file
// name (rpt-parse-nuclei is the verb parse-nuclei), not from here.
type Description struct {
	Summary string `json:"summary"`          // one line: what the plugin does
	Usage   string `json:"usage,omitzero"`   // one line, e.g. "rpt parse-nuclei < results.jsonl"
	Version string `json:"version,omitzero"` // the plugin's own version

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Plugin is a plugin program: its description and the function that does
// its work. Run gets the arguments after the verb and its streams, and
// returns the exit code: 0 success, 1 problems in the input, 2 usage.
type Plugin struct {
	Description
	Run func(args []string, stdin io.Reader, stdout, stderr io.Writer) int
}

// Run runs a plugin: it answers a lone --describe argument itself and
// otherwise calls p.Run. It never exits and never touches os.Stdin,
// os.Stdout or os.Stderr, so plugin tests call it directly.
func Run(p Plugin, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "--describe" {
		if err := json.MarshalWrite(stdout, p.Description, json.Deterministic(true)); err != nil {
			fmt.Fprintln(stderr, "describe:", err)
			return 1
		}
		if _, err := io.WriteString(stdout, "\n"); err != nil {
			return 1
		}
		return 0
	}
	return p.Run(args, stdin, stdout, stderr)
}

// Main is the whole of a plugin's main function:
//
//	func main() { sdk.Main(plugin) }
//
// It calls Run with the process's arguments and streams and exits with the
// code it returns. Exiting skips anything deferred in the plugin's main, so
// put cleanup in Plugin.Run, whose defers always run first.
func Main(p Plugin) {
	os.Exit(Run(p, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// Bin is the rpt to call back into, such as `Bin() findings --json`:
// $RPT_BIN when rpt started the plugin, so it gets the same rpt version,
// otherwise "rpt" from PATH. A plugin never requires being started by rpt.
func Bin() string {
	if b := os.Getenv("RPT_BIN"); b != "" {
		return b
	}
	return "rpt"
}
