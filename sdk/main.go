package sdk

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// Description is what a plugin prints for --describe: one JSON object on
// one line. rpt help shows it; the plugin's name comes from its file
// name (rpt-parse-nuclei is the command parse-nuclei), not from here. Every
// built-in answers --describe the same way.
type Description struct {
	Summary string `json:"summary"`          // one line: what the plugin does
	Usage   string `json:"usage,omitzero"`   // one line, e.g. "rpt parse-nuclei < results.jsonl"
	Version string `json:"version,omitzero"` // the plugin's own version

	// Input and Output name the data the plugin takes and gives: "records"
	// for an rpt JSON Lines stream, otherwise "<format>" or
	// "<format>/<tool>", such as "xml/nessus" or "pdf". Empty is "not said".
	Input  string `json:"input,omitzero"`
	Output string `json:"output,omitzero"`

	// Roles names what the plugin is, so a tool on top of rpt can find,
	// say, every checker: RoleChecker, RoleFilter, RoleWriter,
	// RoleRenderer. A plugin can hold several; empty is "not said".
	Roles []string `json:"roles,omitzero"`

	// Schemas are JSON Schemas (draft 2020-12) for the x- names the plugin
	// owns, which rpt validate checks. Requires says which rpt the plugin
	// works with.
	Schemas  *Schemas  `json:"schemas,omitzero"`
	Requires *Requires `json:"requires,omitzero"`

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Schemas are the JSON Schemas a plugin declares for what it owns, by
// noun. A plugin named <command> owns x-<command> (its config section)
// and the names starting x-<command>- (keys, columns and record kinds); a
// schema for any other name is ignored. A $ref may point inside the
// schema or at one of rpt's schemas by its $id, nowhere else.
type Schemas struct {
	// Finding, Page and Scope map each frontmatter key or scope column to
	// a schema for its value; a scope value is the CSV text.
	Finding map[string]jsontext.Value `json:"finding,omitzero"`
	Page    map[string]jsontext.Value `json:"page,omitzero"`
	Scope   map[string]jsontext.Value `json:"scope,omitzero"`
	// Config is the schema for the plugin's whole x-<command> section of
	// rpt.yaml.
	Config jsontext.Value `json:"config,omitzero"`
	// Kinds maps each x- record kind to a schema for the whole record.
	Kinds map[string]jsontext.Value `json:"kinds,omitzero"`

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Requires lists the rpt versions a plugin works with. A list left out
// fits any; otherwise rpt's own number must be in it.
type Requires struct {
	SchemaVersion []int `json:"schema_version,omitzero"` // record schemas, VersionInfo.SchemaVersion
	Format        []int `json:"format,omitzero"`         // report format, VersionInfo.Format

	// Extra holds any unknown members.
	Extra map[string]jsontext.Value `json:",embed"`
}

// Fits reports whether a plugin requiring r works with an rpt writing
// schemaVersion and reading format.
func (r *Requires) Fits(schemaVersion, format int) bool {
	if r == nil {
		return true
	}
	return (len(r.SchemaVersion) == 0 || slices.Contains(r.SchemaVersion, schemaVersion)) &&
		(len(r.Format) == 0 || slices.Contains(r.Format, format))
}

// The roles a plugin can declare in Description.Roles. Each is a promise
// the protocol's --describe section spells out.
const (
	// RoleChecker emits problem records about the report, exits 1 only
	// when one is an error, and never changes the report.
	RoleChecker = "checker"
	// RoleFilter reads records on stdin and writes records on stdout.
	RoleFilter = "filter"
	// RoleWriter changes the report, only through $RPT_BIN write commands.
	RoleWriter = "writer"
	// RoleRenderer reads a report record and writes a document to a place
	// it's given (a file or folder flag); it never changes the report and
	// writes no records to stdout.
	RoleRenderer = "renderer"
)

// Plugin is a plugin program: its description and the function that does
// its work. Run gets the arguments after the command and its streams, and
// returns the exit code: 0 success, 1 problems in the input, 2 usage.
type Plugin struct {
	Description
	Run func(args []string, stdin io.Reader, stdout, stderr io.Writer) int
	// Complete, if set, gives the candidates for the word being typed,
	// toComplete, after args: each "value" or "value\tdescription". Unset,
	// the shell completes file names.
	Complete func(args []string, toComplete string) []string
}

// Shell completion directives, as cobra's __complete protocol ends its
// answer with ":<directive>".
const (
	completeDefault = 0 // the shell may fall back to file names
	completeNoFiles = 4 // only the candidates given
)

// Run runs a plugin. It answers these itself, doing no work:
//   - a lone --describe: the description, one JSON line;
//   - a lone --help or -h: the usage and summary;
//   - __complete <args...> <word>: shell completion, from p.Complete.
//
// Anything else goes to p.Run. It never exits and never touches os.Stdin,
// os.Stdout or os.Stderr, so plugin tests call it directly.
func Run(p Plugin, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		if p.Usage != "" {
			fmt.Fprintf(stdout, "Usage: %s\n\n", p.Usage)
		}
		fmt.Fprintln(stdout, p.Summary)
		return 0
	}
	if len(args) > 0 && (args[0] == "__complete" || args[0] == "__completeNoDesc") {
		rest := args[1:]
		word := ""
		if len(rest) > 0 {
			rest, word = rest[:len(rest)-1], rest[len(rest)-1]
		}
		directive := completeDefault
		if p.Complete != nil {
			for _, c := range p.Complete(rest, word) {
				if args[0] == "__completeNoDesc" {
					c, _, _ = strings.Cut(c, "\t")
				}
				fmt.Fprintln(stdout, c)
			}
			directive = completeNoFiles
		}
		fmt.Fprintf(stdout, ":%d\n", directive)
		return 0
	}
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

// Bin is the rpt to call back into, such as `Bin() finding get --json`:
// $RPT_BIN when rpt started the plugin, so it gets the same rpt version,
// otherwise "rpt" from PATH. A plugin never requires being started by rpt.
func Bin() string {
	if b := os.Getenv("RPT_BIN"); b != "" {
		return b
	}
	return "rpt"
}
