package main

import (
	"encoding/json/v2"
	"fmt"
	"runtime/debug"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

// version is the release tag, written by the release build with
// -ldflags "-X main.version=<tag>". Empty in any other build.
var version string

// versionVerb prints which rpt this is: its version, the record schema
// version it writes and the report format version it reads.
func versionVerb(e *env, args []string) int {
	flags := newFlagSet(e, "version")
	flags.SetOutput(e.stderr)
	jsonFlag := flags.Bool("json", false, "write JSON Lines even on a terminal")
	if err := flags.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if flags.NArg() != 0 {
		return badUsage(e, "version")
	}
	v := sdk.VersionInfo{Kind: "version", Version: versionString(), SchemaVersion: report.SchemaVersion, Format: report.FormatVersion}
	if isTerminal(e.stdout) && !*jsonFlag {
		fmt.Fprintf(e.stdout, "rpt %s (format %d, schema %d)\n", v.Version, v.Format, v.SchemaVersion)
		return cli.ExitOK
	}
	if err := json.MarshalWrite(e.stdout, v); err != nil {
		e.log.Error(err.Error())
		return cli.ExitUsage
	}
	fmt.Fprintln(e.stdout)
	return cli.ExitOK
}

// versionString is the release tag, else the module version go install
// recorded, else "dev".
func versionString() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}
