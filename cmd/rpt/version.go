package main

import (
	"encoding/json/v2"
	"fmt"
	"runtime/debug"

	"github.com/astr4liteEx/rpt/internal/cli"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
	"github.com/spf13/pflag"
)

// version is the release tag, written by the release build with
// -ldflags "-X main.version=<tag>". Empty in any other build.
var version string

// versionVerb prints which rpt this is: its version, the record schema
// version it writes and the report format version it reads.
func versionVerb(flags *pflag.FlagSet) runner {
	return func(e *env, args []string) int {
		if len(args) != 0 {
			return usageError(e, "takes no arguments")
		}
		v := sdk.VersionInfo{Kind: "version", Version: versionString(), SchemaVersion: report.SchemaVersion, Format: report.FormatVersion}
		if isTerminal(e.stdout) && !e.json {
			fmt.Fprintf(e.stdout, "rpt %s (format %d, schema %d)\n", v.Version, v.Format, v.SchemaVersion)
			return cli.ExitOK
		}
		if err := json.MarshalWrite(e.stdout, v); err != nil {
			e.log.Error(err.Error())
			return cli.ExitProblems
		}
		fmt.Fprintln(e.stdout)
		return cli.ExitOK
	}
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
