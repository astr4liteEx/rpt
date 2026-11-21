package main

import (
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
var version string

func (e *env) newCommand() *cobra.Command {
	var like string
	var pages bool
	c := &cobra.Command{
		Use:         "new <dir>",
		Short:       "Create an empty report in a new or empty folder",
		Annotations: io_("", "records"),
		Args:        cobra.ExactArgs(1),
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return nil, cobra.ShellCompDirectiveFilterDirs
		},
		RunE: func(_ *cobra.Command, args []string) error {
			if pages && like == "" {
				return usagef("--with-pages goes with --like")
			}
			if err := report.New(args[0], like, pages); err != nil {
				return err
			}
			loc, _ := report.Locate(args[0])
			return e.out.Write(loc)
		},
	}
	c.Flags().StringVar(&like, "like", "", "Copy rpt.yaml and the scope.csv columns from this report")
	c.Flags().BoolVar(&pages, "with-pages", false, "With --like, also copy its pages and their evidence")
	c.RegisterFlagCompletionFunc("like", cobra.FixedCompletions(nil, cobra.ShellCompDirectiveFilterDirs))
	return c
}

func (e *env) lsCommand() *cobra.Command {
	var current bool
	c := &cobra.Command{
		Use:         "ls [dir]",
		Short:       "List the reports at or under a folder, or with --current the one rpt acts on",
		Example:     "  rpt ls [dir]\n  rpt ls --current [--report dir]",
		Annotations: io_("", "records"),
		Args:        cobra.MaximumNArgs(1),
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return nil, cobra.ShellCompDirectiveFilterDirs
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if current && len(args) > 0 || !current && cmd.Flags().Changed("report") {
				return usagef("takes one folder, or --current and no folder; --report goes only with --current")
			}
			var dirs []string
			if current {
				dir, err := e.reportDir()
				if err != nil {
					return err
				}
				dirs = []string{dir}
			} else {
				dir := "."
				if len(args) == 1 {
					dir = args[0]
				}
				found, err := report.Find(dir)
				if err != nil {
					return err
				}
				dirs = found
			}
			var ps []report.Problem
			for _, d := range dirs {
				loc, probs := report.Locate(d)
				for _, p := range probs {
					p.Level = report.Warning // rpt validate is the check
					ps = append(ps, p)
				}
				if err := e.out.Write(loc); err != nil {
					return err
				}
			}
			return e.problems(ps)
		},
	}
	c.Flags().BoolVar(&current, "current", false, "Print the report other commands would act on from here")
	return c
}

func (e *env) versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:         "version",
		Short:       "Print the rpt, record schema and report format versions",
		Annotations: io_("", "records"),
		Args:        cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return e.out.Write(sdk.VersionInfo{Kind: "version", Version: rptVersion(), SchemaVersion: report.SchemaVersion, Format: report.FormatVersion})
		},
	}
}

// rptVersion is the release tag, else the module version, else "dev".
func rptVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}
