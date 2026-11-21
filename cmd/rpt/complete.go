package main

import (
	"bytes"
	"context"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/astr4liteEx/rpt/internal/plugin"
	"github.com/astr4liteEx/rpt/internal/report"
)

const noFiles = cobra.ShellCompDirectiveNoFileComp

// withModel completes from the report, or offers nothing when there is
// none in reach.
func (e *env) withModel(f func(m *report.Model) []string) ([]string, cobra.ShellCompDirective) {
	m, err := e.load()
	if err != nil {
		return nil, noFiles
	}
	defer m.Close()
	return f(m), noFiles
}

func docIDs(m *report.Model, k *report.Kind) []string {
	var out []string
	for _, d := range m.Docs(k) {
		if d.Err == nil && d.ID != "" {
			out = append(out, d.ID+"\t"+d.Title)
		}
	}
	return out
}

func scopeIDs(m *report.Model) []string {
	var out []string
	for _, r := range m.Scope.Rows {
		out = append(out, r.ID+"\t"+r.Host)
	}
	return out
}

// completeIDs completes the IDs of kind k not already given.
func (e *env) completeIDs(k *report.Kind) cobra.CompletionFunc {
	return func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		return e.withModel(func(m *report.Model) []string { return without(docIDs(m, k), args) })
	}
}

func (e *env) completeScopeIDs(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	return e.withModel(func(m *report.Model) []string { return without(scopeIDs(m), args) })
}

func (e *env) completeOwners(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	return e.withModel(func(m *report.Model) []string {
		return without(append(docIDs(m, report.FindingKind), docIDs(m, report.PageKind)...), args)
	})
}

func (e *env) completeAnyID(c *cobra.Command, args []string, s string) ([]string, cobra.ShellCompDirective) {
	return e.withModel(func(m *report.Model) []string {
		all := append(docIDs(m, report.FindingKind), docIDs(m, report.PageKind)...)
		return without(append(all, scopeIDs(m)...), args)
	})
}

func (e *env) completeSeverity(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return e.withModel(func(m *report.Model) []string { return m.Config.Severities })
}

// completeDocPath completes a document's ID, then its keys.
func (e *env) completeDocPath(k *report.Kind) cobra.CompletionFunc {
	return func(c *cobra.Command, args []string, s string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return e.completeIDs(k)(c, args, s)
		}
		if len(args) > 1 && c.Name() == "set" {
			if args[1] == "severity" {
				return e.completeSeverity(c, args, s)
			}
			if args[1] == "targets" {
				return e.completeScopeIDs(c, nil, s)
			}
			return nil, noFiles
		}
		return e.withModel(func(m *report.Model) []string {
			keys := []string{"id", "title", "evidence"}
			if k.Sectioned {
				keys = append(keys, "severity", "targets")
				for _, s := range report.FixedSections {
					keys = append(keys, "sections."+s)
				}
			} else {
				keys = append(keys, "body")
			}
			if d, err := m.Get(k, args[0]); err == nil {
				for _, key := range d.Keys() {
					if !slices.Contains(keys, key) {
						keys = append(keys, key)
					}
				}
				for _, s := range d.Sections {
					if !slices.Contains(keys, "sections."+s.Key) {
						keys = append(keys, "sections."+s.Key)
					}
				}
			}
			return without(keys, args[1:])
		})
	}
}

func (e *env) completeScopeColumn(c *cobra.Command, args []string, s string) ([]string, cobra.ShellCompDirective) {
	if len(args) == 0 {
		return e.completeScopeIDs(c, args, s)
	}
	if c.Name() == "set" && len(args) > 1 {
		if args[1] == "protocol" {
			return []string{"tcp", "udp"}, noFiles
		}
		return nil, noFiles
	}
	return e.withModel(func(m *report.Model) []string {
		return without(slices.DeleteFunc(slices.Clone(m.Scope.Header), func(h string) bool { return h == "id" && c.Name() == "unset" }), args[1:])
	})
}

func (e *env) completeConfigPath(c *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 && c.Name() != "unset" {
		if args[0] == "severities" || args[0] == "required_sections" || args[0] == "pages" {
			return e.withModel(func(m *report.Model) []string {
				switch args[0] {
				case "severities":
					return m.Config.Severities
				case "required_sections":
					return report.FixedSections
				}
				return m.PageOrder()
			})
		}
		if strings.HasPrefix(args[0], "rules.") {
			return []string{report.Error, report.Warning}, noFiles
		}
		return nil, noFiles
	}
	return e.withModel(func(m *report.Model) []string {
		keys := []string{"format", "severities", "required_sections", "pages", "required_pages"}
		for _, s := range report.FixedSections {
			keys = append(keys, "sections."+s)
		}
		var more []string
		for r := range report.Rules {
			more = append(more, "rules."+r)
		}
		for _, n := range m.XNames() {
			if n.Noun == "config" {
				more = append(more, n.Name)
			}
		}
		slices.Sort(more)
		return without(append(keys, more...), args)
	})
}

// completeEvidence completes an owner, then its references, then words.
func (e *env) completeEvidence(words ...string) cobra.CompletionFunc {
	return func(c *cobra.Command, args []string, s string) ([]string, cobra.ShellCompDirective) {
		switch len(args) {
		case 0:
			return e.completeOwners(c, args, s)
		case 1:
			return e.withModel(func(m *report.Model) []string {
				d, err := owner(m, args[0])
				if err != nil {
					return nil
				}
				refs, _ := m.Refs(d)
				var out []string
				for _, r := range refs {
					if !slices.Contains(out, r.Ref) {
						out = append(out, r.Ref)
					}
				}
				return out
			})
		case 2:
			return words, noFiles
		}
		return nil, noFiles
	}
}

// completeFromPlugin asks a plugin for completions with cobra's
// __complete protocol, giving up after a second.
func completeFromPlugin(p plugin.Plugin, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.Path, append(append([]string{"__complete"}, args...), toComplete)...)
	cmd.WaitDelay = 100 * time.Millisecond
	out, err := cmd.Output()
	if err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}
	lines := strings.Split(strings.TrimRight(string(bytes.TrimSpace(out)), "\n"), "\n")
	dir := cobra.ShellCompDirectiveDefault
	if n := len(lines); n > 0 && strings.HasPrefix(lines[n-1], ":") {
		if d, err := strconv.Atoi(lines[n-1][1:]); err == nil {
			dir = cobra.ShellCompDirective(d)
		}
		lines = lines[:n-1]
	}
	return lines, dir
}

// without drops completions already given; a completion may carry a
// tab and its description.
func without(all, given []string) []string {
	var out []string
	for _, a := range all {
		v, _, _ := strings.Cut(a, "\t")
		if !slices.ContainsFunc(given, func(g string) bool { return strings.EqualFold(g, v) }) {
			out = append(out, a)
		}
	}
	return out
}
