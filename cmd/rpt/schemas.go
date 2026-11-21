package main

import (
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/astr4liteEx/rpt/internal/pluginschema"
	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/sdk"
)

// rulePluginSchema is the rule for a value that breaks the schema its
// owning plugin declares, and for the plugins and schemas rpt couldn't use.
const rulePluginSchema = "pluginSchema"

// reportLevel is the path of a problem about the report as a whole.
const reportLevel = "."

// An xName is one use of an x- name: a frontmatter key, scope column,
// config section or record kind, with its value and where it is.
type xName struct {
	noun, name string // noun: finding, page, scope, config or kinds
	path       string
	line       int
	value      jsontext.Value
}

// gatherNames lists the x- names r uses, then the x- record kinds in recs.
func gatherNames(r *report.Report, recs []sdk.Rec) []xName {
	var out []xName
	plugin := func(k string) bool { return strings.HasPrefix(k, "x-") }
	fs, _ := r.FindingsWithLines()
	for _, f := range fs {
		if f.Lines == nil {
			continue
		}
		for _, k := range slices.Sorted(maps.Keys(f.Extra)) {
			if plugin(k) {
				out = append(out, xName{"finding", k, f.Path, f.Lines.Frontmatter[k].Line, f.Extra[k]})
			}
		}
	}
	ps, _ := r.PagesWithLines()
	for _, p := range ps {
		if p.Lines == nil {
			continue
		}
		for _, k := range slices.Sorted(maps.Keys(p.Extra)) {
			if plugin(k) {
				out = append(out, xName{"page", k, p.Path, p.Lines.Frontmatter[k].Line, p.Extra[k]})
			}
		}
	}
	rows, _ := r.ScopeWithLines()
	for _, row := range rows {
		if row.Lines == nil {
			continue
		}
		for _, k := range slices.Sorted(maps.Keys(row.Extra)) {
			if plugin(k) {
				out = append(out, xName{"scope", k, report.ScopeFile, row.Lines.Row, row.Extra[k]})
			}
		}
	}
	if c, err := r.ConfigRecord(true); err == nil {
		for _, k := range slices.Sorted(maps.Keys(c.Extra)) {
			if plugin(k) {
				line := 0
				if c.Lines != nil {
					line = c.Lines.Keys[k].Line
				}
				out = append(out, xName{"config", k, report.ConfigFile, line, c.Extra[k]})
			}
		}
	}
	for _, rec := range recs {
		if plugin(rec.Kind) {
			out = append(out, xName{"kinds", rec.Kind, stdinPath, rec.Line, rec.Raw})
		}
	}
	return out
}

// owners are the plugin names that could own name under noun: for
// x-api-export-id, api, api-export and api-export-id; a config section
// x-<command> only <command>.
func owners(noun, name string) []string {
	rest := strings.TrimPrefix(name, "x-")
	if noun == "config" {
		return []string{rest}
	}
	var out []string
	for i, c := range rest {
		if c == '-' && i > 0 {
			out = append(out, rest[:i])
		}
	}
	return append(out, rest)
}

// owns reports whether plugin may declare a schema for name under noun:
// its own config section, or a name starting x-<plugin>-.
func owns(plugin, noun, name string) bool {
	if noun == "config" {
		return name == "x-"+plugin
	}
	return strings.HasPrefix(name, "x-"+plugin+"-")
}

// A schemaChecker checks x- names against the schemas their plugins
// declare. It asks each plugin for --describe at most once.
type schemaChecker struct {
	descs map[string]*sdk.Description // by plugin name; nil when it failed
	errs  map[string]error
	comp  map[string]compiled // by plugin, noun and name
}

type compiled struct {
	sch *jsonschema.Schema
	err error
}

func newSchemaChecker() *schemaChecker {
	return &schemaChecker{descs: map[string]*sdk.Description{}, errs: map[string]error{}, comp: map[string]compiled{}}
}

// describe asks the plugins on PATH named in want, not asked yet, for
// --describe, in parallel.
func (c *schemaChecker) describe(want map[string]bool) {
	var todo []sdk.Command
	for _, p := range findPlugins() {
		if _, done := c.descs[p.Name]; !done && want[p.Name] && !p.Shadowed {
			todo = append(todo, p)
		}
	}
	env, _ := pluginEnv("")
	descs := make([]sdk.Description, len(todo))
	errs := make([]error, len(todo))
	var wg sync.WaitGroup
	for i, p := range todo {
		wg.Go(func() { descs[i], errs[i] = askDescription(p.Path, env) })
	}
	wg.Wait()
	for i, p := range todo {
		if errs[i] != nil {
			c.descs[p.Name], c.errs[p.Name] = nil, errs[i]
			continue
		}
		c.descs[p.Name] = &descs[i]
	}
}

// declared is the schema doc plugin p declares for name under noun.
func declared(d *sdk.Description, plugin, noun, name string) (jsontext.Value, bool) {
	if d.Schemas == nil {
		return nil, false
	}
	var m map[string]jsontext.Value
	switch noun {
	case "finding":
		m = d.Schemas.Finding
	case "page":
		m = d.Schemas.Page
	case "scope":
		m = d.Schemas.Scope
	case "kinds":
		m = d.Schemas.Kinds
	case "config":
		if name == "x-"+plugin && len(d.Schemas.Config) > 0 {
			return d.Schemas.Config, true
		}
		return nil, false
	}
	v, ok := m[name]
	return v, ok
}

// problems checks names, returning a pluginSchema error per way a value
// breaks a schema and a warning per plugin or schema it couldn't use.
// levels are rpt.yaml's rules, which may give the errors another level.
func (c *schemaChecker) problems(names []xName, levels map[string]sdk.Level) []sdk.Problem {
	want := map[string]bool{}
	for _, n := range names {
		for _, o := range owners(n.noun, n.name) {
			want[o] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	c.describe(want)
	var out []sdk.Problem
	warn := func(format string, a ...any) {
		out = append(out, sdk.Problem{Path: reportLevel, Rule: rulePluginSchema, Level: sdk.Warning, Message: fmt.Sprintf(format, a...)})
	}
	plugins := slices.Sorted(maps.Keys(want))
	for _, p := range plugins {
		if err := c.errs[p]; err != nil {
			warn("plugin %s: %v; the x- names it may own are unchecked", p, err)
		}
	}
	// Schemas declared for names a plugin doesn't own are ignored.
	for _, p := range plugins {
		d := c.descs[p]
		if d == nil || d.Schemas == nil {
			continue
		}
		for noun, m := range map[string]map[string]jsontext.Value{"finding": d.Schemas.Finding, "page": d.Schemas.Page, "scope": d.Schemas.Scope, "kinds": d.Schemas.Kinds} {
			for _, name := range slices.Sorted(maps.Keys(m)) {
				if !owns(p, noun, name) {
					warn("plugin %s declares a %s schema for %s, which isn't its own (x-%s-…); ignored", p, noun, name, p)
				}
			}
		}
	}
	warned := map[string]bool{}
	for _, n := range names {
		var claimants []string
		for _, p := range owners(n.noun, n.name) {
			if d := c.descs[p]; d != nil && owns(p, n.noun, n.name) {
				if _, ok := declared(d, p, n.noun, n.name); ok {
					claimants = append(claimants, p)
				}
			}
		}
		if len(claimants) > 1 && !warned[n.noun+n.name] {
			warned[n.noun+n.name] = true
			warn("%s is declared by both %s", n.name, strings.Join(claimants, " and "))
		}
		for _, p := range claimants {
			key := p + "\x00" + n.noun + "\x00" + n.name
			cs, ok := c.comp[key]
			if !ok {
				doc, _ := declared(c.descs[p], p, n.noun, n.name)
				cs.sch, cs.err = pluginschema.Compile(p, n.noun, n.name, doc)
				c.comp[key] = cs
				if cs.err != nil {
					warn("plugin %s: the schema for %s doesn't compile: %v; %s is unchecked", p, n.name, cs.err, n.name)
				}
			}
			if cs.err != nil {
				continue
			}
			var fails []pluginschema.Failure
			if n.noun == "scope" {
				var s string
				_ = json.Unmarshal(n.value, &s)
				fails = pluginschema.CheckValue(cs.sch, s)
			} else {
				var err error
				if fails, err = pluginschema.Check(cs.sch, n.value); err != nil {
					fails = []pluginschema.Failure{{Message: err.Error()}}
				}
			}
			for _, f := range fails {
				msg := n.name + ": "
				if f.Where != "" {
					msg += f.Where + ": "
				}
				level := sdk.Error
				if lv, ok := levels[rulePluginSchema]; ok && (lv == sdk.Error || lv == sdk.Warning) {
					level = lv
				}
				out = append(out, sdk.Problem{Path: n.path, Line: n.line, Rule: rulePluginSchema, Level: level,
					Message: msg + f.Message + " (schema from " + p + ")"})
			}
		}
	}
	return out
}

// sortProblems orders problems as rpt validate does: by path, line, rule
// and message.
func sortProblems(ps []sdk.Problem) {
	slices.SortStableFunc(ps, func(a, b sdk.Problem) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Line, b.Line),
			cmp.Compare(a.Rule, b.Rule), cmp.Compare(a.Message, b.Message))
	})
}
