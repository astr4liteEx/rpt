package plugin

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/astr4liteEx/rpt/internal/report"
	"github.com/astr4liteEx/rpt/schema"
	"github.com/astr4liteEx/rpt/sdk"
)

// Draft is the only JSON Schema draft a plugin may use.
const Draft = "https://json-schema.org/draft/2020-12/schema"

// base is where a plugin's schemas are said to live. Nothing is fetched
// from it: a relative $ref resolving here is refused.
const base = "https://rpt.invalid/plugins/"

// Rule is the validate rule plugin schemas check.
const Rule = "pluginSchema"

// Owner is the plugin among names that owns an x- name: x-<plugin> and the
// names starting x-<plugin>-, the longest plugin name winning. A config
// section x-<plugin> belongs to that plugin alone.
func Owner(noun, name string, names []string) (string, bool) {
	rest, ok := strings.CutPrefix(name, "x-")
	if !ok {
		return "", false
	}
	if noun == "config" {
		if slices.Contains(names, rest) {
			return rest, true
		}
		return "", false
	}
	best := ""
	for _, n := range names {
		if (rest == n || strings.HasPrefix(rest, n+"-")) && len(n) > len(best) {
			best = n
		}
	}
	return best, best != ""
}

// declared is the schema a description declares for name under noun.
func declared(d sdk.Description, plugin, noun, name string) (jsontext.Value, bool) {
	s := d.Schemas
	if s == nil {
		return nil, false
	}
	if noun == "config" {
		return s.Config, len(s.Config) > 0 && name == "x-"+plugin
	}
	v, ok := map[string]map[string]jsontext.Value{"finding": s.Finding, "page": s.Page, "scope": s.Scope, "kinds": s.Kinds}[noun][name]
	return v, ok
}

// Check checks each name against the schema its owner declares, and
// returns a pluginSchema error per way a value fails, and a warning per
// plugin or schema it couldn't use. Problems take the rule's own level.
func Check(names []report.XName, installed []Plugin, answers map[string]Answer) []report.Problem {
	var plugins []string
	for _, p := range installed {
		plugins = append(plugins, p.Name)
	}
	var out []report.Problem
	warned := map[string]bool{}
	warn := func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		if !warned[msg] {
			warned[msg] = true
			out = append(out, report.Problem{Path: ".", Rule: Rule, Level: report.Warning, Message: msg})
		}
	}
	compiled := map[string]*jsonschema.Schema{}
	for _, n := range names {
		owner, ok := Owner(n.Noun, n.Name, plugins)
		if !ok {
			continue
		}
		a := answers[owner]
		if a.Err != nil {
			warn("plugin %s: %v; the x- names it owns are unchecked", owner, a.Err)
			continue
		}
		doc, ok := declared(a.Desc, owner, n.Noun, n.Name)
		if !ok {
			continue
		}
		key := owner + "\x00" + n.Noun + "\x00" + n.Name
		sch, seen := compiled[key]
		if !seen {
			var err error
			if sch, err = Compile(owner, n.Noun, n.Name, doc); err != nil {
				warn("plugin %s: the schema for %s doesn't compile: %v; %s is unchecked", owner, n.Name, err, n.Name)
			}
			compiled[key] = sch
		}
		if sch == nil {
			continue
		}
		fails, err := Validate(sch, n.Value)
		if err != nil {
			fails = []Failure{{Message: err.Error()}}
		}
		for _, f := range fails {
			msg := n.Name + ": "
			if f.Where != "" {
				msg += f.Where + ": "
			}
			out = append(out, report.Problem{Path: n.Path, Line: n.Line, Rule: Rule, Level: report.Error,
				Message: msg + f.Message + " (schema from " + owner + ")"})
		}
	}
	return out
}

// Wanted are the installed plugins that own any of names: the ones to
// describe.
func Wanted(names []report.XName, installed []Plugin) []Plugin {
	var all []string
	for _, p := range installed {
		all = append(all, p.Name)
	}
	want := map[string]bool{}
	for _, n := range names {
		if o, ok := Owner(n.Noun, n.Name, all); ok {
			want[o] = true
		}
	}
	var out []Plugin
	for _, p := range installed {
		if want[p.Name] {
			out = append(out, p)
		}
	}
	return out
}

// rptSchemas are rpt's own schemas by $id, decoded once.
var rptSchemas = sync.OnceValues(func() (map[string]any, error) {
	out := map[string]any{}
	err := fs.WalkDir(schema.Files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := schema.Files.ReadFile(p)
		if err != nil {
			return err
		}
		v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if id, _ := v.(map[string]any)["$id"].(string); id != "" {
			out[id] = v
		}
		return nil
	})
	return out, err
})

// Compile compiles one schema a plugin declares for name under noun.
func Compile(plugin, noun, name string, doc jsontext.Value) (*jsonschema.Schema, error) {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	if m, ok := v.(map[string]any); ok {
		if d, ok := m["$schema"]; ok && d != Draft {
			return nil, fmt.Errorf("$schema %v: only draft 2020-12 (%s) is supported", d, Draft)
		}
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(jsonschema.SchemeURLLoader{}) // no file, no network
	own, err := rptSchemas()
	if err != nil {
		return nil, err
	}
	for id, s := range own {
		if err := c.AddResource(id, s); err != nil {
			return nil, err
		}
	}
	loc := base + url.PathEscape(plugin) + "/" + noun + "/" + url.PathEscape(name) + ".json"
	if err := c.AddResource(loc, v); err != nil {
		return nil, err
	}
	sch, err := c.Compile(loc)
	if err != nil {
		return nil, errors.New(strings.Join(strings.Fields(err.Error()), " "))
	}
	return sch, nil
}

// A Failure is one way a value breaks a schema: Where is the JSON Pointer
// inside the value, "" for the value itself.
type Failure struct{ Where, Message string }

var printer = message.NewPrinter(language.English)

var pointerEscape = strings.NewReplacer("~", "~0", "/", "~1")

// Validate checks a JSON value against sch and returns each way it fails.
func Validate(sch *jsonschema.Schema, v jsontext.Value) ([]Failure, error) {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(v))
	if err != nil {
		return nil, err
	}
	err = sch.Validate(inst)
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		if err != nil {
			return []Failure{{Message: err.Error()}}, nil
		}
		return nil, nil
	}
	var out []Failure
	var walk func(*jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			where := ""
			for _, part := range e.InstanceLocation {
				where += "/" + pointerEscape.Replace(part)
			}
			out = append(out, Failure{Where: where, Message: e.ErrorKind.LocalizedString(printer)})
			return
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)
	return out, nil
}
