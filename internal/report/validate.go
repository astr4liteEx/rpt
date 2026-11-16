package report

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/astr4liteEx/rpt/sdk"
)

// The validate rules. Their names are public API: listed in
// schema/problem.schema.json, never renamed or removed without the
// deprecation rule.
const (
	RuleReadable          = "readable"
	RuleFindingID         = "findingID"
	RuleTitle             = "title"
	RuleKnownSeverity     = "knownSeverity"
	RuleScopeIDsExist     = "scopeIDsExist"
	RuleRequiredSections  = "requiredSections"
	RuleEvidence          = "evidence"
	RuleTextBeforeHeading = "textBeforeHeading" // warning
	RuleConfig            = "config"
	RuleConfigUnknownKey  = "configUnknownKey" // warning
	RuleScope             = "scope"
)

// Validate checks the report against every rule and returns the problems
// found, sorted by path, line, rule and message. The error is for failures
// to read the report at all, not for problems in it.
func (r *Report) Validate() ([]sdk.Problem, error) {
	v := &validation{r: r}
	v.checkConfig()
	v.checkScope()
	files, err := r.findingFiles()
	if err != nil {
		return nil, err
	}
	v.next, _ = r.NextID()
	ids := map[string]string{} // id -> file that has it first
	for _, ff := range files {
		if ff.err != nil {
			v.fileError(RuleReadable, ff.err)
			continue
		}
		v.findingID(ff, ids)
		v.title(ff)
		v.knownSeverity(ff)
		v.scopeIDsExist(ff)
		v.requiredSections(ff)
		v.evidence(ff)
		v.textBeforeHeading(ff)
	}
	slices.SortStableFunc(v.problems, func(a, b sdk.Problem) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Line, b.Line),
			cmp.Compare(a.Rule, b.Rule), cmp.Compare(a.Message, b.Message))
	})
	return v.problems, nil
}

type validation struct {
	r        *Report
	problems []sdk.Problem

	cfg   Config
	cfgOK bool // the config parsed; rules that need it run

	scope   map[string]bool
	scopeOK bool // scope.csv could be read at all; scopeIDsExist runs

	next string // next free finding ID, for messages
}

func (v *validation) add(path string, line int, rule string, level sdk.Level, format string, a ...any) {
	v.problems = append(v.problems, sdk.Problem{
		Kind: "problem", Path: path, Line: line, Rule: rule, Level: level, Message: fmt.Sprintf(format, a...),
	})
}

// fileError reports an error from reading a file under rule.
func (v *validation) fileError(rule string, err error) {
	if fe, ok := errors.AsType[*FileError](err); ok {
		v.add(fe.Path, fe.Line, rule, sdk.Error, "%v", fe.Err)
		return
	}
	v.add("", 0, rule, sdk.Error, "%v", err)
}

// checkConfig runs the config and configUnknownKey rules.
func (v *validation) checkConfig() {
	cfg, err := v.r.Config()
	if err != nil {
		if _, ok := errors.AsType[*FileError](err); ok {
			v.fileError(RuleReadable, err)
		} else {
			v.add(ConfigFile, 0, RuleReadable, sdk.Error, "%v", err)
		}
		return
	}
	v.cfg, v.cfgOK = cfg, true
	line := func(key string) int { return cfg.KeyLines[key] }
	bad := func(key, format string, a ...any) { v.add(ConfigFile, line(key), RuleConfig, sdk.Error, format, a...) }

	if _, ok := cfg.KeyLines["format"]; !ok {
		bad("format", "no format; add format: 1")
	} else if cfg.Format != 1 {
		bad("format", "format %d is not 1, the only format this rpt reads", cfg.Format)
	}
	if strings.TrimSpace(cfg.Name) == "" {
		bad("name", "no name")
	}
	if strings.TrimSpace(cfg.Client) == "" {
		bad("client", "no client")
	}
	start, startOK := v.date("period.start", cfg.Period.Start)
	end, endOK := v.date("period.end", cfg.Period.End)
	if startOK && endOK && start.After(end) {
		bad("period", "period.start %s is after period.end %s", cfg.Period.Start, cfg.Period.End)
	}
	if _, ok := cfg.KeyLines["severities"]; ok && len(cfg.Severities) == 0 {
		bad("severities", "severities is empty; list the levels most severe first, or remove the key for the defaults")
	}
	checkList("severities", cfg.Severities, bad)
	checkList("required_sections", cfg.RequiredSections, bad)
	for _, k := range cfg.UnknownKeys {
		v.add(ConfigFile, line(k), RuleConfigUnknownKey, sdk.Warning, "unknown key %q is ignored and never reaches the report", k)
	}
}

// date checks one period date and parses it.
func (v *validation) date(name, s string) (time.Time, bool) {
	line := v.cfg.KeyLines["period"]
	if s == "" {
		v.add(ConfigFile, line, RuleConfig, sdk.Error, "no %s", name)
		return time.Time{}, false
	}
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		v.add(ConfigFile, line, RuleConfig, sdk.Error, "%s %q is not a date like 2026-11-06", name, s)
		return time.Time{}, false
	}
	return t, true
}

// checkList reports empty and repeated names in a config list.
func checkList[T ~string](key string, items []T, bad func(key, format string, a ...any)) {
	seen := map[T]bool{}
	for _, it := range items {
		switch {
		case strings.TrimSpace(string(it)) == "":
			bad(key, "%s has an empty name", key)
		case seen[it]:
			bad(key, "%s lists %q twice", key, it)
		}
		seen[it] = true
	}
}

// checkScope runs the scope rule and collects the scope IDs.
func (v *validation) checkScope() {
	rows, err := v.r.Scope()
	v.scope = map[string]bool{}
	for _, row := range rows {
		v.scope[row.ID] = true
	}
	v.scopeOK = err == nil || len(rows) > 0
	if err == nil {
		return
	}
	for _, e := range unjoin(err) {
		if errors.Is(e, fs.ErrNotExist) {
			v.add(ScopeFile, 0, RuleScope, sdk.Error, "no scope.csv; a report with no scope has one with only its header row: id,host,port")
			continue
		}
		v.fileError(RuleScope, e)
	}
}

// unjoin splits an errors.Join result into its parts.
func unjoin(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		return j.Unwrap()
	}
	if err != nil {
		return []error{err}
	}
	return nil
}

func (v *validation) findingID(ff findingSrc, ids map[string]string) {
	id, line := ff.f.ID, ff.keyLines["id"]
	switch {
	case id == "":
		v.add(ff.rel, 0, RuleFindingID, sdk.Error, "no id; the next free one is %s", v.next)
	case !ValidID(id):
		v.add(ff.rel, line, RuleFindingID, sdk.Error, "id %q is not F- and at least three digits; the next free one is %s", id, v.next)
	case ids[id] != "":
		v.add(ff.rel, line, RuleFindingID, sdk.Error, "%s is also the id of %s; the next free one is %s", id, ids[id], v.next)
	default:
		ids[id] = ff.rel
	}
}

func (v *validation) title(ff findingSrc) {
	if strings.TrimSpace(ff.f.Title) == "" {
		v.add(ff.rel, ff.keyLines["title"], RuleTitle, sdk.Error, "no title")
	}
}

func (v *validation) knownSeverity(ff findingSrc) {
	levels := v.cfg.Severities
	if !v.cfgOK || len(levels) == 0 || slices.Contains(levels, ff.f.Severity) {
		return
	}
	names := make([]string, len(levels))
	for i, l := range levels {
		names[i] = string(l)
	}
	v.add(ff.rel, ff.keyLines["severity"], RuleKnownSeverity, sdk.Error,
		"severity %q is not one of %s", ff.f.Severity, strings.Join(names, ", "))
}

func (v *validation) scopeIDsExist(ff findingSrc) {
	if !v.scopeOK {
		return
	}
	for _, id := range ff.f.Scope {
		if !v.scope[id] {
			v.add(ff.rel, ff.keyLines["scope"], RuleScopeIDsExist, sdk.Error, "%s is not in scope.csv", id)
		}
	}
}

func (v *validation) requiredSections(ff findingSrc) {
	if !v.cfgOK {
		return
	}
	spans := sectionSpans(ff.body)
	for _, key := range v.cfg.RequiredSections {
		if strings.TrimSpace(key) == "" {
			continue // the config rule reports it
		}
		heading := cmp.Or(sectionHeadings[key], key)
		i := slices.IndexFunc(spans, func(s span) bool { return s.key == key })
		switch {
		case i < 0:
			v.add(ff.rel, 0, RuleRequiredSections, sdk.Error, "no %q section", heading)
		case sectionText(ff.body, spans[i]) == "":
			v.add(ff.rel, ff.bodyLine(spans[i].lineStart), RuleRequiredSections, sdk.Error, "the %q section is empty", heading)
		}
	}
}

func (v *validation) evidence(ff findingSrc) {
	for _, p := range ff.f.Evidence {
		if _, msg := v.r.checkEvidence(ff.f, p); msg != "" {
			v.add(ff.rel, ff.keyLines["evidence"], RuleEvidence, sdk.Error, "%s", msg)
		}
	}
	for _, l := range relLinks(ff.body) {
		if _, msg := v.r.checkEvidence(ff.f, l.path); msg != "" {
			v.add(ff.rel, ff.bodyLine(l.off), RuleEvidence, sdk.Error, "%s", msg)
		}
	}
}

func (v *validation) textBeforeHeading(ff findingSrc) {
	end := len(ff.body)
	if spans := sectionSpans(ff.body); len(spans) > 0 {
		end = spans[0].lineStart
	}
	pre := ff.body[:end]
	if i := bytes.IndexFunc(pre, func(c rune) bool { return c != ' ' && c != '\t' && c != '\n' }); i >= 0 {
		v.add(ff.rel, ff.bodyLine(i), RuleTextBeforeHeading, sdk.Warning,
			"text before the first ## heading is not part of any section and won't reach the report")
	}
}

// findingSrc is one finding file read for validation, with what rules need
// to locate problems in it.
type findingSrc struct {
	rel      string
	err      error // the file doesn't parse; nothing else is set
	f        sdk.Finding
	keyLines map[string]int // frontmatter key -> file line
	body     []byte         // markdown after the frontmatter, LF endings
	first    int            // file line the body starts on
}

// bodyLine is the file line of byte offset off in the body.
func (ff findingSrc) bodyLine(off int) int {
	return ff.first + bytes.Count(ff.body[:off], []byte("\n"))
}

// findingFiles reads every finding file in name order.
func (r *Report) findingFiles() ([]findingSrc, error) {
	entries, err := fs.ReadDir(r.root.FS(), FindingsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", FindingsDir, err)
	}
	var out []findingSrc
	for _, e := range entries {
		if !e.Type().IsRegular() || path.Ext(e.Name()) != ".md" {
			continue
		}
		rel := path.Join(FindingsDir, e.Name())
		src, err := r.root.ReadFile(rel)
		if err != nil {
			out = append(out, findingSrc{rel: rel, err: &FileError{Path: rel, Err: err}})
			continue
		}
		f, err := parseFinding(rel, src)
		if err != nil {
			out = append(out, findingSrc{rel: rel, err: err})
			continue
		}
		head, body, _ := splitFrontmatter(normaliseNewlines(src))
		var doc yaml.Node
		_ = yaml.Unmarshal(head, &doc) // parseFinding already succeeded on it
		lines := keyLines(&doc)
		for k := range lines {
			lines[k]++ // frontmatter starts on file line 2
		}
		out = append(out, findingSrc{rel: rel, f: f, keyLines: lines, body: body,
			first: 2 + bytes.Count(head, []byte("\n")) + 1})
	}
	return out, nil
}
