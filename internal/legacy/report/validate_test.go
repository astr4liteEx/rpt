package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

// finding is a valid finding file with predictable lines: 2 id, 3 title,
// 4 targets, 5 severity, 7 ## Description, 9 its text, 11 ## Remediation,
// 13 its text, 15 ## Proof of concept, 17 its text.
const finding = "---\nid: F-050\ntitle: T\ntargets: [{scope: S-12}]\nseverity: low\n---\n" +
	"## Description\n\nd\n\n## Remediation\n\nr\n\n## Proof of concept\n\np\n"

const config = "format: 2\n"

type want struct {
	path  string
	line  int
	rule  string
	level sdk.Level
	msg   string // a substring of the message
}

func TestValidate(t *testing.T) {
	E, W := sdk.Error, sdk.Warning
	f := func(old, new string) string { return strings.Replace(finding, old, new, 1) }
	tests := []struct {
		name  string
		files map[string]string // written over a copy of the fixture with S-99 fixed
		want  []want
	}{
		{name: "a clean report has no problems"},
		{name: "readable: finding", files: map[string]string{"findings/x.md": "---\nid: F-050\ntitle: : bad\n---\n"},
			want: []want{{"findings/x.md", 3, "readable", E, "mapping values"}}},
		{name: "readable: frontmatter key named like a record member", files: map[string]string{"findings/x.md": f("severity: low\n", "severity: low\npath: elsewhere\n")},
			want: []want{{"findings/x.md", 6, "readable", E, `frontmatter key "path" is reserved`}}},
		{name: "readable: frontmatter key lines", files: map[string]string{"findings/x.md": f("title: T\n", "title: T\nlines: 3\n")},
			want: []want{{"findings/x.md", 4, "readable", E, `frontmatter key "lines" is reserved`}}},
		{name: "readable: config, and config-dependent rules are skipped", files: map[string]string{"rpt.yaml": "format: [1\n"},
			want: []want{{"rpt.yaml", -1, "readable", E, ""}}},
		{name: "findingID: missing names the next free number", files: map[string]string{"findings/x.md": f("id: F-050\n", "")},
			want: []want{{"findings/x.md", 0, "findingID", E, "no id; the next free one is F-004"}}},
		{name: "findingID: malformed", files: map[string]string{"findings/x.md": f("F-050", "F-7")},
			want: []want{{"findings/x.md", 2, "findingID", E, `"F-7" is not F- and at least three digits`}}},
		{name: "findingID: duplicate", files: map[string]string{"findings/x.md": f("F-050", "F-003")},
			want: []want{{"findings/x.md", 2, "findingID", E, "F-003 is also the id of findings/sqli-login.md; the next free one is F-004"}}},
		{name: "title", files: map[string]string{"findings/x.md": f("title: T", `title: "  "`)},
			want: []want{{"findings/x.md", 3, "title", E, "no title"}}},
		{name: "knownSeverity", files: map[string]string{"findings/x.md": f("severity: low", "severity: urgent")},
			want: []want{{"findings/x.md", 5, "knownSeverity", E, `"urgent" is not one of critical, high, medium, low, info`}}},
		{name: "scopeIDsExist", files: map[string]string{"findings/x.md": f("{scope: S-12}", "{scope: S-12}, {scope: S-77}")},
			want: []want{{"findings/x.md", 4, "scopeIDsExist", E, "S-77 is not in scope.csv"}}},
		{name: "targets: none", files: map[string]string{
			"findings/x.md": f("[{scope: S-12}]", "[]"),
			"findings/y.md": strings.NewReplacer("F-050", "F-051", "targets: [{scope: S-12}]\n", "").Replace(finding)},
			want: []want{
				{"findings/x.md", 4, "targets", E, "no targets: a finding must be attributed to scope"},
				{"findings/y.md", 0, "targets", E, "no targets"},
			}},
		{name: "targets: each names a row and fits it", files: map[string]string{
			"findings/x.md": f("[{scope: S-12}]", "[{host: 10.0.0.5}, {scope: S-12, host: 10.0.0.5}, {scope: S-12, port: 80}, {scope: S-20, host: 10.0.2.1}, {scope: S-20, host: 10.0.1.7, port: 22, protocol: udp}]")},
			want: []want{
				{"findings/x.md", 4, "targets", E, "10.0.0.5 has no scope ID"},
				{"findings/x.md", 4, "targets", E, "S-12 is one asset (10.0.0.5), so a target on it takes no host"},
				{"findings/x.md", 4, "targets", E, "host 10.0.2.1 is not inside S-20 (10.0.1.0/24)"},
				{"findings/x.md", 4, "targets", E, "port 80 is not S-12's port 443"},
			}},
		{name: "readable: format 1 scope and target", files: map[string]string{
			"findings/x.md": f("targets: [{scope: S-12}]", "scope: [S-12]"),
			"findings/y.md": strings.NewReplacer("F-050", "F-051", "targets: [{scope: S-12}]", "targets: []\ntarget: {host: a}").Replace(finding)},
			want: []want{
				{"findings/x.md", 4, "readable", E, `frontmatter key "scope" is from report format 1; it is now targets`},
				{"findings/y.md", 5, "readable", E, `frontmatter key "target" is from report format 1`},
			}},
		{name: "config: format 1 says what changed", files: map[string]string{"rpt.yaml": "format: 1\n"},
			want: []want{{"rpt.yaml", 1, "config", E, "replace each finding's scope and target with targets"}}},
		{name: "requiredSections: missing and blank", files: map[string]string{
			"findings/x.md": f("## Remediation\n\nr\n\n", ""),
			"findings/y.md": strings.NewReplacer("F-050", "F-051", "\nd\n", "\n \n").Replace(finding)},
			want: []want{
				{"findings/x.md", 0, "requiredSections", E, `no "Remediation" section`},
				{"findings/y.md", 7, "requiredSections", E, `"Description" section is empty`},
			}},
		{name: "requiredSections: from the config", files: map[string]string{
			"rpt.yaml":      config + "required_sections: [description, References]\n",
			"findings/x.md": f("p\n", "p\n\n## References\n\nrfc\n")},
			want: []want{
				{"findings/sqli-login.md", 0, "requiredSections", E, `no "References" section`},
				{"findings/tls-weak.md", 0, "requiredSections", E, `no "References" section`},
			}},
		{name: "evidence: frontmatter and section links", files: map[string]string{
			"findings/x.md": f("severity: low\n", "severity: low\nevidence: [../../outside.png, missing.png, evidence, evidence/F-003-login.png]\n") +
				"\n![ok](evidence/F-003-login.png) [web](https://example.com) [here](#top) ![gone](nope.png)\n"},
			want: []want{
				{"findings/x.md", 6, "evidence", E, `"../../outside.png" leaves the report`},
				{"findings/x.md", 6, "evidence", E, `"evidence" is not a regular file`},
				{"findings/x.md", 6, "evidence", E, `"missing.png" does not exist`},
				{"findings/x.md", 20, "evidence", E, `"nope.png" does not exist`},
			}},
		{name: "textBeforeHeading", files: map[string]string{"findings/x.md": f("---\n## Description", "---\n\nstray text\n\n## Description")},
			want: []want{{"findings/x.md", 8, "textBeforeHeading", W, "text before the first ## heading is not part of any section"}}},
		{name: "config: format", files: map[string]string{"rpt.yaml": strings.Replace(config, "format: 2", "format: 3", 1)},
			want: []want{{"rpt.yaml", 1, "config", E, "format 3 is not 2"}}},
		{name: "config: lists", files: map[string]string{"rpt.yaml": config +
			"severities: [critical, high, medium, low, info, low]\nrequired_sections: [poc, '']\n"},
			want: []want{
				{"rpt.yaml", 2, "config", E, `severities lists "low" twice`},
				{"rpt.yaml", 3, "config", E, "required_sections has an empty name"},
			}},
		{name: "config: empty severities; knownSeverity has nothing to check against", files: map[string]string{
			"rpt.yaml": config + "severities: []\n"},
			want: []want{{"rpt.yaml", 2, "config", E, "severities is empty"}}},
		{name: "configUnknownKey", files: map[string]string{"rpt.yaml": config + "severites: [high]\n"},
			want: []want{{"rpt.yaml", 2, "configUnknownKey", W, `unknown key "severites"`}}},
		{name: "scope: bad rows", files: map[string]string{"scope.csv": "id,host,port\nS-12,10.0.0.5,443\nS-14,,8443\nS-20,10.0.1.0/24,x\n"},
			want: []want{
				{"scope.csv", 3, "scope", E, "S-14 has no host"},
				{"scope.csv", 4, "scope", E, `port "x"`},
				{"findings/sqli-login.md", 4, "scopeIDsExist", E, "S-14 is not in scope.csv"},
				{"findings/xss-search.md", 4, "scopeIDsExist", E, "S-14 is not in scope.csv"},
			}},
		{name: "scope: missing file", files: map[string]string{"scope.csv": ""},
			want: []want{{"scope.csv", 0, "scope", E, "no scope.csv"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := copyFixture(t)
			fixed := strings.Replace(readFile(t, dir, "findings/tls-weak.md"), "{scope: S-99}", "{scope: S-12}", 1)
			writeFile(t, dir, "findings/tls-weak.md", fixed)
			for rel, content := range tt.files {
				if rel == "scope.csv" && content == "" {
					os.Remove(filepath.Join(dir, rel))
					continue
				}
				writeFile(t, dir, rel, content)
			}
			r, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			got, err := r.Validate()
			if err != nil {
				t.Fatal(err)
			}
			checkProblems(t, got, sortWant(tt.want))
		})
	}
}

// The fixture's planted problem, and only that.
func TestValidateFixture(t *testing.T) {
	got, err := openFixture(t).Validate()
	if err != nil {
		t.Fatal(err)
	}
	checkProblems(t, got, []want{{"findings/tls-weak.md", 5, "scopeIDsExist", sdk.Error, "S-99 is not in scope.csv"}})
}

func readFile(t *testing.T, dir, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// sortWant orders expectations the way Validate orders problems: by path,
// then line, then rule. Validate breaks ties by message; expectations that
// tie are written in that order.
func sortWant(ws []want) []want {
	out := append([]want(nil), ws...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && less(out[j], out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func less(a, b want) bool {
	if a.path != b.path {
		return a.path < b.path
	}
	if a.line != b.line && a.line >= 0 && b.line >= 0 {
		return a.line < b.line
	}
	return a.rule < b.rule
}

func checkProblems(t *testing.T, got []sdk.Problem, wants []want) {
	t.Helper()
	var gs []string
	for _, p := range got {
		gs = append(gs, fmt.Sprintf("%s:%d %s %s: %s", p.Path, p.Line, p.Level, p.Rule, p.Message))
	}
	if len(got) != len(wants) {
		t.Fatalf("got %d problems, want %d:\n%s", len(got), len(wants), strings.Join(gs, "\n"))
	}
	for i, w := range wants {
		p := got[i]
		if p.Kind != "problem" || p.Path != w.path || (w.line >= 0 && p.Line != w.line) || p.Rule != w.rule ||
			p.Level != w.level || !strings.Contains(p.Message, w.msg) {
			t.Errorf("problem %d = %s\nwant %s:%d %s %s: ...%s...", i, gs[i], w.path, w.line, w.level, w.rule, w.msg)
		}
	}
}
