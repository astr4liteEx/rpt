package report

import (
	"fmt"
	"slices"
	"testing"
)

func problems(ps []Problem) []string {
	var out []string
	for _, p := range ps {
		out = append(out, fmt.Sprintf("%s:%d %s %s: %s", p.Path, p.Line, p.Level, p.Rule, p.Message))
	}
	return out
}

func TestCheckFixture(t *testing.T) {
	got := problems(fixture(t, nil).Check())
	want := []string{"findings/tls-weak.md:5 error scopeIDsExist: S-99 is not in scope.csv"}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%q", got)
	}
}

func TestCheckRules(t *testing.T) {
	m := fixture(t, map[string]string{
		ConfigFile: "format: 2\ncolour: red\nrules:\n  textBeforeHeading: error\npages: [P-009, findings]\nrequired_pages: [P-001]\n",
		"findings/a.md": "---\nid: F-1\ntitle: ''\ntargets: [{scope: S-12, port: 80}, {scope: S-20, host: 10.0.9.9}]\nseverity: urgent\n" +
			"evidence: [../../x.png, evidence/missing.png]\n---\n\nLead.\n\n## Description\n\n## Remediation\n\nx\n",
		"findings/b.md":              "---\nid: F-003\ntitle: Dup\ntargets: []\nseverity: low\n---\n\n## Description\n\nx\n\n## Remediation\n\nx\n\n## Proof of concept\n\nx\n",
		"findings/c.md":              "---\nid: F-004\ntitle: [\n---\n",
		"findings/evidence/lost.png": "x",
		"pages/P-001-a.md":           "---\nid: P-001\ntitle: A\n---\n",
	})
	got := problems(m.Check())
	want := []string{
		"findings/a.md:2 error findingID: id \"F-1\" is not of the form F-NNN: the next free one is F-004",
		"findings/a.md:3 error title: no title",
		"findings/a.md:4 error targets: 10.0.9.9 is not in S-20 (10.0.1.0/24)",
		"findings/a.md:4 error targets: port 80 is not S-12's port 443",
		"findings/a.md:5 error knownSeverity: severity \"urgent\" is not one of critical, high, medium, low, info",
		"findings/a.md:6 error evidence: \"../../x.png\" leaves the report",
		"findings/a.md:6 error evidence: \"evidence/missing.png\" doesn't exist (as findings/evidence/missing.png)",
		"findings/a.md:8 error requiredSections: no \"Proof of concept\" section",
		"findings/a.md:8 error textBeforeHeading: text before the first ## heading belongs to no section",
		"findings/a.md:11 error requiredSections: the \"Description\" section is empty",
		"findings/b.md:4 error targets: no targets: a finding names the scope rows it was found on",
		"findings/c.md:3 error readable: did not find expected node content",
		"findings/sqli-login.md:2 error findingID: F-003 is also the id of findings/b.md: the next free one is F-004",
		"findings/tls-weak.md:5 error scopeIDsExist: S-99 is not in scope.csv",
		"pages/P-001-a.md:5 error requiredPages: required page P-001 has no body",
		"rpt.yaml:2 warning configUnknownKey: colour isn't a key rpt knows; plugins keep settings under x-<plugin>",
		"rpt.yaml:5 error pageOrder: pages names P-009, which isn't a page",
	}
	if !slices.Equal(got, want) {
		for _, g := range got {
			t.Log(g)
		}
		t.Error("problems differ")
	}
}
