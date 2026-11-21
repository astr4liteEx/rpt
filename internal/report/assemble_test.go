package report

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAssemble(t *testing.T) {
	m := fixture(t, map[string]string{
		"findings/x.md": "---\nid: F-009\ntitle: X\ntargets: [{scope: S-12}, {scope: S-12, port: 80}]\nseverity: critical\n---\n\n## Description\n\n![shot](<evidence/F-003-login.png> \"t\") and [web](https://x.test/a.png)\n\n## Remediation\n\nr\n\n## Proof of concept\n\np\n",
		"findings/y.md": "---\nid: F-009\ntitle: Dup\ntargets: []\nseverity: low\n---\n",
		"pages/P-002-b.md": "---\nid: P-002\ntitle: B\n---\n\n<img src=\"../findings/evidence/F-003-login.png\">\n",
		ConfigFile: "format: 2\npages: [P-002, findings]\n",
	})
	r, warn := m.Assemble()
	var ids []string
	for _, f := range r.Findings {
		ids = append(ids, f.ID+":"+string(f.Severity))
	}
	if !slices.Equal(ids, []string{"F-009:critical", "F-003:high", "F-001:medium", "F-002:info"}) {
		t.Errorf("findings %v", ids)
	}
	x := r.Findings[0]
	if len(x.Targets) != 1 || x.Targets[0].Scope.ID != "S-12" || x.Targets[0].Scope.Rev != "" {
		t.Errorf("targets %+v", x.Targets)
	}
	abs := filepath.ToSlash(filepath.Join(m.Dir, "findings/evidence/F-003-login.png"))
	if want := "![shot](<" + abs + "> \"t\") and [web](https://x.test/a.png)"; x.Sections["description"] != want {
		t.Errorf("description %q", x.Sections["description"])
	}
	if !slices.Equal(r.Report.Order, []string{"P-002", "findings"}) || r.Pages[0].Body != `<img src="`+abs+`">` {
		t.Errorf("order %v page %q", r.Report.Order, r.Pages[0].Body)
	}
	got := problems(warn)
	want := []string{
		"findings/x.md:4 warning targets: port 80 is not S-12's port 443: the target; left out",
		"findings/y.md:2 warning findingID: F-009 is also the id of findings/x.md: the finding; left out",
		"findings/tls-weak.md:5 warning scopeIDsExist: S-99 is not in scope.csv: the target; left out",
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("warnings\n%s", strings.Join(got, "\n"))
	}
}
