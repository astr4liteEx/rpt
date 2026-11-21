package report

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

// The golden file lives at the repo root so plugin authors can read it as
// an example report record. The report folder's absolute path is written
// as $REPORT so the file is the same on every machine.
const assembleGolden = "../../../testdata/assemble.golden.json"

func TestAssembleFixture(t *testing.T) {
	r := openFixture(t)
	rep, warnings, err := r.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	checkProblems(t, warnings, []want{
		{"findings/tls-weak.md", 5, "scopeIDsExist", sdk.Warning, `"S-99" is not in scope.csv; target left out of the finding`},
	})

	got, err := json.Marshal(rep, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(fixture)
	if err != nil {
		t.Fatal(err)
	}
	got = bytes.ReplaceAll(append(got, '\n'), []byte(abs), []byte("$REPORT"))
	if *update {
		if err := os.WriteFile(assembleGolden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(assembleGolden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s changed: run go test ./internal/report -update and review the diff\n got:\n%s", assembleGolden, got)
	}
	checkRequired(t, want)
}

// checkRequired checks the golden report against the published schema:
// every member the schema requires is present, at every level.
func checkRequired(t *testing.T, golden []byte) {
	t.Helper()
	var schema struct {
		Required []string `json:"required"`
		Defs     map[string]struct {
			Required []string `json:"required"`
		} `json:"$defs"`
	}
	b, err := os.ReadFile("../../../schema/report.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	var rep map[string]any
	if err := json.Unmarshal(golden, &rep); err != nil {
		t.Fatal(err)
	}
	has := func(where string, m map[string]any, keys []string) {
		for _, k := range keys {
			if _, ok := m[k]; !ok {
				t.Errorf("%s has no %q, which the schema requires", where, k)
			}
		}
	}
	has("report record", rep, schema.Required)
	has("report.report", rep["report"].(map[string]any), schema.Defs["reportMeta"].Required)
	findings := rep["findings"].([]any)
	if len(findings) == 0 {
		t.Fatal("golden report has no findings")
	}
	for _, f := range findings {
		has("finding", f.(map[string]any), schema.Defs["reportFinding"].Required)
	}
}

func TestAssembleLeavesOutWhatItCannotUse(t *testing.T) {
	dir := copyFixture(t)
	writeFile(t, dir, "findings/broken.md", "---\nid: F-009\ntitle: : bad\n---\n")
	writeFile(t, dir, "findings/x.md", strings.NewReplacer("severity: low\n", "severity: low\nevidence: [../../outside.png]\n",
		"[{scope: S-12}]", "[{scope: S-12}, {scope: S-12, port: 80}, {port: 22}]").Replace(finding)+"\n![gone](nope.png)\n")
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	rep, warnings, err := r.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	checkProblems(t, warnings, []want{
		{"findings/broken.md", 3, "readable", sdk.Warning, "left out of the report"},
		{"findings/tls-weak.md", 5, "scopeIDsExist", sdk.Warning, "S-99"},
		{"findings/x.md", 4, "targets", sdk.Warning, "port 80 is not S-12's port 443; target left out of the finding"},
		{"findings/x.md", 4, "targets", sdk.Warning, "scope is required: the ID of the scope row it falls in; target left out of the finding"},
		{"findings/x.md", 6, "evidence", sdk.Warning, `evidence "../../outside.png" leaves the report; left out`},
		{"findings/x.md", 20, "evidence", sdk.Warning, `evidence "nope.png" does not exist; left out`},
	})
	if len(rep.Findings) != 4 {
		t.Errorf("got %d findings, want the 4 readable ones", len(rep.Findings))
	}
	for _, f := range rep.Findings {
		if f.ID == "F-050" && len(f.Targets) != 1 {
			t.Errorf("F-050 targets = %+v, want only the one that fits", f.Targets)
		}
		if f.ID == "F-050" && (len(f.Assets) != 0 || !strings.Contains(f.Sections["poc"], "](nope.png)")) {
			t.Errorf("F-050 assets %v, poc %q: a bad link stays as written and is no asset", f.Assets, f.Sections["poc"])
		}
	}
}

func TestAssembleSortsBySeverityThenNumber(t *testing.T) {
	dir := copyFixture(t)
	for _, f := range []struct{ name, id, sev string }{
		{"a.md", "F-1000", "high"}, {"b.md", "F-999", "high"}, {"c.md", "F-050", "critical"},
	} {
		writeFile(t, dir, "findings/"+f.name, strings.NewReplacer("F-050", f.id, "severity: low", "severity: "+f.sev).Replace(finding))
	}
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	rep, _, err := r.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range rep.Findings {
		ids = append(ids, f.ID)
	}
	if got, want := strings.Join(ids, " "), "F-050 F-003 F-999 F-1000 F-001 F-002"; got != want {
		t.Errorf("order = %s, want %s", got, want)
	}
	if rep.Summary["critical"] != 1 || rep.Summary["high"] != 3 || rep.Summary["low"] != 0 {
		t.Errorf("summary = %v", rep.Summary)
	}
}
