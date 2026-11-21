package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setThen sets in a fresh copy and returns the finding file afterwards.
func setThen(t *testing.T, id, path string, values ...string) string {
	t.Helper()
	r, dir := openCopy(t)
	f, err := r.Set(id, path, values...)
	if err != nil {
		t.Fatal(err)
	}
	return string(mustReadFile(t, filepath.Join(dir, f.Path)))
}

func TestSetListItemsAsArguments(t *testing.T) {
	got := setThen(t, "F-003", "targets", "S-12", "{scope: S-20, port: 443}")
	if !strings.Contains(got, "targets: [{scope: S-12}, {scope: S-20, port: 443}]   # both login front-ends\n") {
		t.Errorf("file:\n%s", got)
	}
	// A single bracketed argument is the whole list, as before.
	got = setThen(t, "F-003", "targets", "[{scope: S-14}]")
	if !strings.Contains(got, "targets: [{scope: S-14}]") {
		t.Errorf("file:\n%s", got)
	}
	got = setThen(t, "F-003", "evidence", "evidence/a.png", "evidence/b.png")
	if !strings.Contains(got, "evidence: [evidence/a.png, evidence/b.png]\n") {
		t.Errorf("file:\n%s", got)
	}
	// Any other key given several values gets a list.
	got = setThen(t, "F-003", "cwe", "89", "564")
	if !strings.Contains(got, "cwe: [89, 564]\n") {
		t.Errorf("file:\n%s", got)
	}
}

func TestSetSectionPath(t *testing.T) {
	got := setThen(t, "F-003", "sections.remediation", "Use bound parameters.\n")
	if !strings.Contains(got, "## Remediation\n\nUse bound parameters.\n") {
		t.Errorf("file:\n%s", got)
	}
}

func TestPluginPaths(t *testing.T) {
	r, dir := openCopy(t)
	path := filepath.Join(dir, "findings/sqli-login.md")
	for _, kv := range [][2]string{{"x-burp.issue", "12345"}, {"x-burp.host", "a"}} {
		if _, err := r.Set("F-003", kv[0], kv[1]); err != nil {
			t.Fatal(err)
		}
	}
	if got := string(mustReadFile(t, path)); !strings.Contains(got, "x-burp: {issue: 12345, host: a}\n") {
		t.Errorf("file:\n%s", got)
	}
	f, err := r.Unset("F-003", "x-burp.issue")
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Extra["x-burp"]) != `{"host":"a"}` {
		t.Errorf("x-burp = %s", f.Extra["x-burp"])
	}
	if _, err := r.Unset("F-003", "x-burp.host"); err != nil {
		t.Fatal(err)
	}
	if got := string(mustReadFile(t, path)); strings.Contains(got, "x-burp") {
		t.Errorf("the emptied map stayed:\n%s", got)
	}
	// A dotted key outside sections. and x- is a literal top-level key.
	if _, err := r.Set("F-003", "a.b", "1"); err != nil {
		t.Fatal(err)
	}
	if got := string(mustReadFile(t, path)); !strings.Contains(got, "a.b: 1\n") {
		t.Errorf("file:\n%s", got)
	}
}

func TestUnsetSection(t *testing.T) {
	r, dir := openCopy(t)
	f, err := r.Unset("F-003", "sections.poc")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Sections["poc"]; ok {
		t.Error("poc still there")
	}
	got := string(mustReadFile(t, filepath.Join(dir, f.Path)))
	if strings.Contains(got, "Proof") || !strings.HasSuffix(got, "\n") || strings.HasSuffix(got, "\n\n") {
		t.Errorf("file:\n%q", got)
	}
	// Targets may go: a finding may have none.
	if _, err := r.Unset("F-003", "targets"); err != nil {
		t.Error(err)
	}
}

func TestSetIDRenames(t *testing.T) {
	r, dir := openCopy(t)
	if _, err := r.Add(record(t, `{"kind":"finding","title":"Telnet","severity":"low"}`)); err != nil {
		t.Fatal(err)
	}
	f, err := r.Set("F-004", "id", "f-010") // the new ID in any case
	if err != nil {
		t.Fatal(err)
	}
	if f.ID != "F-010" || f.Path != "findings/F-010-telnet.md" {
		t.Errorf("got %s at %s", f.ID, f.Path)
	}
	if _, err := os.Stat(filepath.Join(dir, "findings/F-004-telnet.md")); err == nil {
		t.Error("the old file stayed")
	}
	// A file not named for its ID keeps its name.
	if f, err = r.Set("F-003", "id", "F-020"); err != nil || f.Path != "findings/sqli-login.md" {
		t.Errorf("got %v at %s", err, f.Path)
	}
}

func TestNextIDCountsBrokenFiles(t *testing.T) {
	r, dir := openCopy(t)
	if err := os.WriteFile(filepath.Join(dir, "findings/F-005-broken.md"), []byte("no frontmatter"), 0o644); err != nil {
		t.Fatal(err)
	}
	if id, err := r.NextID(); err != nil || id != "F-006" {
		t.Errorf("NextID = %s, %v; want F-006", id, err)
	}
}
