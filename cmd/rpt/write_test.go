package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSetTakesValuesStartingWithADash(t *testing.T) {
	dir := fixture(t)
	code, out, errOut := rpt(t, "", "finding", "set", "F-001", "title", "--not a flag")
	if code != 0 || records(t, out)[0]["title"] != "--not a flag" {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	if !strings.Contains(read(t, filepath.Join(dir, "findings/xss-search.md")), "title: --not a flag") {
		t.Error("not written")
	}
}

func TestSectionFromStdin(t *testing.T) {
	dir := fixture(t)
	code, _, errOut := rpt(t, "New text\n\nwith two paragraphs.\n", "finding", "set", "F-001", "sections.remediation")
	got := read(t, filepath.Join(dir, "findings/xss-search.md")) // CRLF, kept
	if code != 0 || !strings.Contains(got, "## Remediation\r\n\r\nNew text\r\n\r\nwith two paragraphs.\r\n") {
		t.Errorf("exit %d %s:\n%s", code, errOut, read(t, filepath.Join(dir, "findings/xss-search.md")))
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	dir := fixture(t)
	before := read(t, filepath.Join(dir, "scope.csv"))
	code, out, _ := rpt(t, "", "scope", "add", "--host", "10.9.9.9", "--dry-run")
	if code != 0 || records(t, out)[0]["id"] == nil || read(t, filepath.Join(dir, "scope.csv")) != before {
		t.Errorf("exit %d %s", code, out)
	}
}

func TestIfRev(t *testing.T) {
	fixture(t)
	_, out, _ := rpt(t, "", "finding", "get", "F-001")
	rev := records(t, out)[0]["rev"].(string)
	if code, _, errOut := rpt(t, "", "finding", "set", "--if-rev", rev, "F-001", "title", "One"); code != 0 {
		t.Fatalf("matching rev refused: %s", errOut)
	}
	code, out, _ := rpt(t, "", "finding", "set", "--if-rev", "F-001="+rev, "F-001", "title", "Two")
	if code != 1 || records(t, out)[0]["rule"] != "rev" {
		t.Errorf("stale rev: exit %d %s", code, out)
	}
	if code, _, _ := rpt(t, "", "finding", "set", "--if-rev", "F-002="+rev, "F-001", "title", "Two"); code != 2 {
		t.Errorf("an --if-rev for a thing not named: exit %d", code)
	}
}

func TestRemoveNeedsYesOffATerminal(t *testing.T) {
	dir := fixture(t)
	if code, _, errOut := rpt(t, "", "finding", "remove", "F-002"); code != 2 || !strings.Contains(errOut, "--yes") {
		t.Errorf("exit %d %q", code, errOut)
	}
	if read(t, filepath.Join(dir, "findings/tls-weak.md")) == "<absent>" {
		t.Fatal("removed without --yes")
	}
	if code, _, _ := rpt(t, "", "finding", "remove", "--yes", "F-002"); code != 0 || read(t, filepath.Join(dir, "findings/tls-weak.md")) != "<absent>" {
		t.Errorf("--yes: exit %d", code)
	}
}

func TestARefusalWritesNothing(t *testing.T) {
	dir := fixture(t)
	stdin := `{"kind":"finding","title":"Good","severity":"low","targets":[{"scope":"S-12"}]}` + "\n" +
		`{"kind":"finding","title":"Bad","severity":"urgent","targets":[{"scope":"S-12"}]}` + "\n"
	code, out, _ := rpt(t, stdin, "finding", "add")
	recs := records(t, out)
	if code != 1 || len(recs) != 1 || recs[0]["kind"] != "problem" || recs[0]["path"] != "-" || recs[0]["line"] != 2.0 {
		t.Errorf("exit %d %s", code, out)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "findings", "F-004*")); len(m) != 0 {
		t.Error("the good record was written")
	}
}

func TestAddFromStdinPassesOtherRecords(t *testing.T) {
	fixture(t)
	stdin := `{"kind":"note", "keep":  "spacing"}` + "\n" + `{"kind":"finding","title":"New","severity":"low","targets":[{"scope":"S-12"}]}` + "\n"
	code, out, errOut := rpt(t, stdin, "finding", "add")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || len(lines) != 2 || lines[0] != `{"kind":"note", "keep":  "spacing"}` || records(t, lines[1])[0]["id"] != "F-004" {
		t.Errorf("exit %d %s %s", code, out, errOut)
	}
}

func TestAnErrorUpstreamStopsAWrite(t *testing.T) {
	dir := fixture(t)
	stdin := `{"kind":"problem","path":"x","rule":"r","level":"error","message":"broken upstream"}` + "\n" +
		`{"kind":"finding","title":"New","severity":"low","targets":[{"scope":"S-12"}]}` + "\n"
	code, out, _ := rpt(t, stdin, "finding", "add")
	if code != 1 || !strings.Contains(out, "broken upstream") || strings.Contains(out, `"kind":"finding"`) {
		t.Errorf("exit %d %s", code, out)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "findings", "F-004*")); len(m) != 0 {
		t.Error("written after an upstream error")
	}
}

func TestScopeRenameCarriesIntoFindings(t *testing.T) {
	dir := fixture(t)
	code, out, errOut := rpt(t, "", "scope", "set", "S-12", "id", "S-50")
	recs := records(t, out)
	if code != 0 || len(recs) != 2 || recs[1]["id"] != "F-003" {
		t.Fatalf("exit %d %s %s", code, out, errOut)
	}
	if !strings.Contains(read(t, filepath.Join(dir, "findings/sqli-login.md")), "S-50") {
		t.Error("finding not rewritten")
	}
}

func TestConfigGetPath(t *testing.T) {
	fixture(t)
	code, out, _ := rpt(t, "", "config", "get", "sections.poc")
	if code != 0 || !strings.Contains(out, `"sections":{"poc":"Proof of concept"}`) || strings.Contains(out, "severities") {
		t.Errorf("exit %d %s", code, out)
	}
	if code, _, _ := rpt(t, "", "config", "get", "nope"); code != 1 {
		t.Errorf("a missing path: exit %d", code)
	}
}

func TestEvidenceAddAndPrune(t *testing.T) {
	dir := fixture(t)
	src := filepath.Join(t.TempDir(), "shot.png")
	writeFile(t, src, "png")
	if code, _, errOut := rpt(t, "", "evidence", "add", "--link", "poc", "F-001", src); code != 0 {
		t.Fatal(errOut)
	}
	if !strings.Contains(read(t, filepath.Join(dir, "findings/xss-search.md")), "![shot.png](evidence/F-001-shot.png)") {
		t.Error("not linked")
	}
	writeFile(t, filepath.Join(dir, "findings/evidence/stray.png"), "x")
	code, out, _ := rpt(t, "", "evidence", "prune", "--yes")
	if code != 0 || !strings.Contains(out, "stray.png") || read(t, filepath.Join(dir, "findings/evidence/stray.png")) != "<absent>" {
		t.Errorf("prune: exit %d %s", code, out)
	}
	if read(t, filepath.Join(dir, "findings/evidence/F-001-shot.png")) != "png" {
		t.Error("pruned a linked file")
	}
}

func TestAFlagAfterTheValuesIsRefused(t *testing.T) {
	dir := fixture(t)
	before := read(t, filepath.Join(dir, "findings/xss-search.md"))
	for _, args := range [][]string{
		{"finding", "set", "F-001", "title", "New", "--dry-run"},
		{"finding", "set", "F-001", "title", "New", "--report=x"},
		{"config", "set", "x-tag.label", "v", "--if-rev", "abc"},
		{"scope", "set", "S-12", "env", "-h"},
	} {
		if code, _, errOut := rpt(t, "", args...); code != 2 || !strings.Contains(errOut, "would be written") {
			t.Errorf("rpt %v: exit %d %q", args, code, errOut)
		}
	}
	if read(t, filepath.Join(dir, "findings/xss-search.md")) != before {
		t.Error("written")
	}
	code, out, _ := rpt(t, "", "finding", "set", "--", "F-001", "title", "--dry-run")
	if code != 0 || records(t, out)[0]["title"] != "--dry-run" {
		t.Errorf("with --: exit %d %s", code, out)
	}
}
