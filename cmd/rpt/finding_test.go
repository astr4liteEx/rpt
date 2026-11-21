package main

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindingNounNeedsAnAction(t *testing.T) {
	for _, args := range [][]string{{"finding"}, {"finding", "list"}} {
		code, out, errOut := runIn(t, "", args...)
		if code != 2 || out != "" || !strings.Contains(errOut, "usage: rpt finding <action>") {
			t.Errorf("rpt %v: exit %d, stdout %q, stderr %q", args, code, out, errOut)
		}
	}
	if code, out, _ := runIn(t, "", "finding", "--help"); code != 0 || !isHelpFor(out, "finding") || !strings.Contains(out, "get [id...]") {
		t.Errorf("--help: exit %d, stdout %q", code, out)
	}
	if code, _, _ := runIn(t, "", "findings", "--report", fixture); code != 2 {
		t.Errorf("findings is gone: exit %d, want 2", code)
	}
}

func TestFindingGetByID(t *testing.T) {
	code, out, errOut := runIn(t, "", "finding", "get", "f-001", "F-003", "F-404", "--report", fixture)
	if code != 1 || pick(t, out, "kind", "id", "rule") != "finding F-001 \nfinding F-003 \nproblem  exists\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestFindingSetList(t *testing.T) {
	dir := reportCopy(t)
	code, out, errOut := runIn(t, "", "finding", "set", "F-003", "targets", "S-12", "{scope: S-20, port: 443}", "--report", dir)
	if code != 0 || !strings.Contains(out, `"targets":[{"scope":"S-12"},{"scope":"S-20","port":443}]`) {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestFindingSetIDRenamesTheFile(t *testing.T) {
	dir := reportCopy(t)
	if code, _, errOut := runIn(t, "", "finding", "add", "--title", "Telnet", "--severity", "low", "--report", dir); code != 0 {
		t.Fatalf("add: exit %d, stderr %q", code, errOut)
	}
	code, out, errOut := runIn(t, "", "finding", "set", "f-004", "id", "F-010", "--report", dir)
	if code != 0 || pick(t, out, "id", "path") != "F-010 findings/F-010-telnet.md\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if code, _, errOut := runIn(t, "", "finding", "set", "F-010", "id", "F-003", "--report", dir); code != 1 || !strings.Contains(errOut, "taken") {
		t.Errorf("a taken ID: exit %d, stderr %q", code, errOut)
	}
}

func TestAddChecksFormOnly(t *testing.T) {
	dir := reportCopy(t)
	code, out, errOut := runIn(t, "", "finding", "add", "--title", "T", "--severity", "urgent", "--report", dir)
	if code != 0 || pick(t, out, "severity") != "urgent\n" {
		t.Errorf("exit %d, stdout %q, stderr %q; validate, not add, judges the severity", code, out, errOut)
	}
}

func TestAddScaffoldsByDefault(t *testing.T) {
	dir := reportCopy(t)
	_, out, _ := runIn(t, "", "finding", "add", "--title", "T", "--severity", "low", "--report", dir)
	if !strings.Contains(out, `"description":""`) {
		t.Errorf("no scaffolded sections: %s", out)
	}
	_, out, _ = runIn(t, "", "finding", "add", "--title", "U", "--severity", "low", "--no-scaffold", "--report", dir)
	if strings.Contains(out, `"sections"`) {
		t.Errorf("--no-scaffold scaffolded: %s", out)
	}
}

func TestBrokenFileIDIsNotReused(t *testing.T) {
	dir := reportCopy(t)
	if err := os.WriteFile(filepath.Join(dir, "findings", "F-005-broken.md"), []byte("not a finding"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, out, errOut := runIn(t, "", "finding", "add", "--title", "T", "--severity", "low", "--report", dir)
	if pick(t, out, "id") != "F-006\n" {
		t.Errorf("stdout %q, stderr %q; want F-006", out, errOut)
	}
}

func TestRemoveNeedsYesWithoutATerminal(t *testing.T) {
	dir := reportCopy(t)
	before := folderState(t, dir)
	code, out, errOut := runIn(t, "", "finding", "remove", "F-003", "--report", dir)
	if code != 2 || out != "" || !strings.Contains(errOut, "rpt: finding remove: pass --yes to remove without asking") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if !maps.Equal(before, folderState(t, dir)) {
		t.Error("removed without --yes")
	}
	// --dry-run never asks, so it needs no --yes.
	if code, out, _ := runIn(t, "", "finding", "remove", "F-003", "--dry-run", "--report", dir); code != 0 || pick(t, out, "id") != "F-003\n" {
		t.Errorf("--dry-run: exit %d, stdout %q", code, out)
	}
	if !maps.Equal(before, folderState(t, dir)) {
		t.Error("--dry-run removed")
	}
}

func TestRemoveAsks(t *testing.T) {
	old := interactive
	interactive = func(*env) bool { return true }
	t.Cleanup(func() { interactive = old })
	for _, tt := range []struct {
		answer  string
		removed bool
	}{{"y\n", true}, {"YES\n", true}, {"\n", false}, {"n\n", false}, {"", false}} {
		dir := reportCopy(t)
		code, out, errOut := runIn(t, tt.answer, "finding", "remove", "F-003", "F-001", "--report", dir)
		if !strings.Contains(unbox(errOut), "Remove 2 findings:\n  F-003  SQL injection in login  findings/sqli-login.md\n") ||
			!strings.Contains(errOut, "evidence prune") || !strings.Contains(errOut, "[y/N]") {
			t.Errorf("%q: prompt %q", tt.answer, errOut)
		}
		_, err := os.Stat(filepath.Join(dir, "findings", "sqli-login.md"))
		if gone := err != nil; gone != tt.removed {
			t.Errorf("%q: removed %v, want %v", tt.answer, gone, tt.removed)
		}
		if !tt.removed && (code != 1 || out != "" || !strings.HasSuffix(errOut, "rpt: nothing removed\n")) {
			t.Errorf("%q: exit %d, stdout %q, stderr %q", tt.answer, code, out, errOut)
		}
	}
	// Checks run before asking: an unknown ID never prompts.
	dir := reportCopy(t)
	if code, _, errOut := runIn(t, "y\n", "finding", "remove", "F-404", "--report", dir); code != 1 || strings.Contains(errOut, "[y/N]") {
		t.Errorf("unknown ID: exit %d, stderr %q", code, errOut)
	}
}

func TestFindingCopiedWithAssets(t *testing.T) {
	src, dst := reportCopy(t), reportCopy(t)
	_, out, _ := runIn(t, "", "finding", "get", "--assets", "F-003", "--report", src)
	if !strings.Contains(out, `"assets":[{"ref":"evidence/F-003-login.png","path":"findings/evidence/F-003-login.png","file":"`) {
		t.Fatalf("get --assets: %s", out)
	}
	// What jq 'del(.id)' does: drop the ID so the copy takes a new one.
	in := strings.Replace(out, `"id":"F-003",`, "", 1)
	code, out, errOut := runIn(t, in, "finding", "add", "--report", dst)
	if code != 0 || pick(t, out, "id", "evidence") != "F-004 [evidence/F-004-f-003-login.png]\n" {
		t.Fatalf("add: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if _, out, _ := runIn(t, "", "validate", "--report", dst); strings.Contains(out, `"rule":"evidence`) {
		t.Errorf("validate after the copy:\n%s", out)
	}
	_, out, _ = runIn(t, "", "finding", "get", "F-004", "--report", dst)
	if !strings.Contains(out, `![login bypass](evidence/F-004-f-003-login.png)`) {
		t.Errorf("link not rewritten: %s", out)
	}
}

func TestFindingAddRefusesMissingAsset(t *testing.T) {
	dir := reportCopy(t)
	in := `{"kind":"finding","title":"T","severity":"low","targets":[{"scope":"S-12"}]}` + "\n" +
		`{"kind":"finding","title":"U","severity":"low","targets":[{"scope":"S-12"}],"assets":[{"ref":"a.png","file":"/no/such.png"}]}` + "\n"
	code, out, _ := runIn(t, in, "finding", "add", "--report", dir)
	if code != 1 || pick(t, out, "path", "line", "rule") != "- 2 evidence\n" {
		t.Errorf("exit %d, stdout %q", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "findings", "F-004-t.md")); err == nil {
		t.Error("the batch was written in part")
	}
}

// unbox gives the text inside the remove prompt's box: the border lines
// dropped, each line's side borders and padding trimmed.
func unbox(s string) string {
	var out []string
	for line := range strings.Lines(s) {
		line = strings.TrimRight(line, "\n")
		if strings.HasPrefix(line, "╭") || strings.HasPrefix(line, "╰") {
			continue
		}
		if l, ok := strings.CutPrefix(line, "│ "); ok {
			line = strings.TrimRight(strings.TrimSuffix(l, "│"), " ")
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
