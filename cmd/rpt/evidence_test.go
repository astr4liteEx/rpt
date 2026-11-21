package main

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// source writes a file outside the report to copy in.
func source(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEvidenceAdd(t *testing.T) {
	dir := reportCopy(t)
	_, before, _ := runIn(t, "", "validate", "--report", dir, "--json")
	shot := source(t, "shot.PNG", "png bytes")

	code, out, errOut := runIn(t, "", "evidence", "add", "--report", dir, "F-001", shot)
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if got := pick(t, out, "id", "evidence"); got != "F-001 [evidence/F-001-shot.png]\n" {
		t.Errorf("stdout = %q, want F-001 with its new evidence", got)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "findings/evidence/F-001-shot.png")); err != nil || string(b) != "png bytes" {
		t.Errorf("copied file = %q, %v", b, err)
	}
	// F-001 is CRLF: only an evidence line is added, with CRLF.
	b, _ := os.ReadFile(filepath.Join(dir, "findings/xss-search.md"))
	if want := "---\r\nid: F-001\r\ntitle: Reflected XSS in search\r\ntargets: [{scope: S-14, port: 8443, protocol: tcp}]\r\nseverity: medium\r\nevidence: [evidence/F-001-shot.png]\r\n---\r\n"; !strings.HasPrefix(string(b), want) {
		t.Errorf("frontmatter\n%q\nwant prefix\n%q", b, want)
	}
	if _, after, _ := runIn(t, "", "validate", "--report", dir, "--json"); after != before {
		t.Errorf("validate changed:\nbefore %s\nafter %s", before, after)
	}

	// The same name again gets -2; F-003's other lines keep their bytes.
	f3 := filepath.Join(dir, "findings/sqli-login.md")
	src3, _ := os.ReadFile(f3)
	if code, _, errOut := runIn(t, "", "evidence", "add", "--report", dir, "F-003", shot, source(t, "shot.png", "x")); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	got3, _ := os.ReadFile(f3)
	want3 := strings.Replace(string(src3), "evidence: [evidence/F-003-login.png]",
		"evidence: [evidence/F-003-login.png, evidence/F-003-shot.png, evidence/F-003-shot-2.png]", 1)
	if string(got3) != want3 {
		t.Errorf("F-003\n%s\nwant\n%s", got3, want3)
	}
	if code, _, _ := runIn(t, "", "evidence", "add", "--report", dir, "F-001", shot); code != 0 {
		t.Error("second add to F-001 failed")
	}
	if _, err := os.Stat(filepath.Join(dir, "findings/evidence/F-001-shot-2.png")); err != nil {
		t.Error(err)
	}
}

func TestEvidenceAddAs(t *testing.T) {
	dir := reportCopy(t)
	a, b := source(t, "a.txt", "a"), source(t, "b.txt", "b")
	if code, _, errOut := runIn(t, "", "evidence", "add", "--report", dir, "--as", "x.txt", "F-001", a, b); code != 2 || !strings.Contains(errOut, "usage: rpt evidence add") {
		t.Errorf("--as with two files: exit %d, stderr %q; want 2", code, errOut)
	}
	if code, _, errOut := runIn(t, "", "evidence", "add", "--report", dir, "--as", "Raw Output.TXT", "F-001", a); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	} else if _, err := os.Stat(filepath.Join(dir, "findings/evidence/Raw Output.TXT")); err != nil {
		t.Errorf("--as name not used exactly: %v", err)
	}
	for _, name := range []string{"Raw Output.TXT", "F-003-login.png", "../x", ".", "a/b"} {
		before := folderState(t, dir)
		if code, _, errOut := runIn(t, "", "evidence", "add", "--report", dir, "--as", name, "F-001", b); code != 1 {
			t.Errorf("--as %q: exit %d, stderr %q; want 1", name, code, errOut)
		}
		if !maps.Equal(before, folderState(t, dir)) {
			t.Errorf("--as %q changed the report", name)
		}
	}
}

func TestEvidenceAddRefusesBadRequests(t *testing.T) {
	good := source(t, "ok.png", "x")
	for name, args := range map[string][]string{
		"unknown ID":       {"F-404", good},
		"missing source":   {"F-001", good, filepath.Join(t.TempDir(), "nope.png")},
		"directory source": {"F-001", t.TempDir()},
	} {
		dir := reportCopy(t)
		before := folderState(t, dir)
		if code, _, errOut := runIn(t, "", append([]string{"evidence", "add", "--report", dir}, args...)...); code != 1 {
			t.Errorf("%s: exit %d, stderr %q; want 1", name, code, errOut)
		}
		if !maps.Equal(before, folderState(t, dir)) {
			t.Errorf("%s: the report changed", name)
		}
	}
}

func TestEvidenceAddRollsBackWhenTheFindingCantBeWritten(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores folder permissions")
	}
	dir := reportCopy(t)
	findings := filepath.Join(dir, "findings")
	if err := os.Chmod(findings, 0o555); err != nil { // evidence/ inside stays writable
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(findings, 0o755) })
	code, _, errOut := runIn(t, "", "evidence", "add", "--report", dir, "F-001", source(t, "shot.png", "x"))
	if code == 0 {
		t.Fatalf("exit 0, stderr %q; want a failure", errOut)
	}
	if left, _ := filepath.Glob(filepath.Join(findings, "evidence", "*")); len(left) != 1 {
		t.Errorf("evidence folder holds %v; the copied file must be removed", left)
	}
}

func TestEvidenceListOrphansAndPrune(t *testing.T) {
	dir := reportCopy(t)
	ev := filepath.Join(dir, "findings", "evidence")
	for _, f := range []string{"stray.txt", ".gitkeep", "old/nested.log"} {
		os.MkdirAll(filepath.Dir(filepath.Join(ev, f)), 0o755)
		if err := os.WriteFile(filepath.Join(ev, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errOut := runIn(t, "", "evidence", "get", "--report", dir)
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	// F-003 lists its screenshot and embeds it in its body.
	abs := filepath.Join(ev, "F-003-login.png")
	want := "F-003 frontmatter evidence/F-003-login.png findings/evidence/F-003-login.png " + abs + " true\n" +
		"F-003 body evidence/F-003-login.png findings/evidence/F-003-login.png " + abs + " true\n"
	if got := pick(t, out, "finding", "source", "ref", "path", "file", "exists"); got != want {
		t.Errorf("listed\n%s\nwant\n%s", got, want)
	}

	_, out, _ = runIn(t, "", "evidence", "get", "--report", dir, "--orphans")
	orphans := "  findings/evidence/old/nested.log\n  findings/evidence/stray.txt\n"
	if got := pick(t, out, "finding", "source", "path"); !strings.HasSuffix(got, orphans) || strings.Count(got, "\n") != 4 {
		t.Errorf("with --orphans\n%s\nwant the two references, then\n%s", got, orphans)
	}

	_, out, _ = runIn(t, "", "validate", "--report", dir, "--json")
	if got := pick(t, out, "path", "rule", "level"); !strings.Contains(got, "findings/evidence/stray.txt evidenceUnlinked warning\n") ||
		!strings.Contains(got, "findings/evidence/old/nested.log evidenceUnlinked warning\n") {
		t.Errorf("validate:\n%s\nwant an evidenceUnlinked warning per orphan", got)
	}

	before := folderState(t, dir)
	if _, out, _ = runIn(t, "", "evidence", "prune", "--report", dir, "--dry-run"); pick(t, out, "path") != "findings/evidence/old/nested.log\nfindings/evidence/stray.txt\n" || !maps.Equal(before, folderState(t, dir)) {
		t.Errorf("--dry-run: stdout %q, or it changed the report", out)
	}
	if code, out, _ = runIn(t, "", "evidence", "prune", "--yes", "--report", dir); code != 0 || strings.Count(out, "\n") != 2 {
		t.Errorf("prune: exit %d, stdout %q", code, out)
	}
	for f, want := range map[string]bool{"stray.txt": false, "old/nested.log": false, ".gitkeep": true, "F-003-login.png": true} {
		if _, err := os.Stat(filepath.Join(ev, f)); (err == nil) != want {
			t.Errorf("%s exists = %v after prune, want %v", f, err == nil, want)
		}
	}
}

func TestEvidencePruneRefusesWhenAFindingIsUnreadable(t *testing.T) {
	dir := reportCopy(t)
	// The broken file might reference stray.txt; prune can't know, so it does nothing.
	os.WriteFile(filepath.Join(dir, "findings/broken.md"), []byte("no frontmatter\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "findings/evidence/stray.txt"), []byte("x"), 0o644)
	before := folderState(t, dir)
	if code, _, errOut := runIn(t, "", "evidence", "prune", "--yes", "--report", dir); code != 1 || !strings.Contains(errOut, "broken.md") {
		t.Errorf("exit %d, stderr %q; want 1 naming broken.md", code, errOut)
	}
	if !maps.Equal(before, folderState(t, dir)) {
		t.Error("prune changed the report")
	}
}

func TestEvidenceUsage(t *testing.T) {
	for _, args := range [][]string{{"bogus"}, {}, {"add", "F-001"}, {"get", "--orphans", "F-001"}, {"prune"}} {
		if code, _, _ := runIn(t, "", append([]string{"evidence"}, args...)...); code != 2 {
			t.Errorf("rpt evidence %v: exit %d, want 2", args, code)
		}
	}
}

func TestEvidenceAddLinksInOneWrite(t *testing.T) {
	dir := reportCopy(t)
	shot := source(t, "shot.png", "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	code, out, errOut := runIn(t, "", "evidence", "add", "F-001", shot, "--link", "poc", "--text", "Login bypass", "--report", dir)
	if code != 0 || pick(t, out, "kind", "id") != "finding F-001\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	_, out, _ = runIn(t, "", "evidence", "get", "F-001", "--report", dir)
	if got := pick(t, out, "source", "text", "image", "section", "media_type"); got != "frontmatter    image/png\nbody Login bypass true poc image/png\n" {
		t.Errorf("evidence get: %q", got)
	}
}

func TestEvidenceAddFromRecords(t *testing.T) {
	dir := reportCopy(t)
	shot := source(t, "chart.png", "x")
	in := `{"kind":"evidence","finding":"f-001","file":"` + shot + `"}` + "\n" + `{"kind":"note"}` + "\n"
	code, out, errOut := runIn(t, in, "evidence", "add", "--report", dir)
	if code != 0 || pick(t, out, "kind") != "finding\nnote\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if code, out, _ := runIn(t, `{"kind":"evidence","finding":"F-001"}`+"\n", "evidence", "add", "--report", dir); code != 1 || pick(t, out, "rule") != "input\n" {
		t.Errorf("no file: exit %d, stdout %q", code, out)
	}
}

func TestEvidenceRemoveAsksAndDetaches(t *testing.T) {
	dir := reportCopy(t)
	if code, _, errOut := runIn(t, "", "evidence", "remove", "F-003", "evidence/F-003-login.png", "--report", dir); code != 2 || !strings.Contains(errOut, "--yes") {
		t.Errorf("off a terminal: exit %d, stderr %q", code, errOut)
	}
	code, out, errOut := runIn(t, "", "evidence", "remove", "F-003", "evidence/F-003-login.png", "--yes", "--report", dir)
	if code != 0 || pick(t, out, "id", "evidence") != "F-003 \n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "findings/evidence/F-003-login.png")); err != nil {
		t.Error("the file went")
	}
	_, out, _ = runIn(t, "", "evidence", "get", "--orphans", "--report", dir)
	if !strings.Contains(out, `"path":"findings/evidence/F-003-login.png"`) {
		t.Errorf("not an orphan now: %s", out)
	}
}

func TestEvidenceSetCaptionAndPath(t *testing.T) {
	dir := reportCopy(t)
	if code, _, errOut := runIn(t, "", "evidence", "set", "F-003", "evidence/F-003-login.png", "caption", "Bypass", "--report", dir); code != 0 {
		t.Fatalf("caption: exit %d, stderr %q", code, errOut)
	}
	code, out, errOut := runIn(t, "", "evidence", "set", "F-003", "evidence/F-003-login.png", "path", "evidence/login.png", "--report", dir)
	if code != 0 || pick(t, out, "id", "evidence") != "F-003 [evidence/login.png]\n" {
		t.Fatalf("path: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	_, out, _ = runIn(t, "", "evidence", "get", "F-003", "--report", dir)
	if got := pick(t, out, "ref", "text"); got != "evidence/login.png \nevidence/login.png Bypass\n" {
		t.Errorf("get: %q", got)
	}
	if code, _, _ := runIn(t, "", "evidence", "unset", "F-003", "evidence/login.png", "caption", "--report", dir); code != 0 {
		t.Errorf("unset caption: exit %d", code)
	}
}

func TestEvidencePruneAsks(t *testing.T) {
	old := interactive
	interactive = func(*env) bool { return true }
	t.Cleanup(func() { interactive = old })
	for _, tt := range []struct {
		answer  string
		removed bool
	}{{"y\n", true}, {"n\n", false}} {
		dir := reportCopy(t)
		stray := filepath.Join(dir, "pages", "evidence", "stray.txt")
		os.MkdirAll(filepath.Dir(stray), 0o755)
		os.WriteFile(stray, []byte("x"), 0o644)
		code, _, errOut := runIn(t, tt.answer, "evidence", "prune", "--report", dir)
		if !strings.Contains(errOut, "pages/evidence/stray.txt") || !strings.Contains(errOut, "[y/N]") {
			t.Errorf("%q: prompt %q", tt.answer, errOut)
		}
		_, err := os.Stat(stray)
		if gone := err != nil; gone != tt.removed || (code == 0) != tt.removed {
			t.Errorf("%q: exit %d, removed %v", tt.answer, code, gone)
		}
	}
}
