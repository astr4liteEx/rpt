package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScopeMatch(t *testing.T) {
	fixture(t)
	stdin := `{"kind":"finding","title":"A","severity":"high","targets":[{"host":"10.0.0.5","port":443}],"x-keep":1}` + "\n" +
		`{"kind":"finding","title":"B","severity":"low","targets":[{"host":"192.168.9.9"}]}` + "\n" +
		`{"kind":"note"}` + "\n"
	code, out, errOut := rpt(t, stdin, "scope", "match", "--drop-out-of-scope")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || len(lines) != 4 || !strings.Contains(lines[0], `"targets":[{"scope":"S-12","port":443}]`) || !strings.Contains(lines[0], `"x-keep":1`) ||
		lines[1] != `{"kind":"note"}` || !strings.Contains(lines[2]+lines[3], "dropped") {
		t.Errorf("exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestValidateStream(t *testing.T) {
	fixture(t)
	good := `{"kind":"finding","title":"A","severity":"high","targets":[{"scope":"S-12"}],"sections":{"description":"d","remediation":"r","poc":"p"}}` + "\n"
	code, out, _ := rpt(t, good, "validate", "-")
	if code != 0 || out != good {
		t.Errorf("a clean stream: exit %d %q", code, out)
	}
	bad := `{"kind":"finding","id":"F-001","title":"A","severity":"high","targets":[{"scope":"S-404"}]}` + "\n"
	code, out, _ = rpt(t, bad, "validate", "-")
	recs := records(t, out)
	if code != 1 || len(recs) == 0 || recs[0]["kind"] != "problem" || strings.Contains(out, `"kind":"finding"`) {
		t.Errorf("a bad stream: exit %d %s", code, out)
	}
}

func TestAssemble(t *testing.T) {
	fixture(t)
	code, out, errOut := rpt(t, "", "assemble")
	recs := records(t, out)
	if code != 0 || recs[0]["kind"] != "report" || !strings.Contains(errOut, "S-99") {
		t.Errorf("exit %d %s %s", code, out[:min(len(out), 200)], errOut)
	}
}

func TestNewAndLs(t *testing.T) {
	src := fixture(t)
	t.Setenv("RPT_REPORT_DIR", "")
	root := t.TempDir()
	dir := filepath.Join(root, "a", "r")
	if code, _, errOut := rpt(t, "", "new", "--like", src, dir); code != 0 {
		t.Fatal(errOut)
	}
	if read(t, filepath.Join(dir, "rpt.yaml")) != read(t, filepath.Join(src, "rpt.yaml")) {
		t.Error("--like didn't copy rpt.yaml")
	}
	if code, _, _ := rpt(t, "", "new", dir); code != 1 {
		t.Error("new over a report")
	}
	code, out, _ := rpt(t, "", "ls", root)
	if recs := records(t, out); code != 0 || len(recs) != 1 || recs[0]["findings"] != 0.0 {
		t.Errorf("ls: exit %d %s", code, out)
	}
	if code, _, _ := rpt(t, "", "ls", "--report", dir); code != 2 {
		t.Error("--report without --current")
	}
}

func TestHelpListsPlugins(t *testing.T) {
	fixture(t)
	plugins(t, map[string]string{
		"tag":     `echo '{"summary":"Tag findings"}'`,
		"old":     `echo '{"summary":"Old","requires":{"format":{"max":1}}}'`,
		"finding": `echo '{"summary":"shadowed"}'`,
	})
	_, out, _ := rpt(t, "", "help")
	if !strings.Contains(out, `"name":"tag"`) || !strings.Contains(out, "Tag findings") || strings.Contains(out, `"name":"old"`) || strings.Contains(out, "shadowed") {
		t.Errorf("help: %s", out)
	}
	_, out, _ = rpt(t, "", "help", "--all")
	if !strings.Contains(out, `"incompatible":true`) || !strings.Contains(out, `"shadowed":true`) {
		t.Errorf("help --all: %s", out)
	}
}

func TestPluginRunsWithItsArgumentsAndEnvironment(t *testing.T) {
	dir := fixture(t)
	plugins(t, map[string]string{"echo": `printf '%s|' "$@"; echo "$RPT_REPORT_DIR $RPT_SCHEMA_VERSION"; exit 3`})
	code, _, _ := rpt(t, "", "echo", "a b", "--report", "x", "--json")
	want := "a b|--report|x|--json|" + dir + " 3\n"
	if code != 3 || pluginOut.String() != want {
		t.Errorf("exit %d, plugin printed %q, want %q", code, pluginOut.String(), want)
	}
}

func TestIncompatiblePluginWarns(t *testing.T) {
	fixture(t)
	plugins(t, map[string]string{"old": `[ "$1" = --describe ] && echo '{"summary":"s","requires":{"schema_version":{"max":1}}}'; exit 0`})
	code, _, errOut := rpt(t, "", "old")
	if code != 0 || strings.Count(errOut, "may not work with this rpt") != 1 || !strings.Contains(errOut, "up to 1") {
		t.Errorf("exit %d %q", code, errOut)
	}
}

func TestValidateChecksPluginSchemas(t *testing.T) {
	dir := fixture(t)
	plugins(t, map[string]string{"api": `echo '{"summary":"s","schemas":{"finding":{"x-api-id":{"type":"integer"}}}}'`})
	f := filepath.Join(dir, "findings/sqli-login.md")
	b, _ := os.ReadFile(f)
	writeFile(t, f, strings.Replace(string(b), "cvss:", "x-api-id: seven\ncvss:", 1))
	_, out, _ := rpt(t, "", "validate")
	if !strings.Contains(out, `"rule":"pluginSchema"`) || !strings.Contains(out, "x-api-id: got string, want integer (schema from api)") {
		t.Errorf("%s", out)
	}
}

// A plugin's help is rendered from its --describe answer, the same way
// whichever form asks for it.
func TestHelpForAPlugin(t *testing.T) {
	fixture(t)
	plugins(t, map[string]string{"tag": `echo '{"summary":"Tag findings","usage":"rpt tag < findings.jsonl"}'`})
	_, want, _ := rpt(t, "", "help", "tag")
	if !strings.Contains(want, "Tag findings") || !strings.Contains(want, "rpt tag < findings.jsonl") {
		t.Fatalf("help tag: %q", want)
	}
	for _, args := range [][]string{{"--help", "tag"}, {"-h", "tag"}, {"--report", ".", "--help", "tag"}} {
		if code, out, _ := rpt(t, "", args...); code != 0 || out != want {
			t.Errorf("rpt %v: exit %d %q", args, code, out)
		}
	}
	if code, out, _ := rpt(t, "", "--help", "finding"); code != 0 || !strings.Contains(out, "Get, add, set, unset and remove findings") {
		t.Errorf("--help finding: exit %d %q", code, out)
	}
}

// recordLines splits output into its problem lines and its other lines.
func recordLines(out string) (recs, problems []string) {
	for _, l := range strings.SplitAfter(out, "\n") {
		switch {
		case l == "":
		case strings.HasPrefix(l, `{"kind":"problem"`):
			problems = append(problems, l)
		default:
			recs = append(recs, l)
		}
	}
	return recs, problems
}

func TestValidateRecordsIsTheGetsFromOneRead(t *testing.T) {
	dir := fixture(t)
	writeFile(t, filepath.Join(dir, "pages/P-001-summary.md"), "---\nid: P-001\ntitle: Summary\n---\n\nSee ![the login](evidence/login.png).\n")
	writeFile(t, filepath.Join(dir, "pages/evidence/login.png"), "png")
	writeFile(t, filepath.Join(dir, "findings/evidence/orphan.png"), "png")

	var want []string
	for _, args := range [][]string{
		{"config", "get", "--lines"},
		{"finding", "get", "--lines"},
		{"page", "get", "--lines"},
		{"scope", "get", "--lines"},
		{"evidence", "get", "--orphans"},
	} {
		_, out, _ := rpt(t, "", args...)
		recs, _ := recordLines(out)
		want = append(want, recs...)
	}
	_, plain, _ := rpt(t, "", "validate")
	_, wantProblems := recordLines(plain)

	code, out, errOut := rpt(t, "", "validate", "--records")
	recs, problems := recordLines(out)
	if code != 1 || strings.Join(recs, "") != strings.Join(want, "") {
		t.Errorf("exit %d; records\n%s\nwant\n%s\nstderr %s", code, strings.Join(recs, ""), strings.Join(want, ""), errOut)
	}
	if strings.Join(problems, "") != strings.Join(wantProblems, "") || len(problems) == 0 {
		t.Errorf("problems\n%s\nwant validate's\n%s", strings.Join(problems, ""), strings.Join(wantProblems, ""))
	}
	if !strings.HasPrefix(recs[0], `{"kind":"config"`) || !strings.HasPrefix(out[len(strings.Join(recs, "")):], `{"kind":"problem"`) {
		t.Errorf("want the config first and the problems last:\n%s", out)
	}
	for _, kind := range []string{"finding", "page", "scope", "evidence"} {
		if !strings.Contains(out, `{"kind":"`+kind+`"`) {
			t.Errorf("no %s record", kind)
		}
	}
}

func TestValidateRecordsWithIDs(t *testing.T) {
	fixture(t)
	code, out, _ := rpt(t, "", "validate", "--records", "F-002", "S-12")
	recs, problems := recordLines(out)
	_, findingOut, _ := rpt(t, "", "finding", "get", "--lines", "F-002")
	_, scopeOut, _ := rpt(t, "", "scope", "get", "--lines", "S-12")
	if code != 1 || strings.Join(recs, "") != findingOut+scopeOut || len(problems) != 1 || !strings.Contains(problems[0], "S-99") {
		t.Errorf("exit %d\n%s", code, out)
	}
	if code, out, _ := rpt(t, "", "validate", "--records", "F-404"); code != 1 || strings.Contains(out, `"kind":"finding"`) {
		t.Errorf("an unknown ID: exit %d %s", code, out)
	}
	if code, _, _ := rpt(t, "", "validate", "--records", "-"); code != 2 {
		t.Errorf("--records with stdin: exit %d, want 2", code)
	}
}

func TestValidateRecordsLeavesOutWhatDoesntRead(t *testing.T) {
	dir := fixture(t)
	writeFile(t, filepath.Join(dir, "findings/broken.md"), "---\nid: [\n---\n")
	writeFile(t, filepath.Join(dir, "findings/evidence/orphan.png"), "png")
	code, out, _ := rpt(t, "", "validate", "--records")
	recs, problems := recordLines(out)
	got := strings.Join(recs, "")
	if code != 1 || strings.Count(got, `"kind":"finding"`) != 3 || strings.Contains(got, "orphan.png") {
		t.Errorf("exit %d\n%s", code, got)
	}
	if !strings.Contains(strings.Join(problems, ""), "findings/broken.md") {
		t.Errorf("the broken file has no problem:\n%s", strings.Join(problems, ""))
	}
}
