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
	want := "a b|--report|x|--json|" + dir + " 2\n"
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
