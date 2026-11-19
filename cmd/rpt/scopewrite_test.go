package main

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureScope = "id,host,port,env\nS-12,10.0.0.5,443,prod\nS-14,10.0.0.6,8443,prod\nS-20,10.0.1.0/24,,staging\n"

func readScope(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "scope.csv"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestScopeAddFromFlags(t *testing.T) {
	dir := reportCopy(t)
	code, out, errOut := runIn(t, "", "scope", "add", "--report", dir, "--host", "10.0.2.0/24", "--port", "22", "--col", "env=dev")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if got := pick(t, out, "id", "host", "port", "env"); got != "S-21 10.0.2.0/24 22 dev\n" {
		t.Errorf("stdout = %q, want the new row with the next free ID", got)
	}
	if got := readScope(t, dir); got != fixtureScope+"S-21,10.0.2.0/24,22,dev\n" {
		t.Errorf("scope.csv = %q", got)
	}
}

func TestScopeAddRefusesWhatTheHeaderLacks(t *testing.T) {
	for _, args := range [][]string{
		{"--host", "h", "--protocol", "tcp"}, // the fixture header has no protocol column
		{"--host", "h", "--col", "owner=me"},
		{"--host", "h", "--id", "S-12"}, // taken
	} {
		dir := reportCopy(t)
		code, _, errOut := runIn(t, "", append([]string{"scope", "add", "--report", dir}, args...)...)
		if code != 1 || readScope(t, dir) != fixtureScope {
			t.Errorf("%v: exit %d, stderr %q; want 1 and scope.csv unchanged", args, code, errOut)
		}
	}
	dir := reportCopy(t)
	if code, _, errOut := runIn(t, "", "scope", "add", "--report", dir, "--port", "22"); code != 2 || !strings.Contains(errOut, "usage: rpt scope add") {
		t.Errorf("no --host: exit %d, stderr %q; want 2 and usage", code, errOut)
	}
}

func TestScopeAddFromStdin(t *testing.T) {
	dir := reportCopy(t)
	if err := os.WriteFile(filepath.Join(dir, "scope.csv"), []byte(strings.ReplaceAll(fixtureScope, "\n", "\r\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	in := `{"kind":"scope","id":"S-30","host":"app.acme.com","env":"prod, eu"}` + "\n" +
		`{"kind":"finding","title":"passes through"}` + "\n" +
		`{"kind":"scope","host":"h","owner":"me"}` + "\n" + // refused: no owner column
		`{"kind":"scope","host":"10.9.9.9","port":8080}` + "\n"
	code, out, errOut := runIn(t, in, "scope", "add", "--report", dir)
	if code != 1 || !strings.Contains(errOut, "stdin:3") {
		t.Errorf("exit %d, stderr %q; want 1 naming stdin line 3", code, errOut)
	}
	if got := pick(t, out, "kind", "id"); got != "scope S-30\nfinding \nscope S-31\n" {
		t.Errorf("stdout = %q", got)
	}
	want := strings.ReplaceAll(fixtureScope+"S-30,app.acme.com,,\"prod, eu\"\nS-31,10.9.9.9,8080,\n", "\n", "\r\n")
	if got := readScope(t, dir); got != want {
		t.Errorf("scope.csv\n%q\nwant\n%q", got, want)
	}
}

func TestScopeDelete(t *testing.T) {
	dir := reportCopy(t)
	before := folderState(t, dir)
	// S-12 is cited by F-003: refused, and nothing changes.
	code, _, errOut := runIn(t, "", "scope", "delete", "--report", dir, "S-12")
	if code != 1 || !strings.Contains(errOut, "F-003") || !maps.Equal(before, folderState(t, dir)) {
		t.Errorf("cited row: exit %d, stderr %q; want 1, F-003 named, nothing changed", code, errOut)
	}
	code, out, errOut := runIn(t, "", "scope", "delete", "--report", dir, "S-20", "S-404")
	if code != 1 || !strings.Contains(errOut, "S-404") || pick(t, out, "id") != "S-20\n" {
		t.Errorf("exit %d, stdout %q, stderr %q; want S-20 deleted, S-404 unknown, exit 1", code, out, errOut)
	}
	if code, _, errOut := runIn(t, "", "scope", "delete", "--report", dir, "--force", "S-12"); code != 0 {
		t.Errorf("--force: exit %d, stderr %q", code, errOut)
	}
	if got := readScope(t, dir); got != "id,host,port,env\nS-14,10.0.0.6,8443,prod\n" {
		t.Errorf("scope.csv = %q", got)
	}
}
