package main

import (
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
	if got := pick(t, out, "id", "host", "port", "env"); got != "S-100 10.0.2.0/24 22 dev\n" {
		t.Errorf("stdout = %q, want the new row with the next free ID", got)
	}
	if got := readScope(t, dir); got != fixtureScope+"S-100,10.0.2.0/24,22,dev\n" {
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
	if code, _, errOut := runIn(t, "", "scope", "add", "--report", dir, "--port", "22"); code != 2 || !strings.Contains(errOut, "Run 'rpt scope add --help' for usage.") {
		t.Errorf("no --host: exit %d, stderr %q; want 2 and usage", code, errOut)
	}
}

// TestScopeLines checks that --lines gives the line each row starts on,
// counting a quoted field that spans lines and skipped blank lines, and
// that scope add ignores lines when its output is fed back in.
func TestScopeLines(t *testing.T) {
	dir := reportCopy(t)
	csv := "id,host,port,env\nS-1,a,80,\"two\nlines\"\n\nS-2,b,,prod\n"
	if err := os.WriteFile(filepath.Join(dir, "scope.csv"), []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runIn(t, "", "scope", "get", "--lines", "--json", "--report", dir)
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	file := filepath.Join(dir, "scope.csv")
	want := `{"kind":"scope","id":"S-1","host":"a","port":80,"lines":{"row":2,"file":` + strconv.Quote(file) + `},"env":"two\nlines"}` + "\n" +
		`{"kind":"scope","id":"S-2","host":"b","lines":{"row":5,"file":` + strconv.Quote(file) + `},"env":"prod"}` + "\n"
	if got := revs.ReplaceAllString(out, ""); got != want {
		t.Errorf("stdout\n%s\nwant\n%s", got, want)
	}
	if _, out, _ := runIn(t, "", "scope", "get", "--json", "--report", dir); strings.Contains(out, `"lines":`) {
		t.Errorf("without --lines, records carry lines:\n%s", out)
	}

	in := strings.ReplaceAll(strings.SplitAfter(out, "\n")[1], `"S-2"`, `"S-3"`)
	code, out, errOut = runIn(t, in, "scope", "add", "--report", dir)
	if code != 0 || strings.Contains(out, `"lines":`) || !strings.HasSuffix(readScope(t, dir), "S-3,b,,prod\n") {
		t.Errorf("scope add of a --lines record: exit %d, stdout %q, stderr %q, scope.csv %q", code, out, errOut, readScope(t, dir))
	}
}

// revs matches a record's rev member, for comparing records whole.
var revs = regexp.MustCompile(`"rev":"[0-9a-f]{16}",?`)

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
	if code != 1 || !strings.Contains(errOut, "-:3") || pick(t, out, "kind", "line", "rule") != "problem 3 write\n" {
		t.Errorf("exit %d, stdout %q, stderr %q; want 1 and a problem at stdin line 3", code, out, errOut)
	}
	if got := readScope(t, dir); got != strings.ReplaceAll(fixtureScope, "\n", "\r\n") {
		t.Errorf("scope.csv changed though a row was refused: %q", got)
	}

	in = strings.Replace(in, `{"kind":"scope","host":"h","owner":"me"}`+"\n", "", 1)
	code, out, errOut = runIn(t, in, "scope", "add", "--report", dir)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if got := pick(t, out, "kind", "id"); got != "scope S-30\nfinding \nscope S-100\n" {
		t.Errorf("stdout = %q", got)
	}
	want := strings.ReplaceAll(fixtureScope+"S-30,app.acme.com,,\"prod, eu\"\nS-100,10.9.9.9,8080,\n", "\n", "\r\n")
	if got := readScope(t, dir); got != want {
		t.Errorf("scope.csv\n%q\nwant\n%q", got, want)
	}
}

func TestScopeDelete(t *testing.T) {
	dir := reportCopy(t)
	before := folderState(t, dir)
	// S-12 is cited by F-003: refused, and nothing changes.
	code, _, errOut := runIn(t, "", "scope", "remove", "--yes", "--report", dir, "S-12")
	if code != 1 || !strings.Contains(errOut, "F-003") || !maps.Equal(before, folderState(t, dir)) {
		t.Errorf("cited row: exit %d, stderr %q; want 1, F-003 named, nothing changed", code, errOut)
	}
	code, out, errOut := runIn(t, "", "scope", "remove", "--yes", "--report", dir, "S-20", "S-404")
	if code != 1 || !strings.Contains(errOut, "S-404") || pick(t, out, "kind", "rule") != "problem exists\n" || !maps.Equal(before, folderState(t, dir)) {
		t.Errorf("exit %d, stdout %q, stderr %q; want S-404 unknown, nothing deleted, exit 1", code, out, errOut)
	}
	if code, out, errOut := runIn(t, "", "scope", "remove", "--yes", "--report", dir, "S-20"); code != 0 || pick(t, out, "id") != "S-20\n" {
		t.Errorf("exit %d, stdout %q, stderr %q; want S-20 deleted", code, out, errOut)
	}
	if code, _, errOut := runIn(t, "", "scope", "remove", "--yes", "--report", dir, "--force", "S-12"); code != 0 {
		t.Errorf("--force: exit %d, stderr %q", code, errOut)
	}
	if got := readScope(t, dir); got != "id,host,port,env\nS-14,10.0.0.6,8443,prod\n" {
		t.Errorf("scope.csv = %q", got)
	}
}

func TestScopeSetRenamePrintsTheFindings(t *testing.T) {
	dir := reportCopy(t)
	code, out, errOut := runIn(t, "", "scope", "set", "s-14", "id", "S-015", "--report", dir)
	if code != 0 || pick(t, out, "kind", "id") != "scope S-015\nfinding F-003\nfinding F-001\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if code, out, _ := runIn(t, "", "validate", "--report", dir); strings.Contains(out, "S-015") || strings.Contains(out, "S-14") {
		t.Errorf("validate after the rename: exit %d\n%s", code, out)
	}
}

func TestScopeSetNarrowing(t *testing.T) {
	dir := reportCopy(t)
	before := folderState(t, dir)
	code, out, errOut := runIn(t, "", "scope", "set", "S-14", "port", "443", "--report", dir)
	if code != 1 || pick(t, out, "rule") != "write\n" || !strings.Contains(errOut, "--cleanup") || !maps.Equal(before, folderState(t, dir)) {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	code, out, errOut = runIn(t, "", "scope", "set", "S-14", "port", "443", "--cleanup", "--report", dir)
	if code != 0 || pick(t, out, "kind", "id") != "scope S-14\nfinding F-001\n" {
		t.Errorf("--cleanup: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestScopeRemoveCleanupAsks(t *testing.T) {
	old := interactive
	interactive = func(*env) bool { return true }
	t.Cleanup(func() { interactive = old })
	dir := reportCopy(t)
	code, out, errOut := runIn(t, "y\n", "scope", "remove", "S-12", "S-20", "--cleanup", "--report", dir)
	if code != 0 || pick(t, out, "kind", "id") != "scope S-12\nfinding F-003\nscope S-20\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if !strings.Contains(unbox(errOut), "Remove 2 scope rows:\n  S-12  10.0.0.5  443\n  S-20  10.0.1.0/24\n\n--cleanup drops S-12's targets from F-003\n") {
		t.Errorf("prompt %q", errOut)
	}
}

func TestScopeNounNeedsAnAction(t *testing.T) {
	if code, _, errOut := runIn(t, "", "scope", "--report", fixture); code != 2 || !strings.Contains(errOut, "Run 'rpt scope --help' for usage.") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}
