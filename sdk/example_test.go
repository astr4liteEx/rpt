package sdk_test

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

// rptBin is rpt built for these tests, so Call and Settings have
// something to call. It is empty outside the rpt repository (the SDK
// module on its own), and the tests that need it skip.
var rptBin string

func TestMain(m *testing.M) {
	if _, err := os.Stat("../cmd/rpt"); err != nil {
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "sdk-test")
	if err != nil {
		panic(err)
	}
	rptBin = filepath.Join(dir, "rpt")
	// rpt is another module: build it from its own folder, where go.work
	// points it at this SDK.
	build := exec.Command("go", "-C", "..", "build", "-o", rptBin, "./cmd/rpt")
	build.Env = append(os.Environ(), "GOWORK=") // the repository's go.work, even under GOWORK=off
	if out, err := build.CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		panic(fmt.Sprintf("build rpt: %v\n%s", err, out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// worked is set when the example plugin's Run does any work.
var worked bool

// tagPlugin tags each finding record on stdin with x-tag-label, from its
// settings (default "triaged"), and ends with a warning counting the
// report's scope rows. It uses every helper the SDK has.
var tagPlugin = sdk.Plugin{
	Description: sdk.Description{
		Summary:  "Tag findings with a label",
		Usage:    "rpt tag < findings.jsonl",
		Input:    "records",
		Output:   "records",
		Roles:    []string{sdk.RoleFilter},
		Requires: &sdk.Requires{SchemaVersion: &sdk.Range{Min: 2}},
		Schemas:  &sdk.Schemas{Finding: map[string]jsontext.Value{"x-tag-label": jsontext.Value(`{"type":"string"}`)}},
	},
	Complete: func(args []string, word string) []string {
		return []string{"--label\tthe label to set"}
	},
	Run: func(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
		worked = true
		settings := struct {
			Label string `json:"label"`
		}{Label: "triaged"}
		if err := sdk.Settings("tag", &settings); err != nil {
			fmt.Fprintln(stderr, "rpt-tag:", err)
			return 1
		}
		for rec, err := range sdk.Records(stdin, sdk.StopAtError()) {
			if errors.Is(err, sdk.ErrStopped) {
				stdout.Write(append(rec.Raw, '\n')) // pass it on; write nothing of our own
				return 1
			}
			if err != nil {
				fmt.Fprintln(stderr, "rpt-tag:", err)
				return 1
			}
			raw := rec.Raw
			if rec.Kind == "finding" {
				if raw, err = sdk.SetMember(raw, "x-tag-label", settings.Label); err != nil {
					fmt.Fprintln(stderr, "rpt-tag:", err)
					return 1
				}
			}
			stdout.Write(append(raw, '\n'))
		}
		res, err := sdk.Call(context.Background(), nil, "scope", "get")
		if err != nil || res.Code != 0 {
			fmt.Fprintln(stderr, "rpt-tag:", err, res.Stderr)
			return 1
		}
		sdk.Emit(stdout, sdk.Problem{Kind: "problem", Path: ".", Rule: "tag", Level: sdk.Warning,
			Message: fmt.Sprintf("%d scope rows", len(res.Records))})
		return 0
	},
}

// report copies the fixture and points the plugin at it, as rpt would.
func report(t *testing.T) string {
	t.Helper()
	if rptBin == "" {
		t.Skip("needs the rpt repository")
	}
	dir := filepath.Join(t.TempDir(), "r")
	if err := os.CopyFS(dir, os.DirFS("../testdata/fixture")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RPT_BIN", rptBin)
	t.Setenv("RPT_REPORT_DIR", dir)
	return dir
}

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	worked = false
	var out, errOut bytes.Buffer
	code := sdk.Run(tagPlugin, args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestExamplePlugin(t *testing.T) {
	dir := report(t)
	if out, err := exec.Command(rptBin, "--report", dir, "config", "set", "x-tag.label", "verified").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	code, out, errOut := run(t, `{"kind":"finding","id":"F-001"}`+"\n"+`{"kind":"note"}`+"\n")
	want := `{"kind":"finding","id":"F-001","x-tag-label":"verified"}` + "\n" + `{"kind":"note"}` + "\n" +
		`{"kind":"problem","path":".","rule":"tag","level":"warning","message":"3 scope rows"}` + "\n"
	if code != 0 || out != want {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestExamplePluginStopsAtAnError(t *testing.T) {
	report(t)
	in := `{"kind":"problem","path":"x","rule":"r","level":"error","message":"m"}` + "\n" + `{"kind":"finding","id":"F-001"}` + "\n"
	code, out, _ := run(t, in)
	if code != 1 || out != strings.SplitAfter(in, "\n")[0] {
		t.Errorf("exit %d, stdout %q", code, out)
	}
}

func TestRunAnswersWithoutWork(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"--help"}, "Usage: rpt tag < findings.jsonl\n\nTag findings with a label\n"},
		{[]string{"__complete", "F-001", "--l"}, "--label\tthe label to set\n:4\n"},
		{[]string{"__completeNoDesc", ""}, "--label\n:4\n"},
		{[]string{"--describe"}, `{"summary":"Tag findings with a label","usage":"rpt tag < findings.jsonl","input":"records","output":"records","roles":["filter"],"schemas":{"finding":{"x-tag-label":{"type":"string"}}},"requires":{"schema_version":{"min":2}}}` + "\n"},
	} {
		code, out, _ := run(t, "", tt.args...)
		if code != 0 || out != tt.want || worked {
			t.Errorf("%v: exit %d, worked %v, stdout %q", tt.args, code, worked, out)
		}
	}
	p := tagPlugin
	p.Complete = nil
	var out bytes.Buffer
	if sdk.Run(p, []string{"__complete", ""}, nil, &out, io.Discard); out.String() != ":0\n" {
		t.Errorf("no Complete: %q", out.String())
	}
}

func TestCallStale(t *testing.T) {
	report(t)
	res, err := sdk.Call(context.Background(), nil, "finding", "set", "--if-rev", "0000", "F-001", "title", "New")
	if err != nil || res.Code != 1 || !res.Stale() || len(res.Problems()) != 1 {
		t.Errorf("%+v, %v", res, err)
	}
}

func ExampleRange_String() {
	for _, r := range []*sdk.Range{nil, {Min: 2}, {Max: 1}, {Min: 2, Max: 2}, {Min: 2, Max: 3}} {
		fmt.Println(r)
	}
	// Output:
	// any
	// 2 or later
	// up to 1
	// 2
	// 2 to 3
}

func TestNullSettingsKeepTheDefaults(t *testing.T) {
	dir := report(t)
	if out, err := exec.Command(rptBin, "--report", dir, "config", "set", "x-tag", "null").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	_, out, errOut := run(t, `{"kind":"finding","id":"F-001"}`+"\n")
	if !strings.Contains(out, `"x-tag-label":"triaged"`) {
		t.Errorf("stdout %q, stderr %q", out, errOut)
	}
}
