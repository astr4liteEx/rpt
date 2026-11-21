package report

import (
	"encoding/json/v2"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

// record decodes a finding record the way rpt findings add receives it.
func record(t *testing.T, line string) sdk.Finding {
	t.Helper()
	var f sdk.Finding
	if err := json.Unmarshal([]byte(line), &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// snapshot reads every file under dir, so a test can tell whether anything
// in the folder changed.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		info, _ := d.Info()
		files[p] = info.Mode().String() + info.ModTime().String() + "\n" + string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func openCopy(t *testing.T) (*Report, string) {
	t.Helper()
	dir := copyFixture(t)
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r, dir
}

const parsed = `{"kind":"finding","title":"Telnet enabled: plaintext logins (port 23)!",` +
	`"targets":[{"scope":"S-20","host":"10.0.1.9","port":23,"protocol":"tcp"},{"scope":"S-12"}],"severity":"high",` +
	`"sections":{"description":"Telnet accepts logins in plaintext.","poc":"nc 10.0.1.9 23","remediation":"Disable telnet.","References":"RFC 854"},` +
	`"source":{"plugin":"nuclei","template":"telnet-detect"}}`

func TestAddNew(t *testing.T) {
	r, dir := openCopy(t)
	f, err := r.Add(record(t, parsed))
	if err != nil {
		t.Fatal(err)
	}
	const want = "findings/F-004-telnet-enabled-plaintext-logins-port-23.md"
	if f.ID != "F-004" || f.Path != want {
		t.Fatalf("added %s at %s, want F-004 at %s", f.ID, f.Path, want)
	}
	got, err := os.ReadFile(filepath.Join(dir, want))
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "add/new", got)
}

func TestAddTwiceAddsTwo(t *testing.T) {
	r, _ := openCopy(t)
	first, err := r.Add(record(t, parsed))
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Add(record(t, parsed))
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != "F-004" || second.ID != "F-005" {
		t.Errorf("IDs = %s, %s; want F-004, F-005", first.ID, second.ID)
	}
}

func TestAddNames(t *testing.T) {
	tests := []struct{ rec, wantPath string }{
		{`{"kind":"finding","id":"F-010","title":"Énumération des utilisateurs","targets":[],"severity":"low"}`, "findings/F-010-num-ration-des-utilisateurs.md"},
		{`{"kind":"finding","title":"!!!","targets":[],"severity":"low"}`, "findings/F-004-finding.md"},
		{`{"kind":"finding","title":"A very long title that goes on and on about one single small problem","targets":[],"severity":"low"}`,
			"findings/F-004-a-very-long-title-that-goes-on-and-on-about-one.md"},
	}
	for _, tt := range tests {
		r, _ := openCopy(t)
		f, err := r.Add(record(t, tt.rec))
		if err != nil {
			t.Fatal(err)
		}
		if f.Path != tt.wantPath {
			t.Errorf("path = %s, want %s", f.Path, tt.wantPath)
		}
	}
}

func TestAddRefuses(t *testing.T) {
	tests := []struct{ name, rec string }{
		{"no title", `{"kind":"finding","targets":[],"severity":"low"}`},
		{"no severity", `{"kind":"finding","title":"t","targets":[]}`},
		{"malformed id", `{"kind":"finding","id":"F-7","title":"t","targets":[],"severity":"low"}`},
		{"id already taken", `{"kind":"finding","id":"F-003","title":"t","targets":[],"severity":"low"}`},
		{"target without scope", `{"kind":"finding","title":"t","targets":[{"port":22}],"severity":"low"}`},
		{"target attributed by host only", `{"kind":"finding","title":"t","targets":[{"host":"10.0.0.5"}],"severity":"low"}`},
		{"format 1 scope", `{"kind":"finding","title":"t","scope":["S-12"],"severity":"low"}`},
		{"format 1 target", `{"kind":"finding","title":"t","targets":[],"severity":"low","target":{"host":"a"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, dir := openCopy(t)
			before := snapshot(t, dir)
			if _, err := r.Add(record(t, tt.rec)); !errors.Is(err, ErrBadValue) {
				t.Errorf("err = %v, want ErrBadValue", err)
			}
			if after := snapshot(t, dir); !maps.Equal(before, after) {
				t.Error("a refused record changed the folder")
			}
		})
	}
}

// A severity the report doesn't define is rpt validate's to report, not
// add's (ADR 0008).
func TestAddChecksFormOnly(t *testing.T) {
	r, _ := openCopy(t)
	if _, err := r.Add(record(t, `{"kind":"finding","title":"t","severity":"urgent"}`)); err != nil {
		t.Errorf("err = %v, want the finding added", err)
	}
}
