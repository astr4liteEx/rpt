package report

import (
	"encoding/json/v2"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

// record decodes a finding record the way rpt add receives it.
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

const parsed = `{"kind":"finding","key":"9c1d0e7f2a3b4c5d","title":"Telnet enabled: plaintext logins (port 23)!",` +
	`"scope":["S-20"],"severity":"high","target":{"host":"10.0.1.9","port":23,"protocol":"tcp"},` +
	`"sections":{"description":"Telnet accepts logins in plaintext.","poc":"nc 10.0.1.9 23","remediation":"Disable telnet.","References":"RFC 854"},` +
	`"source":{"plugin":"nuclei","template":"telnet-detect"}}`

func TestAddNew(t *testing.T) {
	r, dir := openCopy(t)
	res, err := r.Add(record(t, parsed), AddOptions{Staging: true, Upsert: true})
	if err != nil {
		t.Fatal(err)
	}
	const want = "staging/F-006-telnet-enabled-plaintext-logins-port-23.md"
	if res.Skipped || res.Finding.ID != "F-006" || res.Finding.Path != want {
		t.Fatalf("result = %+v, want F-006 written to %s", res, want)
	}
	got, err := os.ReadFile(filepath.Join(dir, want))
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "add/new-staged", got)
}

func TestAddUpsertTwiceLeavesFolderUnchanged(t *testing.T) {
	r, dir := openCopy(t)
	if _, err := r.Add(record(t, parsed), AddOptions{Staging: true, Upsert: true}); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dir)
	res, err := r.Add(record(t, parsed), AddOptions{Staging: true, Upsert: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Finding.ID != "F-006" {
		t.Errorf("second run gave %s, want the same F-006", res.Finding.ID)
	}
	if after := snapshot(t, dir); !maps.Equal(before, after) {
		t.Error("second upsert changed the folder")
	}
}

func TestAddUpsertUpdatesInPlace(t *testing.T) {
	r, dir := openCopy(t)
	// A reviewer's comment and extra key in the staged file must survive.
	const rel = "staging/F-004-ssh-weak-ciphers.md"
	src, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, rel, "---\nreviewer: lite  # checked twice\n"+strings.TrimPrefix(string(src), "---\n"))
	rec := record(t, `{"kind":"finding","id":"F-999","key":"2617ba239ba6c4fa","title":"SSH weak ciphers","scope":["S-20"],"severity":"high",`+
		`"sections":{"description":"The SSH server offers CBC-mode and arcfour ciphers."}}`)
	res, err := r.Add(rec, AddOptions{Staging: true, Upsert: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Finding.ID != "F-004" || res.Finding.Path != rel {
		t.Errorf("result = %s at %s, want F-004 kept at %s", res.Finding.ID, res.Finding.Path, rel)
	}
	got, _ := os.ReadFile(filepath.Join(dir, rel))
	checkGolden(t, "add/upsert-staged", got)
}

func TestAddUpsertSkipsReviewed(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		staging  bool
		wantPath string
	}{
		{"rejected stays rejected", "01b9b837704da8cf", true, "rejected/F-005-open-redirect.md"},
		{"writing to findings/ leaves the staged copy", "2617ba239ba6c4fa", false, "staging/F-004-ssh-weak-ciphers.md"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, dir := openCopy(t)
			before := snapshot(t, dir)
			rec := record(t, `{"kind":"finding","key":"`+tt.key+`","title":"Anything","scope":[],"severity":"low"}`)
			res, err := r.Add(rec, AddOptions{Staging: tt.staging, Upsert: true})
			if err != nil {
				t.Fatal(err)
			}
			if !res.Skipped || res.Finding.Path != tt.wantPath {
				t.Errorf("result = %+v, want skipped because of %s", res, tt.wantPath)
			}
			if after := snapshot(t, dir); !maps.Equal(before, after) {
				t.Error("a skipped record changed the folder")
			}
		})
	}
}

func TestAddWithoutUpsertOrKeyIsAlwaysNew(t *testing.T) {
	for _, tt := range []struct {
		name string
		rec  string
		opts AddOptions
	}{
		{"no key, with --upsert", `{"kind":"finding","title":"Weak password policy","scope":[],"severity":"medium"}`, AddOptions{Upsert: true}},
		{"key, without --upsert", `{"kind":"finding","key":"2617ba239ba6c4fa","title":"SSH weak ciphers","scope":["S-20"],"severity":"medium"}`, AddOptions{Staging: true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := openCopy(t)
			first, err := r.Add(record(t, tt.rec), tt.opts)
			if err != nil {
				t.Fatal(err)
			}
			second, err := r.Add(record(t, tt.rec), tt.opts)
			if err != nil {
				t.Fatal(err)
			}
			if first.Finding.ID != "F-006" || second.Finding.ID != "F-007" {
				t.Errorf("IDs = %s, %s; want F-006, F-007", first.Finding.ID, second.Finding.ID)
			}
		})
	}
}

func TestAddNames(t *testing.T) {
	tests := []struct{ rec, wantPath string }{
		{`{"kind":"finding","id":"F-010","title":"Énumération des utilisateurs","scope":[],"severity":"low"}`, "findings/F-010-num-ration-des-utilisateurs.md"},
		{`{"kind":"finding","title":"!!!","scope":[],"severity":"low"}`, "findings/F-006-finding.md"},
		{`{"kind":"finding","title":"A very long title that goes on and on about one single small problem","scope":[],"severity":"low"}`,
			"findings/F-006-a-very-long-title-that-goes-on-and-on-about-one.md"},
	}
	for _, tt := range tests {
		r, _ := openCopy(t)
		res, err := r.Add(record(t, tt.rec), AddOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Finding.Path != tt.wantPath {
			t.Errorf("path = %s, want %s", res.Finding.Path, tt.wantPath)
		}
	}
}

func TestAddRefuses(t *testing.T) {
	tests := []struct{ name, rec string }{
		{"no title", `{"kind":"finding","scope":[],"severity":"low"}`},
		{"unknown severity", `{"kind":"finding","title":"t","scope":[],"severity":"urgent"}`},
		{"malformed id", `{"kind":"finding","id":"F-7","title":"t","scope":[],"severity":"low"}`},
		{"id already taken", `{"kind":"finding","id":"F-003","title":"t","scope":[],"severity":"low"}`},
		{"target without host", `{"kind":"finding","title":"t","scope":[],"severity":"low","target":{"port":22}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, dir := openCopy(t)
			before := snapshot(t, dir)
			if _, err := r.Add(record(t, tt.rec), AddOptions{}); !errors.Is(err, ErrBadValue) {
				t.Errorf("err = %v, want ErrBadValue", err)
			}
			if after := snapshot(t, dir); !maps.Equal(before, after) {
				t.Error("a refused record changed the folder")
			}
		})
	}
}
