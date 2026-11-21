package report

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/astr4liteEx/rpt/sdk"
)

func TestRevIsStable(t *testing.T) {
	if got := Rev([]byte("a")); got != Rev([]byte("a")) || len(got) != 16 || got == Rev([]byte("b")) {
		t.Errorf("Rev = %q", got)
	}
}

func TestReadsCarryRevs(t *testing.T) {
	r, dir := openCopy(t)
	f, err := r.Set("F-001", "cvss", `"1.0"`)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, f.Path))
	if f.Rev != Rev(b) {
		t.Errorf("set gave rev %q, the file's is %q", f.Rev, Rev(b))
	}
	rows, _ := r.Scope()
	before := rows[0].Rev
	if _, err := r.AddScope(rowFor("new.example")); err != nil {
		t.Fatal(err)
	}
	rows, _ = r.Scope()
	if rows[0].Rev != before {
		t.Error("adding a row changed another row's rev")
	}
}

func TestStaleIfRevWritesNothing(t *testing.T) {
	r, dir := openCopy(t)
	before := readAll(t, dir)
	tx := r.Begin()
	tx.IfRev["F-001"] = "0000000000000000"
	_, err := tx.Set("F-001", "cvss", `"1.0"`)
	if re, ok := errors.AsType[*RevError](err); !ok || re.ID != "F-001" {
		t.Fatalf("err = %v, want a RevError for F-001", err)
	}
	if after := readAll(t, dir); after != before {
		t.Error("the report changed")
	}
}

func TestChangedDuringWriteIsCaught(t *testing.T) {
	r, dir := openCopy(t)
	tx := r.Begin()
	f1, err := tx.Set("F-001", "cvss", `"1.0"`)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := tx.Set("F-002", "cvss", `"2.0"`)
	if err != nil {
		t.Fatal(err)
	}
	// An editor saves F-002 after the write read it.
	p2 := filepath.Join(dir, f2.Path)
	saved := append(mustReadFile(t, p2), "\nedited\n"...)
	if err := os.WriteFile(p2, saved, 0o644); err != nil {
		t.Fatal(err)
	}
	before := mustReadFile(t, filepath.Join(dir, f1.Path))
	err = tx.Commit(false)
	if re, ok := errors.AsType[*RevError](err); !ok || re.Path != f2.Path {
		t.Fatalf("err = %v, want %s changed since read", err, f2.Path)
	}
	if string(mustReadFile(t, filepath.Join(dir, f1.Path))) != string(before) {
		t.Error("F-001 was written though the write was refused")
	}
	if string(mustReadFile(t, p2)) != string(saved) {
		t.Error("the editor's save was overwritten")
	}
	noTempFiles(t, dir)
}

func TestDryRunKeepsNothing(t *testing.T) {
	r, dir := openCopy(t)
	if err := os.RemoveAll(filepath.Join(dir, EvidenceDir)); err != nil {
		t.Fatal(err)
	}
	shot := filepath.Join(t.TempDir(), "shot.png")
	if err := os.WriteFile(shot, []byte("png"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := readAll(t, dir)
	tx := r.Begin()
	rec, err := tx.AddEvidence("F-001", []EvidenceSource{{Path: shot}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(true); err != nil {
		t.Fatal(err)
	}
	if after := readAll(t, dir); after != before {
		t.Errorf("dry run changed the report")
	}
	if _, err := os.Stat(filepath.Join(dir, EvidenceDir)); !errors.Is(err, os.ErrNotExist) {
		t.Error("dry run left the evidence folder it made")
	}
	if f := rec.(sdk.Finding); f.Rev == "" || len(f.Evidence) != 1 {
		t.Errorf("dry run gave %+v; want the finding as it would be", f)
	}
}

func TestNoOpWriteKeepsTheFile(t *testing.T) {
	r, dir := openCopy(t)
	f, err := r.Set("F-001", "severity", "medium") // already medium
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, f.Path)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Set("F-001", "severity", "medium"); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(p); !info.ModTime().Equal(old) {
		t.Error("a no-op write touched the file")
	}
}

func TestHalfwayFailureSaysWhatWasntWritten(t *testing.T) {
	r, dir := openCopy(t)
	tx := r.Begin()
	if _, err := tx.Set("F-001", "cvss", `"1.0"`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.AddScope(rowFor("new.example")); err != nil {
		t.Fatal(err)
	}
	old := rename
	rename = func(root *os.Root, from, to string) error {
		if to == ScopeFile {
			return errors.New("disk on fire")
		}
		return old(root, from, to)
	}
	t.Cleanup(func() { rename = old })
	err := tx.Commit(false)
	nw, ok := errors.AsType[*NotWrittenError](err)
	if !ok || len(nw.Written) != 1 || !strings.HasPrefix(nw.Written[0], FindingsDir) ||
		len(nw.NotWritten) != 1 || nw.NotWritten[0].Path != ScopeFile || nw.NotWritten[0].Reason != "disk on fire" {
		t.Fatalf("err = %#v", err)
	}
	noTempFiles(t, dir)
}

func readAll(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(p + "\n")
		if !d.IsDir() {
			b.Write(mustReadFile(t, p))
		}
		return nil
	})
	return b.String()
}

func mustReadFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func noTempFiles(t *testing.T, dir string) {
	t.Helper()
	filepath.WalkDir(dir, func(p string, d os.DirEntry, _ error) error {
		if strings.HasSuffix(p, ".tmp") {
			t.Errorf("temp file left: %s", p)
		}
		return nil
	})
}

func rowFor(host string) sdk.ScopeRow { return sdk.ScopeRow{Kind: "scope", Host: host} }
