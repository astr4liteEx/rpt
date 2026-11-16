package report

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

func TestEvidenceInfo(t *testing.T) {
	dir := copyFixture(t)
	// A symlink inside the report that points outside it.
	if err := os.Symlink("/etc", filepath.Join(dir, "findings", "evidence", "etc")); err != nil {
		t.Fatal(err)
	}
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	f := sdk.Finding{Path: "findings/sqli-login.md"}

	t.Run("evidence inside the report is found", func(t *testing.T) {
		info, err := r.EvidenceInfo(f, "evidence/F-003-login.png")
		if err != nil {
			t.Fatal(err)
		}
		if info.Name() != "F-003-login.png" {
			t.Errorf("name = %q", info.Name())
		}
	})
	for _, p := range []string{"../../etc/passwd", "../../../../../etc/passwd", "/etc/passwd", "evidence/../../../etc/passwd"} {
		t.Run("refuses "+p, func(t *testing.T) {
			_, err := r.EvidenceInfo(f, p)
			if !errors.Is(err, ErrOutsideReport) {
				t.Errorf("err = %v, want ErrOutsideReport", err)
			}
		})
	}
	t.Run("refuses a symlink that leaves the report", func(t *testing.T) {
		_, err := r.EvidenceInfo(f, "evidence/etc/passwd")
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			t.Errorf("err = %v, want a refusal, not success or not-exist", err)
		}
	})
	t.Run("missing evidence is not-exist, not a crash", func(t *testing.T) {
		_, err := r.EvidenceInfo(f, "evidence/missing.png")
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("err = %v, want fs.ErrNotExist", err)
		}
	})
}
