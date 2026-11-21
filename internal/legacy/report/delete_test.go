package report

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDelete(t *testing.T) {
	dir := copyFixture(t)
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	f, err := r.Delete("F-003")
	if err != nil {
		t.Fatal(err)
	}
	if f.ID != "F-003" || f.Path != "findings/sqli-login.md" || f.Sections["remediation"] != "Use parameterised queries." {
		t.Errorf("returned %+v, want F-003 as it was stored", f)
	}
	if _, err := os.Stat(filepath.Join(dir, "findings/sqli-login.md")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("finding file still there: %v", err)
	}
	// Evidence stays: another finding may cite it.
	if _, err := os.Stat(filepath.Join(dir, "findings/evidence/F-003-login.png")); err != nil {
		t.Errorf("evidence removed: %v", err)
	}
	if _, err := r.Delete("F-003"); !errors.Is(err, ErrNoFinding) {
		t.Errorf("second delete = %v, want ErrNoFinding", err)
	}
	if list, _ := r.Findings(); len(list) != 2 {
		t.Errorf("%d findings left, want 2", len(list))
	}
}
