package report

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

// pngBytes is enough of a PNG for content sniffing.
var pngBytes = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

func evidenceWrite(t *testing.T, r *Report, do func(*Tx) error) {
	t.Helper()
	tx := r.Begin()
	if err := do(tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(false); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceRecordsDescribeLinks(t *testing.T) {
	list, err := openFixture(t).Evidence([]string{"F-003"}, false)
	if err != nil || len(list) != 2 {
		t.Fatalf("%+v, %v", list, err)
	}
	l := list[1]
	if l.Source != "body" || l.Text != "login bypass" || !l.Image || l.Section != "poc" || l.Line != 25 || l.Column != 1 || l.MediaType == "" {
		t.Errorf("%+v", l)
	}
}

func TestAddEvidenceCopiesListsAndLinks(t *testing.T) {
	r, dir := openCopy(t)
	shot := filepath.Join(t.TempDir(), "shot.png")
	if err := os.WriteFile(shot, pngBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	notes := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(notes, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	evidenceWrite(t, r, func(tx *Tx) error {
		_, err := tx.AddEvidence("F-001", []EvidenceSource{{Path: shot, Section: "poc", Text: "Login bypass"}, {Path: notes, Section: "References", Text: "notes"}}, "")
		return err
	})
	got := file(t, dir, "findings/xss-search.md")
	for _, want := range []string{
		"evidence: [evidence/F-001-shot.png, evidence/F-001-notes.txt]\r\n",
		"\r\n\r\n![Login bypass](evidence/F-001-shot.png)\r\n",
		"\r\n\r\n[notes](evidence/F-001-notes.txt)\r\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("file lacks %q:\n%s", want, got)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, EvidenceDir, "F-001-shot.png")); err != nil {
		t.Error(err)
	}
}

func TestAddEvidenceAlreadyInTheReport(t *testing.T) {
	r, dir := openCopy(t)
	before := len(readDir(t, filepath.Join(dir, EvidenceDir)))
	evidenceWrite(t, r, func(tx *Tx) error {
		_, err := tx.AddEvidence("F-001", []EvidenceSource{{Path: filepath.Join(dir, EvidenceDir, "F-003-login.png")}}, "")
		return err
	})
	if got := file(t, dir, "findings/xss-search.md"); !strings.Contains(got, "evidence: [evidence/F-003-login.png]") {
		t.Errorf("file:\n%s", got)
	}
	if after := len(readDir(t, filepath.Join(dir, EvidenceDir))); after != before {
		t.Error("copied a file already in the report")
	}
}

func readDir(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return ents
}

func TestRemoveEvidenceDetaches(t *testing.T) {
	r, dir := openCopy(t)
	// Add a text link to the same file beside the image link.
	evidenceWrite(t, r, func(tx *Tx) error {
		_, err := tx.SetSection("F-003", "remediation", "Use parameterised queries; see [the login form](evidence/F-003-login.png).")
		return err
	})
	evidenceWrite(t, r, func(tx *Tx) error {
		_, err := tx.RemoveEvidence("F-003", "evidence/F-003-login.png", false)
		return err
	})
	got := file(t, dir, "findings/sqli-login.md")
	if strings.Contains(got, "evidence:") || strings.Contains(got, "![login bypass]") || !strings.Contains(got, "see the login form.") {
		t.Errorf("file:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(dir, EvidenceDir, "F-003-login.png")); err != nil {
		t.Error("the file went; it should stay for prune")
	}
	if _, err := r.Begin().RemoveEvidence("F-003", "evidence/F-003-login.png", false); !errors.Is(err, ErrNoEvidence) {
		t.Errorf("again: %v", err)
	}
}

func TestRemoveEvidenceDropText(t *testing.T) {
	r, dir := openCopy(t)
	evidenceWrite(t, r, func(tx *Tx) error {
		_, err := tx.SetSection("F-003", "remediation", "See [the form](evidence/F-003-login.png).")
		return err
	})
	evidenceWrite(t, r, func(tx *Tx) error {
		_, err := tx.RemoveEvidence("F-003", "evidence/F-003-login.png", true)
		return err
	})
	if got := file(t, dir, "findings/sqli-login.md"); !strings.Contains(got, "## Remediation\n\nSee .\n") {
		t.Errorf("file:\n%s", got)
	}
}

func TestSetEvidenceCaption(t *testing.T) {
	r, dir := openCopy(t)
	evidenceWrite(t, r, func(tx *Tx) error {
		_, err := tx.SetEvidence("F-003", "evidence/F-003-login.png", "caption", "Login [bypass]")
		return err
	})
	if got := file(t, dir, "findings/sqli-login.md"); !strings.Contains(got, `![Login \[bypass\]](evidence/F-003-login.png)`) {
		t.Errorf("file:\n%s", got)
	}
	// An unlinked file has no caption.
	shot := filepath.Join(t.TempDir(), "s.png")
	os.WriteFile(shot, pngBytes, 0o644)
	evidenceWrite(t, r, func(tx *Tx) error {
		_, err := tx.AddEvidence("F-001", []EvidenceSource{{Path: shot}}, "")
		return err
	})
	if _, err := r.Begin().SetEvidence("F-001", "evidence/F-001-s.png", "caption", "x"); !errors.Is(err, ErrBadValue) {
		t.Errorf("unlinked: %v", err)
	}
}

func TestSetEvidencePathCarriesThrough(t *testing.T) {
	r, dir := openCopy(t)
	evidenceWrite(t, r, func(tx *Tx) error {
		_, err := tx.AddEvidence("F-001", []EvidenceSource{{Path: filepath.Join(dir, EvidenceDir, "F-003-login.png")}}, "")
		return err
	})
	var recs []any
	evidenceWrite(t, r, func(tx *Tx) error {
		var err error
		recs, err = tx.SetEvidence("F-003", "evidence/F-003-login.png", "path", "evidence/login-form.png")
		return err
	})
	if len(recs) != 2 {
		t.Errorf("%d records changed, want both findings", len(recs))
	}
	if got := file(t, dir, "findings/sqli-login.md"); !strings.Contains(got, "evidence: [evidence/login-form.png]") || !strings.Contains(got, "![login bypass](evidence/login-form.png)") {
		t.Errorf("sqli-login.md:\n%s", got)
	}
	if got := file(t, dir, "findings/xss-search.md"); !strings.Contains(got, "evidence: [evidence/login-form.png]") {
		t.Errorf("xss-search.md:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(dir, EvidenceDir, "F-003-login.png")); err == nil {
		t.Error("the old file stayed")
	}
}

func TestPageEvidenceAndOrphans(t *testing.T) {
	r, dir := withPages(t, "")
	shot := filepath.Join(t.TempDir(), "chart.png")
	os.WriteFile(shot, pngBytes, 0o644)
	evidenceWrite(t, r, func(tx *Tx) error {
		_, err := tx.AddEvidence("P-001", []EvidenceSource{{Path: shot, Section: "body", Text: "Risk chart"}}, "")
		return err
	})
	if got := file(t, dir, "pages/P-001-executive-summary.md"); !strings.Contains(got, "evidence: [evidence/P-001-chart.png]") || !strings.HasSuffix(got, "We tested Acme.\n\n![Risk chart](evidence/P-001-chart.png)\n") {
		t.Errorf("page:\n%s", got)
	}
	os.WriteFile(filepath.Join(dir, PageEvidenceDir, "stray.png"), pngBytes, 0o644)
	list, err := r.Evidence(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	var orphans []string
	for _, e := range list {
		if e.Finding == "" && e.Page == "" {
			orphans = append(orphans, e.Path)
		}
	}
	if len(orphans) != 1 || orphans[0] != "pages/evidence/stray.png" {
		t.Errorf("orphans %v", orphans)
	}
	var gone []sdk.Evidence
	evidenceWrite(t, r, func(tx *Tx) error { var err error; gone, err = tx.PruneEvidence(); return err })
	if len(gone) != 1 {
		t.Errorf("pruned %+v", gone)
	}
}
