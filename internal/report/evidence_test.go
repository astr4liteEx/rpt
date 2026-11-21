package report

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAddEvidenceCopiesAndLinks(t *testing.T) {
	m := fixture(t, nil)
	src := filepath.Join(t.TempDir(), "Login Bypass!.PNG")
	os.WriteFile(src, []byte("png"), 0o644)
	f, _ := m.Get(FindingKind, "F-001")
	d, err := m.AddEvidence(f, []EvidenceSource{{Path: src, Section: "poc", Text: "login bypass"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(d.Evidence, []string{"evidence/F-001-login-bypass.png"}) {
		t.Errorf("evidence %v", d.Evidence)
	}
	poc, _ := d.Section("poc")
	if !strings.HasSuffix(poc.Text, "\n\n![login bypass](evidence/F-001-login-bypass.png)") {
		t.Errorf("poc %q", poc.Text)
	}
	mustSave(t, m)
	if readDisk(t, m, "findings/evidence/F-001-login-bypass.png") != "png" {
		t.Error("not copied")
	}
}

func TestEvidenceInHTMLAndOddNamesIsNotOrphaned(t *testing.T) {
	m := fixture(t, map[string]string{
		"findings/evidence/100%.png":   "a",
		"findings/evidence/html.png":   "b",
		"findings/evidence/shot#1.png": "c",
		"findings/evidence/orphan.png": "d",
		"findings/evidence/.gitkeep":   "e",
		"findings/x.md": "---\nid: F-009\ntitle: X\ntargets: []\nseverity: low\n---\n\n## Description\n\n" +
			"![a](evidence/100%.png)\n\n<img src=\"evidence/html.png\" width=300>\n\n![c](evidence/shot#1.png)\n",
	})
	got, err := m.Orphans()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"findings/evidence/orphan.png"}) {
		t.Errorf("orphans %v", got)
	}
}

func TestRemoveEvidence(t *testing.T) {
	m := fixture(t, map[string]string{
		"findings/evidence/shot.png": "x",
		"findings/x.md": "---\nid: F-009\ntitle: X\ntargets: []\nseverity: low\nevidence: [evidence/shot.png, evidence/F-003-login.png]\n---\n\n## Description\n\n" +
			"See [the shot](evidence/shot.png) here.\n\n![shot](evidence/shot.png)\n\nAfter.\n",
	})
	f, _ := m.Get(FindingKind, "F-009")
	d, err := m.RemoveEvidence(f, "evidence/shot.png", false)
	if err != nil {
		t.Fatal(err)
	}
	want := "\n## Description\n\nSee the shot here.\n\nAfter.\n"
	if d.Body() != want || !slices.Equal(d.Evidence, []string{"evidence/F-003-login.png"}) {
		t.Errorf("body %q evidence %v", d.Body(), d.Evidence)
	}
}

func TestMoveEvidenceRewritesEveryReference(t *testing.T) {
	m := fixture(t, map[string]string{
		"findings/x.md": "---\nid: F-009\ntitle: X\ntargets: []\nseverity: low\n---\n\n## Description\n\n" +
			"[**full**](evidence/F-003-login.png) and [![t](evidence/F-003-login.png)](evidence/F-003-login.png \"t\") and [ref][1]\n\n[1]: <evidence/F-003-login.png>\n",
		"pages/P-001-a.md": "---\nid: P-001\ntitle: A\n---\n\n![x](../findings/evidence/F-003-login.png)\n",
	})
	f, _ := m.Get(FindingKind, "F-003")
	changed, err := m.MoveEvidence(f, "evidence/F-003-login.png", "evidence/login bypass.png")
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 3 {
		t.Errorf("changed %d", len(changed))
	}
	x, _ := m.Get(FindingKind, "F-009")
	want := "[**full**](<evidence/login bypass.png>) and [![t](<evidence/login bypass.png>)](<evidence/login bypass.png> \"t\") and [ref][1]\n\n[1]: <evidence/login bypass.png>\n"
	if !strings.HasSuffix(x.Body(), want) {
		t.Errorf("F-009 body %q", x.Body())
	}
	p, _ := m.Get(PageKind, "P-001")
	if !strings.Contains(p.Body(), "(<../findings/evidence/login bypass.png>)") {
		t.Errorf("page %q", p.Body())
	}
	mustSave(t, m)
	if readDisk(t, m, "findings/evidence/F-003-login.png") != "<absent>" || readDisk(t, m, "findings/evidence/login bypass.png") == "<absent>" {
		t.Error("file not moved")
	}
}

func TestCaption(t *testing.T) {
	m := fixture(t, map[string]string{
		"findings/x.md": "---\nid: F-009\ntitle: X\ntargets: []\nseverity: low\n---\n\n## Description\n\n[see](<evidence/F-003-login.png> \"title\")\n\n```\na\n\n\n\nb\n```\n",
	})
	f, _ := m.Get(FindingKind, "F-009")
	d, err := m.SetCaption(f, "evidence/F-003-login.png", "the login")
	if err != nil {
		t.Fatal(err)
	}
	if want := "[the login](<evidence/F-003-login.png> \"title\")\n\n```\na\n\n\n\nb\n```\n"; !strings.HasSuffix(d.Body(), want) {
		t.Errorf("body %q", d.Body())
	}
}
