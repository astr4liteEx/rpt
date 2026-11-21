package report

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRewriteDestsAtPositions(t *testing.T) {
	md := "![a](a.png) and [b](a.png.bak) and [c][r] and `[d](a.png)`\n\n```\n[e](a.png)\n```\n\n[r]: <a.png>\n"
	got := string(rewriteDests([]byte(md), func(l link) (string, bool) {
		if l.path == "a.png" {
			return "/abs/my a.png", true
		}
		return "", false
	}))
	want := "![a](</abs/my a.png>) and [b](a.png.bak) and [c][r] and `[d](a.png)`\n\n```\n[e](a.png)\n```\n\n[r]: </abs/my a.png>\n"
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestAssembleKeepsLookalikeLinks(t *testing.T) {
	r, dir := openCopy(t)
	for _, n := range []string{"a.png", "a.png.bak"} {
		if err := os.WriteFile(filepath.Join(dir, EvidenceDir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	evidenceWrite(t, r, func(tx *Tx) error {
		_, err := tx.SetSection("F-001", "poc", "![a](evidence/a.png) [b](evidence/a.png.bak)")
		return err
	})
	rep, _, err := r.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if f.ID != "F-001" {
			continue
		}
		abs := filepath.ToSlash(filepath.Join(r.abs, EvidenceDir))
		if want := "![a](" + abs + "/a.png) [b](" + abs + "/a.png.bak)"; f.Sections["poc"] != want {
			t.Errorf("poc %q, want %q", f.Sections["poc"], want)
		}
		if len(f.Assets) != 2 || !strings.HasSuffix(f.Assets[1].File, "a.png.bak") {
			t.Errorf("assets %+v", f.Assets)
		}
	}
}

func TestAddTakesAssets(t *testing.T) {
	r, dir := openCopy(t)
	src := t.TempDir()
	shot, log, extra, loose := filepath.Join(src, "shot.png"), filepath.Join(src, "out.log"), filepath.Join(src, "x.txt"), filepath.Join(src, "loose file.txt")
	for _, f := range []string{shot, log, extra, loose} {
		os.WriteFile(f, []byte("x"), 0o644)
	}
	rec := record(t, `{"kind":"finding","title":"Copied","severity":"low","evidence":["evidence/F-009-shot.png"],
		"sections":{"poc":"![s](evidence/F-009-shot.png) [l][log] [m](</`+filepath.ToSlash(loose[1:])+`>)\n\n[log]: ../old/out.log"},
		"assets":[{"ref":"evidence/F-009-shot.png","file":"`+shot+`"},{"ref":"../old/out.log","file":"`+log+`"},{"ref":"x","file":"`+extra+`"},{"ref":"same","file":"`+shot+`"}]}`)
	evidenceWrite(t, r, func(tx *Tx) error { _, err := tx.Add(rec); return err })
	text := file(t, dir, "findings/F-004-copied.md")
	for _, want := range []string{
		"evidence: [evidence/F-004-shot.png, evidence/F-004-x.txt]",
		"![s](evidence/F-004-shot.png) [l][log] [m](evidence/F-004-loose-file.txt)",
		"[log]: evidence/F-004-out.log",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("file lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "assets") {
		t.Errorf("assets written to the file:\n%s", text)
	}
}

func TestAddAssetInReportIsShared(t *testing.T) {
	r, dir := openCopy(t)
	rec := record(t, `{"kind":"finding","title":"Shared","severity":"low","sections":{"poc":"![a](/elsewhere/a.png)"},
		"assets":[{"ref":"/elsewhere/a.png","file":"`+filepath.Join(dir, EvidenceDir, "F-003-login.png")+`"}]}`)
	before := len(readDir(t, filepath.Join(dir, EvidenceDir)))
	evidenceWrite(t, r, func(tx *Tx) error { _, err := tx.Add(rec); return err })
	if text := file(t, dir, "findings/F-004-shared.md"); !strings.Contains(text, "![a](evidence/F-003-login.png)") {
		t.Errorf("file:\n%s", text)
	}
	if len(readDir(t, filepath.Join(dir, EvidenceDir))) != before {
		t.Error("copied a file already in the report")
	}
}

func TestAddRefusesMissingAsset(t *testing.T) {
	r, _ := openCopy(t)
	for _, line := range []string{
		`{"kind":"finding","title":"T","severity":"low","assets":[{"ref":"a.png","file":"/no/such/a.png"}]}`,
		`{"kind":"finding","title":"T","severity":"low","sections":{"poc":"![a](/no/such/b.png)"}}`,
		`{"kind":"finding","title":"T","severity":"low","assets":[{"ref":"d","file":"` + t.TempDir() + `"}]}`,
	} {
		if _, err := r.Begin().Add(record(t, line)); !errors.Is(err, ErrBadAsset) {
			t.Errorf("%s: %v", line, err)
		}
	}
}
