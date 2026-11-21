package report

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

// withPages returns a fresh fixture copy with two pages added, P-001
// Executive summary (with a body) and P-002 Methodology, then rpt.yaml set
// to yaml.
func withPages(t *testing.T, yaml string) (*Report, string) {
	t.Helper()
	r, dir := openCopy(t)
	defer func() {
		if yaml != "" {
			if err := os.WriteFile(filepath.Join(dir, ConfigFile), []byte(yaml), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}()
	tx := r.Begin()
	if _, err := tx.AddPage(sdk.Page{Title: "Executive summary", Body: "We tested Acme.\n"}); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.AddPage(sdk.Page{Title: "Methodology"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(false); err != nil {
		t.Fatal(err)
	}
	return r, dir
}

func TestAddPage(t *testing.T) {
	r, dir := withPages(t, "")
	if got := file(t, dir, "pages/P-001-executive-summary.md"); got != "---\nid: P-001\ntitle: Executive summary\n---\n\nWe tested Acme.\n" {
		t.Errorf("file %q", got)
	}
	if got := file(t, dir, "pages/P-002-methodology.md"); got != "---\nid: P-002\ntitle: Methodology\n---\n" {
		t.Errorf("file %q", got)
	}
	ps, err := r.PagesWithLines()
	if err != nil || len(ps) != 2 || ps[0].Body != "We tested Acme." || ps[0].Lines.Body != 6 || ps[0].Rev == "" {
		t.Errorf("%+v, %v", ps, err)
	}
}

func TestNextPageIDCountsConfig(t *testing.T) {
	r, _ := withPages(t, "format: 2\nrequired_pages: [P-007]\n")
	tx := r.Begin()
	p, err := tx.AddPage(sdk.Page{Title: "Conclusions"})
	if err != nil || p.ID != "P-008" {
		t.Errorf("%s, %v; want P-008, past the required P-007", p.ID, err)
	}
}

func TestPageOrderAndAssemble(t *testing.T) {
	r, _ := withPages(t, "format: 2\npages: [P-002, findings]\n")
	rep, warns, err := r.Assemble()
	if err != nil || len(warns) != 1 { // tls-weak's S-99
		t.Fatalf("%v, %+v", err, warns)
	}
	if !slices.Equal(rep.Report.Order, []string{"P-002", "findings", "P-001"}) {
		t.Errorf("order %v", rep.Report.Order)
	}
	if len(rep.Pages) != 2 || rep.Pages[0].ID != "P-002" || rep.Pages[1].Body != "We tested Acme." {
		t.Errorf("pages %+v", rep.Pages)
	}
	if got := PageOrder(nil, []sdk.Page{{ID: "P-002"}, {ID: "P-001"}}); !slices.Equal(got, []string{"findings", "P-001", "P-002"}) {
		t.Errorf("no pages key: %v", got)
	}
}

func TestPageRules(t *testing.T) {
	r, dir := withPages(t, "format: 2\npages: [P-001, findings, P-009]\nrequired_pages: [P-002, P-003]\n")
	if err := os.WriteFile(filepath.Join(dir, "pages/x.md"), []byte("---\nid: P-1\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ps, err := r.Validate()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range ps {
		if p.Rule != RuleScopeIDsExist {
			got = append(got, p.Path+" "+p.Rule)
		}
	}
	want := []string{
		"pages/P-002-methodology.md requiredPages",  // empty
		"pages/x.md pageTitle", "pages/x.md pageID", // by line: no title is line 1
		"rpt.yaml pageOrder",     // P-009
		"rpt.yaml requiredPages", // P-003
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestRenamePageCarriesIntoConfig(t *testing.T) {
	r, dir := withPages(t, "format: 2\npages: [P-001, findings]\nrequired_pages: [P-001]\n")
	tx := r.Begin()
	ch, err := tx.SetPage("P-001", "id", "p-010")
	if err != nil || tx.Commit(false) != nil {
		t.Fatal(err)
	}
	if ch.Page.Path != "pages/P-010-executive-summary.md" || ch.Config == nil || !slices.Equal(ch.Config.Pages, []string{"P-010", "findings"}) {
		t.Errorf("%+v", ch)
	}
	if got := file(t, dir, ConfigFile); got != "format: 2\npages: [P-010, findings]\nrequired_pages: [P-010]\n" {
		t.Errorf("rpt.yaml %q", got)
	}
}

func TestRemovePage(t *testing.T) {
	r, dir := withPages(t, "format: 2\npages: [P-001, findings]\n")
	if _, err := r.Begin().RemovePage("P-001", CitedRefuse); !errors.Is(err, ErrInUse) {
		t.Errorf("err = %v", err)
	}
	tx := r.Begin()
	ch, err := tx.RemovePage("P-001", CitedCleanup)
	if err != nil || tx.Commit(false) != nil || ch.Config == nil {
		t.Fatalf("%+v, %v", ch, err)
	}
	if got := file(t, dir, ConfigFile); got != "format: 2\npages: [findings]\n" {
		t.Errorf("rpt.yaml %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "pages/P-001-executive-summary.md")); err == nil {
		t.Error("page stayed")
	}
}

func TestSetPageBodyAndTitle(t *testing.T) {
	r, dir := withPages(t, "")
	tx := r.Begin()
	if _, err := tx.SetPage("P-002", "body", "## Approach\n\nGrey box."); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.SetPage("P-002", "title", "How we tested"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(false); err != nil {
		t.Fatal(err)
	}
	// The title changes; the file keeps its name.
	if got := file(t, dir, "pages/P-002-methodology.md"); got != "---\nid: P-002\ntitle: How we tested\n---\n\n## Approach\n\nGrey box.\n" {
		t.Errorf("file %q", got)
	}
	if _, err := r.Begin().UnsetPage("P-002", "title"); !errors.Is(err, ErrRefusedUnset) {
		t.Errorf("unset title: %v", err)
	}
	if !strings.Contains(file(t, dir, "pages/P-002-methodology.md"), "Grey box") {
		t.Error("refused unset changed the page")
	}
}
