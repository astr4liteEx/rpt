package report

import (
	"encoding/json/jsontext"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

func TestFindingsReadsFixture(t *testing.T) {
	got, err := openFixture(t).Findings()
	if err != nil {
		t.Fatal(err)
	}
	want := []sdk.Finding{
		{
			Kind: "finding", ID: "F-003", Title: "SQL injection in login",
			Scope: []string{"S-12", "S-14"}, Severity: "high", Path: "findings/sqli-login.md",
			Sections: map[string]string{
				"description": "The `user` parameter of `/login` is concatenated into a SQL query.",
				"remediation": "Use parameterised queries.",
				"poc": "```sh\n## not a heading: inside a code fence\n" +
					"curl -d \"user=' OR 1=1--\" https://10.0.0.5/login\n```\n\n" +
					"![login bypass](evidence/F-003-login.png)",
			},
			Evidence: []string{"evidence/F-003-login.png"},
			Extra:    map[string]jsontext.Value{"cvss": jsontext.Value(`"9.1"`)},
		},
		{
			Kind: "finding", ID: "F-002", Title: "Weak TLS configuration",
			Scope: []string{"S-99"}, Severity: "info", Path: "findings/tls-weak.md",
			Sections: map[string]string{
				"description": "TLS 1.0 is still enabled.",
				"remediation": "Disable TLS 1.0 and 1.1.",
				"poc":         "`nmap --script ssl-enum-ciphers -p 443 10.0.0.5`",
			},
		},
		{
			// Saved with CRLF line endings.
			Kind: "finding", ID: "F-001", Title: "Reflected XSS in search",
			Scope: []string{"S-14"}, Severity: "medium", Path: "findings/xss-search.md",
			Sections: map[string]string{
				"description": "The `q` parameter is reflected unescaped.",
				"remediation": "Encode output.",
				"poc":         "`/search?q=<script>alert(1)</script>`",
				"References":  "- OWASP XSS Prevention Cheat Sheet",
			},
		},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("finding %d\n got: %#v\nwant: %#v", i, got[i], want[i])
		}
	}
}

func TestFindingsKeepsGoodFilesWhenOneIsBroken(t *testing.T) {
	dir := copyFixture(t)
	writeFile(t, dir, "findings/broken.md", "---\nid: F-009\ntitle: : bad\n---\n## Description\n")
	writeFile(t, dir, "findings/nofront.md", "## Description\n\nNo frontmatter.\n")
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	got, err := r.Findings()
	if len(got) != 3 {
		t.Errorf("got %d findings, want the 3 good ones", len(got))
	}
	var bad []string
	for _, e := range unjoin(err) {
		fe, ok := errors.AsType[*FileError](e)
		if !ok {
			t.Fatalf("error %v is not a *FileError", e)
		}
		bad = append(bad, fe.Path)
		if fe.Path == "findings/broken.md" && fe.Line != 3 {
			t.Errorf("broken.md line = %d, want 3 (the bad title line)", fe.Line)
		}
		if fe.Path == "findings/nofront.md" && fe.Line != 1 {
			t.Errorf("nofront.md line = %d, want 1", fe.Line)
		}
	}
	if want := []string{"findings/broken.md", "findings/nofront.md"}; !reflect.DeepEqual(bad, want) {
		t.Errorf("errors for %v, want %v", bad, want)
	}
}

// unjoin splits an errors.Join result into its parts.
func unjoin(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		return j.Unwrap()
	}
	if err != nil {
		return []error{err}
	}
	return nil
}

func TestFindingsEdgeCases(t *testing.T) {
	dir := copyFixture(t)
	writeFile(t, dir, "findings/zz-empty.md", "---\n---\n## Description\n\nNo trailing newline")
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := r.Findings()
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if last.Path != "findings/zz-empty.md" || last.Sections["description"] != "No trailing newline" {
		t.Errorf("empty-frontmatter finding = %#v", last)
	}
}

func TestFindingsInReviewFolders(t *testing.T) {
	r := openFixture(t)
	staged, err := r.FindingsIn(StagingDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(staged) != 1 {
		t.Fatalf("got %d staged findings, want 1", len(staged))
	}
	f := staged[0]
	if f.ID != "F-004" || f.Key != "2617ba239ba6c4fa" || f.Path != "staging/F-004-ssh-weak-ciphers.md" {
		t.Errorf("id/key/path = %s/%s/%s", f.ID, f.Key, f.Path)
	}
	if f.Target == nil || f.Target.Host != "10.0.1.5" || f.Target.Port != 22 || f.Target.Protocol != "tcp" {
		t.Errorf("target = %+v, want 10.0.1.5 tcp/22", f.Target)
	}
	if _, ok := f.Extra["key"]; ok {
		t.Error("key also left in Extra")
	}
	if _, ok := f.Extra["target"]; ok {
		t.Error("target also left in Extra")
	}
	if string(f.Extra["source"]) != `{"plugin":"nuclei","template":"ssh-weak-cipher"}` {
		t.Errorf("source = %s, want it passed through", f.Extra["source"])
	}

	dir := copyFixture(t)
	if err := os.RemoveAll(filepath.Join(dir, StagingDir)); err != nil {
		t.Fatal(err)
	}
	r2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	if got, err := r2.FindingsIn(StagingDir); err != nil || len(got) != 0 {
		t.Errorf("missing staging/ = %v, %v; want no findings, no error", got, err)
	}
}
