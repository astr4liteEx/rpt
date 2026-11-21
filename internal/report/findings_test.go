package report

import (
	"encoding/json/jsontext"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
			Targets: []sdk.Target{{Scope: "S-12"}, {Scope: "S-14"}}, Severity: "high", Path: "findings/sqli-login.md",
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
			Targets: []sdk.Target{{Scope: "S-99"}}, Severity: "info", Path: "findings/tls-weak.md",
			Sections: map[string]string{
				"description": "TLS 1.0 is still enabled.",
				"remediation": "Disable TLS 1.0 and 1.1.",
				"poc":         "`nmap --script ssl-enum-ciphers -p 443 10.0.0.5`",
			},
		},
		{
			// Saved with CRLF line endings.
			Kind: "finding", ID: "F-001", Title: "Reflected XSS in search",
			Targets: []sdk.Target{{Scope: "S-14", Port: 8443, Protocol: "tcp"}}, Severity: "medium", Path: "findings/xss-search.md",
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
		if got[i].Rev == "" {
			t.Errorf("finding %d has no rev", i)
		}
		got[i].Rev = "" // compared in rev_test.go
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

func TestFindingsReadsTargets(t *testing.T) {
	dir := copyFixture(t)
	writeFile(t, dir, "findings/ssh.md", "---\nid: F-004\ntitle: SSH weak ciphers\nseverity: medium\ntargets:\n"+
		"  - {scope: S-20, host: 10.0.1.5, port: 22, protocol: tcp, vhost: ssh.acme.com}\n  - {scope: S-12}\nsource: {plugin: nuclei}\n---\n")
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	list, err := r.Findings()
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(list, func(f sdk.Finding) bool { return f.ID == "F-004" })
	if i < 0 {
		t.Fatal("F-004 not read")
	}
	f := list[i]
	want := []sdk.Target{
		{Scope: "S-20", Host: "10.0.1.5", Port: 22, Protocol: "tcp", Extra: map[string]jsontext.Value{"vhost": jsontext.Value(`"ssh.acme.com"`)}},
		{Scope: "S-12"},
	}
	if !reflect.DeepEqual(f.Targets, want) {
		t.Errorf("targets = %+v, want %+v", f.Targets, want)
	}
	if _, ok := f.Extra["targets"]; ok {
		t.Error("targets also left in Extra")
	}
	if string(f.Extra["source"]) != `{"plugin":"nuclei"}` {
		t.Errorf("source = %s, want it passed through", f.Extra["source"])
	}
}

func TestFindingsMissingFolder(t *testing.T) {
	dir := copyFixture(t)
	if err := os.RemoveAll(filepath.Join(dir, FindingsDir)); err != nil {
		t.Fatal(err)
	}
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got, err := r.Findings(); err != nil || len(got) != 0 {
		t.Errorf("missing findings/ = %v, %v; want no findings, no error", got, err)
	}
}

func TestFindingsWithLinesLocatesKeysAndSections(t *testing.T) {
	got, err := openFixture(t).FindingsWithLines()
	if err != nil {
		t.Fatal(err)
	}
	type sl = sdk.SectionLines
	want := map[string]*sdk.Lines{
		"F-003": {
			Frontmatter: map[string]int{"id": 2, "title": 3, "targets": 4, "severity": 5, "evidence": 6, "cvss": 7},
			Sections: map[string]sl{
				"description": {Heading: 10, Text: 12}, "remediation": {Heading: 14, Text: 16}, "poc": {Heading: 18, Text: 20},
			},
		},
		"F-002": { // a comment line sits between title and targets
			Frontmatter: map[string]int{"id": 2, "title": 3, "targets": 5, "severity": 6},
			Sections: map[string]sl{
				"description": {Heading: 9, Text: 11}, "remediation": {Heading: 13, Text: 15}, "poc": {Heading: 17, Text: 19},
			},
		},
		"F-001": { // CRLF line ends
			Frontmatter: map[string]int{"id": 2, "title": 3, "targets": 4, "severity": 5},
			Sections: map[string]sl{
				"description": {Heading: 8, Text: 10}, "remediation": {Heading: 12, Text: 14},
				"poc": {Heading: 16, Text: 18}, "References": {Heading: 20, Text: 22},
			},
		},
	}
	abs, err := filepath.Abs(fixture) // fixture is a relative path
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		// file is the finding file's absolute path, even though the report
		// was opened by a relative one.
		if wantFile := filepath.Join(abs, filepath.FromSlash(f.Path)); f.Lines.File != wantFile {
			t.Errorf("%s file = %q, want %q", f.ID, f.Lines.File, wantFile)
		}
		f.Lines.File = ""
		if !reflect.DeepEqual(f.Lines, want[f.ID]) {
			t.Errorf("%s lines\n got: %+v\nwant: %+v", f.ID, f.Lines, want[f.ID])
		}
	}
}

func TestFindingsWithLinesEdgeCases(t *testing.T) {
	dir := copyFixture(t)
	writeFile(t, dir, "findings/zz-edge.md", "---\nid: F-009\n---\nintro\n\nCustom\n------\n\n\n  indented text\n\n"+
		"## Remediation\n\n## Description\nx\n")
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	list, err := r.FindingsWithLines()
	if err != nil {
		t.Fatal(err)
	}
	got := list[len(list)-1].Lines
	got.File = "" // checked in TestFindingsWithLinesLocatesKeysAndSections
	want := &sdk.Lines{
		Frontmatter: map[string]int{"id": 2},
		Sections: map[string]sdk.SectionLines{
			"Custom":      {Heading: 6, Text: 10}, // setext heading; text keeps its indent
			"remediation": {Heading: 12},          // empty: no text line
			"description": {Heading: 14, Text: 15},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lines\n got: %+v\nwant: %+v", got, want)
	}
}

func TestFindingsLeavesLinesOut(t *testing.T) {
	list, err := openFixture(t).Findings()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range list {
		if f.Lines != nil {
			t.Errorf("%s: Findings set Lines; only FindingsWithLines does", f.ID)
		}
	}
}
