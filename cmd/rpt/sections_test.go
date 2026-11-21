package main

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSectionsVerb(t *testing.T) {
	tests := []struct {
		name, config, want string
	}{
		{"defaults", "format: 2\n",
			"section description Description true true\n" +
				"section remediation Remediation true true\n" +
				"section poc Proof of concept true true\n"},
		{"renamed, partly required, with custom required sections",
			"format: 2\nsections:\n  remediation: Recommendation\n" +
				"required_sections: [Impact, recommendation, References]\n",
			"section description Description true false\n" +
				"section remediation Recommendation true true\n" +
				"section poc Proof of concept true false\n" +
				"section Impact Impact false true\n" +
				"section References References false true\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := renamedReport(t, tt.config, "")
			code, out, errOut := runIn(t, "", "sections", "--report", dir)
			if code != 0 || errOut != "" {
				t.Fatalf("exit %d, stderr %q", code, errOut)
			}
			if got := pick(t, out, "kind", "key", "heading", "fixed", "required"); got != tt.want {
				t.Errorf("stdout\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestSetSectionFromStdin(t *testing.T) {
	crlf := func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }
	// xss-search.md is F-001, saved with CRLF line ends.
	head := "---\nid: F-001\ntitle: Reflected XSS in search\ntargets: [{scope: S-14, port: 8443, protocol: tcp}]\nseverity: medium\n---\n\n## Description\n\n" +
		"The `q` parameter is reflected unescaped.\n\n## Remediation\n\n"
	tail := "## Proof of concept\n\n`/search?q=<script>alert(1)</script>`\n\n## References\n\n- OWASP XSS Prevention Cheat Sheet\n"
	tests := []struct {
		name, key, stdin, want string
	}{
		{"replace by key", "remediation", "\n\nEncode output.\r\nSet a CSP.\n\n", head + "Encode output.\nSet a CSP.\n\n" + tail},
		{"by heading, any case", "REMEDIATION", "Encode output.", head + "Encode output.\n\n" + tail},
		{"empty stdin leaves an empty section", "remediation", "", head + tail},
		{"a missing section is appended", "Impact", "Session theft.\n",
			head + "Encode output.\n\n" + tail + "\n## Impact\n\nSession theft.\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := reportCopy(t)
			code, out, errOut := runIn(t, tt.stdin, "finding", "set", "--report", dir, "F-001", "sections."+tt.key)
			if code != 0 || errOut != "" {
				t.Fatalf("exit %d, stderr %q", code, errOut)
			}
			if pick(t, out, "id") != "F-001\n" {
				t.Errorf("stdout = %q, want the finding", out)
			}
			b, _ := os.ReadFile(filepath.Join(dir, "findings/xss-search.md"))
			if string(b) != crlf(tt.want) {
				t.Errorf("file\n%q\nwant\n%q", b, crlf(tt.want))
			}
		})
	}
}

func TestSetSectionRefuses(t *testing.T) {
	tests := []struct {
		name, file, stdin, wantErr string
	}{
		{"text with its own ## heading", "", "Fix it.\n\n## Sneaky\n\nmore\n", "## heading"},
		{"a section the file has twice", "---\nid: F-009\ntitle: T\ntargets: []\nseverity: low\n---\n## Remediation\n\na\n\n## Remediation\n\nb\n", "x", "twice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := reportCopy(t)
			id := "F-003"
			if tt.file != "" {
				id = "F-009"
				if err := os.WriteFile(filepath.Join(dir, "findings/F-009-t.md"), []byte(tt.file), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			before := folderState(t, dir)
			code, _, errOut := runIn(t, tt.stdin, "finding", "set", "--report", dir, id, "sections.remediation")
			if code != 1 || !strings.Contains(errOut, tt.wantErr) {
				t.Errorf("exit %d, stderr %q; want 1 and %q", code, errOut, tt.wantErr)
			}
			if !maps.Equal(before, folderState(t, dir)) {
				t.Error("folder changed")
			}
		})
	}
}
