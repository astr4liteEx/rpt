package main

import "testing"

func TestSectionsVerb(t *testing.T) {
	tests := []struct {
		name, config, want string
	}{
		{"defaults", "format: 1\n",
			"section description Description true true\n" +
				"section remediation Remediation true true\n" +
				"section poc Proof of concept true true\n"},
		{"renamed, partly required, with custom required sections",
			"format: 1\nsections:\n  remediation: Recommendation\n" +
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
