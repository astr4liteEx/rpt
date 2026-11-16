package main

import (
	"bytes"
	"testing"
)

func TestVersionVerb(t *testing.T) {
	tests := []struct {
		name     string
		stamped  string // what the release build writes into version
		args     []string
		wantCode int
		want     string
	}{
		{"a release build reports its tag", "v0.1.0", []string{"version", "--json"}, 0,
			`{"kind":"version","version":"v0.1.0","schema_version":1,"format":1}` + "\n"},
		{"a local build reports dev", "", []string{"version"}, 0,
			`{"kind":"version","version":"dev","schema_version":1,"format":1}` + "\n"},
		{"arguments are a usage error", "v0.1.0", []string{"version", "extra"}, 2, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := version
			version = tt.stamped
			t.Cleanup(func() { version = old })

			var stdout, stderr bytes.Buffer
			code := run(tt.args, nil, &stdout, &stderr)
			if code != tt.wantCode || stdout.String() != tt.want {
				t.Errorf("code %d, stdout %q; want %d, %q (stderr %q)", code, stdout.String(), tt.wantCode, tt.want, stderr.String())
			}
		})
	}
}
