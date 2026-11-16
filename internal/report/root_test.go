package report

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestRoot(t *testing.T) {
	abs, err := filepath.Abs(fixture)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, flag, env, cwd string
		want                 string
		wantErr              error
	}{
		{name: "flag wins over env", flag: "/from/flag", env: "/from/env", cwd: abs, want: "/from/flag"},
		{name: "env when no flag", env: "/from/env", cwd: abs, want: "/from/env"},
		{name: "walks up to rpt.yaml", cwd: filepath.Join(abs, "findings", "evidence"), want: abs},
		{name: "rpt.yaml in cwd", cwd: abs, want: abs},
		{name: "no report anywhere", cwd: t.TempDir(), wantErr: ErrNoReport},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("RPT_REPORT_DIR", tt.env)
			t.Chdir(tt.cwd)
			got, err := Root(tt.flag)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Root(%q) = %q, want %q", tt.flag, got, tt.want)
			}
		})
	}
}
