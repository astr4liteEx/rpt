package sdk

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	var gotArgs []string
	p := Plugin{
		Description: Description{Summary: "Parse things", Usage: "rpt parse < in", Version: "1.2.3", Input: "xml/nessus", Output: "records", Roles: []string{RoleFilter, RoleChecker}},
		Run: func(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
			gotArgs = args
			in, _ := io.ReadAll(stdin)
			stdout.Write(bytes.ToUpper(in))
			io.WriteString(stderr, "note\n")
			return 3
		},
	}
	tests := []struct {
		name            string
		args            []string
		wantCode        int
		wantOut, wantEr string
		wantRun         bool
	}{
		{name: "--describe is answered by the sdk", args: []string{"--describe"},
			wantOut: `{"summary":"Parse things","usage":"rpt parse < in","version":"1.2.3","input":"xml/nessus","output":"records","roles":["filter","checker"]}` + "\n"},
		{name: "anything else runs the plugin", args: []string{"a b", "", "--describe", "ü"}, wantCode: 3,
			wantOut: "IN\n", wantEr: "note\n", wantRun: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotArgs = nil
			var out, errOut bytes.Buffer
			code := Run(p, tt.args, strings.NewReader("in\n"), &out, &errOut)
			if code != tt.wantCode || out.String() != tt.wantOut || errOut.String() != tt.wantEr {
				t.Errorf("exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
			}
			if tt.wantRun != (gotArgs != nil) || (tt.wantRun && !slices.Equal(gotArgs, tt.args)) {
				t.Errorf("plugin got args %q, want %q (run: %v)", gotArgs, tt.args, tt.wantRun)
			}
		})
	}
}

func TestBin(t *testing.T) {
	t.Setenv("RPT_BIN", "/opt/rpt/bin/rpt")
	if got := Bin(); got != "/opt/rpt/bin/rpt" {
		t.Errorf("dispatched: Bin() = %q", got)
	}
	t.Setenv("RPT_BIN", "")
	if got := Bin(); got != "rpt" {
		t.Errorf("run directly: Bin() = %q, want rpt from PATH", got)
	}
}
