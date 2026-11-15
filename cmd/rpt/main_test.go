package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantCode  int
		wantInErr string
	}{
		{name: "no verb prints usage and exits 2", args: nil, wantCode: 2, wantInErr: "usage: rpt <verb>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, strings.NewReader(""), &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(stderr.String(), tt.wantInErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantInErr)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty: stdout carries only records", stdout.String())
			}
		})
	}
}
