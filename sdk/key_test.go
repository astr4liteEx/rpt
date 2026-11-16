package sdk

import "testing"

// Expected values come from sha256sum over the parts joined with NUL bytes.
func TestKey(t *testing.T) {
	tests := []struct {
		parts []string
		want  string
	}{
		{[]string{"sqli-login", "S-12", "S-14"}, "e7c7e44188183cc1"},
		{[]string{"one"}, "7692c3ad3540bb80"},
		{[]string{"a", "bc"}, "40bb547d936bbd31"}, // the separator keeps these two apart
		{[]string{"ab", "c"}, "6c032e631d39a14d"},
		{nil, "e3b0c44298fc1c14"},
	}
	for _, tt := range tests {
		if got := Key(tt.parts...); got != tt.want {
			t.Errorf("Key(%q) = %s, want %s", tt.parts, got, tt.want)
		}
	}
}
