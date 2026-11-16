package report

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// checkGolden compares got with testdata/<name>.golden, rewriting it with
// -update. Review the diff of any rewritten golden file before committing.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	golden := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s changed: run go test -update and review the diff\n got:\n%s", golden, got)
	}
}

func TestSet(t *testing.T) {
	tests := []struct {
		name, id, key, value, file string
	}{
		{"severity", "F-003", "severity", "critical", "findings/sqli-login.md"},
		{"scope-keeps-comment-spacing", "F-003", "scope", "[S-12, S-20]", "findings/sqli-login.md"},
		{"quoted-stays-quoted", "F-003", "cvss", "9.4", "findings/sqli-login.md"},
		{"new-key-in-crlf-file", "F-001", "retest", "pending", "findings/xss-search.md"},
		{"unchanged-value-is-a-no-op", "F-003", "severity", "high", "findings/sqli-login.md"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := copyFixture(t)
			r, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			f, err := r.Set(tt.id, tt.key, tt.value)
			if err != nil {
				t.Fatal(err)
			}
			if f.ID != tt.id || f.Path != tt.file {
				t.Errorf("returned %s at %s, want %s at %s", f.ID, f.Path, tt.id, tt.file)
			}
			got, err := os.ReadFile(filepath.Join(dir, tt.file))
			if err != nil {
				t.Fatal(err)
			}
			checkGolden(t, "set/"+tt.name, got)
		})
	}
}

func TestSetRefuses(t *testing.T) {
	tests := []struct {
		name, id, key, value string
		want                 error
	}{
		{"unknown ID", "F-404", "severity", "high", ErrNoFinding},
		{"id is permanent", "F-003", "id", "F-010", ErrRefusedKey},
		{"sections are edited by hand", "F-003", "sections", "{}", ErrRefusedKey},
		{"kind", "F-003", "kind", "scope", ErrRefusedKey},
		{"path", "F-003", "path", "x.md", ErrRefusedKey},
		{"unknown severity", "F-003", "severity", "urgent", ErrBadValue},
		{"scope must be a list", "F-003", "scope", "S-12", ErrBadValue},
		{"title must be text", "F-003", "title", "[a, b]", ErrBadValue},
		{"empty title", "F-003", "title", "", ErrBadValue},
		{"target needs a host", "F-003", "target", "{port: 22}", ErrBadValue},
		{"target protocol", "F-003", "target", "{host: a, protocol: icmp}", ErrBadValue},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := copyFixture(t)
			before, _ := os.ReadFile(filepath.Join(dir, "findings/sqli-login.md"))
			r, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if _, err := r.Set(tt.id, tt.key, tt.value); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
			after, _ := os.ReadFile(filepath.Join(dir, "findings/sqli-login.md"))
			if !bytes.Equal(before, after) {
				t.Error("file changed despite the error")
			}
		})
	}
}
