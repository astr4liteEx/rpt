package report

import "testing"

func TestNextID(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string // extra files written into a fixture copy
		want  string
	}{
		{name: "fixture's highest is F-003", want: "F-004"},
		{
			name:  "more than three digits",
			files: map[string]string{"findings/big.md": "---\nid: F-1234\ntitle: t\n---\n"},
			want:  "F-1235",
		},
		{
			name: "malformed IDs and broken files are ignored",
			files: map[string]string{
				"findings/odd.md":    "---\nid: F-9x\ntitle: t\n---\n",
				"findings/short.md":  "---\nid: F-99\ntitle: t\n---\n",
				"findings/broken.md": "---\nid: F-900\ntitle: : bad\n---\n",
			},
			want: "F-004",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := copyFixture(t)
			for rel, content := range tt.files {
				writeFile(t, dir, rel, content)
			}
			r, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			got, err := r.NextID()
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("NextID() = %s, want %s", got, tt.want)
			}
		})
	}
}
