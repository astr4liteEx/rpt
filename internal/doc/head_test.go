package doc

import (
	"errors"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func scalar(v string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Value: v} }

func value(t *testing.T, src string) *yaml.Node {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(src), &n); err != nil {
		t.Fatal(err)
	}
	return n.Content[0]
}

func TestSet(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		path     string
		val      string // YAML
		want     string
	}{
		{
			name: "a scalar keeps everything else, its comment too",
			in:   "id: F-001 # the id\ntitle:   'Odd  spacing'\n\nseverity: high\n",
			path: "severity", val: "low",
			want: "id: F-001 # the id\ntitle:   'Odd  spacing'\n\nseverity: low\n",
		},
		{
			name: "a commented value keeps its comment",
			in:   "id: F-001\nseverity: high # was medium\ntitle: x\n",
			path: "severity", val: "low",
			want: "id: F-001\nseverity: low # was medium\ntitle: x\n",
		},
		{
			name: "one-line frontmatter is rewritten in full, every key kept",
			in:   "{id: F-001, title: Test, targets: [], severity: high}\n",
			path: "severity", val: "low",
			want: "id: F-001\ntitle: Test\ntargets: []\nseverity: low\n",
		},
		{
			name: "a new key goes last",
			in:   "id: F-001\ntitle: x\n# trailing note\n",
			path: "cvss", val: `"9.1"`,
			want: "id: F-001\ntitle: x\ncvss: \"9.1\"\n# trailing note\n",
		},
		{
			name: "a nested key keeps its siblings' comments",
			in:   "id: F-001\nx-foo:\n  a: 1 # keep\n  # note\n  c: 2\nevidence:\n  - a.png\n",
			path: "x-foo.c", val: "3",
			want: "id: F-001\nx-foo:\n  a: 1 # keep\n  # note\n  c: 3\nevidence:\n  - a.png\n",
		},
		{
			name: "a new nested key under an existing mapping",
			in:   "x-foo:\n  a: 1\ntitle: x\n",
			path: "x-foo.b", val: "2",
			want: "x-foo:\n  a: 1\n  b: 2\ntitle: x\n",
		},
		{
			name: "a new nested key makes its mapping",
			in:   "title: x\n",
			path: "x-foo.a.b", val: "1",
			want: "title: x\nx-foo:\n  a:\n    b: 1\n",
		},
		{
			name: "a nested key under a flow mapping rewrites that entry only",
			in:   "a: 1 # stays\nx-foo: {a: 1}\nz: 2\n",
			path: "x-foo.b", val: "2",
			want: "a: 1 # stays\nx-foo:\n  a: 1\n  b: 2\nz: 2\n",
		},
		{
			name: "a nested key under a null value",
			in:   "x-foo:\ntitle: x\n",
			path: "x-foo.a", val: "1",
			want: "x-foo:\n  a: 1\ntitle: x\n",
		},
		{
			name: "replacing a list keeps the lines around it",
			in:   "evidence:\n  - a.png\n  # second\n  - b.png\n# about title\ntitle: x\n",
			path: "evidence", val: "[c.png]",
			want: "evidence: [c.png]\n# about title\ntitle: x\n",
		},
		{
			name: "a block scalar with blank lines",
			in:   "c: |\n  line1\n\n  line3\nd: 2\n",
			path: "c", val: "x",
			want: "c: x\nd: 2\n",
		},
		{
			name: "an empty head",
			in:   "",
			path: "id", val: "F-001",
			want: "id: F-001\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := ParseYAML([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if err := d.Set(value(t, tc.val), strings.Split(tc.path, ".")...); err != nil {
				t.Fatal(err)
			}
			if got := string(d.Bytes()); got != tc.want {
				t.Errorf("got\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}

func TestUnset(t *testing.T) {
	for _, tc := range []struct {
		name, in, path, want string
	}{
		{
			name: "a key and the comment above it",
			in:   "id: F-001\n# the score\ncvss: 9.1\ntitle: x\n",
			path: "cvss",
			want: "id: F-001\ntitle: x\n",
		},
		{
			name: "the last key keeps a trailing comment for what follows",
			in:   "id: F-001\ncvss: 9.1\n\n# end\n",
			path: "cvss",
			want: "id: F-001\n\n# end\n",
		},
		{
			name: "a block list",
			in:   "evidence:\n  - a.png\n  - b.png\ntitle: x\n",
			path: "evidence",
			want: "title: x\n",
		},
		{
			name: "a nested key",
			in:   "x-foo:\n  a: 1 # keep\n  b: 2\ntitle: x\n",
			path: "x-foo.b",
			want: "x-foo:\n  a: 1 # keep\ntitle: x\n",
		},
		{
			name: "the last nested key leaves {}",
			in:   "x-foo:\n  a: 1\ntitle: x\n",
			path: "x-foo.a",
			want: "x-foo: {}\ntitle: x\n",
		},
		{
			name: "from one-line frontmatter",
			in:   "{id: F-001, cvss: 9.1, title: x}\n",
			path: "cvss",
			want: "id: F-001\ntitle: x\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := ParseYAML([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := d.Unset(strings.Split(tc.path, ".")...); err != nil || !ok {
				t.Fatal(ok, err)
			}
			if got := string(d.Bytes()); got != tc.want {
				t.Errorf("got\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}

func TestUnsetAbsent(t *testing.T) {
	d, _ := ParseYAML([]byte("a: 1\n"))
	if ok, err := d.Unset("b"); ok || err != nil {
		t.Fatal(ok, err)
	}
}

func TestFrontmatterRoundTrip(t *testing.T) {
	src := "---\r\nid: F-001\r\ntitle: x\r\n---\r\n\r\n## Description\r\n\r\nText.\r\n"
	d, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if string(d.Bytes()) != src {
		t.Fatalf("round trip changed the file:\n%q", d.Bytes())
	}
	if err := d.Set(scalar("y"), "title"); err != nil {
		t.Fatal(err)
	}
	if want := strings.Replace(src, "title: x", "title: y", 1); string(d.Bytes()) != want {
		t.Fatalf("got %q", d.Bytes())
	}
	if d.BodyLine() != 5 {
		t.Errorf("body line %d", d.BodyLine())
	}
}

func TestParseErrorsGiveFileLines(t *testing.T) {
	_, err := Parse([]byte("---\nid: F-001\ntitle: [\n---\n"))
	var e *Error
	if !errors.As(err, &e) || e.Line < 3 {
		t.Fatalf("got %v", err)
	}
	if _, err := Parse([]byte("id: x\n")); err == nil {
		t.Fatal("no frontmatter accepted")
	}
	if _, err := Parse([]byte("---\nid: x\n")); err == nil {
		t.Fatal("unterminated frontmatter accepted")
	}
	if _, err := Parse([]byte("---\n- a\n---\n")); err == nil {
		t.Fatal("a list head accepted")
	}
}

func TestSetRefusesThroughAScalar(t *testing.T) {
	d, _ := ParseYAML([]byte("title: x\n"))
	if err := d.Set(scalar("1"), "title", "a"); err == nil {
		t.Fatal("set through a scalar")
	}
	if string(d.Bytes()) != "title: x\n" {
		t.Fatal("a refused edit changed the doc")
	}
}
