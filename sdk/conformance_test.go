package sdk

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"io/fs"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The conformance cases in ../testdata/sdk are shared by every SDK; see
// the README there.

func loadCases(t *testing.T, file string, v any) {
	t.Helper()
	b, err := os.ReadFile("../testdata/sdk/" + file)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("needs the rpt repository's testdata/sdk folder")
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
}

type confRec struct {
	Kind string `json:"kind"`
	Raw  string `json:"raw"`
	Line int    `json:"line"`
}

type confYield struct {
	confRec
	ErrorLine int      `json:"error_line,omitzero"`
	Stopped   *confRec `json:"stopped,omitzero"`
}

func TestConformanceStream(t *testing.T) {
	var cases []struct {
		Name        string      `json:"name"`
		Input       string      `json:"input"`
		StopAtError bool        `json:"stop_at_error"`
		Want        []confYield `json:"want"`
	}
	loadCases(t, "stream.json", &cases)
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			var opts []RecordsOption
			if c.StopAtError {
				opts = append(opts, StopAtError())
			}
			got := []confYield{}
			for rec, err := range Records(strings.NewReader(c.Input), opts...) {
				r := confRec{Kind: rec.Kind, Raw: string(rec.Raw), Line: rec.Line}
				switch le, ok := errors.AsType[*LineError](err); {
				case errors.Is(err, ErrStopped):
					got = append(got, confYield{Stopped: &r})
				case ok:
					got = append(got, confYield{ErrorLine: le.Line})
				case err != nil:
					t.Fatal(err)
				default:
					got = append(got, confYield{confRec: r})
				}
			}
			if c.Want == nil {
				c.Want = []confYield{}
			}
			if !reflect.DeepEqual(got, c.Want) {
				t.Errorf("got  %+v\nwant %+v", got, c.Want)
			}
		})
	}
}

func TestConformanceSetMember(t *testing.T) {
	var cases []struct {
		Name   string         `json:"name"`
		In     string         `json:"in"`
		Member string         `json:"member"`
		Value  jsontext.Value `json:"value"`
		Want   string         `json:"want"`
		Error  bool           `json:"error"`
	}
	loadCases(t, "set_member.json", &cases)
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			var v any
			if err := json.Unmarshal(c.Value, &v); err != nil {
				t.Fatal(err)
			}
			got, err := SetMember([]byte(c.In), c.Member, v)
			if c.Error {
				if err == nil {
					t.Errorf("got %s, want an error", got)
				}
				return
			}
			if err != nil || string(got) != c.Want {
				t.Errorf("got  %s (%v)\nwant %s", got, err, c.Want)
			}
		})
	}
}

// roundTripper decodes a record of one type and emits it again.
func roundTripper[T any](in []byte) ([]byte, error) {
	var v T
	if err := json.Unmarshal(in, &v); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err := Emit(&b, v)
	return b.Bytes(), err
}

var roundTrippers = map[string]func([]byte) ([]byte, error){
	KindFinding:   roundTripper[Finding],
	KindPage:      roundTripper[Page],
	KindScope:     roundTripper[ScopeRow],
	KindConfig:    roundTripper[Config],
	KindEvidence:  roundTripper[Evidence],
	KindProblem:   roundTripper[Problem],
	KindReport:    roundTripper[Report],
	KindLocation:  roundTripper[Location],
	KindCommand:   roundTripper[Command],
	KindVersion:   roundTripper[VersionInfo],
	"description": roundTripper[Description],
}

func TestConformanceRoundTrip(t *testing.T) {
	var cases []struct {
		Name string         `json:"name"`
		Type string         `json:"type"`
		In   jsontext.Value `json:"in"`
		Want jsontext.Value `json:"want"`
	}
	loadCases(t, "round_trip.json", &cases)
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			rt, ok := roundTrippers[c.Type]
			if !ok {
				t.Fatalf("unknown type %q", c.Type)
			}
			got, err := rt(c.In)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Count(got, []byte("\n")) != 1 || !bytes.HasSuffix(got, []byte("\n")) {
				t.Errorf("emit wrote %q, want one line", got)
			}
			want := c.Want
			if want == nil {
				want = c.In
			}
			if !jsonEqual(t, got, want) {
				t.Errorf("got  %s\nwant %s", got, want)
			}
		})
	}
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(x, y)
}

func TestConformanceRun(t *testing.T) {
	var suite struct {
		Plugin struct {
			Description jsontext.Value `json:"description"`
			Complete    []string       `json:"complete"`
		} `json:"plugin"`
		Cases []struct {
			Name         string   `json:"name"`
			Args         []string `json:"args"`
			Describe     bool     `json:"describe"`
			Stdout       *string  `json:"stdout"`
			Runs         bool     `json:"runs"`
			NoUsage      bool     `json:"no_usage"`
			NoComplete   bool     `json:"no_complete"`
			CompleteArgs []string `json:"complete_args"`
			CompleteWord string   `json:"complete_word"`
		} `json:"cases"`
	}
	loadCases(t, "run.json", &suite)
	for _, c := range suite.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var p Plugin
			if err := json.Unmarshal(suite.Plugin.Description, &p.Description); err != nil {
				t.Fatal(err)
			}
			if c.NoUsage {
				p.Usage = ""
			}
			var ranWith []string
			p.Run = func(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
				ranWith = append([]string{}, args...)
				return 7
			}
			var gotArgs []string
			var gotWord string
			if !c.NoComplete {
				p.Complete = func(args []string, word string) []string {
					gotArgs, gotWord = append([]string{}, args...), word
					return suite.Plugin.Complete
				}
			}
			var out bytes.Buffer
			code := Run(p, c.Args, strings.NewReader(""), &out, io.Discard)
			if c.Runs {
				if code != 7 || !slices.Equal(ranWith, c.Args) {
					t.Errorf("exit %d, ran with %q, want 7 and %q", code, ranWith, c.Args)
				}
				return
			}
			if code != 0 || ranWith != nil {
				t.Errorf("exit %d, ran with %q; want exit 0 without running", code, ranWith)
			}
			switch {
			case c.Describe:
				if bytes.Count(out.Bytes(), []byte("\n")) != 1 || !bytes.HasSuffix(out.Bytes(), []byte("\n")) ||
					!jsonEqual(t, out.Bytes(), suite.Plugin.Description) {
					t.Errorf("got %q, want the description on one line", out.String())
				}
			case c.Stdout != nil && out.String() != *c.Stdout:
				t.Errorf("got %q, want %q", out.String(), *c.Stdout)
			}
			if c.CompleteArgs != nil && (!slices.Equal(gotArgs, c.CompleteArgs) && len(gotArgs)+len(c.CompleteArgs) > 0 || gotWord != c.CompleteWord) {
				t.Errorf("complete got %q %q, want %q %q", gotArgs, gotWord, c.CompleteArgs, c.CompleteWord)
			}
		})
	}
}
