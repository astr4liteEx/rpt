package sdk

import (
	"errors"
	"strings"
	"testing"
)

type got struct {
	kind, raw string
	line      int
	errLine   int // non-zero when the yield was a *LineError
}

func collect(t *testing.T, in string) []got {
	t.Helper()
	var out []got
	for rec, err := range Records(strings.NewReader(in)) {
		if err != nil {
			le, ok := errors.AsType[*LineError](err)
			if !ok {
				t.Fatalf("non-line error %v", err)
			}
			out = append(out, got{errLine: le.Line})
			continue
		}
		out = append(out, got{kind: rec.Kind, raw: string(rec.Raw), line: rec.Line})
	}
	return out
}

func TestRecords(t *testing.T) {
	in := "{\"kind\":\"finding\",\"id\":\"F-1\"}\r\n" + // 1: CRLF
		"\n" + // 2: blank
		"   \t\n" + // 3: whitespace only
		"not json\n" + // 4: malformed
		"[1,2]\n" + // 5: JSON but not an object
		`{"no":"kind"}` + "\n" + // 6: no kind: still a record
		"null\n" + // 7: null isn't a record
		`{"kind":"scope", "id":"S-1"}` // 8: no final newline; inner spacing kept
	want := []got{
		{kind: "finding", raw: `{"kind":"finding","id":"F-1"}`, line: 1},
		{errLine: 4},
		{errLine: 5},
		{kind: "", raw: `{"no":"kind"}`, line: 6},
		{errLine: 7},
		{kind: "scope", raw: `{"kind":"scope", "id":"S-1"}`, line: 8},
	}
	gotRecs := collect(t, in)
	if len(gotRecs) != len(want) {
		t.Fatalf("got %d yields %+v, want %d", len(gotRecs), gotRecs, len(want))
	}
	for i := range want {
		if gotRecs[i] != want[i] {
			t.Errorf("yield %d = %+v, want %+v", i, gotRecs[i], want[i])
		}
	}
}

func TestRecordsLongLines(t *testing.T) {
	mib := `{"kind":"finding","title":"` + strings.Repeat("a", 1<<20) + `"}`
	huge := `{"kind":"finding","title":"` + strings.Repeat("b", MaxLine) + `"}`
	in := mib + "\n" + huge + "\n" + `{"kind":"scope"}` + "\n"
	gotRecs := collect(t, in)
	if len(gotRecs) != 3 {
		t.Fatalf("got %d yields, want 3", len(gotRecs))
	}
	if gotRecs[0].kind != "finding" || len(gotRecs[0].raw) != len(mib) {
		t.Errorf("1 MiB line not read whole: kind %q, %d bytes", gotRecs[0].kind, len(gotRecs[0].raw))
	}
	if gotRecs[1].errLine != 2 {
		t.Errorf("oversized line = %+v, want a LineError on line 2", gotRecs[1])
	}
	if gotRecs[2].kind != "scope" || gotRecs[2].line != 3 {
		t.Errorf("line after the oversized one = %+v, want scope on line 3", gotRecs[2])
	}
}

func TestLineErrorsSayWhatIsWrong(t *testing.T) {
	for in, want := range map[string]string{
		"null":     "not a record: null",
		"[1]":      "not a record: json: ",
		`{"a":1,}`: "not a record: jsontext: ",
	} {
		for _, err := range Records(strings.NewReader(in)) {
			if err == nil || !strings.HasPrefix(errors.Unwrap(err).Error(), want) {
				t.Errorf("%s: %v, want %s...", in, err, want)
			}
		}
	}
}
