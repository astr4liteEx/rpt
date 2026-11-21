package report

import (
	"slices"
	"testing"
)

func TestCheckRecords(t *testing.T) {
	m := fixture(t, nil)
	recs := []Record{
		{"scope", 1, []byte(`{"kind":"scope","id":"S-99","host":"10.0.0.99","env":"prod"}`)},
		{"finding", 2, []byte(`{"kind":"finding","id":"F-001","title":"XSS","severity":"high","targets":[{"scope":"S-404"}],"sections":{"description":"d","remediation":"r","poc":"p"}}`)},
		{"finding", 3, []byte(`{"kind":"finding","title":"New","severity":"nope","targets":[{"scope":"S-12"}]}`)},
		{"finding", 4, []byte(`{"kind":"finding","id":"F-001","title":"again"}`)},
		{"finding", 5, []byte(`{"kind":"finding","title":[]}`)},
		{"note", 6, []byte(`{"kind":"note"}`)},
	}
	got := problems(m.CheckRecords(recs))
	want := []string{
		"-:2 error scopeIDsExist: F-001: S-404 is not in scope.csv",
		"-:3 error write: severity \"nope\" is not one of critical, high, medium, low, info",
		"-:4 error duplicate: finding F-001 is in the stream twice; the first is on line 2",
		"-:5 error input: finding: json: cannot unmarshal JSON array into Go string within \"/title\"",
	}
	if !slices.Equal(got, want) {
		for _, g := range got {
			t.Log(g)
		}
		t.Error("problems differ")
	}
}
