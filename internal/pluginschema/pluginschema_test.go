package pluginschema

import (
	"encoding/json/jsontext"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	sch, err := Compile("foo", "finding", "x-foo-id", jsontext.Value(`{"type":"array","items":{"type":"string"}}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Check(sch, jsontext.Value(`["a", 1]`))
	if err != nil || len(got) != 1 || got[0].Where != "/1" || !strings.Contains(got[0].Message, "string") {
		t.Errorf("%+v, %v", got, err)
	}
	if got, _ := Check(sch, jsontext.Value(`["a"]`)); len(got) != 0 {
		t.Errorf("valid: %+v", got)
	}
}

func TestRefs(t *testing.T) {
	// A ref to one of rpt's schemas by $id resolves from memory.
	sch, err := Compile("foo", "kinds", "x-foo-row", jsontext.Value(`{"$ref":"https://github.com/astr4liteEx/rpt/schema/scope.schema.json"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := Check(sch, jsontext.Value(`{"kind":"scope"}`)); len(got) == 0 {
		t.Error("a scope record without id passed scope.schema.json")
	}
	for _, doc := range []string{
		`{"$ref":"file:///etc/passwd"}`,
		`{"$ref":"other.json"}`,
		`{"$ref":"https://example.com/s.json"}`,
		`{"$schema":"http://json-schema.org/draft-07/schema#","type":"string"}`,
	} {
		if _, err := Compile("foo", "finding", "x-foo-id", jsontext.Value(doc)); err == nil {
			t.Errorf("%s compiled", doc)
		}
	}
	// A ref inside the schema itself is fine.
	if _, err := Compile("foo", "finding", "x-foo-id", jsontext.Value(`{"$defs":{"s":{"type":"string"}},"$ref":"#/$defs/s"}`)); err != nil {
		t.Error(err)
	}
}
