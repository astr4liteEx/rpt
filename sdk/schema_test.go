package sdk

import (
	"encoding/json/v2"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestSchemasMatchTypes checks that each published JSON Schema in schema/
// names exactly the fields the Go wire type declares, and requires exactly
// the ones that are never omitted, so the two can't drift apart.
func TestSchemasMatchTypes(t *testing.T) {
	tests := []struct {
		file string
		path []string // keys from the schema root down to the object schema
		typ  reflect.Type
	}{
		{"finding.schema.json", nil, reflect.TypeFor[Finding]()},
		{"scope.schema.json", nil, reflect.TypeFor[ScopeRow]()},
		{"problem.schema.json", nil, reflect.TypeFor[Problem]()},
		{"report.schema.json", nil, reflect.TypeFor[Report]()},
		{"report.schema.json", []string{"$defs", "reportMeta"}, reflect.TypeFor[ReportMeta]()},
		{"report.schema.json", []string{"$defs", "reportSection"}, reflect.TypeFor[ReportSection]()},
		{"report.schema.json", []string{"$defs", "reportFinding"}, reflect.TypeFor[ReportFinding]()},
		{"finding.schema.json", []string{"$defs", "target"}, reflect.TypeFor[Target]()},
		{"report.schema.json", []string{"$defs", "reportTarget"}, reflect.TypeFor[ReportTarget]()},
		{"finding.schema.json", []string{"$defs", "lines"}, reflect.TypeFor[Lines]()},
		{"scope.schema.json", []string{"$defs", "lines"}, reflect.TypeFor[ScopeLines]()},
		{"finding.schema.json", []string{"$defs", "sectionLines"}, reflect.TypeFor[SectionLines]()},
		{"version.schema.json", nil, reflect.TypeFor[VersionInfo]()},
		{"severity.schema.json", nil, reflect.TypeFor[SeverityLevel]()},
		{"section.schema.json", nil, reflect.TypeFor[Section]()},
		{"command.schema.json", nil, reflect.TypeFor[Command]()},
		{"location.schema.json", nil, reflect.TypeFor[Location]()},
		{"evidence.schema.json", nil, reflect.TypeFor[Evidence]()},
		{"config.schema.json", nil, reflect.TypeFor[Config]()},
		{"config.schema.json", []string{"properties", "lines"}, reflect.TypeFor[ConfigLines]()},
		{"finding.schema.json", []string{"$defs", "position"}, reflect.TypeFor[Position]()},
		{"command.schema.json", []string{"$defs", "description"}, reflect.TypeFor[Description]()},
	}
	for _, tt := range tests {
		t.Run(tt.typ.Name(), func(t *testing.T) {
			obj := loadSchema(t, tt.file, tt.path)

			var props []string
			for name := range obj.Properties {
				props = append(props, name)
			}
			slices.Sort(props)
			slices.Sort(obj.Required)

			wantProps, wantRequired := jsonFields(tt.typ)
			if !slices.Equal(props, wantProps) {
				t.Errorf("schema properties = %v, Go fields = %v", props, wantProps)
			}
			if !slices.Equal(obj.Required, wantRequired) {
				t.Errorf("schema required = %v, Go non-omitzero fields = %v", obj.Required, wantRequired)
			}
			if !obj.AdditionalProperties {
				t.Error("additionalProperties must be true: records pass through unknown fields")
			}
		})
	}
}

type objectSchema struct {
	Properties           map[string]any `json:"properties"`
	Required             []string       `json:"required"`
	AdditionalProperties bool           `json:"additionalProperties"`
}

func loadSchema(t *testing.T, file string, path []string) objectSchema {
	t.Helper()
	b, err := os.ReadFile("../schema/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var node any
	if err := json.Unmarshal(b, &node); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	for _, key := range path {
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("%s: %v is not an object", file, path)
		}
		node = m[key]
	}
	sub, err := json.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	var obj objectSchema
	if err := json.Unmarshal(sub, &obj); err != nil {
		t.Fatalf("%s %v: %v", file, path, err)
	}
	return obj
}

// jsonFields returns the sorted JSON member names a struct declares, and the
// subset that is always encoded (no omitzero).
func jsonFields(typ reflect.Type) (all, required []string) {
	for f := range typ.Fields() {
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || opts == "embed" {
			continue
		}
		all = append(all, name)
		if !strings.Contains(opts, "omitzero") {
			required = append(required, name)
		}
	}
	slices.Sort(all)
	slices.Sort(required)
	return all, required
}
