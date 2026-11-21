package cli

import (
	"fmt"
	"slices"
	"strings"
)

// A kindColumns is the table columns for one kind of record.
type kindColumns struct {
	kind string
	cols []Column
}

// columns are the table columns for each kind of record, in the order
// tables print.
var columns = []kindColumns{
	{"location", []Column{{Header: "PATH", Field: "path"}, {Header: "FORMAT", Field: "format"}, {Header: "FINDINGS", Field: "findings"}}},
	{"command", []Column{
		{Header: "NAME", Field: "name"}, {Header: "SOURCE", Value: commandSource},
		{Header: "SUMMARY", Field: "summary"}, {Header: "PATH", Field: "path"},
	}},
	{"version", []Column{{Header: "VERSION", Field: "version"}, {Header: "SCHEMA", Field: "schema_version"}, {Header: "FORMAT", Field: "format"}}},
	{"config", []Column{{Header: "KEY", Field: "key"}, {Header: "VALUE", Field: "value"}}},
	{"scope", []Column{{Header: "ID", Field: "id"}, {Header: "HOST", Field: "host"}, {Header: "PORT", Field: "port"}, {Header: "PROTOCOL", Field: "protocol"}}},
	{"finding", []Column{
		{Header: "ID", Field: "id"}, {Header: "SEVERITY", Field: "severity", Severity: true},
		{Header: "TITLE", Field: "title"}, {Header: "SCOPE", Value: findingScope},
	}},
	{"page", []Column{{Header: "ID", Field: "id"}, {Header: "TITLE", Field: "title"}, {Header: "PATH", Field: "path"}}},
	{"evidence", []Column{
		{Header: "OWNER", Value: func(m map[string]any) string { return fmt.Sprint(first(m["finding"], m["page"])) }},
		{Header: "SOURCE", Field: "source"}, {Header: "PATH", Field: "path"}, {Header: "EXISTS", Field: "exists"},
	}},
	{"problem", []Column{
		{Header: "PATH", Field: "path"}, {Header: "LINE", Field: "line"}, {Header: "LEVEL", Field: "level"},
		{Header: "RULE", Field: "rule"}, {Header: "MESSAGE", Field: "message"},
	}},
}

func first(vs ...any) any {
	for _, v := range vs {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// findingScope is the scope rows a finding's targets fall in, once each:
// "S-12,S-14".
func findingScope(m map[string]any) string {
	targets, _ := m["targets"].([]any)
	var ids []string
	for _, t := range targets {
		tm, _ := t.(map[string]any)
		if id, _ := tm["scope"].(string); id != "" && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return strings.Join(ids, ",")
}

// commandSource is where a command comes from, and whether this rpt can
// run it as it asks.
func commandSource(m map[string]any) string {
	src, _ := m["source"].(string)
	if bad, _ := m["incompatible"].(bool); bad {
		src += " (incompatible)"
	}
	return src
}
