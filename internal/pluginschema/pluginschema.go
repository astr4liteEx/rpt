// Package pluginschema compiles the JSON Schemas plugins declare in
// --describe and checks values against them. It never touches the disk or
// the network: a $ref may point inside the schema or at one of rpt's own
// schemas, served from memory by $id.
package pluginschema

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/astr4liteEx/rpt/schema"
)

// Draft is the only JSON Schema draft a plugin may use.
const Draft = "https://json-schema.org/draft/2020-12/schema"

// base is where a plugin's schemas are said to live. Nothing is ever
// fetched from it: a relative $ref resolving here is refused.
const base = "https://rpt.invalid/plugins/"

// Compile compiles one schema plugin declared for name under noun
// (finding, page, scope, config or kinds).
func Compile(plugin, noun, name string, doc jsontext.Value) (*jsonschema.Schema, error) {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	if m, ok := v.(map[string]any); ok {
		if d, ok := m["$schema"]; ok && d != Draft {
			return nil, fmt.Errorf("$schema %v: only draft 2020-12 (%s) is supported", d, Draft)
		}
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(jsonschema.SchemeURLLoader{}) // no file, no network
	if err := addRPTSchemas(c); err != nil {
		return nil, err
	}
	loc := base + url.PathEscape(plugin) + "/" + noun + "/" + url.PathEscape(name) + ".json"
	if err := c.AddResource(loc, v); err != nil {
		return nil, err
	}
	sch, err := c.Compile(loc)
	if err != nil {
		return nil, oneLine(err)
	}
	return sch, nil
}

// addRPTSchemas serves rpt's own schemas from memory, by $id.
func addRPTSchemas(c *jsonschema.Compiler) error {
	return fs.WalkDir(schema.Files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := schema.Files.ReadFile(p)
		if err != nil {
			return err
		}
		v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		id, _ := v.(map[string]any)["$id"].(string)
		if id == "" {
			return nil
		}
		return c.AddResource(id, v)
	})
}

// oneLine is err's message on one line.
func oneLine(err error) error {
	return errors.New(strings.Join(strings.Fields(err.Error()), " "))
}

// A Failure is one way a value breaks a schema: Where is the JSON Pointer
// inside the value ("" for the value itself).
type Failure struct {
	Where, Message string
}

var printer = message.NewPrinter(language.English)

// Check checks the JSON value v against sch and returns each way it fails,
// most specific first.
func Check(sch *jsonschema.Schema, v jsontext.Value) ([]Failure, error) {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(v))
	if err != nil {
		return nil, err
	}
	return CheckValue(sch, inst), nil
}

// CheckValue is Check for a value already decoded, as a string for a
// scope.csv cell.
func CheckValue(sch *jsonschema.Schema, v any) []Failure {
	err := sch.Validate(v)
	ve, ok := errors.AsType[*jsonschema.ValidationError](err)
	if !ok {
		if err != nil {
			return []Failure{{Message: err.Error()}}
		}
		return nil
	}
	var out []Failure
	var walk func(*jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			where := ""
			if len(e.InstanceLocation) > 0 {
				where = "/" + strings.Join(e.InstanceLocation, "/")
			}
			out = append(out, Failure{Where: where, Message: e.ErrorKind.LocalizedString(printer)})
			return
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)
	return out
}
