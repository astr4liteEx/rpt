package sdk

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
)

// SetMember returns the JSON object raw with its member name set to value.
// Every other member keeps its original bytes and position; an existing
// member is replaced where it stands, a new one is appended. Filters use it
// to change one field of a record without re-encoding the rest.
func SetMember(raw []byte, name string, value any) ([]byte, error) {
	val, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("set %q: %w", name, err)
	}
	quoted, err := json.Marshal(name)
	if err != nil {
		return nil, fmt.Errorf("set %q: %w", name, err)
	}
	member := append(append(quoted, ':'), val...)
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		return nil, errors.New("set member: not a JSON object")
	}
	var out bytes.Buffer
	out.WriteByte('{')
	found := false
	for dec.PeekKind() != '}' {
		rawName, err := dec.ReadValue()
		if err != nil {
			return nil, fmt.Errorf("set %q: %w", name, err)
		}
		rawName = bytes.Clone(rawName)
		var key string
		if err := json.Unmarshal(rawName, &key); err != nil {
			return nil, fmt.Errorf("set %q: %w", name, err)
		}
		rawVal, err := dec.ReadValue()
		if err != nil {
			return nil, fmt.Errorf("set %q: %w", name, err)
		}
		if out.Len() > 1 {
			out.WriteByte(',')
		}
		if key == name && !found {
			found = true
			out.Write(member)
			continue
		}
		out.Write(rawName)
		out.WriteByte(':')
		out.Write(rawVal)
	}
	if !found {
		if out.Len() > 1 {
			out.WriteByte(',')
		}
		out.Write(member)
	}
	out.WriteByte('}')
	if _, err := dec.ReadToken(); err != nil {
		return nil, fmt.Errorf("set %q: %w", name, err)
	}
	if _, err := dec.ReadToken(); err != io.EOF {
		return nil, fmt.Errorf("set %q: not one JSON object: more follows it", name)
	}
	return out.Bytes(), nil
}
