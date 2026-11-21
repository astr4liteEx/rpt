package report

import (
	"bytes"
	"encoding/json/jsontext"
	"fmt"
	"math"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// NodeJSON turns a YAML value into JSON as written: a timestamp, a .nan
// or any other value JSON has no form for stays the text it was written
// as, never a reinterpretation of it.
func NodeJSON(n *yaml.Node) jsontext.Value {
	var b bytes.Buffer
	writeJSON(&b, n)
	return jsontext.Value(b.Bytes())
}

func writeJSON(b *bytes.Buffer, n *yaml.Node) {
	for n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			b.WriteString("null")
			return
		}
		writeJSON(b, n.Content[0])
	case yaml.MappingNode:
		b.WriteByte('{')
		seen := map[string]bool{}
		first := true
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if seen[k] {
				continue
			}
			seen[k] = true
			if !first {
				b.WriteByte(',')
			}
			first = false
			writeString(b, k)
			b.WriteByte(':')
			writeJSON(b, n.Content[i+1])
		}
		b.WriteByte('}')
	case yaml.SequenceNode:
		b.WriteByte('[')
		for i, c := range n.Content {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSON(b, c)
		}
		b.WriteByte(']')
	default:
		switch n.ShortTag() {
		case "!!null":
			b.WriteString("null")
		case "!!bool":
			if v, err := strconv.ParseBool(strings.ToLower(n.Value)); err == nil {
				b.WriteString(strconv.FormatBool(v))
				return
			}
			writeString(b, n.Value)
		case "!!int", "!!float":
			var v float64
			if err := yaml.Unmarshal([]byte(n.Value), &v); err == nil && !math.IsNaN(v) && !math.IsInf(v, 0) {
				b.Write(number(n.Value, v))
				return
			}
			writeString(b, n.Value)
		default:
			writeString(b, n.Value)
		}
	}
}

// number is a YAML number in JSON: its text when JSON reads that the
// same (9.1), else its value (0x1F as 31).
func number(text string, v float64) []byte {
	if tv := jsontext.Value(text); tv.IsValid() && tv.Kind() == '0' {
		return []byte(text)
	}
	return strconv.AppendFloat(nil, v, 'g', -1, 64)
}

func writeString(b *bytes.Buffer, s string) {
	out, _ := jsontext.AppendQuote(nil, s)
	b.Write(out)
}

// JSONNode turns a JSON value into a YAML value, members in order.
func JSONNode(v jsontext.Value) (*yaml.Node, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(v))
	n, err := readNode(dec)
	if err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	return n, nil
}

func readNode(dec *jsontext.Decoder) (*yaml.Node, error) {
	tok, err := dec.ReadToken()
	if err != nil {
		return nil, err
	}
	switch tok.Kind() {
	case '{':
		n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for dec.PeekKind() != '}' {
			k, err := dec.ReadToken()
			if err != nil {
				return nil, err
			}
			v, err := readNode(dec)
			if err != nil {
				return nil, err
			}
			n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k.String()}, v)
		}
		_, err := dec.ReadToken()
		return n, err
	case '[':
		n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for dec.PeekKind() != ']' {
			v, err := readNode(dec)
			if err != nil {
				return nil, err
			}
			n.Content = append(n.Content, v)
		}
		_, err := dec.ReadToken()
		return n, err
	case '"':
		return StringNode(tok.String()), nil
	case '0':
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: numberTag(tok.String()), Value: tok.String()}, nil
	case 't', 'f':
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: tok.String()}, nil
	default:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	}
}

func numberTag(s string) string {
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		return "!!int"
	}
	return "!!float"
}

// StringNode is a YAML string, quoted when it would otherwise read as
// something else.
func StringNode(s string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
	if (&yaml.Node{Kind: yaml.ScalarNode, Value: s}).ShortTag() != "!!str" {
		n.Style = yaml.DoubleQuotedStyle
	}
	return n
}

// ParseValue reads a value given on the command line as YAML: 9.1 is a
// number, [a, b] a list, {a: 1} a mapping.
func ParseValue(s string) (*yaml.Node, error) {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		return nil, fmt.Errorf("%q is not a YAML value: %w", s, err)
	}
	if len(n.Content) == 0 {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: ""}, nil
	}
	v := n.Content[0]
	v.Line, v.Column = 0, 0
	return v, nil
}
