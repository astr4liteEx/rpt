package report

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
	"go.yaml.in/yaml/v3"

	"github.com/astr4liteEx/rpt/sdk"
)

// FindingsDir is the folder, relative to the report root, that holds one
// markdown file per finding.
const FindingsDir = "findings"

// sectionKeys maps the fixed section headings to their keys. Any other ##
// heading is kept under its exact text.
var sectionKeys = map[string]string{
	"Description":      "description",
	"Remediation":      "remediation",
	"Proof of concept": "poc",
}

// frontmatterKeys are the frontmatter keys that map to declared Finding
// fields; every other key is kept in Finding.Extra.
var frontmatterKeys = []string{"id", "title", "scope", "severity", "evidence"}

// Findings reads every finding file in the findings folder, in file-name
// order. A malformed file doesn't stop the read: the findings that parsed are
// returned together with a joined error holding one *FileError per bad file.
func (r *Report) Findings() ([]sdk.Finding, error) {
	entries, err := fs.ReadDir(r.root.FS(), FindingsDir)
	if err != nil {
		return nil, fmt.Errorf("read findings: %w", err)
	}
	var (
		findings []sdk.Finding
		errs     []error
	)
	for _, e := range entries {
		if !e.Type().IsRegular() || path.Ext(e.Name()) != ".md" {
			continue
		}
		rel := path.Join(FindingsDir, e.Name())
		src, err := r.root.ReadFile(rel)
		if err != nil {
			errs = append(errs, &FileError{Path: rel, Err: err})
			continue
		}
		f, err := parseFinding(rel, src)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		findings = append(findings, f)
	}
	return findings, errors.Join(errs...)
}

// parseFinding parses one finding file: YAML frontmatter, then markdown
// sections under ## headings.
func parseFinding(rel string, src []byte) (sdk.Finding, error) {
	src = normaliseNewlines(src)
	head, body, err := splitFrontmatter(src)
	if err != nil {
		return sdk.Finding{}, &FileError{Path: rel, Line: 1, Err: err}
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(head, &doc); err != nil {
		return sdk.Finding{}, yamlFileError(rel, 1, err)
	}
	var fm struct {
		ID       string `yaml:"id"`
		Title    string
		Scope    []string
		Severity sdk.Severity
		Evidence []string
	}
	if err := doc.Decode(&fm); err != nil {
		return sdk.Finding{}, yamlFileError(rel, 1, err)
	}
	extra, err := extraFields(&doc)
	if err != nil {
		return sdk.Finding{}, &FileError{Path: rel, Err: err}
	}

	return sdk.Finding{
		Kind:     "finding",
		ID:       fm.ID,
		Title:    fm.Title,
		Scope:    fm.Scope,
		Severity: fm.Severity,
		Path:     rel,
		Sections: sections(body),
		Evidence: fm.Evidence,
		Extra:    extra,
	}, nil
}

// splitFrontmatter cuts src (LF line endings) into the YAML between the
// opening and closing "---" lines, and the markdown body after them.
func splitFrontmatter(src []byte) (head, body []byte, err error) {
	rest, ok := bytes.CutPrefix(src, []byte("---\n"))
	if !ok {
		return nil, nil, errors.New("no frontmatter: the file must start with a --- line")
	}
	for off := 0; off <= len(rest); {
		line, _, _ := bytes.Cut(rest[off:], []byte("\n"))
		if string(line) == "---" {
			end := min(off+len(line)+1, len(rest))
			return rest[:off], rest[end:], nil
		}
		off += len(line) + 1
	}
	return nil, nil, errors.New("unterminated frontmatter: no closing --- line")
}

// extraFields converts the frontmatter keys rpt doesn't declare into JSON
// values, so they pass through in Finding.Extra.
func extraFields(doc *yaml.Node) (map[string]jsontext.Value, error) {
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil
	}
	var extra map[string]jsontext.Value
	m := doc.Content[0].Content
	for i := 0; i+1 < len(m); i += 2 {
		key := m[i].Value
		if slices.Contains(frontmatterKeys, key) {
			continue
		}
		var v any
		if err := m[i+1].Decode(&v); err != nil {
			return nil, fmt.Errorf("frontmatter key %q: %w", key, err)
		}
		b, err := json.Marshal(v, json.Deterministic(true))
		if err != nil {
			return nil, fmt.Errorf("frontmatter key %q: %w", key, err)
		}
		if extra == nil {
			extra = map[string]jsontext.Value{}
		}
		extra[key] = b
	}
	return extra, nil
}

// sections splits a markdown body at its top-level ## headings. Headings
// inside code fences don't count, which is why this parses with goldmark
// instead of scanning lines.
func sections(body []byte) map[string]string {
	doc := goldmark.DefaultParser().Parse(text.NewReader(body))

	type heading struct {
		name              string
		lineStart, bodyAt int
	}
	var hs []heading
	for n := doc.FirstChild(); n != nil; n = n.NextSibling() {
		h, ok := n.(*ast.Heading)
		if !ok || h.Level != 2 || h.Lines().Len() == 0 {
			continue
		}
		first, last := h.Lines().At(0), h.Lines().At(h.Lines().Len()-1)
		lineStart := bytes.LastIndexByte(body[:first.Start], '\n') + 1
		bodyAt := lineEnd(body, last.Stop)
		if !isATX(body[lineStart:]) {
			bodyAt = lineEnd(body, bodyAt) // setext: skip the underline
		}
		var name strings.Builder
		for i := range h.Lines().Len() {
			seg := h.Lines().At(i)
			name.Write(seg.Value(body))
		}
		hs = append(hs, heading{strings.TrimSpace(name.String()), lineStart, bodyAt})
	}
	if len(hs) == 0 {
		return nil
	}

	out := make(map[string]string, len(hs))
	for i, h := range hs {
		end := len(body)
		if i+1 < len(hs) {
			end = hs[i+1].lineStart
		}
		key := h.name
		if k, ok := sectionKeys[h.name]; ok {
			key = k
		}
		content := string(body[min(h.bodyAt, end):end])
		out[key] = strings.TrimRight(strings.TrimLeft(content, "\n"), " \t\n")
	}
	return out
}

// lineEnd returns the offset just past the newline that ends the line
// containing offset i, or len(b).
func lineEnd(b []byte, i int) int {
	if i >= len(b) {
		return len(b)
	}
	if j := bytes.IndexByte(b[i:], '\n'); j >= 0 {
		return i + j + 1
	}
	return len(b)
}

// isATX reports whether a heading line starts with # (after up to three
// spaces of indentation), as opposed to a setext heading.
func isATX(line []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(line, " "), []byte("#"))
}
