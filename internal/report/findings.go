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

// The review folders, relative to the report root. Each holds one markdown
// file per finding; which folder a file is in is its review state.
const (
	FindingsDir = "findings" // promoted: part of the report
	StagingDir  = "staging"  // added by automation, awaiting review
	RejectedDir = "rejected" // judged false; kept so automation never re-adds it
)

// sectionKeys maps the fixed section headings to their keys. Any other ##
// heading is kept under its exact text.
var sectionKeys = map[string]string{
	"Description":      "description",
	"Remediation":      "remediation",
	"Proof of concept": "poc",
}

// frontmatterKeys are the frontmatter keys that map to declared Finding
// fields; every other key is kept in Finding.Extra.
var frontmatterKeys = []string{"id", "key", "title", "scope", "severity", "evidence", "target"}

// Findings reads every finding file in the findings folder; see FindingsIn.
func (r *Report) Findings() ([]sdk.Finding, error) {
	return r.FindingsIn(FindingsDir)
}

// FindingsIn reads every finding file in one review folder, in file-name
// order. A missing folder holds no findings. A malformed file doesn't stop
// the read: the findings that parsed are returned together with a joined
// error holding one *FileError per bad file.
func (r *Report) FindingsIn(dir string) ([]sdk.Finding, error) {
	entries, err := fs.ReadDir(r.root.FS(), dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	var (
		findings []sdk.Finding
		errs     []error
	)
	for _, e := range entries {
		if !e.Type().IsRegular() || path.Ext(e.Name()) != ".md" {
			continue
		}
		rel := path.Join(dir, e.Name())
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
		Key      string
		Title    string
		Scope    []string
		Severity sdk.Severity
		Evidence []string
		Target   any
	}
	if err := doc.Decode(&fm); err != nil {
		return sdk.Finding{}, yamlFileError(rel, 1, err)
	}
	target, err := decodeTarget(fm.Target)
	if err != nil {
		return sdk.Finding{}, &FileError{Path: rel, Err: err}
	}
	extra, err := extraFields(&doc)
	if err != nil {
		return sdk.Finding{}, &FileError{Path: rel, Err: err}
	}

	return sdk.Finding{
		Kind:     "finding",
		ID:       fm.ID,
		Key:      fm.Key,
		Title:    fm.Title,
		Scope:    fm.Scope,
		Severity: fm.Severity,
		Path:     rel,
		Sections: sections(body),
		Evidence: fm.Evidence,
		Target:   target,
		Extra:    extra,
	}, nil
}

// decodeTarget converts a frontmatter target, decoded from YAML, into an
// sdk.Target by way of JSON, so its unknown members land in Target.Extra.
func decodeTarget(v any) (*sdk.Target, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("frontmatter key \"target\": %w", err)
	}
	var t sdk.Target
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("frontmatter key \"target\": %w", err)
	}
	return &t, nil
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

// sectionHeadings maps section keys back to the headings rpt writes.
var sectionHeadings = map[string]string{
	"description": "Description",
	"remediation": "Remediation",
	"poc":         "Proof of concept",
}

// span is one ## section of a markdown body: its key, the offset its
// heading line starts at, the offset its text starts at, and its end.
type span struct {
	key                    string
	lineStart, bodyAt, end int
}

// sectionSpans finds the top-level ## headings of a markdown body. Headings
// inside code fences don't count, which is why this parses with goldmark
// instead of scanning lines.
func sectionSpans(body []byte) []span {
	doc := goldmark.DefaultParser().Parse(text.NewReader(body))
	var spans []span
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
		key := strings.TrimSpace(name.String())
		if k, ok := sectionKeys[key]; ok {
			key = k
		}
		spans = append(spans, span{key: key, lineStart: lineStart, bodyAt: bodyAt})
	}
	for i := range spans {
		spans[i].end = len(body)
		if i+1 < len(spans) {
			spans[i].end = spans[i+1].lineStart
		}
		spans[i].bodyAt = min(spans[i].bodyAt, spans[i].end)
	}
	return spans
}

// sectionText is a section's text without surrounding blank lines.
func sectionText(body []byte, s span) string {
	return strings.TrimRight(strings.TrimLeft(string(body[s.bodyAt:s.end]), "\n"), " \t\n")
}

// sections splits a markdown body at its top-level ## headings.
func sections(body []byte) map[string]string {
	spans := sectionSpans(body)
	if len(spans) == 0 {
		return nil
	}
	out := make(map[string]string, len(spans))
	for _, s := range spans {
		out[s.key] = sectionText(body, s)
	}
	return out
}

// sectionOrder lists section keys in the order rpt writes them: the fixed
// sections first, then the rest by name.
func sectionOrder(secs map[string]string) []string {
	var keys []string
	for _, k := range []string{"description", "remediation", "poc"} {
		if _, ok := secs[k]; ok {
			keys = append(keys, k)
		}
	}
	var rest []string
	for k := range secs {
		if _, fixed := sectionHeadings[k]; !fixed {
			rest = append(rest, k)
		}
	}
	slices.Sort(rest)
	return append(keys, rest...)
}

// setSection replaces the text of the section with the given key, or
// appends the section when the body has none. Text that is already there
// changes nothing.
func (ff *findingFile) setSection(key, text string) {
	text = strings.TrimSpace(text)
	spans := sectionSpans(ff.body)
	for i, s := range spans {
		if s.key != key {
			continue
		}
		if sectionText(ff.body, s) == text {
			return
		}
		repl := "\n" + text + "\n"
		if i < len(spans)-1 {
			repl += "\n"
		}
		ff.body = slices.Concat(ff.body[:s.bodyAt], []byte(repl), ff.body[s.end:])
		return
	}
	heading := key
	if h, ok := sectionHeadings[key]; ok {
		heading = h
	}
	if len(ff.body) > 0 {
		if !bytes.HasSuffix(ff.body, []byte("\n")) {
			ff.body = append(ff.body, '\n')
		}
		ff.body = append(ff.body, '\n')
	}
	ff.body = append(ff.body, "## "+heading+"\n\n"+text+"\n"...)
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
