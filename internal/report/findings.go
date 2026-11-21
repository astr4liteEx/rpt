package report

import (
	"bytes"
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"path/filepath"
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

// FixedSections are the keys of the fixed sections, in the order rpt
// writes them.
var FixedSections = []string{"description", "remediation", "poc"}

// defaultHeadings are the fixed sections' headings when the report config
// doesn't rename them.
var defaultHeadings = Headings{
	"description": "Description",
	"remediation": "Remediation",
	"poc":         "Proof of concept",
}

// Headings maps each fixed section key to the heading a report uses for it.
// A heading matches its fixed key whatever its case; any other ## heading
// is kept under its exact text.
type Headings map[string]string

// newHeadings is the default headings with the renames in sections laid
// over them. Keys that aren't fixed sections and empty headings are left
// out; validate reports them.
func newHeadings(sections map[string]string) Headings {
	h := maps.Clone(defaultHeadings)
	for k, v := range sections {
		if _, fixed := h[k]; fixed && strings.TrimSpace(v) != "" {
			h[k] = strings.TrimSpace(v)
		}
	}
	return h
}

// key returns the section key for a heading: its fixed key if it names a
// fixed section, else the heading itself.
func (h Headings) key(heading string) string {
	for _, k := range FixedSections {
		if strings.EqualFold(h[k], heading) {
			return k
		}
	}
	return heading
}

// heading returns the heading rpt writes for a section key.
func (h Headings) heading(key string) string {
	return cmp.Or(h[key], key)
}

// headings returns the report's section headings, or the defaults when the
// report config can't be read: reading findings doesn't depend on it, and
// validate reports the config's problems.
func (r *Report) headings() Headings {
	if cfg, err := r.Config(); err == nil {
		return cfg.Headings
	}
	return defaultHeadings
}

// frontmatterKeys are the frontmatter keys that map to declared Finding
// fields; every other key is kept in Finding.Extra.
var frontmatterKeys = []string{"id", "title", "targets", "severity", "evidence"}

// formerKeys are frontmatter keys an older report format had, with what
// replaced each. A file using one is unreadable, so it can't be half read.
var formerKeys = map[string]string{
	"scope":  "targets, a list like [{scope: S-12}] (format 2)",
	"target": "targets, a list like [{scope: S-20, host: 10.0.1.5, port: 443}] (format 2)",
}

// Findings reads every finding file in the findings folder, in file-name
// order. A missing folder holds no findings. A malformed file doesn't stop
// the read: the findings that parsed are returned together with a joined
// error holding one *FileError per bad file.
func (r *Report) Findings() ([]sdk.Finding, error) {
	list, err := r.FindingsWithLines()
	for i := range list {
		list[i].Lines = nil
	}
	return list, err
}

// FindingsWithLines is Findings with each finding's Lines set: its file's
// absolute path and where its frontmatter keys and sections sit in it.
func (r *Report) FindingsWithLines() ([]sdk.Finding, error) {
	entries, err := fs.ReadDir(r.root.FS(), FindingsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", FindingsDir, err)
	}
	var (
		findings []sdk.Finding
		errs     []error
		h        = r.headings()
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
		f, err := parseFinding(rel, src, h)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		f.Lines.File = filepath.Join(r.abs, filepath.FromSlash(rel))
		findings = append(findings, f)
	}
	return findings, errors.Join(errs...)
}

// parseFinding parses one finding file: YAML frontmatter, then markdown
// sections under ## headings. Lines is set: this is the one place rpt works
// out where a finding's parts sit.
func parseFinding(rel string, src []byte, h Headings) (sdk.Finding, error) {
	f, err := parseFindingBytes(rel, src, h)
	f.Rev = Rev(src)
	return f, err
}

func parseFindingBytes(rel string, src []byte, h Headings) (sdk.Finding, error) {
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
		Targets  any
		Severity sdk.Severity
		Evidence []string
	}
	if err := doc.Decode(&fm); err != nil {
		return sdk.Finding{}, yamlFileError(rel, 1, err)
	}
	if err := checkReservedKeys(rel, &doc); err != nil {
		return sdk.Finding{}, err
	}
	targets, err := decodeTargets(fm.Targets)
	if err != nil {
		line := keyLines(&doc)["targets"]
		if line > 0 {
			line++ // frontmatter starts on file line 2
		}
		return sdk.Finding{}, &FileError{Path: rel, Line: line, Err: err}
	}
	extra, err := extraFields(&doc)
	if err != nil {
		return sdk.Finding{}, &FileError{Path: rel, Err: err}
	}

	return sdk.Finding{
		Kind:     "finding",
		ID:       fm.ID,
		Title:    fm.Title,
		Targets:  targets,
		Severity: fm.Severity,
		Path:     rel,
		Sections: sections(body, h),
		Evidence: fm.Evidence,
		Lines:    findingLines(&doc, head, body, h),
		Extra:    extra,
	}, nil
}

// bodyFirstLine is the file line a finding's body starts on: after the
// opening ---, the frontmatter and the closing ---.
func bodyFirstLine(head []byte) int {
	return 3 + bytes.Count(head, []byte("\n"))
}

// bodyLine is the file line of byte offset off in a body starting on file
// line first.
func bodyLine(body []byte, first, off int) int {
	return first + bytes.Count(body[:off], []byte("\n"))
}

// findingLines is where a finding's frontmatter keys and sections sit in
// its file. A repeated section is located where its kept text is: the last.
func findingLines(doc *yaml.Node, head, body []byte, h Headings) *sdk.Lines {
	l := &sdk.Lines{Frontmatter: keyLines(doc)}
	for k := range l.Frontmatter {
		l.Frontmatter[k]++ // frontmatter starts on file line 2
	}
	first := bodyFirstLine(head)
	for _, sp := range sectionSpans(body, h) {
		if l.Sections == nil {
			l.Sections = map[string]sdk.SectionLines{}
		}
		sl := sdk.SectionLines{Heading: bodyLine(body, first, sp.lineStart)}
		if sectionText(body, sp) != "" {
			raw := body[sp.bodyAt:sp.end]
			sl.Text = bodyLine(body, first, sp.bodyAt+len(raw)-len(bytes.TrimLeft(raw, "\n")))
		}
		l.Sections[sp.key] = sl
	}
	return l
}

// decodeTargets converts frontmatter targets, decoded from YAML, into
// sdk.Targets by way of JSON, so their unknown members land in
// Target.Extra. Absent targets are an empty list.
func decodeTargets(v any) ([]sdk.Target, error) {
	if v == nil {
		return []sdk.Target{}, nil
	}
	if _, ok := v.([]any); !ok {
		return nil, errors.New("targets must be a list, like [{scope: S-12}]")
	}
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("targets: %w", err)
	}
	var ts []sdk.Target
	if err := json.Unmarshal(b, &ts); err != nil {
		return nil, fmt.Errorf("targets: every item must be a map, like {scope: S-12, port: 443}: %w", err)
	}
	return ts, nil
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

// recordKeys are the finding record members rpt sets itself. A frontmatter
// key with one of these names would clash with them in the record.
var recordKeys = []string{"kind", "path", "rev", "sections", "lines"}

// checkReservedKeys refuses a frontmatter key named like a recordKeys member
// or one of the formerKeys, at its line.
func checkReservedKeys(rel string, doc *yaml.Node) error {
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil
	}
	m := doc.Content[0].Content
	for i := 0; i+1 < len(m); i += 2 {
		key := m[i].Value
		if slices.Contains(recordKeys, key) {
			return &FileError{Path: rel, Line: m[i].Line + 1, // frontmatter starts on file line 2
				Err: fmt.Errorf("frontmatter key %q is reserved: rpt sets it on finding records; rename the key", key)}
		}
		if now, ok := formerKeys[key]; ok {
			return &FileError{Path: rel, Line: m[i].Line + 1,
				Err: fmt.Errorf("frontmatter key %q is from report format 1; it is now %s", key, now)}
		}
	}
	return nil
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

// span is one ## section of a markdown body: its key, the offset its
// heading line starts at, the offset its text starts at, and its end.
type span struct {
	key                    string
	lineStart, bodyAt, end int
}

// sectionSpans finds the top-level ## headings of a markdown body. Headings
// inside code fences don't count, which is why this parses with goldmark
// instead of scanning lines.
func sectionSpans(body []byte, h Headings) []span {
	doc := goldmark.DefaultParser().Parse(text.NewReader(body))
	var spans []span
	for n := doc.FirstChild(); n != nil; n = n.NextSibling() {
		hd, ok := n.(*ast.Heading)
		if !ok || hd.Level != 2 || hd.Lines().Len() == 0 {
			continue
		}
		first, last := hd.Lines().At(0), hd.Lines().At(hd.Lines().Len()-1)
		lineStart := bytes.LastIndexByte(body[:first.Start], '\n') + 1
		bodyAt := lineEnd(body, last.Stop)
		if !isATX(body[lineStart:]) {
			bodyAt = lineEnd(body, bodyAt) // setext: skip the underline
		}
		var name strings.Builder
		for i := range hd.Lines().Len() {
			seg := hd.Lines().At(i)
			name.Write(seg.Value(body))
		}
		key := h.key(strings.TrimSpace(name.String()))
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
func sections(body []byte, h Headings) map[string]string {
	spans := sectionSpans(body, h)
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
	for _, k := range FixedSections {
		if _, ok := secs[k]; ok {
			keys = append(keys, k)
		}
	}
	var rest []string
	for k := range secs {
		if !slices.Contains(FixedSections, k) {
			rest = append(rest, k)
		}
	}
	slices.Sort(rest)
	return append(keys, rest...)
}

// appendSection adds a ## section to the end of the body, after one blank
// line: blank lines already at the end are dropped first, so none pile up.
// An empty section is its heading alone; the blank line before whatever
// comes next is written by that next append. The body then ends with one
// newline after its last non-blank line, which markdown linters ask for.
func (ff *findingFile) appendSection(heading, text string) {
	ff.body = bytes.TrimRight(ff.body, "\n")
	if len(ff.body) > 0 {
		ff.body = append(ff.body, '\n')
	}
	ff.body = append(ff.body, '\n') // a blank line after the frontmatter or the last section
	if text = strings.TrimSpace(text); text == "" {
		ff.body = append(ff.body, "## "+heading+"\n"...)
		return
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
