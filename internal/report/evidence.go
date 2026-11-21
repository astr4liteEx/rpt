package report

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/astr4liteEx/rpt/internal/doc"
)

// A Ref is one reference a finding or page makes to a file: an entry in
// its evidence list, or a link or image in its text.
type Ref struct {
	Doc    *Doc
	Ref    string    // as written: the list entry, or the link's destination as markdown reads it
	Path   string    // the file it names, relative to the report root; "" when it leaves the report
	Source string    // "frontmatter" or "body"
	Link   *doc.Link // for a body reference
	Line   int       // file line
}

var scheme = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)

// isFileRef reports whether a link destination names a file rather than a
// web address or a place in the same page.
func isFileRef(dest string) bool {
	return dest != "" && !scheme.MatchString(dest) && !strings.HasPrefix(dest, "#") && !strings.HasPrefix(dest, "//")
}

// Refs lists the references d makes, the list first, then the links in
// its text in order. Links rpt can't place are returned as errors.
func (m *Model) Refs(d *Doc) ([]Ref, []error) {
	if d.Err != nil {
		return nil, nil
	}
	var out []Ref
	for i, e := range d.Evidence {
		line := d.KeyLine("evidence")
		if n := d.src.Get("evidence"); n != nil && i < len(n.Content) {
			line = n.Content[i].Line + d.src.HeadLine() - 1
		}
		out = append(out, Ref{Doc: d, Ref: e, Path: m.resolve(d, e), Source: "frontmatter", Line: line})
	}
	links, errs := d.src.Links()
	for i := range links {
		l := &links[i]
		if !isFileRef(l.Dest) {
			continue
		}
		out = append(out, Ref{Doc: d, Ref: l.Dest, Path: m.resolve(d, l.Dest), Source: "body", Link: l, Line: l.Line + d.BodyLine() - 1})
	}
	var placeErrs []error
	for _, err := range errs {
		var u *doc.UnplacedError
		if errors.As(err, &u) && isFileRef(u.Dest) {
			placeErrs = append(placeErrs, &FileError{Path: d.Path, Line: u.Line + d.BodyLine() - 1, Err: errors.New(strings.TrimPrefix(err.Error(), fmt.Sprintf("line %d: ", u.Line)))})
		}
	}
	return out, placeErrs
}

// resolve is the file a reference in d names, relative to the report
// root, or "" when it leaves the report. A destination is taken as
// written; when no such file exists but its percent-decoded form does,
// that one.
func (m *Model) resolve(d *Doc, ref string) string {
	rel := within(path.Dir(d.Path), ref)
	if rel == "" {
		return ""
	}
	if !m.exists(rel) {
		if dec, err := url.PathUnescape(ref); err == nil && dec != ref {
			if r := within(path.Dir(d.Path), dec); r != "" && m.exists(r) {
				return r
			}
		}
	}
	return rel
}

// within joins ref to dir, or "" when the result leaves the report.
func within(dir, ref string) string {
	if path.IsAbs(ref) || filepath.IsAbs(ref) {
		return ""
	}
	rel := path.Join(dir, ref)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return ""
	}
	return rel
}

// exists reports whether rel is a regular file, as this command sees the
// report. A symlink that leaves the report doesn't count.
func (m *Model) exists(rel string) bool {
	if f, ok := m.files[rel]; ok && f.dirty {
		return !f.remove
	}
	info, err := m.root.Stat(rel)
	return err == nil && info.Mode().IsRegular()
}

// relFrom is the path of rel, relative to the report root, as written in
// a file in dir.
func relFrom(dir, rel string) string {
	r, err := filepath.Rel(filepath.FromSlash(dir), filepath.FromSlash(rel))
	if err != nil {
		return rel
	}
	return filepath.ToSlash(r)
}

// MediaType is a file's type: from its extension, else from its first
// bytes.
func (m *Model) MediaType(rel string) string {
	if t := mime.TypeByExtension(strings.ToLower(path.Ext(rel))); t != "" {
		return strings.Split(t, ";")[0]
	}
	f, err := m.root.Open(rel)
	if err != nil {
		return ""
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	return strings.Split(http.DetectContentType(head[:n]), ";")[0]
}

// An EvidenceSource is a file to add to a document's evidence, and where
// to link it.
type EvidenceSource struct {
	Path    string // an OS path
	Section string // a finding's section key, or body for a page; "" for no link
	Text    string // the link's text
}

// AddEvidence lists each source in d's evidence. A file already in the
// report is listed where it is; any other is copied into the kind's
// evidence folder as <id>-<slug>.<ext>, -2, -3 on a clash, or exactly as
// as (one source only; it must not exist). A source with a Section is
// also linked there: an image as ![text](ref), anything else as
// [text](ref).
func (m *Model) AddEvidence(d *Doc, srcs []EvidenceSource, as string) (*Doc, error) {
	if as != "" && len(srcs) != 1 {
		return nil, refuse(d.Path, "--as names one file")
	}
	rootAbs, err := filepath.EvalSymlinks(m.Dir)
	if err != nil {
		return nil, err
	}
	rootAbs, _ = filepath.Abs(rootAbs)
	refs := slices.Clone(d.Evidence)
	var links []EvidenceSource
	for _, src := range srcs {
		abs, err := filepath.Abs(src.Path)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(abs)
		if err != nil || !info.Mode().IsRegular() {
			return nil, refuse(d.Path, "%s is not a file", src.Path)
		}
		var rel string
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			if r, err := filepath.Rel(rootAbs, real); err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) {
				rel = filepath.ToSlash(r) // already in the report
			}
		}
		if rel == "" {
			name := as
			if name == "" {
				ext := strings.ToLower(filepath.Ext(abs))
				rel = m.freePath(d.Kind.EvidenceDir, d.ID+"-"+slug(strings.TrimSuffix(filepath.Base(abs), filepath.Ext(abs)), "evidence"), ext)
			} else {
				if strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
					return nil, refuse(d.Path, "--as is a file name, not a path")
				}
				rel = path.Join(d.Kind.EvidenceDir, name)
				if _, ok, _ := m.read(rel); ok {
					return nil, refuse(rel, "%s already exists", rel)
				}
			}
			if err := m.copyIn(rel, abs); err != nil {
				return nil, err
			}
		}
		ref := relFrom(path.Dir(d.Path), rel)
		if !slices.Contains(refs, ref) {
			refs = append(refs, ref)
		}
		if src.Section != "" {
			links = append(links, EvidenceSource{Path: ref, Section: src.Section, Text: src.Text})
		}
	}
	return m.edit(d, func(s *doc.Doc) error {
		if !slices.Equal(refs, d.Evidence) {
			if err := s.Set(keepListStyle(s.Get("evidence"), refs), "evidence"); err != nil {
				return err
			}
		}
		for _, l := range links {
			if err := m.appendLink(d.Kind, s, l); err != nil {
				return err
			}
		}
		return nil
	})
}

// keepListStyle is the list vs, written block style when the old list
// was.
func keepListStyle(old *yaml.Node, vs []string) *yaml.Node {
	n := listNode(vs)
	if old != nil && old.Kind == yaml.SequenceNode && old.Style&yaml.FlowStyle == 0 && len(vs) > 0 {
		n.Style &^= yaml.FlowStyle
	}
	return n
}

// appendLink adds a link to ref at the end of a section (a finding) or
// the body (a page).
func (m *Model) appendLink(k *Kind, s *doc.Doc, l EvidenceSource) error {
	text := strings.NewReplacer(`[`, `\[`, `]`, `\]`).Replace(l.Text)
	link := "[" + text + "](" + markdownDest(l.Path) + ")"
	if strings.HasPrefix(m.mediaTypeOf(l.Path), "image/") {
		link = "!" + link
	}
	if !k.Sectioned {
		if l.Section != "body" {
			return fmt.Errorf("a page links evidence in its body: --link body")
		}
		body := strings.TrimRight(string(s.Body()), "\n")
		if strings.TrimSpace(body) != "" {
			body += "\n\n"
		} else {
			body = "\n"
		}
		s.SetBody([]byte(body + link + "\n"))
		return nil
	}
	key := m.Config.SectionKey(l.Section)
	secs, _ := s.Sections()
	for i, sec := range secs {
		if m.Config.SectionKey(sec.Heading) == key {
			txt := string(s.SectionText(sec))
			if txt != "" {
				txt += "\n\n"
			}
			return s.SetSection(i, []byte(txt+link))
		}
	}
	return s.AppendSection(m.Config.Heading(key), []byte(link))
}

// mediaTypeOf is MediaType by extension alone, for a file not yet copied.
func (m *Model) mediaTypeOf(ref string) string {
	return strings.Split(mime.TypeByExtension(strings.ToLower(path.Ext(ref))), ";")[0]
}

// markdownDest writes a destination so markdown reads it back exactly.
func markdownDest(p string) string {
	if strings.ContainsAny(p, " ()<>\t") {
		return "<" + strings.NewReplacer(`<`, `\<`, `>`, `\>`).Replace(p) + ">"
	}
	return strings.NewReplacer(`\`, `\\`).Replace(p)
}

// target finds the file a reference given on the command line names, as
// seen from d.
func (m *Model) target(d *Doc, ref string) (string, error) {
	rel := m.resolve(d, ref)
	if rel == "" {
		return "", refuse(d.Path, "%s leaves the report", ref)
	}
	return rel, nil
}

// placeable refuses when a link rpt can't place in d names rel: it
// couldn't be rewritten with the others.
func (m *Model) placeable(d *Doc, rel string) error {
	_, errs := d.src.Links()
	for _, err := range errs {
		var u *doc.UnplacedError
		if errors.As(err, &u) && isFileRef(u.Dest) && m.resolve(d, u.Dest) == rel {
			return refuse(d.Path, "%s:%d: can't find the link to %s exactly; edit it by hand", d.Path, u.Line+d.BodyLine()-1, u.Dest)
		}
	}
	return nil
}

// RemoveEvidence detaches the file ref names from d: its list entry and
// image links go, text links keep their words unless dropText. The file
// stays, for prune.
func (m *Model) RemoveEvidence(d *Doc, ref string, dropText bool) (*Doc, error) {
	rel, err := m.target(d, ref)
	if err != nil {
		return nil, err
	}
	if err := m.placeable(d, rel); err != nil {
		return nil, err
	}
	refs, _ := m.Refs(d)
	var keep []string
	var spans []doc.Span
	found := false
	for _, r := range refs {
		if r.Path != rel {
			if r.Source == "frontmatter" {
				keep = append(keep, r.Ref)
			}
			continue
		}
		found = true
		if r.Link == nil {
			continue
		}
		body := d.src.Body()
		switch {
		case r.Link.Image || r.Link.HTML || dropText:
			spans = append(spans, wholeLine(body, r.Link.Start, r.Link.End))
		default:
			spans = append(spans, doc.Span{Start: r.Link.Start, End: r.Link.End, Text: r.Link.Text})
		}
	}
	if !found {
		return nil, refuse(d.Path, "%s %s doesn't list or link %s", d.Kind.Name, d.ID, ref)
	}
	return m.edit(d, func(s *doc.Doc) error {
		if len(keep) != len(d.Evidence) {
			if len(keep) == 0 {
				if _, err := s.Unset("evidence"); err != nil {
					return err
				}
			} else if err := s.Set(keepListStyle(s.Get("evidence"), keep), "evidence"); err != nil {
				return err
			}
		}
		return s.RewriteSpans(spans)
	})
}

// wholeLine is a span removing body[start:end], and its line when nothing
// else is on it.
func wholeLine(body []byte, start, end int) doc.Span {
	ls := strings.LastIndexByte(string(body[:start]), '\n') + 1
	le := end
	for le < len(body) && body[le] != '\n' {
		le++
	}
	if strings.TrimSpace(string(body[ls:start])) == "" && strings.TrimSpace(string(body[end:le])) == "" {
		if le < len(body) {
			le++
		}
		// A paragraph of its own: one of the blank lines around it goes too.
		if strings.HasSuffix(string(body[:ls]), "\n\n") && le < len(body) && body[le] == '\n' {
			le++
		}
		return doc.Span{Start: ls, End: le}
	}
	return doc.Span{Start: start, End: end}
}

// SetCaption sets the text of every link in d to the file ref names.
func (m *Model) SetCaption(d *Doc, ref, text string) (*Doc, error) {
	rel, err := m.target(d, ref)
	if err != nil {
		return nil, err
	}
	if err := m.placeable(d, rel); err != nil {
		return nil, err
	}
	refs, _ := m.Refs(d)
	var spans []doc.Span
	for _, r := range refs {
		if r.Path == rel && r.Link != nil && !r.Link.HTML {
			spans = append(spans, doc.Span{Start: r.Link.TextStart, End: r.Link.TextEnd, Text: strings.NewReplacer(`[`, `\[`, `]`, `\]`).Replace(text)})
		}
	}
	if len(spans) == 0 {
		return nil, refuse(d.Path, "nothing in %s links %s, so it has no caption", d.ID, ref)
	}
	return m.edit(d, func(s *doc.Doc) error { return s.RewriteSpans(spans) })
}

// MoveEvidence moves the file ref names, seen from d, to newRef, also
// seen from d, and rewrites every reference to it in every finding and
// page. It returns the documents it rewrote.
func (m *Model) MoveEvidence(d *Doc, ref, newRef string) ([]*Doc, error) {
	from, err := m.target(d, ref)
	if err != nil {
		return nil, err
	}
	if !m.exists(from) {
		return nil, refuse(d.Path, "%s doesn't exist", from)
	}
	to := within(path.Dir(d.Path), newRef)
	if to == "" {
		return nil, refuse(d.Path, "%s leaves the report", newRef)
	}
	if _, ok, _ := m.read(to); ok || m.exists(to) {
		return nil, refuse(to, "%s already exists", to)
	}
	var changed []*Doc
	for _, k := range Kinds {
		for _, o := range slices.Clone(m.docs[k]) {
			if o.Err != nil {
				return nil, refuse(o.Path, "%s doesn't parse, so references to %s in it can't be followed; fix it first", o.Path, from)
			}
			if err := m.placeable(o, from); err != nil {
				return nil, err
			}
			refs, _ := m.Refs(o)
			newList := slices.Clone(o.Evidence)
			var spans []doc.Span
			seen := map[int]bool{}
			i := 0
			for _, r := range refs {
				if r.Source == "frontmatter" {
					if r.Path == from {
						newList[i] = relFrom(path.Dir(o.Path), to)
					}
					i++
					continue
				}
				if r.Path != from || seen[r.Link.DestStart] {
					continue
				}
				seen[r.Link.DestStart] = true // reference links share a definition
				dest := relFrom(path.Dir(o.Path), to)
				if !r.Link.HTML && strings.ContainsAny(dest, " ()<>") && o.src.Body()[r.Link.DestStart-1] != '<' {
					dest = markdownDest(dest)
				}
				spans = append(spans, doc.Span{Start: r.Link.DestStart, End: r.Link.DestEnd, Text: dest})
			}
			if slices.Equal(newList, o.Evidence) && len(spans) == 0 {
				continue
			}
			nd, err := m.edit(o, func(s *doc.Doc) error {
				if !slices.Equal(newList, o.Evidence) {
					if err := s.Set(keepListStyle(s.Get("evidence"), newList), "evidence"); err != nil {
						return err
					}
				}
				return s.RewriteSpans(spans)
			})
			if err != nil {
				return nil, err
			}
			changed = append(changed, nd)
		}
	}
	abs := filepath.Join(m.Dir, filepath.FromSlash(from))
	if err := m.copyIn(to, abs); err != nil {
		return nil, err
	}
	return changed, m.remove(from)
}

// Orphans lists the files in the evidence folders nothing lists or links,
// hidden ones aside. It fails while a finding or page doesn't parse,
// since that file may reference what looks orphaned.
func (m *Model) Orphans() ([]string, error) {
	used := map[string]bool{}
	for _, k := range Kinds {
		for _, d := range m.docs[k] {
			if d.Err != nil {
				return nil, refuse(d.Path, "%s doesn't parse, so it may reference what looks orphaned; fix it first", d.Path)
			}
			refs, _ := m.Refs(d)
			for _, r := range refs {
				used[r.Path] = true
			}
			// A link rpt can't place still names its file.
			_, errs := d.src.Links()
			for _, err := range errs {
				var u *doc.UnplacedError
				if errors.As(err, &u) && isFileRef(u.Dest) {
					used[m.resolve(d, u.Dest)] = true
				}
			}
		}
	}
	var out []string
	for _, k := range Kinds {
		fs.WalkDir(m.root.FS(), k.EvidenceDir, func(p string, e fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return nil
			case strings.HasPrefix(e.Name(), ".") && p != k.EvidenceDir:
				if e.IsDir() {
					return fs.SkipDir
				}
			case e.Type().IsRegular() && !used[p]:
				if f, ok := m.files[p]; !ok || !f.remove {
					out = append(out, p)
				}
			}
			return nil
		})
	}
	return out, nil
}

// PruneEvidence removes the orphans and returns them.
func (m *Model) PruneEvidence() ([]string, error) {
	gone, err := m.Orphans()
	if err != nil {
		return nil, err
	}
	for _, rel := range gone {
		if err := m.remove(rel); err != nil {
			return nil, err
		}
	}
	return gone, nil
}
