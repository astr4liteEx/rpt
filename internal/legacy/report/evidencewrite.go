package report

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// EvidenceDir and PageEvidenceDir are the folders, relative to the report
// root, that rpt evidence add copies files into for findings and pages,
// and the only ones orphans are looked for in.
const (
	EvidenceDir     = FindingsDir + "/evidence"
	PageEvidenceDir = PagesDir + "/evidence"
)

// Errors from evidence writes, all mistakes in the request.
var (
	ErrBadSource  = errors.New("bad evidence source")
	ErrNoEvidence = errors.New("no such evidence")
)

// An owner is a finding or a page: what lists and links evidence.
type owner struct {
	id, rel  string
	page     bool
	evidence []string
	body     []byte // after the frontmatter, LF endings
	first    int    // the file line body starts on
	rev      string
	h        Headings
}

// ownerFrom reads the owner file at rel.
func ownerFrom(rel string, src []byte, page bool, h Headings) (owner, error) {
	o := owner{rel: rel, page: page, rev: Rev(src), h: h}
	head, body, err := splitFrontmatter(normaliseNewlines(src))
	if err != nil {
		return owner{}, &FileError{Path: rel, Line: 1, Err: err}
	}
	o.body, o.first = body, bodyFirstLine(head)
	if page {
		p, err := parsePage(rel, src)
		if err != nil {
			return owner{}, err
		}
		o.id, o.evidence = p.ID, p.Evidence
	} else {
		f, err := parseFinding(rel, src, h)
		if err != nil {
			return owner{}, err
		}
		o.id, o.evidence = f.ID, f.Evidence
	}
	return o, nil
}

// dir is the evidence folder add copies the owner's files into.
func (o owner) dir() string {
	if o.page {
		return PageEvidenceDir
	}
	return EvidenceDir
}

// stub is enough of the owner for evidencePath and checkEvidence.
func (o owner) stub() sdk.Finding { return sdk.Finding{ID: o.id, Path: o.rel} }

// set names the owner on an evidence record.
func (o owner) set(e *sdk.Evidence) {
	if o.page {
		e.Page = o.id
	} else {
		e.Finding = o.id
	}
}

// owners reads every finding, then every page, from disk. Files that don't
// parse are returned as errors.
func (r *Report) owners() ([]owner, []error, error) {
	h := r.headings()
	var out []owner
	var errs []error
	for _, d := range []struct {
		dir  string
		page bool
	}{{FindingsDir, false}, {PagesDir, true}} {
		ents, err := fs.ReadDir(r.fsys(), d.dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", d.dir, err)
		}
		for _, e := range ents {
			if !e.Type().IsRegular() || path.Ext(e.Name()) != ".md" {
				continue
			}
			rel := path.Join(d.dir, e.Name())
			src, err := r.readFile(rel)
			if err != nil {
				errs = append(errs, &FileError{Path: rel, Err: err})
				continue
			}
			o, err := ownerFrom(rel, src, d.page, h)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			out = append(out, o)
		}
	}
	return out, errs, nil
}

// ownerOf reads the finding or page id as this write sees it.
func (tx *Tx) ownerOf(id string) (owner, error) {
	page := strings.HasPrefix(id, "P-")
	var rel string
	var err error
	if page {
		rel, err = tx.locatePage(id)
	} else {
		rel, err = tx.r.locate(id)
	}
	if err != nil {
		return owner{}, err
	}
	src, _, err := tx.read(rel)
	if err != nil {
		return owner{}, err
	}
	return ownerFrom(rel, src, page, tx.headings())
}

// editOwner changes the owner's file and returns its record as stored.
func (tx *Tx) editOwner(o owner, change func(*findingFile) error) (any, error) {
	if o.page {
		return tx.editPage(o.id, o.rel, change)
	}
	return tx.edit(o.id, o.rel, change)
}

// Evidence lists every reference the findings and pages make to evidence
// files, or with ids only theirs: each owner's evidence list, then the
// links in its text, owners in file-name order, findings first. With
// orphans, it then lists each file in the evidence folders that nothing
// references, by path; hidden files and folders are skipped. A file that
// doesn't parse is reported in the error; with orphans, the orphans are
// then left out, since that file's references are unknown.
func (r *Report) Evidence(ids []string, orphans bool) ([]sdk.Evidence, error) {
	all, errs, err := r.owners()
	if err != nil {
		return nil, err
	}
	var out []sdk.Evidence
	for _, o := range all {
		if len(ids) == 0 || slices.Contains(ids, o.id) {
			out = append(out, r.references(o)...)
		}
	}
	if len(ids) == 0 && orphans && len(errs) == 0 {
		found, err := r.orphans(out)
		if err != nil {
			return out, err
		}
		out = append(out, found...)
	}
	return out, errors.Join(errs...)
}

// references are the evidence records for one owner's references.
func (r *Report) references(o owner) []sdk.Evidence {
	var out []sdk.Evidence
	for _, ref := range o.evidence {
		out = append(out, r.reference(o, ref, "frontmatter"))
	}
	var spans []span
	if !o.page {
		spans = sectionSpans(o.body, o.h)
	}
	for _, l := range relLinks(o.body) {
		e := r.reference(o, l.path, "body")
		e.Text, e.Image = l.text, l.image
		at := l.off
		if l.start >= 0 {
			at = l.start
		}
		e.Line, e.Column = lineCol(o.body, o.first, at)
		for _, sp := range spans {
			if at >= sp.lineStart && at < sp.end {
				e.Section = sp.key
			}
		}
		out = append(out, e)
	}
	return out
}

// assets are the files o lists and links, one per source and ref, in the
// order references gives them. A ref leaving the report is left out; with
// existing, so is one naming no regular file.
func (r *Report) assets(o owner, existing bool) []sdk.Asset {
	out := []sdk.Asset{}
	seen := map[[2]string]bool{}
	for _, e := range r.references(o) {
		k := [2]string{e.Source, e.Ref}
		if seen[k] || e.File == "" || existing && !e.Exists {
			continue
		}
		seen[k] = true
		out = append(out, sdk.Asset{Ref: e.Ref, Path: e.Path, File: e.File, Source: e.Source, MediaType: e.MediaType, Text: e.Text, Image: e.Image})
	}
	return out
}

// AssetsOf gives the files the finding or page in the report file rel
// lists and links, one per source and ref; any that leaves the report is
// left out.
func (r *Report) AssetsOf(rel string) ([]sdk.Asset, error) {
	src, err := r.readFile(rel)
	if err != nil {
		return nil, &FileError{Path: rel, Err: err}
	}
	o, err := ownerFrom(rel, src, strings.HasPrefix(rel, PagesDir+"/"), r.headings())
	if err != nil {
		return nil, err
	}
	return r.assets(o, false), nil
}

// reference is the record for one reference o makes to ref.
func (r *Report) reference(o owner, ref, source string) sdk.Evidence {
	e := sdk.Evidence{Kind: "evidence", Ref: ref, Source: source, Rev: o.rev}
	o.set(&e)
	rel, err := evidencePath(o.stub(), ref)
	if err != nil {
		return e
	}
	e.Path, e.File = rel, filepath.Join(r.abs, filepath.FromSlash(rel))
	info, err := r.stat(rel)
	e.Exists = err == nil && info.Mode().IsRegular()
	if e.Exists {
		e.MediaType = r.mediaType(rel)
	}
	return e
}

// mediaType is the media type of the report file at rel: from its first
// bytes, or from its extension when they say only text or binary.
func (r *Report) mediaType(rel string) string {
	f, err := r.open(rel)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	return detectMediaType(rel, buf[:n])
}

func detectMediaType(name string, head []byte) string {
	t, _, _ := mime.ParseMediaType(http.DetectContentType(head))
	if t == "application/octet-stream" || t == "text/plain" {
		if byExt, _, err := mime.ParseMediaType(mime.TypeByExtension(path.Ext(name))); err == nil && byExt != "" {
			return byExt
		}
	}
	return t
}

// orphans lists the files in the evidence folders that no reference in
// refs names, sorted by path.
func (r *Report) orphans(refs []sdk.Evidence) ([]sdk.Evidence, error) {
	used := map[string]bool{}
	for _, e := range refs {
		used[e.Path] = true
	}
	var out []sdk.Evidence
	for _, dir := range []string{EvidenceDir, PageEvidenceDir} {
		err := fs.WalkDir(r.fsys(), dir, func(p string, d fs.DirEntry, err error) error {
			if errors.Is(err, fs.ErrNotExist) && p == dir {
				return fs.SkipAll
			}
			if err != nil {
				return err
			}
			if p != dir && strings.HasPrefix(d.Name(), ".") {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() || used[p] {
				return nil
			}
			out = append(out, sdk.Evidence{Kind: "evidence", Path: p, File: filepath.Join(r.abs, filepath.FromSlash(p)), Exists: true, MediaType: r.mediaType(p)})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", dir, err)
		}
	}
	slices.SortFunc(out, func(a, b sdk.Evidence) int { return strings.Compare(a.Path, b.Path) })
	return out, nil
}

// PruneEvidence removes the orphans Evidence finds and returns them. It
// removes nothing while any finding or page file doesn't parse, since that
// file may reference what looks orphaned.
func (tx *Tx) PruneEvidence() ([]sdk.Evidence, error) {
	all, err := tx.r.Evidence(nil, true)
	if err != nil {
		return nil, err
	}
	var gone []sdk.Evidence
	for _, e := range all {
		if e.Finding != "" || e.Page != "" {
			continue
		}
		if err := tx.del(e.Path, rankGone); err != nil {
			return nil, err
		}
		gone = append(gone, e)
	}
	return gone, nil
}

// EvidenceSource is one file evidence add adds: Path on disk, and with
// Section a link to it in that section (a finding's section key or
// heading, or body for a page), captioned Text.
type EvidenceSource struct {
	Path, Section, Text string
}

// AddEvidence lists each source in the owner's evidence: a file already in
// the report is listed where it is; any other is copied into the owner's
// evidence folder, named as (one source only, which must not exist) or
// <id>-<slug>.<ext> with -2, -3, ... on a clash. A source with a Section
// is also linked there: an image as ![text](ref), anything else as
// [text](ref). It returns the owner's record as stored.
func (tx *Tx) AddEvidence(id string, srcs []EvidenceSource, as string) (any, error) {
	o, err := tx.ownerOf(id)
	if err != nil {
		return nil, err
	}
	var copies []string
	type added struct {
		ref, media string
		src        EvidenceSource
	}
	var adds []added
	for _, s := range srcs {
		info, err := os.Stat(s.Path) // follows a symlink to the file it names
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadSource, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: %s is not a regular file", ErrBadSource, s.Path)
		}
		abs, err := filepath.Abs(s.Path)
		if err != nil {
			return nil, err
		}
		if in, err := filepath.Rel(tx.r.abs, abs); err == nil && in != ".." && !strings.HasPrefix(in, ".."+string(filepath.Separator)) && as == "" {
			// Already in the report: list it where it is.
			ref, err := filepath.Rel(filepath.Dir(filepath.FromSlash(o.rel)), in)
			if err != nil {
				return nil, err
			}
			head, _ := os.ReadFile(abs)
			adds = append(adds, added{ref: filepath.ToSlash(ref), media: detectMediaType(abs, head[:min(len(head), 512)]), src: s})
			continue
		}
		copies = append(copies, s.Path)
		adds = append(adds, added{src: s})
	}
	names, err := tx.evidenceNames(o.dir(), o.id, copies, as)
	if err != nil {
		return nil, err
	}
	n := 0
	for i := range adds {
		if adds[i].ref != "" {
			continue
		}
		data, err := os.ReadFile(adds[i].src.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadSource, err)
		}
		rel := path.Join(o.dir(), names[n])
		if err := tx.put(rel, data, rankAsset); err != nil {
			return nil, err
		}
		adds[i].ref = path.Join("evidence", names[n])
		adds[i].media = detectMediaType(rel, data[:min(len(data), 512)])
		n++
	}
	list := slices.Clone(o.evidence)
	for _, a := range adds {
		if !slices.Contains(list, a.ref) {
			list = append(list, a.ref)
		}
	}
	val, err := toNode(list)
	if err != nil {
		return nil, err
	}
	rec, err := tx.editOwner(o, func(ff *findingFile) error { return ff.setEntry("evidence", val) })
	if err != nil {
		return nil, err
	}
	for _, a := range adds {
		if a.src.Section == "" {
			continue
		}
		md := "[" + escapeLinkText(a.src.Text) + "](" + linkDest(a.ref) + ")"
		if strings.HasPrefix(a.media, "image/") {
			md = "!" + md
		}
		if rec, err = tx.appendLink(o, a.src.Section, md); err != nil {
			return nil, err
		}
	}
	return rec, nil
}

// appendLink adds a paragraph holding md at the end of a finding's section
// (made if missing) or of a page's body.
func (tx *Tx) appendLink(o owner, section, md string) (any, error) {
	if o.page {
		if section != "body" {
			return nil, fmt.Errorf("%w: --link: a page has no sections; link into its body", ErrBadValue)
		}
		p, err := tx.locatePage(o.id)
		if err != nil {
			return nil, err
		}
		src, _, err := tx.read(p)
		if err != nil {
			return nil, err
		}
		pg, err := parsePage(p, src)
		if err != nil {
			return nil, err
		}
		ch, err := tx.SetPage(o.id, "body", strings.TrimSpace(pg.Body+"\n\n"+md))
		return ch.Page, err
	}
	src, _, err := tx.read(o.rel)
	if err != nil {
		return nil, err
	}
	f, err := parseFinding(o.rel, src, tx.headings())
	if err != nil {
		return nil, err
	}
	key := tx.headings().key(strings.TrimSpace(section))
	return tx.SetSection(o.id, key, strings.TrimSpace(f.Sections[key]+"\n\n"+md))
}

// escapeLinkText escapes the characters that would end a link's text.
func escapeLinkText(s string) string {
	return strings.NewReplacer(`\`, `\\`, "[", `\[`, "]", `\]`, "\n", " ").Replace(s)
}

// linkDest writes a path as a link destination, in angle brackets when it
// holds spaces or parentheses.
func linkDest(p string) string {
	if strings.ContainsAny(p, " ()<>") {
		return "<" + p + ">"
	}
	return p
}

// refersTo reports whether a reference ref, made by o, names the report
// file at rel.
func (o owner) refersTo(ref, rel string) bool {
	p, err := evidencePath(o.stub(), ref)
	return err == nil && p == rel
}

// RemoveEvidence detaches ref from the owner: its evidence list entry and
// image links go; text links keep their words, unless dropText. The file
// stays, for evidence prune.
func (tx *Tx) RemoveEvidence(id, ref string, dropText bool) (any, error) {
	o, err := tx.ownerOf(id)
	if err != nil {
		return nil, err
	}
	rel, err := evidencePath(o.stub(), ref)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadValue, err)
	}
	found := false
	rec, err := tx.editOwner(o, func(ff *findingFile) error {
		list := slices.DeleteFunc(slices.Clone(o.evidence), func(e string) bool { return o.refersTo(e, rel) })
		if len(list) != len(o.evidence) {
			found = true
			if len(list) == 0 {
				if err := ff.removeEntry("evidence"); err != nil {
					return err
				}
			} else {
				val, err := toNode(list)
				if err != nil {
					return err
				}
				if err := ff.setEntry("evidence", val); err != nil {
					return err
				}
			}
		}
		body, n, err := rewriteLinks(ff.body, o, rel, func(l link) string {
			if l.image || dropText {
				return ""
			}
			return l.text
		})
		ff.body, found = body, found || n > 0
		return err
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %s doesn't list or link %s", ErrNoEvidence, id, ref)
	}
	return rec, nil
}

// rewriteLinks replaces each inline link in body naming rel with what
// with returns for it, and returns the new body and how many it replaced.
// A link with nothing left drops the blank lines it leaves. A
// reference-style link to rel is refused: rpt doesn't rewrite those.
func rewriteLinks(body []byte, o owner, rel string, with func(link) string) ([]byte, int, error) {
	ls := relLinks(body)
	n := 0
	out := slices.Clone(body)
	for i := len(ls) - 1; i >= 0; i-- {
		l := ls[i]
		if !o.refersTo(l.path, rel) {
			continue
		}
		if l.start < 0 {
			return nil, 0, fmt.Errorf("%s links %s reference-style; edit that link by hand", o.rel, l.dest)
		}
		repl := with(l)
		start, end := l.start, l.end
		if repl == "" {
			// A link alone on its line takes the line with it.
			ls := bytes.LastIndexByte(out[:start], '\n') + 1
			le := end
			for le < len(out) && out[le] != '\n' {
				le++
			}
			if strings.TrimSpace(string(out[ls:start])) == "" && strings.TrimSpace(string(out[end:le])) == "" {
				start, end = ls, min(le+1, len(out))
			}
		}
		out = slices.Concat(out[:start], []byte(repl), out[end:])
		n++
	}
	for bytes.Contains(out, []byte("\n\n\n")) {
		out = bytes.ReplaceAll(out, []byte("\n\n\n"), []byte("\n\n"))
	}
	return out, n, nil
}

// SetEvidence changes one thing about ref, of the owner: its caption, the
// text of every link to it (refused when nothing links it), or its path,
// moving the file and rewriting every reference to it in every finding and
// page.
func (tx *Tx) SetEvidence(id, ref, what, value string) ([]any, error) {
	o, err := tx.ownerOf(id)
	if err != nil {
		return nil, err
	}
	rel, err := evidencePath(o.stub(), ref)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadValue, err)
	}
	switch what {
	case "caption":
		n := 0
		rec, err := tx.editOwner(o, func(ff *findingFile) error {
			var err error
			ff.body, n, err = rewriteLinks(ff.body, o, rel, func(l link) string {
				md := "[" + escapeLinkText(value) + "](" + l.dest + ")"
				if l.image {
					md = "!" + md
				}
				return md
			})
			return err
		})
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, fmt.Errorf("%w: %s doesn't link %s, so it has no caption; link it with rpt evidence add --link", ErrBadValue, id, ref)
		}
		return []any{rec}, nil
	case "path":
		return tx.moveEvidence(o, rel, value)
	}
	return nil, fmt.Errorf("%w: evidence has caption and path, not %q", ErrBadValue, what)
}

// moveEvidence moves the report file rel to to, a path relative to o's
// file, and rewrites every reference to it.
func (tx *Tx) moveEvidence(o owner, rel, to string) ([]any, error) {
	dest, err := evidencePath(o.stub(), to)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadValue, err)
	}
	data, exists, err := tx.read(rel)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("%w: %s doesn't exist", ErrNoEvidence, rel)
	}
	if _, there, err := tx.read(dest); err != nil {
		return nil, err
	} else if there {
		return nil, fmt.Errorf("%w: %s already exists", ErrBadValue, dest)
	}
	if err := tx.put(dest, data, rankAsset); err != nil {
		return nil, err
	}
	if err := tx.del(rel, rankGone); err != nil {
		return nil, err
	}
	owners, errs, err := tx.r.owners()
	if err != nil {
		return nil, err
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%w: %v; fix it first, since it may refer to %s", ErrBadValue, errs[0], rel)
	}
	var out []any
	for _, ow := range owners {
		cur, err := tx.ownerOf(ow.id)
		if err != nil {
			return nil, err
		}
		newRef, err := filepath.Rel(filepath.Dir(filepath.FromSlash(cur.rel)), filepath.FromSlash(dest))
		if err != nil {
			return nil, err
		}
		nr := filepath.ToSlash(newRef)
		touched := false
		list := slices.Clone(cur.evidence)
		for i, e := range list {
			if cur.refersTo(e, rel) {
				list[i], touched = nr, true
			}
		}
		if !touched && !slices.ContainsFunc(fileLinks(cur.body), func(l link) bool { return cur.refersTo(l.path, rel) }) {
			continue
		}
		rec, err := tx.editOwner(cur, func(ff *findingFile) error {
			if touched {
				val, err := toNode(list)
				if err != nil {
					return err
				}
				if err := ff.setEntry("evidence", val); err != nil {
					return err
				}
			}
			ff.body = rewriteDests(ff.body, func(l link) (string, bool) { return nr, cur.refersTo(l.path, rel) })
			return nil
		})
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

// evidenceNames picks the file name each source is copied to.
func (tx *Tx) evidenceNames(dir, id string, srcs []string, as string) ([]string, error) {
	taken := func(name string) bool {
		_, exists, _ := tx.read(path.Join(dir, name))
		if c, ok := tx.files[path.Join(dir, name)]; ok && c.touched && !c.remove {
			return true
		}
		_, err := tx.r.lstat(path.Join(dir, name))
		return exists || !errors.Is(err, fs.ErrNotExist)
	}
	if as != "" {
		if len(srcs) != 1 {
			return nil, fmt.Errorf("%w: --as names one file, not %d", ErrBadValue, len(srcs))
		}
		if as == "." || as == ".." || strings.ContainsAny(as, `/\`) {
			return nil, fmt.Errorf("%w: --as %q is not a plain file name", ErrBadValue, as)
		}
		if taken(as) {
			return nil, fmt.Errorf("%w: %s/%s already exists", ErrBadValue, dir, as)
		}
		return []string{as}, nil
	}
	var names []string
	for _, s := range srcs {
		base := filepath.Base(s)
		ext := filepath.Ext(base)
		if ext == base { // a dotfile such as .bashrc has no extension
			ext = ""
		}
		stem := evidenceSlug(strings.TrimSuffix(base, ext), 40)
		if stem == "" {
			stem = "evidence"
		}
		if ext = evidenceSlug(ext, 40); ext != "" {
			ext = "." + ext
		}
		name := id + "-" + stem + ext
		for n := 2; taken(name) || slices.Contains(names, name); n++ {
			name = id + "-" + stem + "-" + strconv.Itoa(n) + ext
		}
		names = append(names, name)
	}
	return names, nil
}

// evidenceSlug lowercases s, turns each run of characters other than a-z
// and 0-9 into one hyphen, trims hyphens from the ends, and keeps at most
// limit characters.
func evidenceSlug(s string, limit int) string {
	var b strings.Builder
	gap := false
	for _, c := range strings.ToLower(s) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			if gap && b.Len() > 0 {
				b.WriteByte('-')
			}
			gap = false
			b.WriteRune(c)
			continue
		}
		gap = true
	}
	out := b.String()
	if len(out) > limit {
		out = strings.TrimRight(out[:limit], "-")
	}
	return out
}
