package doc

import (
	"bytes"
	"errors"
	"slices"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
)

// A Section is a part of the body that starts at a top-level ## heading
// and runs to the next one. Offsets are into the body.
type Section struct {
	Heading    string // the heading's text, as written, trimmed
	Start      int    // the heading's first line
	TextStart  int    // the line after the heading
	End        int    // the next heading's first line, or the body's end
	Line, Text int    // body lines (1-based) of the heading and of the text's first line; Text is 0 when the text is empty
}

// The body's text between TextStart and End without the blank lines
// around it.
func (s Section) text(body []byte) []byte {
	return bytes.Trim(body[s.TextStart:s.End], "\n")
}

var md = goldmark.New()

func parseBody(body []byte) ast.Node {
	return md.Parser().Parse(text.NewReader(body), parser.WithContext(parser.NewContext()))
}

// Sections splits the body at its top-level ## headings, in order. Lead is
// the text before the first one, trimmed.
func (d *Doc) Sections() (secs []Section, lead []byte) {
	return sections(d.body)
}

// SectionText is the text of a section without the blank lines around it.
func (d *Doc) SectionText(s Section) []byte { return s.text(d.body) }

func sections(body []byte) ([]Section, []byte) {
	root := parseBody(body)
	var out []Section
	for n := root.FirstChild(); n != nil; n = n.NextSibling() {
		h, ok := n.(*ast.Heading)
		if !ok || h.Level != 2 {
			continue
		}
		start := lineStart(body, h.Pos())
		end := lineEnd(body, h.Pos())
		var heading []byte
		if l := h.Lines(); l.Len() > 0 {
			last := l.At(l.Len() - 1)
			end = lineEnd(body, last.Start)
			if !bytes.HasPrefix(bytes.TrimLeft(body[start:], " "), []byte("#")) {
				end = lineEnd(body, end) // setext: the underline line too
			}
			for i := range l.Len() {
				s := l.At(i)
				heading = append(heading, s.Value(body)...)
			}
		}
		out = append(out, Section{Heading: string(bytes.TrimSpace(heading)), Start: start, TextStart: end})
	}
	for i := range out {
		if i+1 < len(out) {
			out[i].End = out[i+1].Start
		} else {
			out[i].End = len(body)
		}
		out[i].Line = 1 + bytes.Count(body[:out[i].Start], []byte("\n"))
		if t := out[i].text(body); len(t) > 0 {
			off := out[i].TextStart + bytes.Index(body[out[i].TextStart:out[i].End], t)
			out[i].Text = 1 + bytes.Count(body[:off], []byte("\n"))
		}
	}
	leadEnd := len(body)
	if len(out) > 0 {
		leadEnd = out[0].Start
	}
	return out, bytes.TrimSpace(body[:leadEnd])
}

// lineStart is the offset of the line holding off; lineEnd is the offset
// just past it.
func lineStart(b []byte, off int) int { return bytes.LastIndexByte(b[:off], '\n') + 1 }

func lineEnd(b []byte, off int) int {
	if i := bytes.IndexByte(b[off:], '\n'); i >= 0 {
		return off + i + 1
	}
	return len(b)
}

// ErrSwallows is section text that would change the body's other
// sections, such as one with an unclosed code fence.
var ErrSwallows = errors.New("the text would change the sections after it (an unclosed code fence or HTML block?)")

// ErrHeading is section text holding a ## heading of its own.
var ErrHeading = errors.New("the text holds a ## heading, which would start a new section")

// SetSection replaces the text of section i.
func (d *Doc) SetSection(i int, txt []byte) error {
	secs, _ := sections(d.body)
	s := secs[i]
	var b []byte
	b = append(b, d.body[:s.TextStart]...)
	b = append(b, para(txt, i+1 < len(secs))...)
	b = append(b, d.body[s.End:]...)
	return d.setBodyChecked(b, headings(secs), i, txt)
}

// AppendSection adds a section at the end of the body.
func (d *Doc) AppendSection(heading string, txt []byte) error {
	secs, _ := sections(d.body)
	b := bytes.Clone(d.body)
	if len(bytes.TrimSpace(b)) > 0 {
		b = append(bytes.TrimRight(b, "\n"), "\n\n"...)
	} else {
		b = append(b[:0], '\n')
	}
	b = append(b, "## "...)
	b = append(b, heading...)
	b = append(b, '\n')
	b = append(b, para(txt, false)...)
	return d.setBodyChecked(b, append(headings(secs), heading), len(secs), txt)
}

// RemoveSection removes section i, heading and all.
func (d *Doc) RemoveSection(i int) error {
	secs, _ := sections(d.body)
	s := secs[i]
	b := append(bytes.Clone(d.body[:s.Start]), d.body[s.End:]...)
	if i == len(secs)-1 {
		b = append(bytes.TrimRight(b, "\n"), '\n')
	}
	return d.setBodyChecked(b, slices.Delete(headings(secs), i, i+1), -1, nil)
}

// SetHeading rewrites section i's heading line as "## heading".
func (d *Doc) SetHeading(i int, heading string) error {
	secs, _ := sections(d.body)
	s := secs[i]
	b := slices.Concat(d.body[:s.Start], []byte("## "+heading+"\n"), d.body[s.TextStart:])
	want := headings(secs)
	want[i] = heading
	return d.setBodyChecked(b, want, -1, nil)
}

// para is section text as written: a blank line, the text, and a blank
// line before the next heading.
func para(txt []byte, more bool) []byte {
	txt = bytes.Trim(lf(txt), "\n")
	if len(txt) == 0 {
		if more {
			return []byte("\n")
		}
		return nil
	}
	out := append([]byte("\n"), txt...)
	out = append(out, '\n')
	if more {
		out = append(out, '\n')
	}
	return out
}

func headings(secs []Section) []string {
	out := make([]string, len(secs))
	for i, s := range secs {
		out[i] = s.Heading
	}
	return out
}

// setBodyChecked keeps body b only if its headings are want and, with
// i >= 0, section i holds txt.
func (d *Doc) setBodyChecked(b []byte, want []string, i int, txt []byte) error {
	secs, _ := sections(b)
	got := headings(secs)
	if !slices.Equal(got, want) {
		if len(got) > len(want) {
			return ErrHeading
		}
		return ErrSwallows
	}
	if i >= 0 && !bytes.Equal(secs[i].text(b), bytes.Trim(lf(txt), "\n")) {
		return ErrSwallows
	}
	d.body = b
	return nil
}
