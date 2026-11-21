package cli

import (
	"fmt"
	"image/color"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/term"
)

// The terminal look: the terminal's own ANSI colours, so output follows
// the user's theme. Only terminal output is styled; records are never.

var (
	grey    = lipgloss.Color("8")
	magenta = lipgloss.Color("5")
	red     = lipgloss.Color("1")
	yellow  = lipgloss.Color("3")
	blue    = lipgloss.Color("4")

	severityColors = map[string]color.Color{
		"critical": red,
		"high":     lipgloss.Color("208"), // 256-colour orange: ANSI has none
		"medium":   yellow,
		"low":      blue,
		"info":     grey,
	}

	dim  = lipgloss.NewStyle().Faint(true)
	bold = lipgloss.NewStyle().Bold(true)
)

// ReadingWidth is the width prose is wrapped at, and rules drawn to.
const ReadingWidth = 80

// Styled wraps a terminal writer: colour is dropped, and the layout kept,
// under NO_COLOR or TERM=dumb, and everything is plain when w isn't a
// terminal. lipgloss is never asked to query the terminal.
func Styled(w io.Writer) io.Writer {
	return colorprofile.NewWriter(w, os.Environ())
}

// Width is w's width in columns when it is a terminal, else 0.
func Width(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok {
		return 0
	}
	width, _, err := term.GetSize(f.Fd())
	if err != nil {
		return 0
	}
	return width
}

// Severity is a severity level in its colour; critical and high are bold.
func Severity(level string) string {
	c, ok := severityColors[level]
	if !ok {
		return level
	}
	return lipgloss.NewStyle().Foreground(c).Bold(level == "critical" || level == "high").Render(level)
}

// Dim is secondary text.
func Dim(s string) string { return dim.Render(s) }

// Bold is emphasised text.
func Bold(s string) string { return bold.Render(s) }

// Rule is a grey rule width wide.
func Rule(width int) string {
	return lipgloss.NewStyle().Foreground(grey).Render(strings.Repeat("─", width))
}

// Markdown shows markdown as written, for reading: heading lines in
// magenta, code fences dimmed, prose wrapped at ReadingWidth with no
// padding, and code never wrapped, so it copies as written.
func Markdown(md string) string {
	h := lipgloss.NewStyle().Foreground(magenta).Bold(true)
	var out []string
	fence := ""
	for _, l := range strings.Split(strings.TrimRight(md, "\n"), "\n") {
		trimmed := strings.TrimLeft(l, " ")
		switch {
		case fence == "" && (strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~")):
			fence = trimmed[:3]
			out = append(out, dim.Render(l))
		case fence != "" && strings.HasPrefix(trimmed, fence):
			fence = ""
			out = append(out, dim.Render(l))
		case fence != "":
			out = append(out, l)
		case strings.HasPrefix(l, "#"):
			out = append(out, h.Render(l))
		default:
			out = append(out, ansi.Wordwrap(l, ReadingWidth, ""))
		}
	}
	return strings.Join(out, "\n")
}

// A ReadingView prints records for reading, each between grey rules: one
// above, one under its header, one after its body. Records share rules,
// so one rule separates two.
type ReadingView struct {
	w     io.Writer
	count int
}

// NewReadingView prints reading views on w, a terminal.
func NewReadingView(w io.Writer) *ReadingView { return &ReadingView{w: Styled(w)} }

// Record prints one record: its ID and title, a line of facts (already
// styled), and its markdown body.
func (v *ReadingView) Record(id, title, facts, body string) error {
	head := bold.Render(id + "  " + title)
	if facts != "" {
		head += "\n" + facts
	}
	rule := Rule(max(ReadingWidth, lipgloss.Width(head)))
	var b strings.Builder
	if v.count == 0 {
		b.WriteString(rule + "\n")
	}
	b.WriteString(head + "\n" + rule + "\n")
	if body = strings.TrimSpace(body); body != "" {
		b.WriteString("\n" + Markdown(body) + "\n\n")
	}
	b.WriteString(rule + "\n")
	v.count++
	_, err := io.WriteString(v.w, b.String())
	return err
}

// Facts joins a record's facts, dimmed, with " · " between.
func Facts(parts ...string) string {
	var kept []string
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, dim.Render("  ·  "))
}

// Box is a rounded box with a border in warning yellow, for a question.
func Box(s string) string {
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(yellow).Padding(0, 1).Render(s)
}

var (
	errorStyle   = lipgloss.NewStyle().Foreground(red).Bold(true)
	warningStyle = lipgloss.NewStyle().Foreground(yellow).Bold(true)
	gutterStyle  = lipgloss.NewStyle().Foreground(blue)
)

// Diagnostics prints problems compiler-style on a terminal's stderr:
//
//	error[rule] message
//	  --> path:line:column
//	   |
//	 5 | the source line
//	   |     ^^^^^
//
// then, from Totals, "N errors, M warnings". Root, when set, is the
// folder problem paths are relative to; the source line is read from it.
type Diagnostics struct {
	w        io.Writer
	Root     string
	errors   int
	warnings int
}

// NewDiagnostics prints problems on w, a terminal.
func NewDiagnostics(w io.Writer) *Diagnostics { return &Diagnostics{w: Styled(w)} }

// A Diagnostic is one problem to print.
type Diagnostic struct {
	Path, Rule, Message string
	Error               bool
	Line, Column, End   int // End is the last column, inclusive; 0 for one
}

// Print prints one problem.
func (d *Diagnostics) Print(p Diagnostic) {
	style, level := warningStyle, "warning"
	if p.Error {
		style, level = errorStyle, "error"
		d.errors++
	} else {
		d.warnings++
	}
	if p.Rule != "" {
		level += "[" + p.Rule + "]"
	}
	var b strings.Builder
	b.WriteString(style.Render(level) + " " + bold.Render(p.Message) + "\n")
	if p.Path != "" {
		loc := p.Path
		if p.Line > 0 {
			loc += fmt.Sprintf(":%d", p.Line)
			if p.Column > 0 {
				loc += fmt.Sprintf(":%d", p.Column)
			}
		}
		b.WriteString("  " + gutterStyle.Render("-->") + " " + loc + "\n")
	}
	if src, ok := d.source(p.Path, p.Line); ok {
		num := strconv.Itoa(p.Line)
		pad := strings.Repeat(" ", len(num))
		bar := gutterStyle.Render("|")
		b.WriteString(pad + "  " + bar + "\n")
		b.WriteString(" " + gutterStyle.Render(num) + " " + bar + " " + src + "\n")
		if p.Column > 0 && p.Column <= len(src)+1 {
			n := 1
			if p.End >= p.Column {
				n = p.End - p.Column + 1
			}
			// The caret sits under the column's character, counted in
			// screen cells, as the line shows.
			b.WriteString(pad + "  " + bar + " " + strings.Repeat(" ", ansi.StringWidth(src[:p.Column-1])) + style.Render(strings.Repeat("^", n)) + "\n")
		}
	}
	b.WriteString("\n")
	_, _ = io.WriteString(d.w, b.String())
}

// source is the line of the file at path, relative to Root, tabs shown
// as spaces.
func (d *Diagnostics) source(path string, line int) (string, bool) {
	if d.Root == "" || path == "" || path == "-" || line < 1 || filepath.IsAbs(path) {
		return "", false
	}
	data, err := os.ReadFile(filepath.Join(d.Root, filepath.FromSlash(path)))
	if err != nil {
		return "", false
	}
	lines := strings.Split(string(data), "\n")
	if line > len(lines) {
		return "", false
	}
	return strings.TrimRight(lines[line-1], "\r"), true
}

// Totals prints "N errors, M warnings" if any problem was printed.
func (d *Diagnostics) Totals() {
	if d.errors+d.warnings == 0 {
		return
	}
	var parts []string
	if d.errors > 0 {
		parts = append(parts, errorStyle.Render(plural(d.errors, "error")))
	}
	if d.warnings > 0 {
		parts = append(parts, warningStyle.Render(plural(d.warnings, "warning")))
	}
	_, _ = io.WriteString(d.w, strings.Join(parts, ", ")+"\n")
}

func plural(n int, noun string) string {
	if n != 1 {
		noun += "s"
	}
	return fmt.Sprintf("%d %s", n, noun)
}
