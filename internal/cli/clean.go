package cli

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Clean makes text from a report safe to print on a terminal: control
// characters other than newline and tab, and the bidirectional controls
// that reorder what a line shows, are written as visible escapes (\x1b,
// ‮), and bytes that aren't UTF-8 as \xNN. A report is plain files
// anyone may have written; nothing in it may drive the terminal.
func Clean(s string) string {
	if clean(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case unsafe(r):
			if r < 0x100 {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

// CleanLine is Clean for text that must stay on one line, a table cell:
// newlines, carriage returns and tabs become spaces.
func CleanLine(s string) string {
	return Clean(strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ", "\t", " ").Replace(s))
}

func clean(s string) bool {
	for _, r := range s {
		if r == utf8.RuneError || unsafe(r) {
			return false
		}
	}
	return true
}

func unsafe(r rune) bool {
	switch {
	case r == '\n' || r == '\t':
		return false
	case r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0:
		return true
	case r == 0x061c || r == 0x200e || r == 0x200f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}
