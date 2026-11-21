package doc

import (
	"errors"
	"slices"
	"testing"
)

func bodyDoc(t *testing.T, body string) *Doc {
	t.Helper()
	d, err := Parse([]byte("---\nid: F-001\n---\n" + body))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSections(t *testing.T) {
	d := bodyDoc(t, "Lead text.\n\n## Description\n\nText.\n\n```\n## not a heading\n```\n\n##\n\nUnder an empty heading.\n\nRemediation\n-----------\n\nFix it.\n")
	secs, lead := d.Sections()
	var got []string
	for _, s := range secs {
		got = append(got, s.Heading+"="+string(d.SectionText(s)))
	}
	want := []string{
		"Description=Text.\n\n```\n## not a heading\n```",
		"=Under an empty heading.",
		"Remediation=Fix it.",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q", got)
	}
	if string(lead) != "Lead text." {
		t.Errorf("lead %q", lead)
	}
	if secs[0].Line != 3 || secs[0].Text != 5 {
		t.Errorf("lines %d %d", secs[0].Line, secs[0].Text)
	}
}

func TestSetSection(t *testing.T) {
	d := bodyDoc(t, "\n## Description\n\nOld.\n\n## PoC\n\nx\n")
	if err := d.SetSection(0, []byte("    $ curl x\n    200 OK\n")); err != nil {
		t.Fatal(err)
	}
	want := "\n## Description\n\n    $ curl x\n    200 OK\n\n## PoC\n\nx\n"
	if string(d.Body()) != want {
		t.Errorf("got %q", d.Body())
	}
}

func TestSectionTextCantSwallowTheRest(t *testing.T) {
	for _, txt := range []string{"```\ncurl x", "<pre>\nx", "text\n\n## Sneaky"} {
		d := bodyDoc(t, "\n## Description\n\nOld.\n\n## PoC\n\nx\n")
		before := string(d.Body())
		err := d.SetSection(0, []byte(txt))
		if !errors.Is(err, ErrSwallows) && !errors.Is(err, ErrHeading) {
			t.Errorf("%q: got %v", txt, err)
		}
		if string(d.Body()) != before {
			t.Errorf("%q: a refused edit changed the body", txt)
		}
	}
	d := bodyDoc(t, "\n## Description\n\nOld.\n")
	if err := d.AppendSection("Notes", []byte("text\n\n## Sneaky")); !errors.Is(err, ErrHeading) {
		t.Errorf("append with a heading: got %v", err)
	}
}

func TestAppendAndRemoveSection(t *testing.T) {
	d := bodyDoc(t, "\n## Description\n\nText.\n")
	if err := d.AppendSection("Remediation", []byte("Fix.")); err != nil {
		t.Fatal(err)
	}
	if want := "\n## Description\n\nText.\n\n## Remediation\n\nFix.\n"; string(d.Body()) != want {
		t.Fatalf("got %q", d.Body())
	}
	if err := d.RemoveSection(0); err != nil {
		t.Fatal(err)
	}
	if want := "\n## Remediation\n\nFix.\n"; string(d.Body()) != want {
		t.Fatalf("got %q", d.Body())
	}
	if err := d.SetHeading(0, "Recommendation"); err != nil {
		t.Fatal(err)
	}
	if want := "\n## Recommendation\n\nFix.\n"; string(d.Body()) != want {
		t.Fatalf("got %q", d.Body())
	}
}

func TestLinks(t *testing.T) {
	body := "" +
		"![shot](evidence/a.png)\n" + // 1
		"[see](<evidence/my shot.png> \"title\")\n" + // 2
		"[**bold**](evidence/b.png)\n" + // 3
		"[`code`](evidence/c.png)\n" + // 4
		"[![thumb](evidence/t.png)](evidence/full.png)\n" + // 5
		"[x](a(1).png)\n" + // 6
		"[x](a\\_b.png)\n" + // 7
		"![p](evidence/100%.png)\n" + // 8
		"<img src=\"evidence/html.png\" width=300>\n" + // 9
		"\n" +
		"[ref][r] and [r]\n" + // 11
		"\n" +
		"> [r]: <evidence/ref one.png>\n" + // 13
		"\n" +
		"```\n[x](not/a/link.png)\n```\n" +
		"`[x](inline/code.png)`\n"
	d := bodyDoc(t, body)
	ls, errs := d.Links()
	if len(errs) > 0 {
		t.Fatalf("unplaced: %v", errs)
	}
	var got []string
	for _, l := range ls {
		written := string(d.Body()[l.DestStart:l.DestEnd])
		got = append(got, l.Dest+"|"+written+"|"+l.Text)
	}
	want := []string{
		"evidence/a.png|evidence/a.png|shot",
		"evidence/my shot.png|evidence/my shot.png|see",
		"evidence/b.png|evidence/b.png|**bold**",
		"evidence/c.png|evidence/c.png|`code`",
		"evidence/full.png|evidence/full.png|![thumb](evidence/t.png)",
		"evidence/t.png|evidence/t.png|thumb",
		"a(1).png|a(1).png|x",
		"a_b.png|a\\_b.png|x",
		"evidence/100%.png|evidence/100%.png|p",
		"evidence/html.png|evidence/html.png|",
		"evidence/ref one.png|evidence/ref one.png|ref",
		"evidence/ref one.png|evidence/ref one.png|r",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%q\nwant\n%q", got, want)
	}
}

func TestRewriteKeepsEverythingElse(t *testing.T) {
	body := "[see](<evidence/my shot.png> \"title\")\n\n```\na\n\n\n\nb\n```\n"
	d := bodyDoc(t, body)
	ls, _ := d.Links()
	l := ls[0]
	if err := d.RewriteSpans([]Span{{l.TextStart, l.TextEnd, "new caption"}}); err != nil {
		t.Fatal(err)
	}
	want := "[new caption](<evidence/my shot.png> \"title\")\n\n```\na\n\n\n\nb\n```\n"
	if string(d.Body()) != want {
		t.Errorf("got %q", d.Body())
	}
}
