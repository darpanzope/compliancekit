package ui

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTable_PlainModeAscii(t *testing.T) {
	tbl := NewTable("ID", "STATUS", "TITLE")
	tbl.AddRow("do-spaces-public-acl", "fail", "Spaces bucket has public ACL")
	tbl.AddRow("do-droplet-no-firewall", "pass", "Droplet has firewall attached")

	got := tbl.Render(newStylerForTest(false))

	// In plain mode the frame is ASCII (+ - |); no unicode boxes leak.
	if strings.ContainsAny(got, "┌┐└┘─│┬┴├┤┼") {
		t.Errorf("plain mode should not contain unicode box-drawing chars\n%s", got)
	}
	if !strings.Contains(got, "+--") {
		t.Errorf("plain mode should use ASCII frame; got:\n%s", got)
	}
	if !strings.Contains(got, "ID") || !strings.Contains(got, "STATUS") || !strings.Contains(got, "TITLE") {
		t.Errorf("headers missing:\n%s", got)
	}
	if !strings.Contains(got, "do-spaces-public-acl") {
		t.Errorf("first row missing:\n%s", got)
	}
}

func TestTable_ColorModeUsesUnicode(t *testing.T) {
	tbl := NewTable("CHECK", "SEVERITY")
	tbl.AddRow("aws-s3-no-acl", "high")

	got := tbl.Render(newStylerForTest(true))

	// Color mode renders the unicode frame.
	if !strings.Contains(got, "┌") || !strings.Contains(got, "┘") {
		t.Errorf("color mode should contain unicode corners; got:\n%s", got)
	}
	if !strings.Contains(got, "─") || !strings.Contains(got, "│") {
		t.Errorf("color mode should contain unicode edges; got:\n%s", got)
	}
}

func TestTable_AutoFitColumnWidths(t *testing.T) {
	tbl := NewTable("A", "B")
	tbl.AddRow("short", "a-longer-cell")
	tbl.AddRow("medium-length", "x")

	got := tbl.Render(newStylerForTest(false))

	// Column A widest cell is "medium-length" (13), column B widest is
	// "a-longer-cell" (13). Both header + every row should render at
	// 13-wide columns (15 with the ±1 padding columns).
	for _, line := range strings.Split(got, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Every border + data line should be the same total width.
		// 1 (left) + 2 (padding-A) + 13 (col-A) + 1 (mid) + 2 (padding-B) + 13 (col-B) + 1 (right) = 33.
		if n := utf8.RuneCountInString(line); n != 33 {
			t.Errorf("inconsistent line width %d: %q", n, line)
		}
	}
}

func TestTable_MaxWidthTruncatesWithEllipsis(t *testing.T) {
	tbl := NewTable("NAME", "DESC")
	tbl.MaxWidth(1, 10)
	tbl.AddRow("ok", "this is a much longer description that should get truncated")

	got := tbl.Render(newStylerForTest(false))
	if !strings.Contains(got, "this is a…") {
		t.Errorf("expected truncation with ellipsis; got:\n%s", got)
	}
}
