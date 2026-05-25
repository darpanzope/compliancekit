package report

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRenderPrintHTML_IncludesTOCAndHeaders(t *testing.T) {
	out := RenderPrintHTML(PrintDocument{
		Title:       "Executive Overview",
		BodyHTML:    `<section class="ck-section" id="score">Score 78</section>`,
		HeaderLeft:  "compliancekit",
		HeaderRight: "SOC 2",
		FooterLeft:  "confidential",
		Watermark:   "for auditor@firm.com — 2026-05-25",
		TOC:         []TOCEntry{{Label: "Score", Anchor: "score"}},
		GeneratedAt: time.Date(2026, 5, 25, 10, 0, 0, 0, time.UTC),
	})
	if !strings.Contains(out, "<title>Executive Overview</title>") {
		t.Errorf("missing title")
	}
	if !strings.Contains(out, "<a href=\"#score\">Score</a>") {
		t.Errorf("missing TOC entry")
	}
	if !strings.Contains(out, "for auditor@firm.com") {
		t.Errorf("missing watermark")
	}
	if !strings.Contains(out, "@top-left") {
		t.Errorf("missing @page header rules")
	}
	if !strings.Contains(out, "counter(page)") {
		t.Errorf("missing page-number rule")
	}
}

func TestHTMLOnlyRenderer_ReturnsHTML(t *testing.T) {
	out, ct, err := HTMLOnlyRenderer{}.Render(context.Background(), PrintDocument{
		Title:    "x",
		BodyHTML: "<p>body</p>",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if ct != "text/html" {
		t.Errorf("content-type = %q want text/html", ct)
	}
	if !strings.Contains(string(out), "<p>body</p>") {
		t.Errorf("body not embedded")
	}
}

func TestChromedpDataURL_EncodesHash(t *testing.T) {
	got := chromedpDataURL("a#b")
	if got != "a%23b" {
		t.Errorf("encode hash: %q want a%%23b", got)
	}
}

// ChromedpRenderer.Render is not exercised end-to-end here because
// CI rarely has Chrome installed; the daemon documents the optional
// dependency in the scheduled-email path. The HTMLOnlyRenderer
// fallback handles the test environment.
