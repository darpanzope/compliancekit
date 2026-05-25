// v1.14 phase 9 — print-ready HTML + chromedp-backed PDF renderer.
//
// The HTML side ships unconditionally: PrintDocument wraps content
// with TOC anchors, page-break-friendly CSS, a per-page header/
// footer, page-number running text via CSS counters, and an
// optional watermark overlay. The output renders as PDF in any
// browser via Cmd+P / Print to PDF, no daemon-side Chrome needed.
//
// chromedp lives behind ChromedpRenderer for headless automated
// rendering (the v1.14 phase 6 scheduled-email attachment path).
// Operators without Chrome can use the HTML-print path; CI without
// a browser falls back to the HTML body so tests don't require a
// chromium download.

package report

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// PrintDocument is the input shape for HTML → print-ready render.
type PrintDocument struct {
	Title       string
	BodyHTML    template.HTML // already-rendered (e.g. dashboard SVG widgets)
	Watermark   string        // empty = no watermark overlay
	HeaderLeft  string
	HeaderRight string
	FooterLeft  string
	TOC         []TOCEntry
	GeneratedAt time.Time
}

// TOCEntry is one anchor in the print-ready table of contents.
type TOCEntry struct {
	Label  string
	Anchor string // matches an id="" attribute somewhere in BodyHTML
}

// RenderPrintHTML wraps doc in the print-friendly layout. The
// output is a self-contained HTML document with @page CSS rules for
// page size + header/footer running content, anchor-targeted TOC,
// and an optional rotated watermark overlay rendered as an SVG.
func RenderPrintHTML(doc PrintDocument) string {
	if doc.GeneratedAt.IsZero() {
		doc.GeneratedAt = time.Now().UTC()
	}
	var buf bytes.Buffer
	_ = printTemplate.Execute(&buf, doc)
	return buf.String()
}

// printTemplate is parsed once. The body uses CSS Paged Media (@page)
// so any browser's "Print to PDF" produces the same layout chromedp
// would render headlessly.
var printTemplate = template.Must(template.New("print").Funcs(template.FuncMap{
	"formatTime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ .Title }}</title>
<style>
@page {
  size: Letter;
  margin: 0.75in 0.5in;
  @top-left { content: "{{ .HeaderLeft }}"; font-size: 9pt; color: #64748b; }
  @top-right { content: "{{ .HeaderRight }}"; font-size: 9pt; color: #64748b; }
  @bottom-left { content: "{{ .FooterLeft }}"; font-size: 9pt; color: #64748b; }
  @bottom-right { content: "page " counter(page) " of " counter(pages); font-size: 9pt; color: #64748b; }
}
body { font-family: -apple-system, "Segoe UI", Roboto, system-ui, sans-serif; color: #0f172a; line-height: 1.5; font-size: 11pt; }
h1, h2, h3 { page-break-after: avoid; }
.ck-toc { page-break-after: always; }
.ck-toc ol { list-style: none; padding-left: 0; }
.ck-toc li { padding: 2px 0; border-bottom: 1px dotted #e2e8f0; display: flex; justify-content: space-between; }
.ck-toc a { color: #1f2937; text-decoration: none; }
.ck-toc a::after { content: leader('.') target-counter(attr(href), page); }
.ck-section { page-break-before: auto; padding-top: 1em; }
.ck-watermark {
  position: fixed; inset: 0; pointer-events: none; opacity: 0.08; z-index: 9999;
  display: flex; align-items: center; justify-content: center;
  font-size: 64pt; font-weight: 700; transform: rotate(-30deg); color: #64748b;
}
</style>
</head>
<body>
{{ if .Watermark }}<div class="ck-watermark">{{ .Watermark }}</div>{{ end }}

<header>
  <h1 style="margin-bottom: 0;">{{ .Title }}</h1>
  <p style="color: #64748b; font-size: 9pt; margin-top: 4px;">Generated {{ formatTime .GeneratedAt }}</p>
</header>

{{ if .TOC }}
<section class="ck-toc">
  <h2>Contents</h2>
  <ol>
    {{ range .TOC }}<li><a href="#{{ .Anchor }}">{{ .Label }}</a></li>{{ end }}
  </ol>
</section>
{{ end }}

<main>
  {{ .BodyHTML }}
</main>
</body>
</html>`))

// PDFRenderer renders the same PrintDocument shape to bytes. Phase 9
// ships two implementations:
//
//   - HTMLOnlyRenderer wraps RenderPrintHTML for environments
//     without chromedp / Chrome; the "PDF" bytes are the print-
//     ready HTML the user feeds to their browser.
//   - ChromedpRenderer drives a headless Chrome via chromedp; the
//     daemon's scheduled-email path uses this when Chrome is on
//     PATH.
type PDFRenderer interface {
	Render(ctx context.Context, doc PrintDocument) (body []byte, contentType string, err error)
}

// HTMLOnlyRenderer is the no-Chrome fallback. Content-type is
// text/html; the caller may rename the file to .pdf and let the
// browser handle the conversion.
type HTMLOnlyRenderer struct{}

// Render implements PDFRenderer.
func (HTMLOnlyRenderer) Render(_ context.Context, doc PrintDocument) (body []byte, contentType string, err error) {
	return []byte(RenderPrintHTML(doc)), "text/html", nil
}

// ChromedpRenderer drives a headless Chrome via chromedp.Run. The
// default ExecAllocator path inherits the parent process env, so
// chromedp.NoSandbox / chromedp.Headless can be tweaked by the
// daemon at startup if needed.
type ChromedpRenderer struct {
	// AllocatorOpts overrides the default chromedp.ExecAllocator
	// options. Empty = chromedp's defaults.
	AllocatorOpts []chromedp.ExecAllocatorOption
}

// Render implements PDFRenderer. Builds a fresh allocator + browser
// context per call so concurrent renders don't share state.
func (r ChromedpRenderer) Render(ctx context.Context, doc PrintDocument) (body []byte, contentType string, err error) {
	opts := r.AllocatorOpts
	if len(opts) == 0 {
		opts = append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Headless)
	}
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()
	browserCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	html := RenderPrintHTML(doc)
	pdf, err := renderPDFViaChromedp(browserCtx, html)
	if err != nil {
		return nil, "", fmt.Errorf("chromedp render: %w", err)
	}
	return pdf, "application/pdf", nil
}

// renderPDFViaChromedp navigates a fresh page to the inlined HTML +
// invokes Chrome's Page.printToPDF DevTools method. Honors the
// @page CSS so the operator's print-ready layout (TOC, page
// numbers, header/footer) lands in the binary as-is.
func renderPDFViaChromedp(ctx context.Context, html string) ([]byte, error) {
	var pdf []byte
	if err := chromedp.Run(ctx,
		chromedp.Navigate("data:text/html;charset=utf-8,"+chromedpDataURL(html)),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.ActionFunc(func(ctx context.Context) error {
			buf, _, err := page.PrintToPDF().
				WithPrintBackground(true).
				WithDisplayHeaderFooter(false). // headers come from @page CSS
				Do(ctx)
			if err != nil {
				return err
			}
			pdf = buf
			return nil
		}),
	); err != nil {
		return nil, err
	}
	if len(pdf) == 0 {
		return nil, errors.New("chromedp returned empty bytes")
	}
	return pdf, nil
}

func chromedpDataURL(s string) string {
	// URL-encode the bare minimum so chromedp.Navigate accepts the
	// data:URL. Operators with large dashboards should run chromedp
	// with the host's HTTP target instead of data-URL inlining; the
	// inline path is the simple default for the scheduled-email
	// attachment.
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '#', '%':
			out = append(out, '%', hexNibble(c>>4), hexNibble(c&0x0f))
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

func hexNibble(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'a' + b - 10
}
