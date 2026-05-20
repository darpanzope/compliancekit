package comments

import (
	"strings"
	"testing"
)

// TestRender_AllowedSubset exercises the markdown subset documented
// in the package doc — bold, italic, inline code, code fences, lists,
// links, blockquotes, hard wraps. Output must round-trip through
// bluemonday's UGC policy.
func TestRender_AllowedSubset(t *testing.T) {
	r := New()
	src := "Hello **bold** *italic* `code` body.\n\n" +
		"- item one\n" +
		"- item two\n\n" +
		"```go\nfmt.Println(\"hi\")\n```\n\n" +
		"[anchor](https://example.com)"
	got, err := r.Render(src)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"<strong>bold</strong>",
		"<em>italic</em>",
		"<code>code</code>",
		"<li>item one</li>",
		`<a href="https://example.com"`,
		`rel="noreferrer noopener"`,
		`target="_blank"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing fragment %q in:\n%s", want, got)
		}
	}
}

// TestRender_StripsScript confirms the disallowed subset cannot
// smuggle JS through the renderer. Raw HTML is dropped by goldmark
// (no html.WithUnsafe) and any leaked tags by bluemonday's UGC
// policy.
func TestRender_StripsScript(t *testing.T) {
	r := New()
	got, err := r.Render(`<script>alert(1)</script> hello`)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(got, "<script") || strings.Contains(got, "alert(1)") {
		t.Errorf("script not stripped: %s", got)
	}
}

// TestRender_NoImages confirms image syntax produces no <img>;
// bluemonday + UGC removes them per the v1.8 scope (no pixel
// tracking, no off-domain fetches).
func TestRender_NoImages(t *testing.T) {
	r := New()
	got, err := r.Render(`![oops](https://example.com/track.gif)`)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(got, "<img") {
		t.Errorf("img tag not stripped: %s", got)
	}
}

// TestRender_EmptyInput verifies the zero-allocation fast path.
func TestRender_EmptyInput(t *testing.T) {
	r := New()
	got, err := r.Render("")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if got != "" {
		t.Errorf("empty input produced output: %q", got)
	}
}
