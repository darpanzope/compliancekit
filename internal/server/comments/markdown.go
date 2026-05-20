// Package comments owns the goldmark+bluemonday pipeline that turns
// operator-authored markdown into the sanitized HTML cached in the
// comments table. Renderer instances are safe for concurrent use;
// the package exposes a default instance via Default() for the
// daemon's hot path.
//
// Allowed markdown subset (per v1.8 issue scope):
//   - bold + italic + inline code + code fences
//   - bulleted + numbered lists
//   - links (with rel="noopener noreferrer" + target="_blank")
//   - headings (h1–h3)
//   - blockquotes
//
// Disallowed:
//   - raw HTML (stripped by bluemonday before rendering)
//   - images (potential pixel-tracking, off-domain fetches)
//   - tables / footnotes (kept out at v1.8; revisit if operators ask)
//   - scripts / styles (stripped by bluemonday)
package comments

import (
	"bytes"
	"sync"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"
)

// Renderer wraps goldmark + bluemonday with a fixed allowlist policy.
// Reusable across requests; no per-render state escapes.
type Renderer struct {
	md     goldmark.Markdown
	policy *bluemonday.Policy
}

// New returns a Renderer with the v1.8 allowlist policy applied.
func New() *Renderer {
	// Build a tight allowlist from scratch — UGCPolicy is too
	// permissive (allows <img>, ToC anchors, etc.). We want only
	// the markdown subset documented in the package doc.
	policy := bluemonday.NewPolicy()
	policy.AllowElements("p", "br", "hr",
		"strong", "em", "del", "code", "pre",
		"ul", "ol", "li",
		"h1", "h2", "h3", "h4", "h5", "h6",
		"blockquote")
	// Links — require absolute http(s) URLs; open in new tab with
	// noopener/noreferrer for the v1.8 collaboration surface.
	policy.AllowAttrs("href").OnElements("a")
	policy.RequireParseableURLs(true)
	policy.AllowURLSchemes("http", "https", "mailto")
	policy.RequireNoFollowOnLinks(false)
	policy.RequireNoReferrerOnLinks(true)
	policy.AddTargetBlankToFullyQualifiedLinks(true)
	// Code fences carry class="language-foo" from goldmark.
	policy.AllowAttrs("class").Matching(bluemonday.SpaceSeparatedTokens).OnElements("code", "pre")

	md := goldmark.New(
		goldmark.WithExtensions(extension.Strikethrough, extension.Linkify),
		goldmark.WithRendererOptions(
			// XHTML closes self-terminating tags; safer for HTML embedding.
			html.WithXHTML(),
			// Render hard line breaks the way operators expect them in
			// a chat-style comment thread (single newline = <br/>).
			html.WithHardWraps(),
		),
	)
	return &Renderer{md: md, policy: policy}
}

// Render converts markdown source into sanitized HTML. The output is
// safe to embed in an HTML response without further escaping.
//
// Empty input returns an empty string; invalid markdown still
// renders (goldmark is lenient) — bluemonday is the final gate that
// strips anything outside the allowlist.
func (r *Renderer) Render(src string) (string, error) {
	if src == "" {
		return "", nil
	}
	var buf bytes.Buffer
	if err := r.md.Convert([]byte(src), &buf); err != nil {
		return "", err
	}
	return r.policy.Sanitize(buf.String()), nil
}

var (
	defaultOnce sync.Once
	defaultR    *Renderer
)

// Default returns the package-global renderer, lazily constructed on
// first use. Daemon handlers should call this rather than allocating
// their own Renderer per request.
func Default() *Renderer {
	defaultOnce.Do(func() { defaultR = New() })
	return defaultR
}
