// Package compress is the v1.11 phase 4 HTTP-compression middleware.
// Negotiates brotli (preferred) → gzip → identity from the request's
// Accept-Encoding header; sets `Vary: Accept-Encoding` so caches
// don't serve a brotli body to a gzip-only client.
//
// Only compresses responses with a compressible Content-Type
// (text/*, application/json, application/javascript, image/svg+xml).
// Skips already-compressed media (PNG, JPEG, .min.js + .min.css
// served from /assets/ are explicit allowlist entries because Tailwind
// + htmx + Alpine ship as text/javascript without the .min marker).
//
// Minimum body length: 1 KiB. Compressing 200-byte responses costs
// more CPU than it saves bandwidth.
//
// SSE streams (`text/event-stream`) intentionally pass through
// unmodified — buffered compression breaks the event-flush semantics
// the v1.6 bus relies on.
package compress

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
)

// minCompressSize is the floor below which we skip compression
// entirely. Compressing < 1 KiB wastes more CPU than it saves
// bandwidth.
const minCompressSize = 1024

// Encoding tokens canonicalized so negotiate + init stay in lockstep.
const (
	encBrotli = "br"
	encGzip   = "gzip"
)

// compressibleTypes is the allow-list of Content-Type prefixes the
// middleware compresses. application/* needs explicit per-subtype
// gating because images / fonts are pre-compressed.
var compressibleTypes = []string{
	"text/",
	"application/json",
	"application/javascript",
	"application/xml",
	"application/x-yaml",
	"application/yaml",
	"image/svg+xml",
}

// Middleware returns the compression middleware. Wraps every
// non-SSE GET/HEAD/POST response with the negotiated encoder.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always advertise Vary so caches key on encoding.
		w.Header().Add("Vary", "Accept-Encoding")

		enc := negotiate(r.Header.Get("Accept-Encoding"))
		if enc == "" {
			next.ServeHTTP(w, r)
			return
		}
		// Wrap; the wrapper defers the actual encoder construction
		// until first Write so we can sniff Content-Type + skip SSE
		// + skip below-floor responses.
		cw := &compressWriter{ResponseWriter: w, encoding: enc, request: r}
		defer cw.Close()
		next.ServeHTTP(cw, r)
	})
}

// negotiate picks the best supported encoding from the client's
// Accept-Encoding header. Returns "" when none acceptable.
func negotiate(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.Split(header, ",")
	hasBr, hasGz := false, false
	for _, p := range parts {
		// Drop q-values; we don't honor preference ordering across
		// equal-q values since the spec is permissive.
		token := strings.TrimSpace(strings.SplitN(p, ";", 2)[0])
		switch strings.ToLower(token) {
		case encBrotli:
			hasBr = true
		case encGzip:
			hasGz = true
		}
	}
	if hasBr {
		return encBrotli
	}
	if hasGz {
		return encGzip
	}
	return ""
}

// compressWriter is the response-writer wrapper. Lazy-initializes
// the encoder on first Write so we can sniff Content-Type +
// short-circuit pass-through cases.
type compressWriter struct {
	http.ResponseWriter
	encoding string
	request  *http.Request

	// Once-initialized on first Write.
	once      sync.Once
	encoder   io.WriteCloser
	skip      bool // true when this response is passing through unmodified
	hdrStatus int
}

// WriteHeader captures the status code so we can write it through
// after deciding to compress or skip. Doesn't write to the wire
// yet — that happens on the first body Write.
func (c *compressWriter) WriteHeader(status int) {
	c.hdrStatus = status
}

func (c *compressWriter) Header() http.Header { return c.ResponseWriter.Header() }

// Write decides on first call whether to compress + then forwards
// every subsequent byte through the chosen path.
func (c *compressWriter) Write(p []byte) (int, error) {
	c.once.Do(func() { c.init(p) })
	if c.skip {
		return c.ResponseWriter.Write(p)
	}
	return c.encoder.Write(p)
}

// init runs on the first body write. Inspects the response headers
// + first-byte sample to pick a path:
//   - SSE: pass through (no compression breaks event-flush semantics)
//   - non-compressible Content-Type: pass through
//   - already-encoded (existing Content-Encoding): pass through
//   - response too small (heuristic — only known from Content-Length
//     when set, else compress optimistically): compress
//   - otherwise: install brotli or gzip writer
func (c *compressWriter) init(firstChunk []byte) {
	h := c.ResponseWriter.Header()
	if h.Get("Content-Encoding") != "" {
		c.skip = true
		c.flushStatus()
		return
	}
	ct := h.Get("Content-Type")
	if ct == "" {
		// Best-effort sniff so JSON / HTML responses without explicit
		// Content-Type still get compressed.
		ct = http.DetectContentType(firstChunk)
	}
	if strings.HasPrefix(ct, "text/event-stream") || !isCompressible(ct) {
		c.skip = true
		c.flushStatus()
		return
	}
	if cl := h.Get("Content-Length"); cl != "" {
		// Cheap floor check when we know the size up-front.
		if n := parseInt(cl); n > 0 && n < minCompressSize {
			c.skip = true
			c.flushStatus()
			return
		}
	}
	// Install the encoder. Content-Length is unknown post-compress
	// so we strip it; Content-Encoding is the negotiated value.
	h.Del("Content-Length")
	h.Set("Content-Encoding", c.encoding)
	switch c.encoding {
	case encBrotli:
		c.encoder = brotli.NewWriterLevel(c.ResponseWriter, brotli.BestSpeed)
	case encGzip:
		gz, _ := gzip.NewWriterLevel(c.ResponseWriter, gzip.BestSpeed)
		c.encoder = gz
	default:
		c.skip = true
	}
	c.flushStatus()
}

func (c *compressWriter) flushStatus() {
	if c.hdrStatus != 0 {
		c.ResponseWriter.WriteHeader(c.hdrStatus)
		c.hdrStatus = 0
	}
}

// Close is called by the middleware via defer. Closes the encoder
// (flushes pending bytes) if it was installed.
func (c *compressWriter) Close() {
	if c.hdrStatus != 0 {
		c.flushStatus()
	}
	if c.encoder != nil {
		_ = c.encoder.Close()
	}
}

// Flush exposes the http.Flusher interface so SSE + streaming
// handlers keep working. Brotli + gzip writers don't flush mid-
// stream by default — we delegate the underlying flush through.
func (c *compressWriter) Flush() {
	if c.encoder != nil {
		// Best-effort flush via the encoder's underlying buffer.
		if f, ok := c.encoder.(interface{ Flush() error }); ok {
			_ = f.Flush()
		}
	}
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func isCompressible(contentType string) bool {
	if contentType == "" {
		return false
	}
	// Strip charset / boundary parameters.
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = strings.TrimSpace(contentType[:i])
	}
	for _, prefix := range compressibleTypes {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}
	return false
}

// parseInt is a tiny stdlib-free strconv.Atoi for the
// Content-Length parse-then-floor-check path.
func parseInt(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
