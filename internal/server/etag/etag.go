// Package etag is the v1.11 phase 5 HTTP caching middleware.
// Generates a weak ETag from the response body's sha256 + handles
// If-None-Match short-circuit to 304 Not Modified.
//
// Why weak ETags: the daemon serves compressed bodies (v1.11 phase 4)
// where the same logical content can have multiple byte
// representations. The weak comparison (per RFC 9110 §13.1.1) lets
// clients cache across encodings.
//
// SSE streams (`text/event-stream`) and explicit no-store responses
// are passed through unmodified — buffering would break the
// event-flush semantics + violate Cache-Control intent.
package etag

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// maxBuffer is the upper bound on buffered response size. Anything
// larger flushes through unmodified — we'd rather skip the ETag
// than pin a 10MB findings dump in memory.
const maxBuffer = 4 * 1024 * 1024

// Middleware returns the ETag middleware. Wraps responses with a
// buffer-then-hash pass; serves 304 when If-None-Match matches.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only GET + HEAD are cacheable; mutations pass through.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		// SSE passes through — buffering would break flush semantics.
		// We can't know the content-type before the handler writes,
		// so the etagWriter sniffs on first write + sets skip=true.
		ew := &etagWriter{
			ResponseWriter: w,
			buf:            new(bytes.Buffer),
			ifNoneMatch:    r.Header.Get("If-None-Match"),
			req:            r,
		}
		next.ServeHTTP(ew, r)
		ew.commit()
	})
}

// etagWriter buffers the response body so we can hash it after the
// handler completes. Once the buffer crosses maxBuffer, it stops
// buffering + becomes a passthrough (best-effort: large payloads
// skip ETag).
type etagWriter struct {
	http.ResponseWriter
	buf         *bytes.Buffer
	ifNoneMatch string
	req         *http.Request

	statusCode int
	wroteHdr   bool
	skip       bool
}

func (e *etagWriter) WriteHeader(status int) {
	if e.skip {
		e.ResponseWriter.WriteHeader(status)
		e.wroteHdr = true
		return
	}
	// Defer the actual WriteHeader until commit so we can layer ETag
	// + handle 304 before the status line goes out.
	e.statusCode = status
}

func (e *etagWriter) Write(p []byte) (int, error) {
	if e.skip {
		return e.ResponseWriter.Write(p)
	}
	// Once-only sniff: SSE / no-store / oversized → passthrough.
	if !e.wroteHdr {
		if e.shouldSkip(p) {
			e.skip = true
			if e.statusCode != 0 {
				e.ResponseWriter.WriteHeader(e.statusCode)
			}
			e.wroteHdr = true
			return e.ResponseWriter.Write(p)
		}
	}
	if e.buf.Len()+len(p) > maxBuffer {
		// Too big to ETag; flush what we have + switch to passthrough.
		e.skip = true
		if e.statusCode != 0 {
			e.ResponseWriter.WriteHeader(e.statusCode)
		}
		if _, err := e.ResponseWriter.Write(e.buf.Bytes()); err != nil {
			return 0, err
		}
		e.buf.Reset()
		e.wroteHdr = true
		return e.ResponseWriter.Write(p)
	}
	return e.buf.Write(p)
}

func (e *etagWriter) shouldSkip(firstChunk []byte) bool {
	ct := e.ResponseWriter.Header().Get("Content-Type")
	if ct == "" {
		ct = http.DetectContentType(firstChunk)
	}
	if strings.HasPrefix(ct, "text/event-stream") {
		return true
	}
	cc := e.ResponseWriter.Header().Get("Cache-Control")
	return strings.Contains(cc, "no-store")
}

// commit is the post-handler step. Hashes the buffer + compares to
// If-None-Match; on hit responds 304, otherwise writes the buffer +
// the computed ETag.
func (e *etagWriter) commit() {
	if e.skip {
		return
	}
	// Empty bodies (304-on-empty would be confusing) skip ETag.
	if e.buf.Len() == 0 {
		if e.statusCode != 0 {
			e.ResponseWriter.WriteHeader(e.statusCode)
		}
		return
	}
	sum := sha256.Sum256(e.buf.Bytes())
	tag := `W/"` + hex.EncodeToString(sum[:8]) + `"`
	e.ResponseWriter.Header().Set("ETag", tag)

	if matchesIfNoneMatch(e.ifNoneMatch, tag) {
		// 304 must have no body but should preserve cache-relevant
		// headers (ETag, Vary, Cache-Control) per RFC 9110 §15.4.5.
		e.ResponseWriter.Header().Del("Content-Length")
		e.ResponseWriter.WriteHeader(http.StatusNotModified)
		return
	}
	if e.statusCode != 0 {
		e.ResponseWriter.WriteHeader(e.statusCode)
	}
	_, _ = e.ResponseWriter.Write(e.buf.Bytes())
}

// Flush delegates so SSE-class handlers (where shouldSkip already
// flipped skip=true) keep working.
func (e *etagWriter) Flush() {
	if f, ok := e.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// matchesIfNoneMatch parses the If-None-Match header (comma-sep tag
// list, * wildcard, weak prefix tolerant) and reports whether the
// computed tag matches any entry.
func matchesIfNoneMatch(header, tag string) bool {
	if header == "" {
		return false
	}
	if strings.TrimSpace(header) == "*" {
		return true
	}
	// Weak comparison: strip W/ prefix on both sides before equality.
	wantStripped := stripWeak(tag)
	for _, raw := range strings.Split(header, ",") {
		if stripWeak(strings.TrimSpace(raw)) == wantStripped {
			return true
		}
	}
	return false
}

func stripWeak(tag string) string {
	tag = strings.TrimSpace(tag)
	return strings.TrimPrefix(tag, "W/")
}
