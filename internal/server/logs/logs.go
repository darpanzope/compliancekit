// Package logs is the v1.6 phase 6 in-UI log tail. A small ring
// buffer captures every slog line the daemon emits; the SSE
// handler streams the backlog + live tail to an admin-gated UI
// page at /admin/logs.
//
// Implementation as a slog.Handler that wraps the daemon's default
// handler so structured log output still flows to stderr but ALSO
// fans out into the ring + every subscribed SSE consumer.
package logs

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// ringSize caps the in-memory backlog. 500 × ~300 B / line ≈ 150 KB.
const ringSize = 500

// Line is one captured log entry in the buffer + SSE wire format.
type Line struct {
	ID     uint64    `json:"id"`
	Time   time.Time `json:"time"`
	Level  string    `json:"level"`
	Msg    string    `json:"msg"`
	Attrs  string    `json:"attrs,omitempty"` // flattened "k=v k=v" for terse render
	Source string    `json:"source,omitempty"`
}

// Buffer is the shared ring + fan-out hub. Constructed once in
// cli/serve.go + installed as a wrapping slog.Handler.
type Buffer struct {
	mu          sync.RWMutex
	nextID      uint64
	ring        []Line
	subscribers map[uint64]chan Line
	subSeq      uint64
}

// New returns an empty Buffer. Wire via Handler(inner) to install
// as the slog default; Handler.HTTP returns the SSE endpoint.
func New() *Buffer {
	return &Buffer{
		ring:        make([]Line, 0, ringSize),
		subscribers: make(map[uint64]chan Line),
	}
}

// Handler returns a slog.Handler that writes records to `inner`
// (typically stderr's TextHandler) AND captures them into the ring.
// Pass nil for inner to capture only — the daemon still gets the
// stderr stream because the wrapper is chained after it.
func (b *Buffer) Handler(inner slog.Handler) slog.Handler {
	return &chained{inner: inner, buf: b}
}

// chained implements slog.Handler.
type chained struct {
	inner slog.Handler
	buf   *Buffer
	group string
	attrs []slog.Attr
}

func (h *chained) Enabled(ctx context.Context, l slog.Level) bool {
	if h.inner != nil && h.inner.Enabled(ctx, l) {
		return true
	}
	return true // always buffer; visibility filter happens at SSE render
}

func (h *chained) Handle(ctx context.Context, r slog.Record) error {
	if h.inner != nil {
		_ = h.inner.Handle(ctx, r)
	}
	attrs := flattenAttrs(r)
	h.buf.append(Line{
		Time:  r.Time,
		Level: r.Level.String(),
		Msg:   r.Message,
		Attrs: attrs,
	})
	return nil
}

func (h *chained) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := *h
	out.attrs = append(out.attrs, attrs...)
	if h.inner != nil {
		out.inner = h.inner.WithAttrs(attrs)
	}
	return &out
}

func (h *chained) WithGroup(name string) slog.Handler {
	out := *h
	out.group = name
	if h.inner != nil {
		out.inner = h.inner.WithGroup(name)
	}
	return &out
}

func flattenAttrs(r slog.Record) string {
	var s string
	r.Attrs(func(a slog.Attr) bool {
		if s != "" {
			s += " "
		}
		s += a.Key + "=" + a.Value.String()
		return true
	})
	return s
}

func (b *Buffer) append(l Line) {
	b.mu.Lock()
	b.nextID++
	l.ID = b.nextID
	if len(b.ring) == ringSize {
		copy(b.ring, b.ring[1:])
		b.ring = b.ring[:len(b.ring)-1]
	}
	b.ring = append(b.ring, l)
	subs := make([]chan Line, 0, len(b.subscribers))
	for _, ch := range b.subscribers {
		subs = append(subs, ch)
	}
	b.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- l:
		default: // drop-oldest semantics for slow tailers
		}
	}
}

// Subscribe returns a channel of live log lines + the current
// backlog snapshot (filtered by ?since cursor). Always called via
// Defer-Unsubscribe in the SSE handler.
func (b *Buffer) Subscribe(since uint64) (subID uint64, ch <-chan Line, backlog []Line) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subSeq++
	subID = b.subSeq
	outCh := make(chan Line, 64)
	b.subscribers[subID] = outCh
	ch = outCh
	backlog = make([]Line, 0)
	for _, l := range b.ring {
		if l.ID > since {
			backlog = append(backlog, l)
		}
	}
	return subID, ch, backlog
}

// Unsubscribe drops + closes the subscriber. Idempotent.
func (b *Buffer) Unsubscribe(id uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ch, ok := b.subscribers[id]; ok {
		delete(b.subscribers, id)
		close(ch)
	}
}

// StreamHandler returns the GET /admin/logs/stream SSE handler.
// MUST be wrapped by an admin-only gate before mounting.
func (b *Buffer) StreamHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		subID, ch, backlog := b.Subscribe(0)
		defer b.Unsubscribe(subID)

		for _, l := range backlog {
			if !writeLine(w, l) {
				return
			}
		}
		flusher.Flush()

		ping := time.NewTicker(15 * time.Second)
		defer ping.Stop()
		timeout := time.After(10 * time.Minute)
		for {
			select {
			case <-r.Context().Done():
				return
			case <-timeout:
				return
			case <-ping.C:
				if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
					return
				}
				flusher.Flush()
			case l, open := <-ch:
				if !open {
					return
				}
				if !writeLine(w, l) {
					return
				}
				flusher.Flush()
			}
		}
	}
}

func writeLine(w http.ResponseWriter, l Line) bool {
	body, err := json.Marshal(l)
	if err != nil {
		return true
	}
	_, err = fmt.Fprintf(w, "id: %d\nevent: log\ndata: %s\n\n", l.ID, body)
	return err == nil
}
