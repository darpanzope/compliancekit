package events

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Handler returns the HTTP handler for GET /api/v1/events. Native
// SSE (no external dep, mirrors the v1.4 scan-progress pattern from
// internal/server/ui/scannew.go). Subscribers receive the cursor-
// replay backlog first, then a live stream of every Publish.
//
// Query params:
//   - ?since=<id>   resume cursor; defaults to 0 (only backlog
//     within the 5-min retention window — usually
//     empty for fresh connections)
//
// Headers:
//   - Content-Type: text/event-stream
//   - Cache-Control: no-cache
//   - X-Accel-Buffering: no   (defeats nginx proxy buffering)
//
// SSE framing per line: `id: <event-id>\nevent: <type>\ndata: <json>\n\n`.
// Heartbeat comment line (`: ping`) every 15s so reverse proxies +
// browsers don't time out the long-lived connection.
//
// Connection cap: 5 minutes per long-poll. Clients are expected to
// reconnect with the last-seen `id:` as the new `?since=`. This
// matches the v1.4 scan-progress timeout + lets the daemon reclaim
// resources from forgotten tabs.
func (p *Producer) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		var since uint64
		if v := r.URL.Query().Get("since"); v != "" {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				since = n
			}
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		subID, ch, backlog := p.Subscribe(since)
		defer p.Unsubscribe(subID)

		// Emit backlog first so the client catches up before live
		// events start arriving.
		for _, ev := range backlog {
			if !writeEvent(w, ev) {
				return
			}
		}
		flusher.Flush()

		ping := time.NewTicker(15 * time.Second)
		defer ping.Stop()
		timeout := time.After(5 * time.Minute)

		for {
			select {
			case <-r.Context().Done():
				return
			case <-timeout:
				// Polite close; client reconnects with the last
				// `id:` it saw.
				fmt.Fprint(w, "event: timeout\ndata: {\"message\":\"reconnect please\"}\n\n")
				flusher.Flush()
				return
			case <-ping.C:
				// SSE comment line — never delivered as an event
				// to the client, but keeps middleboxes alive.
				if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
					return
				}
				flusher.Flush()
			case ev, open := <-ch:
				if !open {
					return
				}
				if !writeEvent(w, ev) {
					return
				}
				flusher.Flush()
			}
		}
	}
}

// writeEvent serializes one Event in SSE framing. Returns false on
// a write error — the caller closes the connection.
func writeEvent(w http.ResponseWriter, ev Event) bool {
	body, err := json.Marshal(ev)
	if err != nil {
		return true // skip malformed; don't kill the connection
	}
	_, err = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", ev.ID, ev.Type, body)
	return err == nil
}
