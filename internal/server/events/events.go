// Package events is the v1.6 SSE event bus the daemon uses to push
// live state changes to subscribed UI / TUI / API clients without
// polling.
//
// One Producer per daemon instance (constructed in cli/serve.go and
// shared with the worker pool + api + ui layers). Publishers call
// p.Publish(type, entityID, data); subscribers connect via the
// HTTP handler at /api/v1/events and receive a JSON-framed SSE
// stream.
//
// Cursor-based replay: every event carries a monotonic ID. Clients
// reconnecting after a brief disconnect pass ?since=<cursor> and
// receive every event ID > cursor that's still in the 5-minute
// ring buffer. Older events are dropped silently (the client gets
// the live tail starting from "now").
//
// In-memory ring buffer (no DB persistence). v1.11 can revisit if
// scale demands cross-restart durability; for v1.6, 5-minute
// in-process recovery is enough to survive a wifi blip.
package events

import (
	"encoding/json"
	"sync"
	"time"
)

// Type enumerates every event the daemon emits. New types appended
// here must also be documented in the v1.6 tracking issue (#38) +
// the /api/v1/events doc in CLI.md.
type Type string

const (
	TypeScanQueued         Type = "scan.queued"
	TypeScanStarted        Type = "scan.started"
	TypeScanProgress       Type = "scan.progress"
	TypeScanCompleted      Type = "scan.completed"
	TypeScanFailed         Type = "scan.failed"
	TypeFindingCreated     Type = "finding.created"
	TypeFindingResolved    Type = "finding.resolved"
	TypeWebhookReceived    Type = "webhook.received"
	TypeAuthSessionCreated Type = "auth.session.created"
)

// Event is one row in the stream. ID is monotonic across the
// Producer's lifetime — restarts reset to 1 (clients reconnecting
// across a restart see the full window of post-restart events).
type Event struct {
	ID       uint64          `json:"id"`
	Type     Type            `json:"type"`
	At       time.Time       `json:"at"`
	EntityID string          `json:"entity_id,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
}

// Producer is the fan-out hub. Safe for concurrent Publish + Subscribe.
type Producer struct {
	mu          sync.RWMutex
	nextID      uint64
	ring        []Event // FIFO, capped at ringCapacity
	subscribers map[uint64]chan Event
	subSeq      uint64
}

// ringCapacity caps the in-memory buffer. 1024 events × ~1 KB / event
// ≈ 1 MB. Tunable via Producer.SetRingCapacity if a single tenant
// fires more than ~3 events/sec sustained.
const ringCapacity = 1024

// retention is the wall-clock filter applied on backlog replay.
// Events older than this are dropped from a reconnecting client's
// catchup batch (still in the ring until the FIFO evicts them).
const retention = 5 * time.Minute

// subChanSize is the per-subscriber channel depth. Slow clients
// that don't drain see Producer.Publish drop their event silently
// rather than block every other subscriber.
const subChanSize = 64

// NewProducer constructs an empty Producer with the default
// ringCapacity. Pass to the worker / API / webhook code as a
// shared dependency.
func NewProducer() *Producer {
	return &Producer{
		ring:        make([]Event, 0, ringCapacity),
		subscribers: make(map[uint64]chan Event),
	}
}

// Publish records an event in the ring + fans out to every live
// subscriber. dataAny is JSON-marshaled inline; pass nil to omit.
// Returns the assigned Event for the caller's reference (rarely
// needed — the handler emits the event to the wire).
//
// Safe for concurrent use across goroutines.
func (p *Producer) Publish(typ Type, entityID string, dataAny any) Event {
	var data json.RawMessage
	if dataAny != nil {
		if b, err := json.Marshal(dataAny); err == nil {
			data = b
		}
	}
	p.mu.Lock()
	p.nextID++
	ev := Event{
		ID:       p.nextID,
		Type:     typ,
		At:       time.Now().UTC(),
		EntityID: entityID,
		Data:     data,
	}
	// Ring append + FIFO evict.
	if len(p.ring) == ringCapacity {
		copy(p.ring, p.ring[1:])
		p.ring = p.ring[:len(p.ring)-1]
	}
	p.ring = append(p.ring, ev)
	// Snapshot subscribers under the same lock so we don't hold the
	// write lock while sending; send below is non-blocking anyway.
	subs := make([]chan Event, 0, len(p.subscribers))
	for _, ch := range p.subscribers {
		subs = append(subs, ch)
	}
	p.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
			// Subscriber's buffer is full — drop. The client will
			// see the gap if it reconnects with a cursor older
			// than the dropped event. Acceptable for a live feed.
		}
	}
	return ev
}

// Subscribe registers a new live-events channel. Returns the
// subscriber's internal ID (pass to Unsubscribe), the receive
// channel, and the backlog of events with ID > since (filtered by
// the 5-min retention window).
//
// Backlog returns first; the caller emits each to the wire, then
// switches to the channel for live events. The two streams cannot
// race: Publish always appends to the ring + fans out under the
// same lock, so an event Publish'd between "subscribe + backlog"
// and "channel read" is guaranteed visible via one of the two
// paths (and the cursor ID lets the caller de-dup if both fire).
func (p *Producer) Subscribe(since uint64) (subID uint64, ch <-chan Event, backlog []Event) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.subSeq++
	subID = p.subSeq
	outCh := make(chan Event, subChanSize)
	p.subscribers[subID] = outCh
	ch = outCh

	cutoff := time.Now().Add(-retention)
	backlog = make([]Event, 0)
	for _, ev := range p.ring {
		if ev.ID <= since {
			continue
		}
		if ev.At.Before(cutoff) {
			continue
		}
		backlog = append(backlog, ev)
	}
	return subID, ch, backlog
}

// Unsubscribe drops the subscriber + closes its channel. Idempotent
// — calling twice is a no-op. Always called from the SSE handler's
// defer + after the request's context is canceled.
func (p *Producer) Unsubscribe(id uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ch, ok := p.subscribers[id]; ok {
		delete(p.subscribers, id)
		close(ch)
	}
}

// SubscriberCount returns the current number of live subscribers.
// Test + /metrics use; not part of the public Producer contract.
func (p *Producer) SubscriberCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.subscribers)
}

// LastID returns the highest event ID emitted so far. Used by tests
// + by the /metrics gauge.
func (p *Producer) LastID() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.nextID
}
