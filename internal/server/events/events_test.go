package events

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newCancellableReqCtx wraps an httptest request so the handler
// observes a real ctx.Done() instead of running until timeout.
func newCancellableReqCtx(_ *http.Request) (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}

// TestProducerPublishAssignsMonotonicIDs guards the cursor contract.
func TestProducerPublishAssignsMonotonicIDs(t *testing.T) {
	p := NewProducer()
	e1 := p.Publish(TypeScanQueued, "scan-1", nil)
	e2 := p.Publish(TypeScanStarted, "scan-1", nil)
	e3 := p.Publish(TypeScanCompleted, "scan-1", nil)
	if e1.ID != 1 || e2.ID != 2 || e3.ID != 3 {
		t.Errorf("want IDs 1/2/3, got %d/%d/%d", e1.ID, e2.ID, e3.ID)
	}
	if got := p.LastID(); got != 3 {
		t.Errorf("LastID = %d, want 3", got)
	}
}

// TestSubscribeBacklogFiltersBySince exercises cursor replay.
func TestSubscribeBacklogFiltersBySince(t *testing.T) {
	p := NewProducer()
	p.Publish(TypeScanQueued, "s1", nil)    // ID 1
	p.Publish(TypeScanStarted, "s1", nil)   // ID 2
	p.Publish(TypeScanCompleted, "s1", nil) // ID 3
	_, _, backlog := p.Subscribe(1)
	if len(backlog) != 2 {
		t.Fatalf("backlog len = %d, want 2 (events 2 + 3)", len(backlog))
	}
	if backlog[0].ID != 2 || backlog[1].ID != 3 {
		t.Errorf("backlog IDs = %d,%d; want 2,3", backlog[0].ID, backlog[1].ID)
	}
}

// TestSubscribeReceivesLiveEvents confirms post-subscribe Publish
// reaches the channel.
func TestSubscribeReceivesLiveEvents(t *testing.T) {
	p := NewProducer()
	_, ch, _ := p.Subscribe(0)
	p.Publish(TypeFindingCreated, "f-1", map[string]string{"sev": "critical"})
	select {
	case ev := <-ch:
		if ev.Type != TypeFindingCreated || ev.EntityID != "f-1" {
			t.Errorf("got event %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received within 1s")
	}
}

// TestUnsubscribeClosesChannel ensures the handler can detect
// shutdown via channel close.
func TestUnsubscribeClosesChannel(t *testing.T) {
	p := NewProducer()
	id, ch, _ := p.Subscribe(0)
	p.Unsubscribe(id)
	if _, open := <-ch; open {
		t.Error("channel should be closed after Unsubscribe")
	}
}

// TestHandlerEmitsBacklogAndLiveEvents end-to-ends the SSE wire path.
func TestHandlerEmitsBacklogAndLiveEvents(t *testing.T) {
	p := NewProducer()
	p.Publish(TypeScanCompleted, "s1", nil) // ID 1 — backlog

	req := httptest.NewRequest("GET", "/api/v1/events?since=0", nil)
	rec := httptest.NewRecorder()

	// Run handler in a goroutine; let it write backlog + emit one
	// live event, then cancel via context.
	done := make(chan struct{})
	ctx, cancel := newCancellableReqCtx(req)
	go func() {
		p.Handler()(rec, req.WithContext(ctx))
		close(done)
	}()
	// Give the handler a moment to subscribe + write backlog.
	time.Sleep(50 * time.Millisecond)
	p.Publish(TypeFindingCreated, "f-1", nil) // ID 2 — live
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	body := rec.Body.String()
	if !strings.Contains(body, "id: 1") || !strings.Contains(body, "id: 2") {
		t.Errorf("response missing expected event ids; got:\n%s", body)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}
}
