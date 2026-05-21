package respcache

// Invalidator wires the v1.6 SSE event bus into the cache so
// mutating events bust the cached findings + scans + resources
// lists. Operators never see stale data after a finding lands.
//
// Subscribes via Producer.Subscribe so the invalidator runs
// independently of the per-request hot path; the goroutine
// lifetime is bound to the daemon's ctx.

import (
	"context"
	"log/slog"

	"github.com/darpanzope/compliancekit/internal/server/events"
)

// Invalidator listens to the SSE bus + drops cache entries for
// mutating event types.
type Invalidator struct {
	cache  *Cache
	prod   *events.Producer
	logger *slog.Logger
}

// NewInvalidator wires the listener. Call Run to start consuming;
// stop by canceling the passed context.
func NewInvalidator(cache *Cache, prod *events.Producer, logger *slog.Logger) *Invalidator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Invalidator{cache: cache, prod: prod, logger: logger}
}

// Run blocks until ctx is canceled. Subscribes to the v1.6 bus +
// busts the cache on each mutating event.
//
// The prefix map below maps event type → cache key prefix; an
// event drops every cache entry whose key starts with the matching
// prefix. "findings:" covers /api/v1/findings + /findings/rows
// (both keyed via respcache.KeyFor("findings", ...)).
func (in *Invalidator) Run(ctx context.Context) {
	if in.prod == nil || in.cache == nil {
		return
	}
	// Subscribe with since=0 — we don't need backlog replay; only
	// the live stream matters for invalidation.
	subID, ch, _ := in.prod.Subscribe(0)
	defer in.prod.Unsubscribe(subID)

	bustMap := map[events.Type][]string{
		events.TypeFindingCreated:  {"findings:"},
		events.TypeFindingResolved: {"findings:"},
		events.TypeScanCompleted:   {"findings:", "scans:", "resources:"},
		events.TypeScanFailed:      {"scans:"},
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			prefixes, found := bustMap[ev.Type]
			if !found {
				continue
			}
			for _, prefix := range prefixes {
				if n := in.cache.Invalidate(prefix); n > 0 {
					in.logger.Debug("respcache: invalidated on event",
						"event", string(ev.Type), "prefix", prefix, "dropped", n)
				}
			}
		}
	}
}
