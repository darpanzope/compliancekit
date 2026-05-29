package search

import (
	"context"
	"time"
)

// Indexer keeps an Index fresh: an initial build at Start, then a
// rebuild every tickEvery, plus on-demand rebuilds coalesced through a
// trigger channel (so a burst of SSE events causes at most one rebuild
// per debounce window). v1.19 phase 5.
type Indexer struct {
	idx      *Index
	tick     time.Duration
	debounce time.Duration
	trigger  chan struct{}
}

// NewIndexer wires an Indexer over idx. tickEvery <= 0 falls back to
// 60s (the v1.19 plumbing contract).
func NewIndexer(idx *Index, tickEvery time.Duration) *Indexer {
	if tickEvery <= 0 {
		tickEvery = 60 * time.Second
	}
	return &Indexer{
		idx:      idx,
		tick:     tickEvery,
		debounce: 2 * time.Second,
		trigger:  make(chan struct{}, 1),
	}
}

// Trigger requests an out-of-band rebuild (e.g. from a finding.created
// SSE event). Non-blocking + coalescing — extra triggers while one is
// pending are dropped.
func (ix *Indexer) Trigger() {
	select {
	case ix.trigger <- struct{}{}:
	default:
	}
}

// Run builds the index once, then keeps it fresh until ctx is done.
// Blocks — run it in a goroutine.
func (ix *Indexer) Run(ctx context.Context) {
	_ = ix.idx.Rebuild(ctx)
	ticker := time.NewTicker(ix.tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = ix.idx.Rebuild(ctx)
		case <-ix.trigger:
			// Debounce: wait out a short window so a burst of events
			// collapses into one rebuild.
			select {
			case <-ctx.Done():
				return
			case <-time.After(ix.debounce):
			}
			// Drain any trigger that arrived during the debounce.
			select {
			case <-ix.trigger:
			default:
			}
			_ = ix.idx.Rebuild(ctx)
		}
	}
}
