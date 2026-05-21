// Package respcache is the v1.11 phase 6 in-memory LRU for hot
// list responses. Caches `(filter_query, cursor, user_scope) →
// serialized JSON body + ETag` for 60s; the v1.6 SSE event bus
// busts the cache on finding.created / finding.resolved /
// scan.completed events so operators never see stale data after
// a mutation.
//
// Scope: the findings explorer (/api/v1/findings + /findings/rows)
// is the only consumer at v1.11.0 — it's the highest-traffic
// hot path on a busy daemon. /scans + /resources can layer onto
// the same cache shape in a v1.11.x follow-up if their numbers
// justify it.
//
// Per-user keying: cache keys include the session user_id so an
// admin's full-scope filter view doesn't leak to a non-admin
// hitting the same query string. Token callers share an empty-
// scope bucket (their bearer-scope already lives in the cursor's
// filter set + the daemon enforces it server-side).
package respcache

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// DefaultSize caps the cache at 512 distinct (filter, cursor, user)
// keys. Each entry is a JSON body + ETag string; at the median
// 50-row response size (~12 KB) the cache footprint stays under
// 8 MB. The LRU's promote-on-get behavior keeps hot pages resident.
const DefaultSize = 512

// DefaultTTL is the per-entry expiry. Tighter than the v1.6 ring's
// 5-min retention so a finding.created event can't race past a
// stale cache.
const DefaultTTL = 60 * time.Second

// Entry is the cached JSON body + the matching ETag.
type Entry struct {
	Body     []byte
	ETag     string
	StoredAt time.Time
}

// Cache is the LRU + invalidation hook bundle.
type Cache struct {
	lru *lru.Cache[string, Entry]
	ttl time.Duration

	hits   atomic.Uint64
	misses atomic.Uint64

	// invalidatePrefixes is the set of key-prefix matches the
	// SSE-event handler busts on. Mutating events (finding.created /
	// finding.resolved / scan.completed) drop every entry sharing
	// the prefix so callers always see the post-event state.
	mu sync.RWMutex
}

// New constructs a Cache. Pass size=0 to use DefaultSize, ttl=0
// for DefaultTTL.
func New(size int, ttl time.Duration) (*Cache, error) {
	if size <= 0 {
		size = DefaultSize
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	l, err := lru.New[string, Entry](size)
	if err != nil {
		return nil, err
	}
	return &Cache{lru: l, ttl: ttl}, nil
}

// Get returns the cached entry + true when the key is present and
// not expired. Updates hit/miss counters atomically.
func (c *Cache) Get(key string) (Entry, bool) {
	e, ok := c.lru.Get(key)
	if !ok {
		c.misses.Add(1)
		return Entry{}, false
	}
	if time.Since(e.StoredAt) > c.ttl {
		c.lru.Remove(key)
		c.misses.Add(1)
		return Entry{}, false
	}
	c.hits.Add(1)
	return e, true
}

// Set stores (or replaces) an entry under key.
func (c *Cache) Set(key string, body []byte, etag string) {
	c.lru.Add(key, Entry{
		Body:     body,
		ETag:     etag,
		StoredAt: time.Now(),
	})
}

// Invalidate drops every entry whose key starts with prefix. The
// LRU exposes Keys() so we scan + remove matches in one pass.
// O(n) over the cache size; acceptable at DefaultSize=512.
func (c *Cache) Invalidate(prefix string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := c.lru.Keys()
	n := 0
	for _, k := range keys {
		if startsWith(k, prefix) {
			c.lru.Remove(k)
			n++
		}
	}
	return n
}

// Purge drops every entry — the catastrophic-reset path used when
// the daemon restarts under leader-election.
func (c *Cache) Purge() { c.lru.Purge() }

// Stats returns the running hit / miss / size counters. Exposed
// via the daemon's /metrics endpoint + the doctor command.
func (c *Cache) Stats() (hits, misses uint64, size int) {
	return c.hits.Load(), c.misses.Load(), c.lru.Len()
}

// HitRate returns the fraction of Get calls that found a live entry.
// Returns 0 when the cache hasn't been queried yet.
func (c *Cache) HitRate() float64 {
	h, m, _ := c.Stats()
	total := h + m
	if total == 0 {
		return 0
	}
	return float64(h) / float64(total)
}

// KeyFor builds a stable cache key from the components callers
// already have lying around. Hashing keeps the key bounded even
// when the filter set is large.
func KeyFor(endpoint, filterQuery, cursor, userID string) string {
	h := sha256.New()
	h.Write([]byte(endpoint))
	h.Write([]byte{0})
	h.Write([]byte(filterQuery))
	h.Write([]byte{0})
	h.Write([]byte(cursor))
	h.Write([]byte{0})
	h.Write([]byte(userID))
	return endpoint + ":" + hex.EncodeToString(h.Sum(nil)[:16])
}

func startsWith(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}
