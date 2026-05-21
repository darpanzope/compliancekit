package respcache

import (
	"testing"
	"time"
)

func TestCache_BasicGetSet(t *testing.T) {
	c, err := New(0, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.Set("k", []byte("body"), `W/"deadbeef"`)
	got, ok := c.Get("k")
	if !ok {
		t.Fatal("Get returned !ok after Set")
	}
	if string(got.Body) != "body" {
		t.Errorf("Body = %q, want body", got.Body)
	}
	if got.ETag != `W/"deadbeef"` {
		t.Errorf("ETag = %q", got.ETag)
	}
}

func TestCache_Miss(t *testing.T) {
	c, _ := New(0, 0)
	if _, ok := c.Get("missing"); ok {
		t.Error("Get on missing key returned ok")
	}
	_, m, _ := c.Stats()
	if m != 1 {
		t.Errorf("misses = %d, want 1", m)
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	c, _ := New(0, 10*time.Millisecond)
	c.Set("k", []byte("x"), "tag")
	time.Sleep(20 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Error("expired entry should miss")
	}
}

func TestCache_InvalidatePrefix(t *testing.T) {
	c, _ := New(0, 0)
	c.Set("findings:a", []byte("1"), "")
	c.Set("findings:b", []byte("2"), "")
	c.Set("scans:c", []byte("3"), "")
	n := c.Invalidate("findings:")
	if n != 2 {
		t.Errorf("Invalidate dropped %d, want 2", n)
	}
	if _, ok := c.Get("scans:c"); !ok {
		t.Error("scans:c should survive findings: invalidate")
	}
}

func TestCache_LRUEviction(t *testing.T) {
	c, _ := New(2, 0)
	c.Set("a", []byte("1"), "")
	c.Set("b", []byte("2"), "")
	c.Set("c", []byte("3"), "") // evicts a
	if _, ok := c.Get("a"); ok {
		t.Error("a should have been evicted")
	}
	if _, ok := c.Get("b"); !ok {
		t.Error("b should still be cached")
	}
}

func TestCache_HitRate(t *testing.T) {
	c, _ := New(0, 0)
	c.Set("k", []byte("v"), "")
	_, _ = c.Get("k")       // hit
	_, _ = c.Get("k")       // hit
	_, _ = c.Get("missing") // miss
	if hr := c.HitRate(); hr <= 0.5 || hr > 0.8 {
		t.Errorf("HitRate = %v, want ≈2/3", hr)
	}
}

func TestKeyFor_DeterministicAndScoped(t *testing.T) {
	// Same inputs → same key.
	k1 := KeyFor("findings", "severity=high", "abc", "u1")
	k2 := KeyFor("findings", "severity=high", "abc", "u1")
	if k1 != k2 {
		t.Error("KeyFor not deterministic")
	}
	// Per-user scoping: different user_id → different key.
	if KeyFor("findings", "severity=high", "abc", "u1") == KeyFor("findings", "severity=high", "abc", "u2") {
		t.Error("KeyFor leaks across users")
	}
	// Endpoint prefix preserved so Invalidate("findings:") works.
	k := KeyFor("findings", "", "", "u1")
	if k[:9] != "findings:" {
		t.Errorf("key %q missing endpoint prefix", k)
	}
}
