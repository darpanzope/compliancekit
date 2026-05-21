package worker

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestMedianLast(t *testing.T) {
	cases := []struct {
		name string
		s    []int
		n    int
		want int
	}{
		{"empty", []int{}, 5, 0},
		{"zero_n", []int{1, 2, 3}, 0, 0},
		{"single", []int{7}, 5, 7},
		{"odd", []int{1, 3, 2, 5, 4}, 5, 3},
		{"even_takes_upper_mid", []int{1, 2, 3, 4}, 4, 3},
		{"window_clamped", []int{10, 20, 30, 1, 2, 3}, 3, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := medianLast(c.s, c.n); got != c.want {
				t.Errorf("medianLast(%v, %d) = %d, want %d", c.s, c.n, got, c.want)
			}
		})
	}
}

// recordObserver implements DepthObserver for tests.
type recordObserver struct{ calls atomic.Int32 }

func (r *recordObserver) ObserveQueueDepth(int) { r.calls.Add(1) }

// TestDepthObserver_NoopWhenNil confirms the noop path doesn't
// crash when the daemon wires nil.
func TestDepthObserver_NoopWhenNil(t *testing.T) {
	o := noopObserver{}
	o.ObserveQueueDepth(42) // must not panic
}

// TestDepthObserver_RecordsCalls verifies a test observer accumulates
// invocations the autoscale loop would emit.
func TestDepthObserver_RecordsCalls(t *testing.T) {
	o := &recordObserver{}
	o.ObserveQueueDepth(1)
	o.ObserveQueueDepth(2)
	if got := o.calls.Load(); got != 2 {
		t.Errorf("calls = %d, want 2", got)
	}
}

// TestStartDepthSampler_ExitsOnCancel ensures the goroutine
// lifecycle is bound to ctx. We construct a Pool with no DB +
// canceled ctx; startDepthSampler should return immediately
// without trying to query a nil DB.
func TestStartDepthSampler_ExitsOnCancel(t *testing.T) {
	p := &Pool{
		observer:       &recordObserver{},
		concurrency:    1,
		maxConcurrency: 1, // burst disabled
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel
	done := make(chan struct{})
	go func() {
		p.startDepthSampler(ctx)
		// wait briefly for any sampler goroutines to exit
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("startDepthSampler did not exit within 2s of ctx cancel")
	}
}
