package worker

// v1.11 phase 8 — Queue-depth metric + autoscaling worker pool.
//
// Pool.depthSampler runs in its own goroutine and:
//   - measures the queued + running scan count every sampleEvery
//   - publishes the result via the registered DepthObserver
//     (Prometheus gauge in the daemon's metrics path)
//   - decides every checkAutoscaleEvery whether to spawn an extra
//     worker or let the burst pool drain
//
// Autoscale policy:
//   - if median depth > scaleUpDepth for scaleUpWindow → +1 worker
//     (capped at MaxConcurrency)
//   - if median depth < scaleDownDepth for scaleDownWindow → -1
//     worker (floored at the base Concurrency)
//
// Burst workers run for as long as needed; they stop themselves when
// the goroutine receives a stop signal via burstStop.

import (
	"context"
	"sync/atomic"
	"time"
)

const (
	sampleEvery          = 5 * time.Second
	checkAutoscaleEvery  = 30 * time.Second
	scaleUpDepthThresh   = 5
	scaleDownDepthThresh = 1
	scaleUpWindow        = 1 * time.Minute
	scaleDownWindow      = 5 * time.Minute
	defaultMaxBurst      = 4
)

// DepthObserver is the metric sink. The daemon's metricsRegistry
// implements this with a Prometheus gauge; tests pass an in-memory
// recorder.
type DepthObserver interface {
	ObserveQueueDepth(d int)
}

// noopObserver lets the pool stay nil-safe when no observer is wired.
type noopObserver struct{}

func (noopObserver) ObserveQueueDepth(int) {}

// startDepthSampler kicks off the goroutine. Returns immediately;
// the goroutine exits when ctx is canceled.
func (p *Pool) startDepthSampler(ctx context.Context) {
	if p.observer == nil {
		p.observer = noopObserver{}
	}
	maxBurst := p.maxConcurrency - p.concurrency
	if maxBurst < 0 {
		maxBurst = 0
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		sampleTick := time.NewTicker(sampleEvery)
		defer sampleTick.Stop()
		scaleTick := time.NewTicker(checkAutoscaleEvery)
		defer scaleTick.Stop()

		// Rolling depth window — keeps the last (scaleDownWindow /
		// sampleEvery) samples so the two-window decision logic stays
		// O(window/sample). At default sizes that's 60 entries.
		windowSize := int(scaleDownWindow / sampleEvery)
		samples := make([]int, 0, windowSize)

		var burstActive atomic.Int32

		for {
			select {
			case <-ctx.Done():
				return
			case <-sampleTick.C:
				d := p.measureDepth(ctx)
				p.observer.ObserveQueueDepth(d)
				if len(samples) >= windowSize {
					samples = samples[1:]
				}
				samples = append(samples, d)
			case <-scaleTick.C:
				if maxBurst <= 0 || len(samples) < int(scaleUpWindow/sampleEvery) {
					continue
				}
				up := medianLast(samples, int(scaleUpWindow/sampleEvery))
				down := medianLast(samples, len(samples))
				cur := int(burstActive.Load())
				switch {
				case up > scaleUpDepthThresh && cur < maxBurst:
					burstActive.Add(1)
					p.spawnBurstWorker(ctx)
					p.log.Info("worker: autoscale up",
						"burst", cur+1, "max_burst", maxBurst, "median_depth", up)
				case down < scaleDownDepthThresh && cur > 0:
					// Decrement intent; the burst goroutine reads
					// burstActive on each handleJob exit and dies when
					// active drops below it.
					burstActive.Add(-1)
					p.log.Info("worker: autoscale down",
						"burst", cur-1, "median_depth", down)
				}
			}
		}
	}()
}

// measureDepth returns the count of scans currently queued. Includes
// 'running' so the gauge reflects total in-flight work, not just
// backlog. Errors return 0 — the metric prefers under-reporting to
// false-positive autoscale.
func (p *Pool) measureDepth(ctx context.Context) int {
	var n int
	err := p.store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM scans WHERE status IN ('queued', 'running')`).Scan(&n)
	if err != nil {
		return 0
	}
	return n
}

// spawnBurstWorker adds one more consumer goroutine listening on
// the existing jobs channel. The goroutine exits when the channel
// is closed (parent ctx cancel) — autoscale-down doesn't kill the
// goroutine; it just blocks new ones from spawning.
func (p *Pool) spawnBurstWorker(ctx context.Context) {
	if p.burstJobs == nil {
		return
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for j := range p.burstJobs {
			p.handleJob(ctx, j)
		}
	}()
}

// medianLast returns the median of the last n samples. Uses a
// copy-and-sort path; n is small (<=60 at default settings).
func medianLast(s []int, n int) int {
	if n <= 0 || len(s) == 0 {
		return 0
	}
	if n > len(s) {
		n = len(s)
	}
	cp := make([]int, n)
	copy(cp, s[len(s)-n:])
	// Insertion sort — tiny n.
	for i := 1; i < len(cp); i++ {
		for j := i; j > 0 && cp[j-1] > cp[j]; j-- {
			cp[j-1], cp[j] = cp[j], cp[j-1]
		}
	}
	return cp[len(cp)/2]
}
