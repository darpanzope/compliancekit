package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/darpanzope/compliancekit/internal/config"
	"github.com/darpanzope/compliancekit/internal/engine"
	"github.com/darpanzope/compliancekit/internal/waivers"
)

// applyWaivers is the scan-time hook that loads waivers.yaml (when
// configured), runs WaiverList.Apply against result.Findings, and
// appends the synthesized expired-waiver findings. v0.18+.
//
// No-op when cfg.Waivers.File is empty — running without waivers
// stays the zero-config default. Load errors fail the scan loudly
// (an unparseable waiver file means an operator's expected mute
// won't take effect, and shipping a noisy scan is worse than
// failing fast). Per-entry validation errors get the same treatment
// because individual rejected entries are still load failures.
//
// `now` is wall-clock at scan time. Tests injecting a clock have
// to run runScan via a different entry point; the production path
// uses time.Now().UTC() so expiry classification is stable for the
// duration of the scan.
func applyWaivers(w io.Writer, result *engine.Result, cfg *config.Config) error {
	if cfg.Waivers.File == "" {
		return nil
	}
	now := time.Now().UTC()
	list, errs := waivers.LoadFile(cfg.Waivers.File, now)
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(w, "waivers: %v\n", e)
		}
		return fmt.Errorf("waivers: load failed (%d error(s))", len(errs))
	}

	muted, synth := list.Apply(result.Findings, now)
	result.Findings = append(result.Findings, synth...)

	active, expired, expiring := list.Counts(now)
	fmt.Fprintf(w, "waivers: %d active, %d expired, %d expiring within 30d — muted %d finding(s)\n",
		active, expired, expiring, muted)
	if expired > 0 {
		fmt.Fprintf(w, "waivers: %d expired waiver(s) emitted as info-level `compliancekit-waiver-expired` findings\n", expired)
	}
	return nil
}
