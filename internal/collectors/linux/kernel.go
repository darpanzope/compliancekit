package linux

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// sysctlCommand reads every kernel parameter checks currently
// consult. Keeping them in one round-trip is much cheaper than
// spawning one ssh session per sysctl.
const sysctlCommand = `sysctl -n -e kernel.randomize_va_space net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.send_redirects 2>/dev/null`

// gatherKernel returns a sub-map of sysctl values:
//
//	"randomize_va_space"        int  (kernel.randomize_va_space)
//	"accept_source_route_all"   int  (net.ipv4.conf.all.accept_source_route)
//	"send_redirects_all"        int  (net.ipv4.conf.all.send_redirects)
//
// Missing keys mean the sysctl was unavailable (kernel build option
// or permission); checks Skip in that case.
func gatherKernel(ctx context.Context, client *ssh.Client) (map[string]any, error) {
	output, _, err := RunCommand(ctx, client, sysctlCommand)
	if err != nil {
		return nil, fmt.Errorf("sysctl probe: %w", err)
	}
	values := parseSysctlNValues(output)

	out := map[string]any{}
	if v, ok := values[0]; ok {
		out["randomize_va_space"] = v
	}
	if v, ok := values[1]; ok {
		out["accept_source_route_all"] = v
	}
	if v, ok := values[2]; ok {
		out["send_redirects_all"] = v
	}
	return out, nil
}

// parseSysctlNValues parses the output of `sysctl -n` which is one
// value per line in argument order. Non-integer lines are skipped so
// we don't blow up if a key is unavailable and the kernel emits an
// empty / non-numeric stand-in.
//
// Returns a map of position -> value so callers can correlate by
// position with their request order (the only stable contract).
func parseSysctlNValues(output string) map[int]int {
	out := map[int]int{}
	for i, raw := range strings.Split(strings.TrimSpace(output), "\n") {
		v, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		out[i] = v
	}
	return out
}
