package bash

import (
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 1 — bash strategy for linux-distro-supported.
// Pre-flight gate that bails out of an SSH hardening script if the
// host runs an unsupported distro.

func init() {
	register("bash-linux-distro-supported",
		[]string{"linux-distro-supported"}, renderDistroSupportedBash)
}

func renderDistroSupportedBash(_ compliancekit.Finding) (remediate.Snippet, error) {
	body := `# Pre-flight gate: refuse to run the hardening script on a distro
# compliancekit doesn't model.
. /etc/os-release
case "${ID:-unknown}" in
  ubuntu|debian|rhel|centos|rocky|almalinux|fedora|alpine|amzn) ;;
  *)
    printf 'unsupported distro: %s (id=%s)\n' "${PRETTY_NAME:-unknown}" "$ID" >&2
    exit 1
    ;;
esac
printf 'distro %s OK\n' "$PRETTY_NAME"`
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: body,
		Notes: "Embed at the top of every hardening script. Distro detection follows the same allowlist as the compliancekit check.",
	}, nil
}
