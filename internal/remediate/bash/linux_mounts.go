package bash

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 3 — bash strategies for the 15 filesystem-hardening
// checks (6 separate-partition + 9 mount-option). Separate-partition
// fixes require downtime + repartitioning so the renderer emits a
// guided procedure; mount-option fixes are runtime + fstab edits.

// ----- separate-partition (manual) --------------------------------------

var mountSepBashCheckIDs = []string{
	"linux-mount-tmp-separate",
	"linux-mount-var-separate",
	"linux-mount-var-tmp-separate",
	"linux-mount-var-log-separate",
	"linux-mount-var-log-audit-separate",
	"linux-mount-home-separate",
}

func init() {
	for _, id := range mountSepBashCheckIDs {
		id := id
		register("bash-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			target := mountTargetFromID(id)
			body := fmt.Sprintf(`# Re-partitioning %s requires a maintenance window.
# Sketch of the procedure for an LVM-backed host:
#   1. Boot single-user mode (or rescue if /var is involved).
#   2. lvcreate -L 8G -n %s_lv vg_root
#   3. mkfs.ext4 /dev/vg_root/%s_lv
#   4. Mount the new LV at /mnt/%s, rsync existing data.
#   5. Update /etc/fstab to mount /dev/vg_root/%s_lv at %s with
#      defaults,nodev,nosuid,noexec (where applicable per CIS).
#   6. Reboot + verify mount via 'findmnt %s'.
findmnt %s || echo '%s is NOT a separate mount' >&2`,
				target, mountSlug(target), mountSlug(target), mountSlug(target),
				mountSlug(target), target, target, target, target)
			return remediate.Snippet{
				Risk: remediate.RiskManual, Idempotent: false, Content: body,
				VerifyCmd: fmt.Sprintf("findmnt %s", target),
				Notes:     "Re-partitioning is a planned change. Snapshot first; coordinate with on-call.",
			}, nil
		})
	}
}

// ----- mount-option (runtime + fstab) -----------------------------------

var mountOptBashSpecs = map[string]struct{ target, opt string }{
	"linux-mount-tmp-nodev":      {"/tmp", "nodev"},
	"linux-mount-tmp-nosuid":     {"/tmp", "nosuid"},
	"linux-mount-tmp-noexec":     {"/tmp", "noexec"},
	"linux-mount-home-nodev":     {"/home", "nodev"},
	"linux-mount-home-nosuid":    {"/home", "nosuid"},
	"linux-mount-dev-shm-nodev":  {"/dev/shm", "nodev"},
	"linux-mount-dev-shm-nosuid": {"/dev/shm", "nosuid"},
	"linux-mount-dev-shm-noexec": {"/dev/shm", "noexec"},
	"linux-mount-var-tmp-noexec": {"/var/tmp", "noexec"},
}

func init() {
	for id, s := range mountOptBashSpecs {
		id := id
		s := s
		register("bash-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := fmt.Sprintf(`# Apply at runtime + persist via fstab edit.
# 1. Live remount (no reboot needed):
sudo mount -o remount,%s %s

# 2. Persist across reboot — append %s to the fstab options column:
sudo sed -ri '/[[:space:]]%s[[:space:]]/ s/(defaults[^[:space:]]*)/\1,%s/' /etc/fstab

# 3. Verify:
findmnt %s`, s.opt, s.target, s.opt, escapeRegex(s.target), s.opt, s.target)
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true, Content: body,
				VerifyCmd: fmt.Sprintf("findmnt %s -o OPTIONS | tail -1 | grep -w %s", s.target, s.opt),
				Notes:     "Live remount picks up immediately. Verify fstab edit didn't duplicate the option (idempotent sed handles that).",
			}, nil
		})
	}
}

// mountTargetFromID maps a check ID like "linux-mount-tmp-separate" or
// "linux-mount-var-log-audit-separate" back to its target path. Keeps
// the strategy code parameter-free.
func mountTargetFromID(id string) string {
	switch id {
	case "linux-mount-tmp-separate":
		return "/tmp"
	case "linux-mount-var-separate":
		return "/var"
	case "linux-mount-var-tmp-separate":
		return "/var/tmp"
	case "linux-mount-var-log-separate":
		return "/var/log"
	case "linux-mount-var-log-audit-separate":
		return "/var/log/audit"
	case "linux-mount-home-separate":
		return "/home"
	}
	return "/UNKNOWN"
}

// mountSlug returns a filesystem-safe slug for a mount path, used as
// an LV name in the rendered remediation procedure.
func mountSlug(target string) string {
	out := []byte{}
	for i := 0; i < len(target); i++ {
		c := target[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		case c == '/':
			if len(out) > 0 {
				out = append(out, '_')
			}
		}
	}
	if len(out) == 0 {
		return "root"
	}
	return string(out)
}

// escapeRegex escapes the / characters in a path for safe insertion
// into a sed regex.
func escapeRegex(path string) string {
	out := []byte{}
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			out = append(out, '\\', '/')
			continue
		}
		out = append(out, path[i])
	}
	return string(out)
}
