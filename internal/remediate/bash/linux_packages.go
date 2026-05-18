package bash

import (
	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// v0.20 phase 9 — bash strategies for the 10 packages/MAC checks.

func init() {
	register("bash-linux-mac-selinux-enforcing",
		[]string{"linux-mac-selinux-enforcing"},
		func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := `# Live + persistent.
sudo setenforce 1
sudo sed -ri 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config`
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true, Content: body,
				VerifyCmd: "getenforce",
			}, nil
		})

	register("bash-linux-mac-apparmor-active",
		[]string{"linux-mac-apparmor-active"},
		func(_ compliancekit.Finding) (remediate.Snippet, error) {
			body := `sudo apt-get install -y apparmor apparmor-utils
sudo systemctl enable --now apparmor
# Enforce every shipped profile:
sudo aa-enforce /etc/apparmor.d/*`
			return remediate.Snippet{
				Risk: remediate.RiskReview, Idempotent: true, Content: body,
				VerifyCmd: "sudo aa-status",
			}, nil
		})

	manualPackagesHints := map[string]string{
		"linux-pkg-gpg-keys-trusted-only":          "apt-key list 2>/dev/null || dnf repolist --enablerepo='*'",
		"linux-pkg-no-unattended-upgrades":         "systemctl is-active unattended-upgrades 2>/dev/null || systemctl is-active dnf-automatic.timer 2>/dev/null",
		"linux-pkg-aide-installed":                 "which aide && systemctl is-active aidecheck.timer",
		"linux-pkg-no-orphaned-packages":           "apt-get autoremove --dry-run 2>/dev/null || dnf autoremove --assumeno 2>/dev/null",
		"linux-pkg-prelink-absent":                 "dpkg -l prelink 2>/dev/null || rpm -q prelink 2>/dev/null",
		"linux-mac-selinux-no-permissive-services": "sudo semanage permissive -l 2>/dev/null",
		"linux-mac-apparmor-no-complain-mode":      "sudo aa-status 2>/dev/null | grep -A 100 'profiles are in complain mode'",
		"linux-pkg-cron-restricted-to-root":        "ls -la /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null",
	}
	for id, hint := range manualPackagesHints {
		id := id
		hint := hint
		register("bash-"+id, []string{id}, func(_ compliancekit.Finding) (remediate.Snippet, error) {
			return remediate.Snippet{
				Risk: remediate.RiskManual, Idempotent: false,
				Content: "# Manual-verify — inspect + record evidence in waivers.yaml.\n" + hint + "\n",
			}, nil
		})
	}
}
