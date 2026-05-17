package digitalocean

import (
	"context"
	"fmt"
	"time"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

const imageMaxAgeDays = 365

// --- CDN (2) ---

var CheckCDNHasCustomDomain = core.Check{
	ID:           "do-cdn-no-custom-domain",
	Title:        "CDN endpoints should use a custom domain",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "cdn",
	ResourceType: docol.CDNType,
	Description: "A CDN endpoint without a custom domain serves traffic on " +
		"the ondigitaloceanspaces.com subdomain. Production traffic " +
		"should resolve under your domain so DNS-level controls (CAA, " +
		"DNSSEC) apply and the user-visible URL matches your brand.",
	Remediation: "Configure a custom domain via 'doctl compute cdn update " +
		"<id> --custom-domain cdn.example.com --certificate-id <cert-id>' " +
		"and point your DNS at the CDN's endpoint.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"cdn"},
	Scanner: "cdn.CustomDomain",
}

func CDNHasCustomDomain(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, c := range g.ByType(docol.CDNType) {
		has, _ := c.Attributes["has_custom_domain"].(bool)
		f := core.Finding{
			CheckID:  CheckCDNHasCustomDomain.ID,
			Severity: CheckCDNHasCustomDomain.Severity,
			Resource: c.Ref(),
			Tags:     CheckCDNHasCustomDomain.Tags,
		}
		if has {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("cdn %q: custom domain", c.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("cdn %q: no custom domain", c.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckCDNHasCustomCert = core.Check{
	ID:           "do-cdn-no-custom-cert",
	Title:        "CDN endpoints with custom domains should use a custom cert",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "cdn",
	ResourceType: docol.CDNType,
	Description: "A CDN with a custom domain but no attached certificate " +
		"serves the domain over HTTP only or relies on the DO default " +
		"cert which doesn't cover your apex. Pair every custom domain " +
		"with a managed (Let's Encrypt) or uploaded certificate.",
	Remediation: "Create a managed cert via 'doctl compute certificate " +
		"create --type lets_encrypt --domains cdn.example.com'. Update " +
		"the CDN: 'doctl compute cdn update <id> --certificate-id <id>'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.10"},
	},
	Tags:    []string{"cdn", "tls"},
	Scanner: "cdn.CustomCert",
}

func CDNHasCustomCert(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, c := range g.ByType(docol.CDNType) {
		hasDomain, _ := c.Attributes["has_custom_domain"].(bool)
		if !hasDomain {
			continue
		}
		hasCert, _ := c.Attributes["has_custom_cert"].(bool)
		f := core.Finding{
			CheckID:  CheckCDNHasCustomCert.ID,
			Severity: CheckCDNHasCustomCert.Severity,
			Resource: c.Ref(),
			Tags:     CheckCDNHasCustomCert.Tags,
		}
		if hasCert {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("cdn %q: custom cert attached", c.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("cdn %q: custom domain but no cert", c.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// --- Reserved IPs (2) ---

var CheckReservedIPOrphan = core.Check{
	ID:           "do-reserved-ip-orphan",
	Title:        "Reserved IPs should be attached to a droplet",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "reserved_ips",
	ResourceType: docol.ReservedIPType,
	Description: "An unattached reserved IP bills regardless of use. " +
		"Common shape: a droplet was destroyed without releasing its " +
		"reserved IP, and the IP sits forever paying a fee.",
	Remediation: "Either attach to a droplet ('doctl compute reserved-ip " +
		"action assign <ip> <droplet-id>') or release ('doctl compute " +
		"reserved-ip delete <ip>').",
	Frameworks: map[string][]string{
		"soc2":     {"CC9.1"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"reserved-ip", "hygiene", "cost"},
	Scanner: "reservedips.Orphan",
}

func ReservedIPOrphan(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ip := range g.ByType(docol.ReservedIPType) {
		attached, _ := ip.Attributes["attached"].(bool)
		f := core.Finding{
			CheckID:  CheckReservedIPOrphan.ID,
			Severity: CheckReservedIPOrphan.Severity,
			Resource: ip.Ref(),
			Tags:     CheckReservedIPOrphan.Tags,
		}
		if attached {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("ip %q: attached", ip.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("ip %q: orphan (unattached)", ip.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckReservedIPInProject = core.Check{
	ID:           "do-reserved-ip-no-project",
	Title:        "Reserved IPs should be assigned to a project",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "reserved_ips",
	ResourceType: docol.ReservedIPType,
	Description: "Reserved IPs without a project_id sit in the default " +
		"project, making cost attribution + access control awkward.",
	Remediation: "Move the IP to a named project via the DO control panel " +
		"or 'doctl projects resources assign'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC1.4"},
		"iso27001": {"A.5.9"},
		"cis-v8":   {"1.1"},
	},
	Tags:    []string{"reserved-ip", "projects"},
	Scanner: "reservedips.InProject",
}

func ReservedIPInProject(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ip := range g.ByType(docol.ReservedIPType) {
		pid, _ := ip.Attributes["project_id"].(string)
		f := core.Finding{
			CheckID:  CheckReservedIPInProject.ID,
			Severity: CheckReservedIPInProject.Severity,
			Resource: ip.Ref(),
			Tags:     CheckReservedIPInProject.Tags,
		}
		if pid != "" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("ip %q: project=%s", ip.Name, pid)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("ip %q: no project assignment", ip.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// --- SSH keys (2) ---

var CheckSSHKeyAlgorithm = core.Check{
	ID:           "do-ssh-key-weak-algorithm",
	Title:        "Account SSH keys must use strong algorithms",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "ssh_keys",
	ResourceType: docol.SSHKeyType,
	Description: "DSA keys, RSA keys shorter than 3072 bits, or unknown " +
		"algorithms should not exist in the DO account SSH key list. " +
		"Anyone holding the corresponding private key can land on " +
		"every droplet that imports authorized_keys from this account.",
	Remediation: "Generate a new key: 'ssh-keygen -t ed25519'. Add via " +
		"'doctl compute ssh-key import <name> --public-key-file " +
		"~/.ssh/id_ed25519.pub'. Delete the weak key.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.5", "A.8.24"},
		"cis-v8":   {"3.10", "5.4"},
	},
	Tags:    []string{"ssh-keys", "crypto-agility"},
	Scanner: "sshkeys.Algorithm",
}

func SSHKeyAlgorithm(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, k := range g.ByType(docol.SSHKeyType) {
		weak, _ := k.Attributes["is_weak_algo"].(bool)
		algo, _ := k.Attributes["algorithm"].(string)
		f := core.Finding{
			CheckID:  CheckSSHKeyAlgorithm.ID,
			Severity: CheckSSHKeyAlgorithm.Severity,
			Resource: k.Ref(),
			Tags:     CheckSSHKeyAlgorithm.Tags,
		}
		if weak {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("key %q: weak algorithm %q", k.Name, algo)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("key %q: %s", k.Name, algo)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// Maximum number of SSH keys before we flag the account as having
// accumulated too many. 20 is a generous bound; any production
// account with more than 20 keys at the account level (each one
// landing on every droplet) is over-broad.
const sshKeyCountThreshold = 20

var CheckSSHKeyCount = core.Check{
	ID:           "do-ssh-key-too-many",
	Title:        "Account-level SSH key count should be bounded",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "ssh_keys",
	ResourceType: docol.SSHKeyType,
	Description: "DO account-level SSH keys are auto-injected into every " +
		"new droplet's root authorized_keys. The more keys live at " +
		"the account level, the more former-employee or former-laptop " +
		"keys propagate to new droplets. Prune to active humans only; " +
		"prefer per-droplet provisioning for ephemeral access.",
	Remediation: "List + audit: 'doctl compute ssh-key list'. Delete " +
		"obsolete keys with 'doctl compute ssh-key delete <id>'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.16", "A.8.2"},
		"cis-v8":   {"5.3", "6.7"},
	},
	Tags:    []string{"ssh-keys", "credential-hygiene"},
	Scanner: "sshkeys.Count",
}

func SSHKeyCount(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	keys := g.ByType(docol.SSHKeyType)
	// Single finding attached to the account anchor; everyone's
	// view of "too many" is the count, not which specific keys.
	accounts := g.ByType(docol.AccountType)
	if len(accounts) == 0 {
		return nil, nil
	}
	f := core.Finding{
		CheckID:  CheckSSHKeyCount.ID,
		Severity: CheckSSHKeyCount.Severity,
		Resource: accounts[0].Ref(),
		Tags:     CheckSSHKeyCount.Tags,
	}
	if len(keys) > sshKeyCountThreshold {
		f.Status = core.StatusFail
		f.Message = fmt.Sprintf("account has %d SSH keys (> %d threshold)", len(keys), sshKeyCountThreshold)
	} else {
		f.Status = core.StatusPass
		f.Message = fmt.Sprintf("account has %d SSH keys", len(keys))
	}
	return []core.Finding{f}, nil
}

// --- Images (2) ---

var CheckImageNotPublic = core.Check{
	ID:           "do-image-public",
	Title:        "Custom images should not be marked public",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "images",
	ResourceType: docol.ImageType,
	Description: "A custom image (built from your droplet) marked public " +
		"is downloadable by any DO user. Custom images frequently " +
		"embed credentials in /etc, /home, or /root; making one " +
		"public is a leak of those secrets to the entire platform.",
	Remediation: "Set the image private via the DO control panel " +
		"(Images > Snapshots / Custom Images > Settings).",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.3"},
		"cis-v8":   {"3.3"},
	},
	Tags:    []string{"images", "data-exposure"},
	Scanner: "images.NotPublic",
}

func ImageNotPublic(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, img := range g.ByType(docol.ImageType) {
		pub, _ := img.Attributes["public"].(bool)
		f := core.Finding{
			CheckID:  CheckImageNotPublic.ID,
			Severity: CheckImageNotPublic.Severity,
			Resource: img.Ref(),
			Tags:     CheckImageNotPublic.Tags,
		}
		if pub {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("image %q: MARKED PUBLIC", img.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("image %q: private", img.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

var CheckImageAge = core.Check{
	ID:           "do-image-too-old",
	Title:        "Custom images older than 1 year should be reviewed",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "images",
	ResourceType: docol.ImageType,
	Description: "A custom image built more than a year ago is almost " +
		"certainly far behind on patches; restoring it would produce " +
		"a system out of patch compliance immediately.",
	Remediation: "Rebuild the image from a current base, then delete " +
		"the stale one.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1"},
		"iso27001": {"A.8.8"},
		"cis-v8":   {"7.4"},
	},
	Tags:    []string{"images", "patching"},
	Scanner: "images.Age",
}

func ImageAge(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	threshold := time.Now().UTC().Add(-imageMaxAgeDays * 24 * time.Hour)
	for _, img := range g.ByType(docol.ImageType) {
		created, _ := img.Attributes["created_at"].(string)
		f := core.Finding{
			CheckID:  CheckImageAge.ID,
			Severity: CheckImageAge.Severity,
			Resource: img.Ref(),
			Tags:     CheckImageAge.Tags,
		}
		t, err := time.Parse(time.RFC3339, created)
		switch {
		case err != nil:
			f.Status = core.StatusSkip
			f.Message = fmt.Sprintf("image %q: unparsable created_at=%q", img.Name, created)
		case t.Before(threshold):
			days := int(time.Since(t).Hours() / 24)
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("image %q: %d days old", img.Name, days)
		default:
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("image %q: created %s", img.Name, created)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// --- Monitoring (2) ---

var CheckAccountHasAlerts = core.Check{
	ID:           "do-monitoring-no-alerts",
	Title:        "Account should have at least one configured alert policy",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "monitoring",
	ResourceType: docol.AccountType,
	Description: "An account with zero alert policies has no signal " +
		"channel for the standard ops events (high CPU, low disk, " +
		"droplet down). Configure at least the four basics: CPU " +
		"sustained, memory sustained, disk usage, droplet status.",
	Remediation: "Create an alert: 'doctl monitoring alert create " +
		"--type v1/insights/droplet/cpu --description \"high cpu\" " +
		"--compare GreaterThan --value 80 --window 10m --emails " +
		"ops@example.com'.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2", "CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"monitoring", "alerting"},
	Scanner: "monitoring.HasAlerts",
}

func AccountHasAlerts(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	alerts := g.ByType(docol.AlertPolicyType)
	accounts := g.ByType(docol.AccountType)
	if len(accounts) == 0 {
		return nil, nil
	}
	enabled := 0
	for _, a := range alerts {
		if on, _ := a.Attributes["enabled"].(bool); on {
			enabled++
		}
	}
	f := core.Finding{
		CheckID:  CheckAccountHasAlerts.ID,
		Severity: CheckAccountHasAlerts.Severity,
		Resource: accounts[0].Ref(),
		Tags:     CheckAccountHasAlerts.Tags,
	}
	if enabled > 0 {
		f.Status = core.StatusPass
		f.Message = fmt.Sprintf("account has %d enabled alert policies", enabled)
	} else {
		f.Status = core.StatusFail
		f.Message = "account has no enabled alert policies"
	}
	return []core.Finding{f}, nil
}

var CheckAlertEnabled = core.Check{
	ID:           "do-monitoring-disabled-alert",
	Title:        "Configured alert policies should be enabled",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "monitoring",
	ResourceType: docol.AlertPolicyType,
	Description: "A disabled alert policy is dead weight: it shows up in " +
		"the audit trail but never fires. Common cause: a one-off " +
		"silence during incident response that was never re-enabled.",
	Remediation: "Either delete the policy or re-enable it. Avoid the " +
		"long-lived 'disabled' state.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"monitoring", "alerting", "hygiene"},
	Scanner: "monitoring.AlertEnabled",
}

func AlertEnabled(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AlertPolicyType) {
		on, _ := a.Attributes["enabled"].(bool)
		f := core.Finding{
			CheckID:  CheckAlertEnabled.ID,
			Severity: CheckAlertEnabled.Severity,
			Resource: a.Ref(),
			Tags:     CheckAlertEnabled.Tags,
		}
		if on {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("alert %q: enabled", a.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("alert %q: disabled", a.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// --- Projects (2) ---

func init() {
	core.Register(CheckCDNHasCustomDomain, CDNHasCustomDomain)
	core.Register(CheckCDNHasCustomCert, CDNHasCustomCert)
	core.Register(CheckReservedIPOrphan, ReservedIPOrphan)
	core.Register(CheckReservedIPInProject, ReservedIPInProject)
	core.Register(CheckSSHKeyAlgorithm, SSHKeyAlgorithm)
	core.Register(CheckSSHKeyCount, SSHKeyCount)
	core.Register(CheckImageNotPublic, ImageNotPublic)
	core.Register(CheckImageAge, ImageAge)
	core.Register(CheckAccountHasAlerts, AccountHasAlerts)
	core.Register(CheckAlertEnabled, AlertEnabled)
	// v0.22 phase 4 — Project hygiene checks moved to projects_hygiene.go.
}
