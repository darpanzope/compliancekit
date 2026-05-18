package gcp

import (
	"context"
	"fmt"
	"strings"

	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// CheckNoDefaultNetwork forbids the auto-mode default VPC network.
// CIS GCP Foundations 3.1 prescribes against it.
var CheckNoDefaultNetwork = compliancekit.Check{
	ID:           "gcp-compute-no-default-network",
	Title:        "GCP projects must not use the auto-mode default VPC network",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "gcp",
	Service:      "compute",
	ResourceType: gcpcol.ComputeNetworkType,
	Description: "GCP's auto-mode default VPC creates a subnet in every " +
		"region with predefined firewall rules (allow-ssh, allow-rdp, " +
		"allow-internal). For production workloads this is too permissive; " +
		"a purpose-built custom-mode VPC with explicit subnet and firewall " +
		"design is the right shape. CIS GCP Foundations 3.1.",
	Remediation: "Migrate workloads to a custom-mode VPC: 'gcloud compute " +
		"networks create my-vpc --subnet-mode=custom'. Then delete the " +
		"default network: 'gcloud compute networks delete default'. The " +
		"delete fails if anything still uses it.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.4", "12.2"},
	},
	Tags:    []string{"compute", "network"},
	Scanner: "compute.NoDefaultNetwork",
}

func NoDefaultNetwork(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, n := range g.ByType(gcpcol.ComputeNetworkType) {
		isDefault, _ := n.Attributes["is_default"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckNoDefaultNetwork.ID,
			Severity: CheckNoDefaultNetwork.Severity,
			Resource: n.Ref(),
			Tags:     CheckNoDefaultNetwork.Tags,
		}
		if !isDefault {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("network %q: not the default VPC", n.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("network %q: auto-mode default VPC exists", n.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckNoSSHFromAny forbids ingress firewall rules permitting tcp:22
// from 0.0.0.0/0. CIS GCP 3.6.
var CheckNoSSHFromAny = compliancekit.Check{
	ID:           "gcp-compute-no-ssh-from-any",
	Title:        "Firewall rules must not allow SSH (tcp:22) from 0.0.0.0/0",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "gcp",
	Service:      "compute",
	ResourceType: gcpcol.ComputeFirewallType,
	Description: "SSH (tcp:22) exposed to 0.0.0.0/0 is the canonical brute-" +
		"force attack target. CIS GCP Foundations 3.6 prescribes scoping " +
		"SSH ingress to a known CIDR (office IP, VPN, IAP tunnel range). " +
		"Identity-Aware Proxy (IAP) tunnel is the GCP-native preferred " +
		"path for SSH access without exposing port 22 at all.",
	Remediation: "Narrow the source CIDR: 'gcloud compute firewall-rules " +
		"update <rule> --source-ranges=<your-cidr>'. For zero exposed-port " +
		"access set up IAP tunneling: " +
		"https://cloud.google.com/iap/docs/using-tcp-forwarding .",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.21"},
		"cis-v8":   {"4.4", "12.2"},
	},
	Tags:    []string{"compute", "firewall", "ssh", "exposure"},
	Scanner: "compute.NoSSHFromAny",
}

func NoSSHFromAny(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, fw := range g.ByType(gcpcol.ComputeFirewallType) {
		direction, _ := fw.Attributes["direction"].(string)
		disabled, _ := fw.Attributes["disabled"].(bool)
		openToAny, _ := fw.Attributes["open_to_any"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckNoSSHFromAny.ID,
			Severity: CheckNoSSHFromAny.Severity,
			Resource: fw.Ref(),
			Tags:     CheckNoSSHFromAny.Tags,
		}
		// Only ingress rules with 0.0.0.0/0 sources can violate.
		if disabled || direction != "INGRESS" || !openToAny {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("firewall %q: no SSH-from-any ingress", fw.Name)
			findings = append(findings, f)
			continue
		}
		// Inspect allowed protocol/port pairs for tcp:22 (or all-tcp).
		allowed, _ := fw.Attributes["allowed"].([]map[string]any)
		if firewallAllowsSSH(allowed) {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("firewall %q: tcp:22 ingress from 0.0.0.0/0", fw.Name)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("firewall %q: 0.0.0.0/0 ingress but not on tcp:22", fw.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func firewallAllowsSSH(allowed []map[string]any) bool {
	for _, rule := range allowed {
		proto, _ := rule["protocol"].(string)
		if proto != "tcp" && proto != "all" {
			continue
		}
		ports, _ := rule["ports"].([]string)
		if len(ports) == 0 {
			// Empty ports means all ports for this protocol.
			return true
		}
		for _, p := range ports {
			if portCovers22(p) {
				return true
			}
		}
	}
	return false
}

// portCovers22 reports whether p is "22" or a range like "20-30"
// that includes 22.
func portCovers22(p string) bool {
	if p == "22" {
		return true
	}
	if !strings.Contains(p, "-") {
		return false
	}
	parts := strings.SplitN(p, "-", 2)
	if len(parts) != 2 {
		return false
	}
	var lo, hi int
	_, err := fmt.Sscanf(parts[0]+" "+parts[1], "%d %d", &lo, &hi)
	if err != nil {
		return false
	}
	return lo <= 22 && hi >= 22
}

// CheckOSLoginEnabled requires OS Login at the project metadata
// level. CIS GCP 4.4.
var CheckOSLoginEnabled = compliancekit.Check{
	ID:           "gcp-compute-os-login-enabled",
	Title:        "OS Login must be enabled at project level",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "gcp",
	Service:      "compute",
	ResourceType: gcpcol.ComputeProjectType,
	Description: "OS Login replaces SSH key management with IAM: an operator " +
		"with the required IAM role gets short-lived SSH credentials, and " +
		"revoking access is a single IAM unbind rather than chasing " +
		"per-instance authorized_keys files. CIS GCP Foundations 4.4 " +
		"prescribes enabling OS Login at the project metadata level so all " +
		"new instances inherit it.",
	Remediation: "'gcloud compute project-info add-metadata " +
		"--metadata enable-oslogin=TRUE'. Then grant " +
		"roles/compute.osLogin (or osAdminLogin) to the principals who " +
		"should be able to SSH in.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.2", "A.8.5"},
		"cis-v8":   {"5.4", "6.5"},
	},
	Tags:    []string{"compute", "ssh", "iam"},
	Scanner: "compute.OSLoginEnabled",
}

func OSLoginEnabled(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, p := range g.ByType(gcpcol.ComputeProjectType) {
		enabled, _ := p.Attributes["os_login_enabled"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckOSLoginEnabled.ID,
			Severity: CheckOSLoginEnabled.Severity,
			Resource: p.Ref(),
			Tags:     CheckOSLoginEnabled.Tags,
		}
		if enabled {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("project %q: OS Login enabled", p.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("project %q: OS Login not enabled", p.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckShieldedVM requires every running instance to have shielded
// VM enabled (all three: secure boot, vTPM, integrity monitoring).
// CIS GCP 4.8.
var CheckShieldedVM = compliancekit.Check{
	ID:           "gcp-compute-shielded-vm",
	Title:        "GCE instances must have Shielded VM fully enabled",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "gcp",
	Service:      "compute",
	ResourceType: gcpcol.ComputeInstanceType,
	Description: "Shielded VM uses a hardened firmware (UEFI), Secure Boot " +
		"(only Google-signed bootloaders), vTPM (virtual trusted platform " +
		"module), and integrity monitoring (boot-time checks against a " +
		"trusted baseline) to defend the boot chain. Without it, a " +
		"rootkit-level compromise is much harder to detect. CIS GCP 4.8 " +
		"prescribes all three options on.",
	Remediation: "Shielded VM settings are set at instance create time; " +
		"recreate the instance with all three options enabled. For " +
		"existing instances, the simpler path is 'gcloud compute instances " +
		"stop <name>' then 'gcloud compute instances update <name> " +
		"--shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring' " +
		"then start it back up.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6", "CC7.1"},
		"iso27001": {"A.8.7", "A.8.8"},
		"cis-v8":   {"3.10", "4.1"},
	},
	Tags:    []string{"compute", "shielded-vm", "boot-integrity"},
	Scanner: "compute.ShieldedVM",
}

func ShieldedVM(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, inst := range g.ByType(gcpcol.ComputeInstanceType) {
		status, _ := inst.Attributes["status"].(string)
		if status != "RUNNING" {
			// Stopped instances can have settings updated; skip until
			// they're actually running.
			continue
		}
		sb, _ := inst.Attributes["shielded_secure_boot"].(bool)
		vtpm, _ := inst.Attributes["shielded_vtpm"].(bool)
		im, _ := inst.Attributes["shielded_integrity_monitoring"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckShieldedVM.ID,
			Severity: CheckShieldedVM.Severity,
			Resource: inst.Ref(),
			Tags:     CheckShieldedVM.Tags,
		}
		missing := []string{}
		if !sb {
			missing = append(missing, "secure_boot")
		}
		if !vtpm {
			missing = append(missing, "vtpm")
		}
		if !im {
			missing = append(missing, "integrity_monitoring")
		}
		if len(missing) == 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("instance %q: shielded VM fully enabled", inst.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("instance %q: shielded VM partial -- missing %s",
				inst.Name, strings.Join(missing, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckNoBroadScopes forbids instances running with auto-attached
// service accounts that have the cloud-platform scope (full access).
// CIS GCP 4.1 + 4.2.
var CheckNoBroadScopes = compliancekit.Check{
	ID:           "gcp-compute-no-broad-scopes",
	Title:        "GCE instances must not run with cloud-platform service-account scope",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "gcp",
	Service:      "compute",
	ResourceType: gcpcol.ComputeInstanceType,
	Description: "The cloud-platform OAuth scope grants the attached " +
		"service account access to every GCP API the SA has IAM " +
		"permissions for. Combined with the default Compute Engine SA " +
		"(which has roles/editor by default), this gives any process on " +
		"the instance project-wide write access. CIS GCP 4.1 + 4.2 " +
		"prescribe narrower scopes (specific service-level scopes) or " +
		"IAM-only access control with no scopes.",
	Remediation: "Stop the instance, change its scopes to specific service " +
		"scopes only (e.g. logging-write, monitoring-write): 'gcloud " +
		"compute instances set-service-account <name> --scopes=logging-" +
		"write,monitoring-write,storage-ro'. Better: rely on IAM " +
		"permissions and remove the cloud-platform scope.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"5.4", "6.7"},
	},
	Tags:    []string{"compute", "service-account", "least-privilege"},
	Scanner: "compute.NoBroadScopes",
}

const cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

func NoBroadScopes(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, inst := range g.ByType(gcpcol.ComputeInstanceType) {
		sas, _ := inst.Attributes["service_accounts"].([]map[string]any)
		offenders := []string{}
		for _, sa := range sas {
			scopes, _ := sa["scopes"].([]string)
			email, _ := sa["email"].(string)
			for _, scope := range scopes {
				if scope == cloudPlatformScope {
					offenders = append(offenders, email)
					break
				}
			}
		}
		f := compliancekit.Finding{
			CheckID:  CheckNoBroadScopes.ID,
			Severity: CheckNoBroadScopes.Severity,
			Resource: inst.Ref(),
			Tags:     CheckNoBroadScopes.Tags,
		}
		if len(offenders) == 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("instance %q: no SA with cloud-platform scope", inst.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("instance %q: SAs with cloud-platform scope: %s",
				inst.Name, strings.Join(offenders, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckNoDefaultNetwork, NoDefaultNetwork)
	compliancekit.Register(CheckNoSSHFromAny, NoSSHFromAny)
	compliancekit.Register(CheckOSLoginEnabled, OSLoginEnabled)
	compliancekit.Register(CheckShieldedVM, ShieldedVM)
	compliancekit.Register(CheckNoBroadScopes, NoBroadScopes)
}
