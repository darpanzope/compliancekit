package k8s

import (
	"context"
	"fmt"
	"strings"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// EKS enrichment checks. EKS resources come from the AWS collector
// (provider="aws") but the checks are registered under the kubernetes
// provider since they enrich the K8s posture picture.

// ----- Public endpoint with open CIDR ---------------------------

var CheckEKSPublicEndpoint = compliancekit.Check{
	ID:           "k8s-eks-public-endpoint-open",
	Title:        "EKS API endpoint should not be publicly reachable without CIDR restriction",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "eks",
	ResourceType: awscol.EKSClusterType,
	Description: "An EKS cluster with `endpointPublicAccess: true` and " +
		"publicAccessCidrs of 0.0.0.0/0 exposes the Kubernetes API " +
		"to the entire internet. The first defense is RBAC, but the " +
		"primary mitigation is to restrict the API endpoint to your " +
		"operator CIDRs or run with private-only access.",
	Remediation: "`aws eks update-cluster-config --name <c> " +
		"--resources-vpc-config endpointPublicAccess=true," +
		"publicAccessCidrs=<your-cidr>`. Better: switch to " +
		"`endpointPrivateAccess=true,endpointPublicAccess=false` and " +
		"reach the API via VPN/bastion.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.5", "13.6"},
	},
	Tags:    []string{"k8s", "eks", "exposure", "critical"},
	Scanner: "eks.PublicEndpoint",
}

func EKSPublicEndpoint(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, c := range g.ByType(awscol.EKSClusterType) {
		pub, _ := c.Attributes["endpoint_public"].(bool)
		cidrs, _ := c.Attributes["public_access_cidrs"].([]string)
		f := compliancekit.Finding{
			CheckID:  CheckEKSPublicEndpoint.ID,
			Severity: CheckEKSPublicEndpoint.Severity,
			Resource: c.Ref(),
			Tags:     CheckEKSPublicEndpoint.Tags,
		}
		switch {
		case !pub:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("eks cluster %q: endpoint private only", c.Name)
		case containsString(cidrs, "0.0.0.0/0"):
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("eks cluster %q: public endpoint open to 0.0.0.0/0", c.Name)
		case len(cidrs) == 0:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("eks cluster %q: public endpoint without publicAccessCidrs", c.Name)
		default:
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("eks cluster %q: public endpoint restricted to %v", c.Name, cidrs)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Private endpoint ------------------------------------------

var CheckEKSPrivateEndpoint = compliancekit.Check{
	ID:           "k8s-eks-private-endpoint",
	Title:        "EKS clusters should enable the private API endpoint",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "eks",
	ResourceType: awscol.EKSClusterType,
	Description: "Enabling `endpointPrivateAccess` puts the API server " +
		"on a VPC endpoint reachable from within the VPC without " +
		"transit through the public internet. Even when public access " +
		"is also enabled, the private endpoint is the preferred path " +
		"for in-cluster controllers (which would otherwise NAT out " +
		"and back in).",
	Remediation: "`aws eks update-cluster-config --name <c> " +
		"--resources-vpc-config endpointPrivateAccess=true`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"12.5"},
	},
	Tags:    []string{"k8s", "eks", "endpoint"},
	Scanner: "eks.PrivateEndpoint",
}

func EKSPrivateEndpoint(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return eksBoolCheck(g, CheckEKSPrivateEndpoint, "endpoint_private",
		"private endpoint enabled", "private endpoint disabled"), nil
}

// ----- Secrets KMS encryption ----------------------------------

var CheckEKSSecretsKMS = compliancekit.Check{
	ID:           "k8s-eks-secrets-encryption",
	Title:        "EKS clusters should encrypt secrets with KMS",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "eks",
	ResourceType: awscol.EKSClusterType,
	Description: "EKS supports envelope encryption of Kubernetes Secrets " +
		"with a customer KMS key. Without it, Secret values rest in " +
		"plaintext in etcd. Enabling encryptionConfig at cluster create " +
		"is the only path; re-encryption of existing clusters requires " +
		"a cluster replacement.",
	Remediation: "At cluster creation: `aws eks create-cluster ... " +
		"--encryption-config resources=secrets,provider={keyArn=<arn>}`. " +
		"For existing clusters, plan a blue/green migration.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.10", "A.8.24"},
		"cis-v8":   {"3.11"},
	},
	Tags:    []string{"k8s", "eks", "encryption", "secrets"},
	Scanner: "eks.SecretsKMS",
}

func EKSSecretsKMS(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return eksBoolCheck(g, CheckEKSSecretsKMS, "has_secrets_kms",
		"secrets KMS encryption enabled", "no secrets KMS encryption"), nil
}

// ----- Control plane logging -----------------------------------

var CheckEKSControlPlaneLogging = compliancekit.Check{
	ID:           "k8s-eks-control-plane-logging",
	Title:        "EKS clusters should enable all control-plane log types",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "eks",
	ResourceType: awscol.EKSClusterType,
	Description: "Control-plane logging ships api / audit / authenticator " +
		"/ controllerManager / scheduler logs to CloudWatch. Without " +
		"audit logs in particular, incident response on a cluster " +
		"compromise is severely limited.",
	Remediation: "`aws eks update-cluster-config --name <c> " +
		"--logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\"," +
		"\"authenticator\",\"controllerManager\",\"scheduler\"]," +
		"\"enabled\":true}]}'`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC4.1", "CC7.2"},
		"iso27001": {"A.8.15", "A.8.16"},
		"cis-v8":   {"8.5", "8.10"},
	},
	Tags:    []string{"k8s", "eks", "logging"},
	Scanner: "eks.ControlPlaneLogging",
}

func EKSControlPlaneLogging(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	required := []string{"api", "audit", "authenticator", "controllerManager", "scheduler"}
	findings := []compliancekit.Finding{}
	for _, c := range g.ByType(awscol.EKSClusterType) {
		enabled, _ := c.Attributes["log_types_enabled"].([]string)
		missing := []string{}
		for _, t := range required {
			if !containsString(enabled, t) {
				missing = append(missing, t)
			}
		}
		f := compliancekit.Finding{
			CheckID:  CheckEKSControlPlaneLogging.ID,
			Severity: CheckEKSControlPlaneLogging.Severity,
			Resource: c.Ref(),
			Tags:     CheckEKSControlPlaneLogging.Tags,
		}
		if len(missing) == 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("eks cluster %q: all 5 control-plane log types enabled", c.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("eks cluster %q: missing log types: %s", c.Name, strings.Join(missing, ", "))
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- OIDC provider (IRSA) -----------------------------------

var CheckEKSIRSA = compliancekit.Check{
	ID:           "k8s-eks-irsa-enabled",
	Title:        "EKS clusters should expose an OIDC provider for IRSA",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "eks",
	ResourceType: awscol.EKSClusterType,
	Description: "IAM Roles for Service Accounts (IRSA) requires the " +
		"EKS cluster to expose an OIDC issuer. Without it, in-cluster " +
		"workloads must use the node's instance profile credentials — " +
		"a much broader privilege grant than per-SA roles.",
	Remediation: "`eksctl utils associate-iam-oidc-provider --cluster " +
		"<name>` (or terraform aws_iam_openid_connect_provider). Then " +
		"annotate SAs with `eks.amazonaws.com/role-arn`.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"6.7"},
	},
	Tags:    []string{"k8s", "eks", "iam", "irsa"},
	Scanner: "eks.IRSA",
}

func EKSIRSA(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	return eksBoolCheck(g, CheckEKSIRSA, "has_oidc",
		"OIDC provider exposed (IRSA available)", "no OIDC provider"), nil
}

// ----- Authentication mode --------------------------------------

var CheckEKSAuthMode = compliancekit.Check{
	ID:           "k8s-eks-authentication-mode",
	Title:        "EKS clusters should use API access entries (not aws-auth ConfigMap)",
	Severity:     compliancekit.SeverityLow,
	Provider:     "kubernetes",
	Service:      "eks",
	ResourceType: awscol.EKSClusterType,
	Description: "The legacy aws-auth ConfigMap is error-prone — one " +
		"typo locks operators out of the cluster. EKS Access Entries " +
		"(GA in 2024) are the API-driven replacement: per-principal " +
		"grants without a YAML round-trip. `authenticationMode: API` " +
		"or `API_AND_CONFIG_MAP` enables them.",
	Remediation: "`aws eks update-cluster-config --name <c> " +
		"--access-config authenticationMode=API_AND_CONFIG_MAP` (with " +
		"migration window) then API once aws-auth is fully migrated.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.3"},
		"iso27001": {"A.5.15", "A.8.2"},
		"cis-v8":   {"6.7"},
	},
	Tags:    []string{"k8s", "eks", "auth"},
	Scanner: "eks.AuthMode",
}

func EKSAuthMode(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, c := range g.ByType(awscol.EKSClusterType) {
		mode, _ := c.Attributes["authentication_mode"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckEKSAuthMode.ID,
			Severity: CheckEKSAuthMode.Severity,
			Resource: c.Ref(),
			Tags:     CheckEKSAuthMode.Tags,
		}
		switch mode {
		case "API", "API_AND_CONFIG_MAP":
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("eks cluster %q: authenticationMode=%s", c.Name, mode)
		default:
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("eks cluster %q: authenticationMode=%s (legacy aws-auth only)", c.Name, mode)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Cluster status --------------------------------------------

var CheckEKSStatus = compliancekit.Check{
	ID:           "k8s-eks-cluster-active",
	Title:        "EKS clusters should be in ACTIVE status",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "eks",
	ResourceType: awscol.EKSClusterType,
	Description: "A cluster in CREATING / UPDATING / DELETING is mid-" +
		"lifecycle; in FAILED state it has a control-plane issue that " +
		"requires AWS support to resolve. ACTIVE is the only steady-" +
		"state.",
	Remediation: "Open an AWS support case if a cluster is stuck in " +
		"FAILED. For long UPDATING runs, check `aws eks describe-update " +
		"...` for the in-flight change.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.1", "CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.11"},
	},
	Tags:    []string{"k8s", "eks", "reliability"},
	Scanner: "eks.Status",
}

func EKSStatus(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, c := range g.ByType(awscol.EKSClusterType) {
		status, _ := c.Attributes["status"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckEKSStatus.ID,
			Severity: CheckEKSStatus.Severity,
			Resource: c.Ref(),
			Tags:     CheckEKSStatus.Tags,
		}
		if status == "ACTIVE" {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("eks cluster %q: ACTIVE", c.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("eks cluster %q: status=%s", c.Name, status)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Nodegroup AMI type ---------------------------------------

var CheckEKSVersion = compliancekit.Check{
	ID:           "k8s-eks-version-supported",
	Title:        "EKS clusters should run a supported K8s version",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "kubernetes",
	Service:      "eks",
	ResourceType: awscol.EKSClusterType,
	Description: "EKS supports each minor version for 14 months. A " +
		"cluster on a deprecated minor will be force-upgraded by AWS, " +
		"often at an inconvenient time. Stay on a current minor (1.28+ " +
		"as of mid-2026).",
	Remediation: "`aws eks update-cluster-version --name <c> " +
		"--kubernetes-version 1.30`. Plan node-group version updates " +
		"after the control plane is upgraded.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1"},
		"iso27001": {"A.8.8"},
		"cis-v8":   {"7.4"},
	},
	Tags:    []string{"k8s", "eks", "upgrade"},
	Scanner: "eks.Version",
}

// Minimum K8s minor we consider current. Pinned at v0.11 release time
// (2026-05). Bump per AWS support window changes.
const eksMinVersion = "1.28"

func EKSVersion(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, c := range g.ByType(awscol.EKSClusterType) {
		v, _ := c.Attributes["version"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckEKSVersion.ID,
			Severity: CheckEKSVersion.Severity,
			Resource: c.Ref(),
			Tags:     CheckEKSVersion.Tags,
		}
		if compareMinor(v, eksMinVersion) >= 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("eks cluster %q: version=%s (min %s)", c.Name, v, eksMinVersion)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("eks cluster %q: version=%s below minimum %s", c.Name, v, eksMinVersion)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- helpers + init -------------------------------------------

func init() {
	compliancekit.Register(CheckEKSPublicEndpoint, EKSPublicEndpoint)
	compliancekit.Register(CheckEKSPrivateEndpoint, EKSPrivateEndpoint)
	compliancekit.Register(CheckEKSSecretsKMS, EKSSecretsKMS)
	compliancekit.Register(CheckEKSControlPlaneLogging, EKSControlPlaneLogging)
	compliancekit.Register(CheckEKSIRSA, EKSIRSA)
	compliancekit.Register(CheckEKSAuthMode, EKSAuthMode)
	compliancekit.Register(CheckEKSStatus, EKSStatus)
	// v0.22 phase 4 — NodeGroup checks moved to eks_nodegroups.go.
	compliancekit.Register(CheckEKSVersion, EKSVersion)
}

func eksBoolCheck(g *compliancekit.ResourceGraph, check compliancekit.Check, attr, passMsg, failMsg string) []compliancekit.Finding {
	findings := []compliancekit.Finding{}
	for _, c := range g.ByType(awscol.EKSClusterType) {
		v, _ := c.Attributes[attr].(bool)
		f := compliancekit.Finding{
			CheckID:  check.ID,
			Severity: check.Severity,
			Resource: c.Ref(),
			Tags:     check.Tags,
		}
		if v {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("eks cluster %q: %s", c.Name, passMsg)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("eks cluster %q: %s", c.Name, failMsg)
		}
		findings = append(findings, f)
	}
	return findings
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// compareMinor compares two semver-ish version strings of the form
// "X.Y" or "X.Y.Z". Returns -1, 0, +1. Ignores Z when present.
func compareMinor(a, b string) int {
	aMaj, aMinor := parseMinor(a)
	bMaj, bMinor := parseMinor(b)
	switch {
	case aMaj < bMaj:
		return -1
	case aMaj > bMaj:
		return 1
	case aMinor < bMinor:
		return -1
	case aMinor > bMinor:
		return 1
	}
	return 0
}

func parseMinor(v string) (major, minor int) {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, 0
	}
	major = atoiSafe(parts[0])
	minor = atoiSafe(parts[1])
	return
}

func atoiSafe(s string) int {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			break
		}
		n = n*10 + int(ch-'0')
	}
	return n
}
