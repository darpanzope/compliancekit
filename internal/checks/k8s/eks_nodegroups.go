package k8s

import (
	"context"
	"fmt"
	"strings"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/internal/core"
)

// v0.22 phase 4 — EKS NodeGroup checks split out of eks.go.

var CheckEKSNGAmiType = core.Check{
	ID:           "k8s-eks-nodegroup-bottlerocket",
	Title:        "EKS node groups should use Bottlerocket or AL2023",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "eks",
	ResourceType: awscol.EKSNodegroupType,
	Description: "Bottlerocket is purpose-built for K8s nodes — minimal " +
		"attack surface, immutable rootfs, kubelet pre-configured. " +
		"AL2023 is the modern Amazon Linux. AL2 is EOL on the EKS " +
		"roadmap; Windows AMIs have their own audit considerations.",
	Remediation: "Set `amiType: BOTTLEROCKET_x86_64` (or " +
		"`BOTTLEROCKET_ARM_64`) on new node groups. Migrate existing " +
		"AL2 node groups via blue/green replacement.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.8"},
		"iso27001": {"A.8.8", "A.8.9"},
		"cis-v8":   {"4.1", "4.7"},
	},
	Tags:    []string{"k8s", "eks", "nodegroup", "ami"},
	Scanner: "eks.NGAmiType",
}

func EKSNGAmiType(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ng := range g.ByType(awscol.EKSNodegroupType) {
		ami, _ := ng.Attributes["ami_type"].(string)
		f := core.Finding{
			CheckID:  CheckEKSNGAmiType.ID,
			Severity: CheckEKSNGAmiType.Severity,
			Resource: ng.Ref(),
			Tags:     CheckEKSNGAmiType.Tags,
		}
		if strings.HasPrefix(ami, "BOTTLEROCKET_") || strings.HasPrefix(ami, "AL2023_") {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("nodegroup %q: amiType=%s", ng.Name, ami)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("nodegroup %q: amiType=%s (consider Bottlerocket or AL2023)", ng.Name, ami)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Nodegroup remote SSH access ------------------------------

var CheckEKSNGSSH = core.Check{
	ID:           "k8s-eks-nodegroup-ssh",
	Title:        "EKS node groups should not enable SSH remote access",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "eks",
	ResourceType: awscol.EKSNodegroupType,
	Description: "SSH into a node bypasses every K8s control: kubelet " +
		"credentials, network policy, RBAC. The modern operational " +
		"replacement is SSM Session Manager, which provides per-session " +
		"auth + audit. Disable EC2-key-based SSH on node groups.",
	Remediation: "Recreate the node group without `remoteAccess.ec2SshKey`. " +
		"For break-glass node access, use SSM Session Manager with " +
		"per-engineer IAM grants.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.2", "A.8.20"},
		"cis-v8":   {"4.1", "12.5"},
	},
	Tags:    []string{"k8s", "eks", "nodegroup", "ssh"},
	Scanner: "eks.NGSSH",
}

func EKSNGSSH(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ng := range g.ByType(awscol.EKSNodegroupType) {
		ssh, _ := ng.Attributes["remote_access_ssh"].(bool)
		f := core.Finding{
			CheckID:  CheckEKSNGSSH.ID,
			Severity: CheckEKSNGSSH.Severity,
			Resource: ng.Ref(),
			Tags:     CheckEKSNGSSH.Tags,
		}
		if ssh {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("nodegroup %q: SSH remote access key configured", ng.Name)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("nodegroup %q: no SSH key", ng.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Nodegroup version skew -----------------------------------

var CheckEKSNGVersion = core.Check{
	ID:           "k8s-eks-nodegroup-version-skew",
	Title:        "EKS node group version should match the cluster version",
	Severity:     core.SeverityMedium,
	Provider:     "kubernetes",
	Service:      "eks",
	ResourceType: awscol.EKSNodegroupType,
	Description: "K8s supports kubelet versions up to 3 minor releases " +
		"behind the API server (post-1.28) — but the operational sweet " +
		"spot is to keep node groups aligned. A persistent skew " +
		"indicates a stalled upgrade.",
	Remediation: "`aws eks update-nodegroup-version --cluster-name <c> " +
		"--nodegroup-name <ng>`. For managed node groups, this triggers " +
		"a rolling replacement.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.1", "CC8.1"},
		"iso27001": {"A.8.8"},
		"cis-v8":   {"7.4"},
	},
	Tags:    []string{"k8s", "eks", "nodegroup", "upgrade"},
	Scanner: "eks.NGVersion",
}

func EKSNGVersion(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	clusters := map[string]string{}
	for _, c := range g.ByType(awscol.EKSClusterType) {
		v, _ := c.Attributes["version"].(string)
		clusters[c.Name] = v
	}
	findings := []core.Finding{}
	for _, ng := range g.ByType(awscol.EKSNodegroupType) {
		clusterName, _ := ng.Attributes["cluster_name"].(string)
		ngVer, _ := ng.Attributes["version"].(string)
		clusterVer := clusters[clusterName]
		f := core.Finding{
			CheckID:  CheckEKSNGVersion.ID,
			Severity: CheckEKSNGVersion.Severity,
			Resource: ng.Ref(),
			Tags:     CheckEKSNGVersion.Tags,
		}
		if clusterVer == "" || ngVer == clusterVer {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("nodegroup %q: version=%s (cluster %s)", ng.Name, ngVer, clusterVer)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("nodegroup %q: version=%s vs cluster %s", ng.Name, ngVer, clusterVer)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Nodegroup launch template ---------------------------------

var CheckEKSNGLaunchTemplate = core.Check{
	ID:           "k8s-eks-nodegroup-launch-template",
	Title:        "EKS node groups should use a launch template",
	Severity:     core.SeverityLow,
	Provider:     "kubernetes",
	Service:      "eks",
	ResourceType: awscol.EKSNodegroupType,
	Description: "Without a launch template, EKS provisions instances " +
		"with default IMDS config (hop limit 2, allowing pods to reach " +
		"the metadata service and acquire the node role's credentials). " +
		"A custom launch template lets you set `httpPutResponseHopLimit: " +
		"1` plus user-data hardening.",
	Remediation: "Create an EC2 launch template with " +
		"`metadataOptions.httpPutResponseHopLimit: 1` and " +
		"`httpTokens: required`. Reference it in the nodegroup spec.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1"},
		"iso27001": {"A.8.2", "A.8.9"},
		"cis-v8":   {"4.1"},
	},
	Tags:    []string{"k8s", "eks", "nodegroup", "imds"},
	Scanner: "eks.NGLaunchTemplate",
}

func EKSNGLaunchTemplate(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, ng := range g.ByType(awscol.EKSNodegroupType) {
		hasLT, _ := ng.Attributes["has_launch_template"].(bool)
		f := core.Finding{
			CheckID:  CheckEKSNGLaunchTemplate.ID,
			Severity: CheckEKSNGLaunchTemplate.Severity,
			Resource: ng.Ref(),
			Tags:     CheckEKSNGLaunchTemplate.Tags,
		}
		if hasLT {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("nodegroup %q: launch template attached", ng.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("nodegroup %q: no launch template (IMDS hop limit defaults to 2)", ng.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ----- Cluster version supported --------------------------------

func init() {
	core.Register(CheckEKSNGAmiType, EKSNGAmiType)
	core.Register(CheckEKSNGSSH, EKSNGSSH)
	core.Register(CheckEKSNGVersion, EKSNGVersion)
	core.Register(CheckEKSNGLaunchTemplate, EKSNGLaunchTemplate)
}
