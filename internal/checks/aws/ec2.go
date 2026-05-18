package aws

import (
	"context"
	"fmt"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// ========================================================================
// EC2 checks
// ========================================================================

// CheckEC2SGNoIngressFromAny forbids security groups with 0.0.0.0/0
// (or ::/0) ingress except on the explicit "public ports" 80, 443.
// SG ingress from the world on anything else is the textbook AWS
// breach vector. CIS AWS Foundations 5.2 / 5.3.
var CheckEC2SGNoIngressFromAny = compliancekit.Check{
	ID:           "aws-ec2-sg-no-ingress-from-any",
	Title:        "EC2 security groups must not allow ingress from 0.0.0.0/0 except on 80/443",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "aws",
	Service:      "ec2",
	ResourceType: awscol.EC2SGType,
	Description: "Security groups with 0.0.0.0/0 (or ::/0) ingress expose " +
		"every port they cover to the entire internet. SSH (22), RDP (3389), " +
		"and database ports are the high-leverage attacker targets; only " +
		"HTTP (80) and HTTPS (443) have any business being open to all. " +
		"CIS AWS Foundations 5.2 (ingress from any to administrative ports) " +
		"and 5.3 (default SGs allow all egress).",
	Remediation: "Narrow the source CIDR to the actual caller: " +
		"'aws ec2 revoke-security-group-ingress --group-id <id> --protocol tcp " +
		"--port 22 --cidr 0.0.0.0/0' then re-authorize with the office or " +
		"VPN CIDR. For long-running access prefer SSM Session Manager over " +
		"open-port SSH.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20", "A.8.21"},
		"cis-v8":   {"4.4", "12.2"},
	},
	Tags:    []string{"ec2", "network", "exposure"},
	Scanner: "ec2.SGNoIngressFromAny",
}

func EC2SGNoIngressFromAny(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, sg := range g.ByType(awscol.EC2SGType) {
		v4, _ := sg.Attributes["open_to_any_v4"].(bool)
		v6, _ := sg.Attributes["open_to_any_v6"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckEC2SGNoIngressFromAny.ID,
			Severity: CheckEC2SGNoIngressFromAny.Severity,
			Resource: sg.Ref(),
			Tags:     CheckEC2SGNoIngressFromAny.Tags,
		}
		if !v4 && !v6 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("security group %q: no ingress from 0.0.0.0/0 or ::/0", sg.Name)
			findings = append(findings, f)
			continue
		}
		// At least one open rule; check whether it's an allowed "public"
		// port (HTTP 80, HTTPS 443) on tcp.
		ingress, _ := sg.Attributes["ingress_rules"].([]map[string]any)
		nonPublic := nonPublicOpenIngressPorts(ingress)
		if len(nonPublic) == 0 {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("security group %q: open ingress only on 80/443 (allowed)", sg.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("security group %q: open ingress on non-public ports: %v", sg.Name, nonPublic)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func nonPublicOpenIngressPorts(ingress []map[string]any) []int {
	out := []int{}
	publicPorts := map[int]bool{80: true, 443: true}
	for _, rule := range ingress {
		proto, _ := rule["protocol"].(string)
		if proto != "tcp" && proto != "-1" {
			continue
		}
		v4, _ := rule["ipv4_cidrs"].([]string)
		v6, _ := rule["ipv6_cidrs"].([]string)
		openV4 := false
		for _, c := range v4 {
			if c == "0.0.0.0/0" {
				openV4 = true
				break
			}
		}
		openV6 := false
		for _, c := range v6 {
			if c == "::/0" {
				openV6 = true
				break
			}
		}
		if !openV4 && !openV6 {
			continue
		}
		from, _ := rule["from_port"].(int)
		to, _ := rule["to_port"].(int)
		// "All TCP" or wide ranges count as non-public.
		if proto == "-1" || from == 0 || (to-from) > 1 {
			out = append(out, from)
			continue
		}
		if !publicPorts[from] {
			out = append(out, from)
		}
	}
	return out
}

// CheckEC2NoDefaultVPCInUse flags any EC2 instance running in the
// default VPC. The default VPC has overly permissive defaults (open
// SG, public subnet); production workloads belong in a purpose-built
// VPC.
var CheckEC2NoDefaultVPCInUse = compliancekit.Check{
	ID:           "aws-ec2-no-default-vpc-in-use",
	Title:        "EC2 instances must not run in the default VPC",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "aws",
	Service:      "ec2",
	ResourceType: awscol.EC2InstanceType,
	Description: "AWS provisions a default VPC in every region with overly " +
		"permissive defaults: every subnet is public, the default security " +
		"group allows all egress, and instances launched without explicit " +
		"network config land here. Production workloads belong in a " +
		"purpose-built VPC with private subnets and explicit ingress/egress " +
		"rules.",
	Remediation: "Build a new VPC ('aws ec2 create-vpc --cidr-block 10.0.0.0/16'), " +
		"create private subnets across two AZs, set up NAT for outbound, then " +
		"migrate workloads. Consider deleting the default VPC in every region " +
		"with no workloads ('aws ec2 delete-vpc --vpc-id <default-vpc>').",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.6"},
		"iso27001": {"A.8.20", "A.8.22"},
		"cis-v8":   {"4.4", "12.2"},
	},
	Tags:    []string{"ec2", "network", "vpc"},
	Scanner: "ec2.NoDefaultVPCInUse",
}

func EC2NoDefaultVPCInUse(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	// Build a set of default VPC IDs from the graph.
	defaultVPCs := map[string]bool{}
	for _, v := range g.ByType(awscol.EC2VPCType) {
		if isDefault, _ := v.Attributes["is_default"].(bool); isDefault {
			id, _ := v.Attributes["vpc_id"].(string)
			defaultVPCs[id] = true
		}
	}

	findings := []compliancekit.Finding{}
	for _, inst := range g.ByType(awscol.EC2InstanceType) {
		state, _ := inst.Attributes["state"].(string)
		if state != "running" {
			// Stopped/terminated instances are not actively exposed.
			continue
		}
		vpcID, _ := inst.Attributes["vpc_id"].(string)
		f := compliancekit.Finding{
			CheckID:  CheckEC2NoDefaultVPCInUse.ID,
			Severity: CheckEC2NoDefaultVPCInUse.Severity,
			Resource: inst.Ref(),
			Tags:     CheckEC2NoDefaultVPCInUse.Tags,
		}
		if defaultVPCs[vpcID] {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("instance %q runs in default VPC %s", inst.Name, vpcID)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("instance %q runs in non-default VPC %s", inst.Name, vpcID)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckEC2IMDSv2Required requires every running instance to enforce
// IMDSv2. CIS AWS Foundations 5.6.
var CheckEC2IMDSv2Required = compliancekit.Check{
	ID:           "aws-ec2-imdsv2-required",
	Title:        "EC2 instances must require IMDSv2",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "aws",
	Service:      "ec2",
	ResourceType: awscol.EC2InstanceType,
	Description: "Instance Metadata Service v2 requires session-token " +
		"authentication for every metadata request, which defeats the SSRF " +
		"+ IMDSv1 = credential exfiltration attack that has produced multiple " +
		"high-profile cloud breaches (e.g. Capital One 2019). CIS AWS " +
		"Foundations 5.6 mandates IMDSv2 on every running instance.",
	Remediation: "Enforce IMDSv2: 'aws ec2 modify-instance-metadata-options " +
		"--instance-id <id> --http-tokens required --http-endpoint enabled'. " +
		"For new instances bake this into launch templates and AMI defaults.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.20"},
		"cis-v8":   {"4.1", "4.4"},
	},
	Tags:    []string{"ec2", "metadata-service", "ssrf"},
	Scanner: "ec2.IMDSv2Required",
}

func EC2IMDSv2Required(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, inst := range g.ByType(awscol.EC2InstanceType) {
		state, _ := inst.Attributes["state"].(string)
		if state != "running" {
			continue
		}
		required, _ := inst.Attributes["imdsv2_required"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckEC2IMDSv2Required.ID,
			Severity: CheckEC2IMDSv2Required.Severity,
			Resource: inst.Ref(),
			Tags:     CheckEC2IMDSv2Required.Tags,
		}
		if required {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("instance %q: IMDSv2 required", inst.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("instance %q: IMDSv2 not required (IMDSv1 still accepted)", inst.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckEC2EBSEncrypted requires every EBS volume to be encrypted.
// CIS AWS Foundations 2.2.1 (regional default) and 2.2.2 (per-volume).
var CheckEC2EBSEncrypted = compliancekit.Check{
	ID:           "aws-ec2-ebs-encrypted",
	Title:        "EBS volumes must be encrypted at rest",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "aws",
	Service:      "ec2",
	ResourceType: awscol.EC2VolumeType,
	Description: "EBS volumes hold the persistent data attached to EC2 " +
		"instances. Encryption at rest defends against snapshot disclosure " +
		"and disk reuse. AWS lets you enable default encryption per region " +
		"so new volumes are encrypted automatically; this check catches " +
		"existing volumes that pre-date that flag. CIS AWS Foundations 2.2.",
	Remediation: "Create a snapshot of the unencrypted volume, copy the " +
		"snapshot with --encrypted, restore a new volume from the encrypted " +
		"snapshot, detach the old volume from the instance, and attach the " +
		"new one. Enable the region-wide default ('aws ec2 " +
		"enable-ebs-encryption-by-default') so future volumes are encrypted " +
		"automatically.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.8.24"},
		"cis-v8":   {"3.11"},
	},
	Tags:    []string{"ec2", "ebs", "encryption", "data-at-rest"},
	Scanner: "ec2.EBSEncrypted",
}

func EC2EBSEncrypted(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, vol := range g.ByType(awscol.EC2VolumeType) {
		encrypted, _ := vol.Attributes["encrypted"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckEC2EBSEncrypted.ID,
			Severity: CheckEC2EBSEncrypted.Severity,
			Resource: vol.Ref(),
			Tags:     CheckEC2EBSEncrypted.Tags,
		}
		if encrypted {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("volume %q: encrypted", vol.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("volume %q: not encrypted", vol.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckEC2NoPublicAMIs flags AMIs owned by this account that are
// public. Public AMIs may leak baked-in secrets, internal IP
// schemes, and pre-installed software inventory.
var CheckEC2NoPublicAMIs = compliancekit.Check{
	ID:           "aws-ec2-no-public-amis",
	Title:        "AMIs owned by this account must not be public",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "aws",
	Service:      "ec2",
	ResourceType: awscol.EC2AMIType,
	Description: "Public AMIs are visible to every AWS account. A public " +
		"AMI may leak baked-in secrets (credentials in cloud-init, hardcoded " +
		"API keys in software), internal IP schemes, and a complete list of " +
		"installed software an attacker can fingerprint for vulnerabilities. " +
		"Public AMIs are only appropriate for software the organization " +
		"explicitly distributes to other AWS users.",
	Remediation: "Mark the AMI private: 'aws ec2 modify-image-attribute " +
		"--image-id <ami-id> --launch-permission Remove='[{\"Group\":\"all\"}]'. " +
		"Review the AMI's installed software for any leaked secrets before " +
		"continuing to use it; an exposed AMI is a credential-disclosure " +
		"incident.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.6"},
		"iso27001": {"A.8.3", "A.8.12"},
		"cis-v8":   {"3.3", "3.4"},
	},
	Tags:    []string{"ec2", "ami", "data-exposure"},
	Scanner: "ec2.NoPublicAMIs",
}

func EC2NoPublicAMIs(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, ami := range g.ByType(awscol.EC2AMIType) {
		public, _ := ami.Attributes["public"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckEC2NoPublicAMIs.ID,
			Severity: CheckEC2NoPublicAMIs.Severity,
			Resource: ami.Ref(),
			Tags:     CheckEC2NoPublicAMIs.Tags,
		}
		if public {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("AMI %q: public (visible to every AWS account)", ami.Name)
		} else {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("AMI %q: private", ami.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckEC2SGNoIngressFromAny, EC2SGNoIngressFromAny)
	compliancekit.Register(CheckEC2NoDefaultVPCInUse, EC2NoDefaultVPCInUse)
	compliancekit.Register(CheckEC2IMDSv2Required, EC2IMDSv2Required)
	compliancekit.Register(CheckEC2EBSEncrypted, EC2EBSEncrypted)
	compliancekit.Register(CheckEC2NoPublicAMIs, EC2NoPublicAMIs)
}
