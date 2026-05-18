package aws

import (
	"context"
	"fmt"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// CheckConfigRecorderOn requires AWS Config to be actively
// recording in every region in scope. CIS AWS Foundations 3.5.
var CheckConfigRecorderOn = compliancekit.Check{
	ID:           "aws-config-recorder-on",
	Title:        "AWS Config must be enabled in every region",
	Severity:     compliancekit.SeverityMedium,
	Provider:     "aws",
	Service:      "config",
	ResourceType: awscol.ConfigRegionType,
	Description: "AWS Config records resource state changes over time, " +
		"providing the change-log a forensic investigation needs to answer " +
		"'when did this resource look the way it did?' Without it, the " +
		"answer is 'we don't know.' CIS AWS Foundations 3.5 prescribes a " +
		"recorder in every region.",
	Remediation: "Enable Config in the region: AWS Console -> Config -> " +
		"Get started, or via CLI: 'aws configservice put-configuration-recorder " +
		"--configuration-recorder ... --recording-group ...' then " +
		"'aws configservice start-configuration-recorder --configuration-recorder-name ...'. " +
		"Consider an org-level Config aggregator if you scan many accounts.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2", "CC7.3"},
		"iso27001": {"A.8.15", "A.8.16"},
		"cis-v8":   {"8.5"},
	},
	Tags:    []string{"config", "audit-logging", "change-tracking"},
	Scanner: "config.RecorderOn",
}

func ConfigRecorderOn(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, r := range g.ByType(awscol.ConfigRegionType) {
		on, _ := r.Attributes["recorder_on"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckConfigRecorderOn.ID,
			Severity: CheckConfigRecorderOn.Severity,
			Resource: r.Ref(),
			Tags:     CheckConfigRecorderOn.Tags,
		}
		if on {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("region %q: Config recorder on", r.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("region %q: Config recorder NOT recording", r.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckConfigDeliveryChannel requires a delivery channel to be
// configured in every region with Config enabled. Without a
// delivery channel the recorder runs but the events have nowhere
// to land.
var CheckConfigDeliveryChannel = compliancekit.Check{
	ID:           "aws-config-delivery-channel",
	Title:        "AWS Config must have a delivery channel configured",
	Severity:     compliancekit.SeverityLow,
	Provider:     "aws",
	Service:      "config",
	ResourceType: awscol.ConfigRegionType,
	Description: "Config's recorder produces a stream of events; the " +
		"delivery channel is the S3 bucket (and optional SNS topic) those " +
		"events get written to. Without a delivery channel the recorder " +
		"records into the void -- the audit trail is invisible to the " +
		"operator.",
	Remediation: "Configure a delivery channel: " +
		"'aws configservice put-delivery-channel --delivery-channel ...'. " +
		"The S3 bucket should be in the same region and tightly access-controlled.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2"},
		"iso27001": {"A.8.15"},
		"cis-v8":   {"8.5", "8.10"},
	},
	Tags:    []string{"config", "audit-logging"},
	Scanner: "config.DeliveryChannel",
}

func ConfigDeliveryChannel(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, r := range g.ByType(awscol.ConfigRegionType) {
		channel, _ := r.Attributes["delivery_channel"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckConfigDeliveryChannel.ID,
			Severity: CheckConfigDeliveryChannel.Severity,
			Resource: r.Ref(),
			Tags:     CheckConfigDeliveryChannel.Tags,
		}
		if channel {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("region %q: Config delivery channel configured", r.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("region %q: no Config delivery channel", r.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckGuardDutyEnabled requires GuardDuty to be enabled (detector
// present + status Enabled) in every region in scope. CIS AWS
// Foundations 3.10.
var CheckGuardDutyEnabled = compliancekit.Check{
	ID:           "aws-guardduty-enabled",
	Title:        "GuardDuty must be enabled in every region",
	Severity:     compliancekit.SeverityHigh,
	Provider:     "aws",
	Service:      "guardduty",
	ResourceType: awscol.GuardDutyRegionType,
	Description: "GuardDuty is AWS's managed threat-detection service. It " +
		"analyzes VPC Flow Logs, CloudTrail, and DNS logs for known IOCs " +
		"and behavioral anomalies -- credential exfiltration, crypto-mining " +
		"workloads, communication with known C2 endpoints. CIS AWS " +
		"Foundations 3.10 prescribes GuardDuty in every region.",
	Remediation: "Enable: 'aws guardduty create-detector --enable'. " +
		"Consider organization-level GuardDuty for multi-account coverage. " +
		"Wire findings into a SIEM or compliancekit ingest at v0.13 once " +
		"the OCSF ingest path ships.",
	Frameworks: map[string][]string{
		"soc2":     {"CC7.2", "CC7.3"},
		"iso27001": {"A.8.16"},
		"cis-v8":   {"8.5", "13.1"},
	},
	Tags:    []string{"guardduty", "threat-detection"},
	Scanner: "guardduty.Enabled",
}

func GuardDutyEnabled(_ context.Context, g *compliancekit.ResourceGraph) ([]compliancekit.Finding, error) {
	findings := []compliancekit.Finding{}
	for _, r := range g.ByType(awscol.GuardDutyRegionType) {
		enabled, _ := r.Attributes["detector_enabled"].(bool)
		f := compliancekit.Finding{
			CheckID:  CheckGuardDutyEnabled.ID,
			Severity: CheckGuardDutyEnabled.Severity,
			Resource: r.Ref(),
			Tags:     CheckGuardDutyEnabled.Tags,
		}
		if enabled {
			f.Status = compliancekit.StatusPass
			f.Message = fmt.Sprintf("region %q: GuardDuty enabled", r.Name)
		} else {
			f.Status = compliancekit.StatusFail
			f.Message = fmt.Sprintf("region %q: GuardDuty NOT enabled", r.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	compliancekit.Register(CheckConfigRecorderOn, ConfigRecorderOn)
	compliancekit.Register(CheckConfigDeliveryChannel, ConfigDeliveryChannel)
	compliancekit.Register(CheckGuardDutyEnabled, GuardDutyEnabled)
}
