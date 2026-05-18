package report

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// goldenFixedTime is the timestamp every golden render uses for the
// Generated field. Pinned so the rendered HTML is byte-stable across
// machines + clocks.
var goldenFixedTime = time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

// TestHTML_GoldenSnapshots renders three canonical fixture sets
// (empty / mixed / all-clear) against the live HTML template and
// compares byte-for-byte against the committed .golden file. Catches
// inline CSS / JS / template regressions without needing to eyeball
// 11 MB of output. v1.2 phase 9.
//
// Update goldens after an intentional template change with:
//
//	GOLDEN_UPDATE=1 go test ./internal/report/ -run GoldenSnapshots
func TestHTML_GoldenSnapshots(t *testing.T) {
	// Pin the clock so Generated is deterministic.
	original := nowFn
	nowFn = func() time.Time { return goldenFixedTime }
	t.Cleanup(func() { nowFn = original })

	cases := []struct {
		name     string
		findings []compliancekit.Finding
	}{
		{name: "empty", findings: nil},
		{name: "all_clear", findings: goldenAllPass()},
		{name: "mixed", findings: goldenMixed()},
		{name: "critical_only", findings: goldenCriticalOnly()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := NewHTML().Render(context.Background(), tc.findings, nil, &buf); err != nil {
				t.Fatalf("Render: %v", err)
			}
			got := buf.Bytes()
			path := filepath.Join("testdata", "findings_"+tc.name+".html.golden")
			if os.Getenv("GOLDEN_UPDATE") != "" {
				if err := os.MkdirAll("testdata", 0o750); err != nil {
					t.Fatalf("mkdir testdata: %v", err)
				}
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				t.Logf("updated golden: %s (%d bytes)", path, len(got))
				return
			}
			want, err := os.ReadFile(path) //nolint:gosec // test fixture path is intentional
			if err != nil {
				t.Fatalf("read golden %s: %v (run with GOLDEN_UPDATE=1 to create)", path, err)
			}
			if !bytes.Equal(want, got) {
				t.Errorf("golden mismatch for %s (golden=%d bytes, got=%d bytes). Run GOLDEN_UPDATE=1 to refresh after an intentional template change.", path, len(want), len(got))
			}
		})
	}
}

// goldenAllPass is a tiny fixture where every finding passes — drives
// the IsAllClear celebration panel.
func goldenAllPass() []compliancekit.Finding {
	return []compliancekit.Finding{
		{
			CheckID:  "linux-passwd-permissions",
			Status:   compliancekit.StatusPass,
			Severity: compliancekit.SeverityHigh,
			Resource: compliancekit.ResourceRef{ID: "host-01", Name: "host-01", Type: "linux.host"},
			Message:  "permissions on /etc/passwd are 0644",
		},
		{
			CheckID:  "linux-ssh-rootlogin",
			Status:   compliancekit.StatusPass,
			Severity: compliancekit.SeverityCritical,
			Resource: compliancekit.ResourceRef{ID: "host-01", Name: "host-01", Type: "linux.host"},
			Message:  "PermitRootLogin is no",
		},
	}
}

// goldenMixed exercises the typical scan rendering — severity mix,
// some pass, some fail, multiple resources, multiple providers.
func goldenMixed() []compliancekit.Finding {
	return []compliancekit.Finding{
		{
			CheckID:  "aws-iam-mfa",
			Status:   compliancekit.StatusFail,
			Severity: compliancekit.SeverityCritical,
			Resource: compliancekit.ResourceRef{ID: "111111111111", Name: "prod-account", Type: "aws.account"},
			Message:  "root account does not have MFA enabled",
		},
		{
			CheckID:  "linux-ssh-rootlogin",
			Status:   compliancekit.StatusFail,
			Severity: compliancekit.SeverityHigh,
			Resource: compliancekit.ResourceRef{ID: "host-02", Name: "host-02", Type: "linux.host"},
			Message:  "PermitRootLogin is yes",
		},
		{
			CheckID:  "k8s-pod-runasnonroot",
			Status:   compliancekit.StatusFail,
			Severity: compliancekit.SeverityMedium,
			Resource: compliancekit.ResourceRef{ID: "prod/web-7d4b", Name: "web-7d4b", Type: "k8s.pod"},
			Message:  "pod runs as root",
		},
		{
			CheckID:  "linux-passwd-permissions",
			Status:   compliancekit.StatusPass,
			Severity: compliancekit.SeverityLow,
			Resource: compliancekit.ResourceRef{ID: "host-02", Name: "host-02", Type: "linux.host"},
			Message:  "permissions on /etc/passwd are 0644",
		},
	}
}

// goldenCriticalOnly exercises the case where one severity dominates
// the report.
func goldenCriticalOnly() []compliancekit.Finding {
	return []compliancekit.Finding{
		{
			CheckID:  "aws-iam-mfa",
			Status:   compliancekit.StatusFail,
			Severity: compliancekit.SeverityCritical,
			Resource: compliancekit.ResourceRef{ID: "111111111111", Name: "prod-account", Type: "aws.account"},
			Message:  "root account does not have MFA enabled",
		},
		{
			CheckID:  "aws-s3-public",
			Status:   compliancekit.StatusFail,
			Severity: compliancekit.SeverityCritical,
			Resource: compliancekit.ResourceRef{ID: "arn:aws:s3:::public-bucket", Name: "public-bucket", Type: "aws.s3.bucket"},
			Message:  "bucket allows public read",
		},
	}
}
