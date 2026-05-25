package report

import (
	"strings"
	"testing"
	"time"
)

func TestSummary_HappyPath(t *testing.T) {
	in := SummaryInput{
		AsOf:                 time.Date(2026, 5, 25, 10, 0, 0, 0, time.UTC),
		Score:                78,
		PriorScore:           75,
		ResourceCount:        430,
		FailingResourceCount: 62,
		TopFindings: []SummaryFinding{
			{CheckID: "aws.iam.user.mfa-enabled", Severity: "critical", ResourceName: "root", Message: "Root account missing MFA"},
			{CheckID: "aws.s3.bucket.public", Severity: "high", ResourceName: "backups", Message: "Public-read bucket"},
		},
		Wins:                   []SummaryFinding{{CheckID: "aws.cloudtrail.enabled"}},
		Regressions:            []SummaryFinding{{CheckID: "aws.kms.rotation"}},
		FrameworkCoverage:      map[string]int{"soc2": 82, "iso27001": 70},
		PriorFrameworkCoverage: map[string]int{"soc2": 78, "iso27001": 70},
	}
	out := Summary(in)
	if !strings.Contains(out, "**Score: 78**") {
		t.Errorf("missing score: %s", out)
	}
	if !strings.Contains(out, "+3") {
		t.Errorf("missing delta: %s", out)
	}
	if !strings.Contains(out, "Top findings") {
		t.Errorf("missing top findings header")
	}
	if !strings.Contains(out, "Wins") {
		t.Errorf("missing wins block")
	}
	if !strings.Contains(out, "soc2") || !strings.Contains(out, "improved by **4 points**") {
		t.Errorf("missing framework headline: %s", out)
	}
	if !strings.Contains(out, "as of 2026-05-25 10:00 UTC") {
		t.Errorf("missing timestamp footer: %s", out)
	}
}

func TestSummary_NoPriorWindow(t *testing.T) {
	out := Summary(SummaryInput{Score: 50})
	if !strings.Contains(out, "no prior window") {
		t.Errorf("expected no-prior callout: %s", out)
	}
}

func TestSummary_ScoreRegression(t *testing.T) {
	out := Summary(SummaryInput{Score: 60, PriorScore: 70})
	if !strings.Contains(out, "**-10**") {
		t.Errorf("expected negative delta: %s", out)
	}
}

func TestFrameworkHeadline_RegressionWins(t *testing.T) {
	got := frameworkHeadline(
		map[string]int{"soc2": 60, "iso": 70},
		map[string]int{"soc2": 75, "iso": 70},
	)
	if !strings.Contains(got, "soc2") || !strings.Contains(got, "regressed") {
		t.Errorf("expected regression callout, got %q", got)
	}
}

func TestSummarizeIDs_Truncates(t *testing.T) {
	in := []SummaryFinding{
		{CheckID: "a"}, {CheckID: "b"}, {CheckID: "c"}, {CheckID: "d"}, {CheckID: "e"},
	}
	got := summarizeIDs(in, 3)
	if !strings.Contains(got, "+2 more") {
		t.Errorf("expected truncation: %s", got)
	}
}
