package tui

import (
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// fixture builds a small deterministic findings set for the
// model/diff/graph tests.
func fixture() []compliancekit.Finding {
	return []compliancekit.Finding{
		{
			CheckID:  "do-droplet-no-vpc",
			Severity: compliancekit.SeverityCritical,
			Status:   compliancekit.StatusFail,
			Resource: compliancekit.ResourceRef{ID: "droplet-1", Name: "web-01", Type: "do.droplet", Provider: "digitalocean"},
		},
		{
			CheckID:  "do-firewall-broad",
			Severity: compliancekit.SeverityHigh,
			Status:   compliancekit.StatusFail,
			Resource: compliancekit.ResourceRef{ID: "fw-1", Name: "default", Type: "do.firewall", Provider: "digitalocean"},
		},
		{
			CheckID:  "aws-iam-no-mfa",
			Severity: compliancekit.SeverityHigh,
			Status:   compliancekit.StatusFail,
			Resource: compliancekit.ResourceRef{ID: "user-alice", Name: "alice", Type: "aws.iam_user", Provider: "aws"},
		},
		{
			CheckID:  "aws-s3-public",
			Severity: compliancekit.SeverityMedium,
			Status:   compliancekit.StatusPass,
			Resource: compliancekit.ResourceRef{ID: "bucket-1", Name: "logs", Type: "aws.s3_bucket", Provider: "aws"},
		},
	}
}

func TestNewListModelDerivesProviders(t *testing.T) {
	m := newListModel(fixture())
	if got, want := len(m.providers), 2; got != want {
		t.Errorf("providers len = %d, want %d", got, want)
	}
	if m.providers[0].name != "aws" || m.providers[1].name != "digitalocean" {
		t.Errorf("providers not alphabetically sorted: %+v", m.providers)
	}
}

func TestCursorJKWithinList(t *testing.T) {
	m := newListModel(fixture())
	m.focused = paneList
	m.cursorDown()
	if m.listCursor != 1 {
		t.Errorf("after j: cursor = %d, want 1", m.listCursor)
	}
	m.cursorBottom()
	if m.listCursor != len(m.filtered)-1 {
		t.Errorf("after G: cursor = %d, want %d", m.listCursor, len(m.filtered)-1)
	}
	m.cursorTop()
	if m.listCursor != 0 {
		t.Errorf("after g: cursor = %d, want 0", m.listCursor)
	}
}

func TestApplyProviderFilter(t *testing.T) {
	m := newListModel(fixture())
	m.providerSel = "aws"
	m.applyFilter()
	if len(m.filtered) != 2 {
		t.Errorf("aws filter: %d findings, want 2", len(m.filtered))
	}
	m.providerSel = ""
	m.applyFilter()
	if len(m.filtered) != 4 {
		t.Errorf("clear filter: %d findings, want 4", len(m.filtered))
	}
}

func TestCommandFilterSeverityGTE(t *testing.T) {
	m := newListModel(fixture())
	m.filter = parseCommandLine(":sev>=high")
	m.applyFilter()
	// 1 critical + 2 high = 3 rows
	if len(m.filtered) != 3 {
		t.Errorf("sev>=high: %d findings, want 3", len(m.filtered))
	}
}

func TestCommandFilterStatusAndProvider(t *testing.T) {
	m := newListModel(fixture())
	m.filter = parseCommandLine(":status=fail provider=aws")
	m.applyFilter()
	if len(m.filtered) != 1 {
		t.Errorf("status=fail provider=aws: %d findings, want 1", len(m.filtered))
	}
}

func TestSearchCommitClearsCursor(t *testing.T) {
	m := newListModel(fixture())
	m.focused = paneList
	m.listCursor = 3
	m.mode = modeSearch
	m.input = "iam"
	m.commitEditor()
	if m.listCursor != 0 {
		t.Errorf("after search commit, cursor = %d, want 0", m.listCursor)
	}
	if len(m.filtered) != 1 || !strings.Contains(m.filtered[0].CheckID, "iam") {
		t.Errorf("search 'iam' filtered wrong: %+v", m.filtered)
	}
}

func TestGraphBucketsRollup(t *testing.T) {
	rows := buildGraphRows(fixture())
	// 2 providers + 4 distinct resource_types + 4 resources = 10 rows
	if got, want := len(rows), 10; got != want {
		t.Errorf("rows = %d, want %d (%+v)", got, want, rows)
	}
	// Worst severity at the digitalocean provider level should be
	// critical (rolled up from do-droplet-no-vpc).
	for _, r := range rows {
		if r.depth == 0 && r.label == "digitalocean" && r.worstSev != compliancekit.SeverityCritical {
			t.Errorf("digitalocean worst = %v, want critical", r.worstSev)
		}
	}
}

func TestComputeDiffCategorizes(t *testing.T) {
	current := fixture()
	baseline := current[:2] // baseline has only the two DO findings
	perFP, resolved := computeDiff(current, baseline)
	newCount := 0
	for _, k := range perFP {
		if k == diffNew {
			newCount++
		}
	}
	// Two AWS findings are new vs. baseline.
	if newCount != 2 {
		t.Errorf("new = %d, want 2", newCount)
	}
	if len(resolved) != 0 {
		t.Errorf("resolved = %d, want 0 (baseline is a subset)", len(resolved))
	}
}

func TestParseCommandLineSeverityVariants(t *testing.T) {
	cases := []struct {
		in   string
		want compliancekit.Severity
	}{
		{":sev=critical", compliancekit.SeverityCritical},
		{":sev=crit", compliancekit.SeverityCritical},
		{":sev=high", compliancekit.SeverityHigh},
		{":sev=medium", compliancekit.SeverityMedium},
		{":sev=med", compliancekit.SeverityMedium},
		{":sev=low", compliancekit.SeverityLow},
	}
	for _, c := range cases {
		got := parseCommandLine(c.in)
		if !got.sevEqSet {
			t.Errorf("%q: sevEqSet not flipped", c.in)
			continue
		}
		if got.sevEq != c.want {
			t.Errorf("%q: sev = %v, want %v", c.in, got.sevEq, c.want)
		}
	}
}
