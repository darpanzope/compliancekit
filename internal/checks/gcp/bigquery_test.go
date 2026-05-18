package gcp

import (
	"context"
	"testing"

	gcpcol "github.com/darpanzope/compliancekit/internal/collectors/gcp"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func mkDataset(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID:         "gcp.bigquery.dataset." + name,
		Type:       gcpcol.BigQueryDatasetType,
		Name:       name,
		Provider:   "gcp",
		Attributes: attrs,
	}
}

func TestBQNoPublicDatasets(t *testing.T) {
	cases := []struct {
		name   string
		access []map[string]any
		want   compliancekit.Status
	}{
		{
			"private",
			[]map[string]any{
				{"role": "READER", "user_by_email": "x@y.com"},
			},
			compliancekit.StatusPass,
		},
		{
			"all-authenticated-special-group",
			[]map[string]any{
				{"role": "READER", "special_group": "allAuthenticatedUsers"},
			},
			compliancekit.StatusFail,
		},
		{
			"all-users-iam-member",
			[]map[string]any{
				{"role": "READER", "iam_member": "allUsers"},
			},
			compliancekit.StatusFail,
		},
		{
			"empty-access",
			nil,
			compliancekit.StatusPass,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraphWith(mkDataset(c.name, map[string]any{"access": c.access}))
			findings, _ := BQNoPublicDatasets(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestBQNoAllAuthenticated(t *testing.T) {
	cases := []struct {
		name   string
		access []map[string]any
		want   compliancekit.Status
	}{
		{
			"all-users-still-passes-this-check",
			[]map[string]any{{"iam_member": "allUsers"}},
			compliancekit.StatusPass,
		},
		{
			"all-authenticated-special-group",
			[]map[string]any{{"special_group": "allAuthenticatedUsers"}},
			compliancekit.StatusFail,
		},
		{
			"all-authenticated-iam-member",
			[]map[string]any{{"iam_member": "allAuthenticatedUsers"}},
			compliancekit.StatusFail,
		},
		{
			"private",
			[]map[string]any{{"user_by_email": "x@y.com"}},
			compliancekit.StatusPass,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGraphWith(mkDataset(c.name, map[string]any{"access": c.access}))
			findings, _ := BQNoAllAuthenticated(context.Background(), g)
			if findings[0].Status != c.want {
				t.Errorf("got %v, want %v: %s", findings[0].Status, c.want, findings[0].Message)
			}
		})
	}
}

func TestBQDefaultCMEK(t *testing.T) {
	g := newGraphWith(
		mkDataset("on", map[string]any{"default_cmek": true, "default_cmek_key": "projects/p/locations/us/keyRings/r/cryptoKeys/k"}),
		mkDataset("off", map[string]any{"default_cmek": false}),
	)
	findings, _ := BQDefaultCMEK(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "off" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v: %s", f.Resource.Name, f.Status, f.Message)
		}
	}
}
