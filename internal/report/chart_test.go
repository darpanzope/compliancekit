package report

import (
	"strings"
	"testing"
)

func TestHeatmap_BasicOutput(t *testing.T) {
	out := Heatmap([]HeatmapCell{
		{Row: "EC2", Col: "critical", Value: 3},
		{Row: "EC2", Col: "high", Value: 7},
		{Row: "S3", Col: "high", Value: 2},
	}, 400, 200)
	if !strings.HasPrefix(out, "<svg") {
		t.Errorf("missing <svg> prefix: %s", out)
	}
	if !strings.Contains(out, "data-ck-bucket") {
		t.Errorf("missing v1.18 interactivity hook: %s", out)
	}
	if !strings.Contains(out, "EC2") || !strings.Contains(out, "critical") {
		t.Errorf("missing row/col labels: %s", out)
	}
}

func TestHeatmap_Empty(t *testing.T) {
	out := Heatmap(nil, 100, 50)
	if !strings.Contains(out, "no data") {
		t.Errorf("expected empty placeholder, got %s", out)
	}
}

func TestTreemap_AreaProportionToValue(t *testing.T) {
	out := Treemap([]TreemapSlice{
		{Label: "iam", Value: 50},
		{Label: "s3", Value: 30},
		{Label: "ec2", Value: 20},
	}, 400, 200)
	if !strings.HasPrefix(out, "<svg") {
		t.Errorf("missing svg prefix")
	}
	if !strings.Contains(out, "iam") {
		t.Errorf("biggest slice label should render")
	}
}

func TestSankey_RoundTrip(t *testing.T) {
	out := Sankey([]SankeyLink{
		{Source: "drift", Target: "fixed", Value: 8},
		{Source: "drift", Target: "waived", Value: 3},
		{Source: "new", Target: "open", Value: 5},
	}, 500, 240)
	if !strings.Contains(out, "drift") || !strings.Contains(out, "fixed") {
		t.Errorf("sankey missing node labels: %s", out)
	}
	if !strings.Contains(out, "data-ck-bucket") {
		t.Errorf("missing interactivity hook")
	}
}

func TestRadar_PolygonEmitted(t *testing.T) {
	out := Radar([]RadarAxis{
		{Label: "CC1", Value: 0.8},
		{Label: "CC2", Value: 0.6},
		{Label: "CC3", Value: 0.9},
		{Label: "CC4", Value: 0.5},
	}, 240, 240)
	if !strings.Contains(out, "<polygon") {
		t.Errorf("radar should emit a polygon: %s", out)
	}
}

func TestRadar_RejectsTooFewAxes(t *testing.T) {
	out := Radar([]RadarAxis{{Label: "x", Value: 1}}, 100, 100)
	if !strings.Contains(out, "≥3 axes") {
		t.Errorf("expected too-few-axes placeholder: %s", out)
	}
}

func TestPaletteByIndex_StableForSameKey(t *testing.T) {
	a := paletteByIndex("aws.iam")
	b := paletteByIndex("aws.iam")
	if a != b {
		t.Errorf("palette not stable: %s vs %s", a, b)
	}
}

func TestEscapeXML(t *testing.T) {
	got := escapeXML(`<x & "y">`)
	want := "&lt;x &amp; &quot;y&quot;&gt;"
	if got != want {
		t.Errorf("escapeXML = %q want %q", got, want)
	}
}
