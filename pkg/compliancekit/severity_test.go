package compliancekit

import (
	"encoding/json"
	"testing"
)

func TestSeverity_String(t *testing.T) {
	cases := []struct {
		sev  Severity
		want string
	}{
		{SeverityInfo, "info"},
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
		{SeverityUnknown, "unknown"},
	}
	for _, c := range cases {
		if got := c.sev.String(); got != c.want {
			t.Errorf("Severity(%d).String() = %q, want %q", c.sev, got, c.want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in      string
		want    Severity
		wantErr bool
	}{
		{"info", SeverityInfo, false},
		{"LOW", SeverityLow, false},
		{" High ", SeverityHigh, false},
		{"critical", SeverityCritical, false},
		{"", SeverityUnknown, true},
		{"bogus", SeverityUnknown, true},
	}
	for _, c := range cases {
		got, err := ParseSeverity(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseSeverity(%q) expected error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSeverity(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseSeverity(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSeverity_Ordering(t *testing.T) {
	// The CLI --fail-on filter relies on ascending impact order.
	if !(SeverityInfo < SeverityLow &&
		SeverityLow < SeverityMedium &&
		SeverityMedium < SeverityHigh &&
		SeverityHigh < SeverityCritical) {
		t.Error("severities must be in ascending impact order")
	}
}

func TestSeverity_JSONRoundTrip(t *testing.T) {
	type wrap struct {
		Severity Severity `json:"severity"`
	}
	for _, sev := range []Severity{
		SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical,
	} {
		b, err := json.Marshal(wrap{Severity: sev})
		if err != nil {
			t.Fatalf("marshal %s: %v", sev, err)
		}
		var got wrap
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", string(b), err)
		}
		if got.Severity != sev {
			t.Errorf("round-trip %s: got %s", sev, got.Severity)
		}
	}
}

func TestSeverity_UnmarshalJSONRejectsUnknown(t *testing.T) {
	var s Severity
	if err := json.Unmarshal([]byte(`"bogus"`), &s); err == nil {
		t.Error("expected error unmarshaling unknown severity")
	}
}
