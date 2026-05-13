package linux

import "testing"

func TestParseUFWDefault_HappyPath(t *testing.T) {
	output := `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip
`
	cases := map[string]string{
		"incoming": "deny",
		"outgoing": "allow",
		"routed":   "disabled",
	}
	for dir, want := range cases {
		got := parseUFWDefault(output, dir)
		if got != want {
			t.Errorf("parseUFWDefault(_, %q) = %q, want %q", dir, got, want)
		}
	}
}

func TestParseUFWDefault_MissingDirectionReturnsEmpty(t *testing.T) {
	output := `Status: active
Default: deny (incoming), allow (outgoing)
`
	if got := parseUFWDefault(output, "routed"); got != "" {
		t.Errorf("missing direction returned %q, want empty", got)
	}
}

func TestParseUFWDefault_NoDefaultLine(t *testing.T) {
	output := `Status: inactive`
	if got := parseUFWDefault(output, "incoming"); got != "" {
		t.Errorf("no Default line returned %q, want empty", got)
	}
}

func TestParseUFWDefault_HandlesExtraWhitespace(t *testing.T) {
	output := `Default:    deny (incoming),   allow (outgoing)`
	if got := parseUFWDefault(output, "incoming"); got != "deny" {
		t.Errorf("got %q, want deny", got)
	}
	if got := parseUFWDefault(output, "outgoing"); got != "allow" {
		t.Errorf("got %q, want allow", got)
	}
}
