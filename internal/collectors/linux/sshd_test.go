package linux

import (
	"testing"

	"github.com/darpanzope/compliancekit/internal/core"
)

// Compile-time assertion that *Collector satisfies core.Collector.
// (Lives in this file to keep collector_test.go optional for v0.2.)
var _ core.Collector = (*Collector)(nil)

func TestParseSSHDConfig_BasicDirectives(t *testing.T) {
	input := `
# This is a comment
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 4
LoginGraceTime 60
`
	got := parseSSHDConfig(input)

	cases := map[string]string{
		"port":                   "22",
		"protocol":               "2",
		"permitrootlogin":        "no",
		"passwordauthentication": "no",
		"maxauthtries":           "4",
		"logingracetime":         "60",
	}
	for k, want := range cases {
		if got[k] != want {
			t.Errorf("parsed[%q] = %q, want %q", k, got[k], want)
		}
	}
	if len(got) != len(cases) {
		t.Errorf("got %d entries, want %d", len(got), len(cases))
	}
}

func TestParseSSHDConfig_LowercaseKeys(t *testing.T) {
	// `sshd -T` emits lowercase keys; sshd_config files use mixed case.
	// Both must produce the same lowercase keys in the parsed map so
	// checks can read consistently.
	input := `PermitRootLogin no`
	got := parseSSHDConfig(input)
	if got["permitrootlogin"] != "no" {
		t.Errorf("expected lowercase key, got map: %v", got)
	}
}

func TestParseSSHDConfig_HandlesTabs(t *testing.T) {
	// Some operators use tabs as the separator.
	input := "PermitRootLogin\tno\nPort\t22"
	got := parseSSHDConfig(input)
	if got["permitrootlogin"] != "no" || got["port"] != "22" {
		t.Errorf("tab-separated parse failed: %v", got)
	}
}

func TestParseSSHDConfig_HandlesValuesWithSpaces(t *testing.T) {
	// AllowUsers / Match values can have multiple space-separated parts.
	// The whole tail is the value.
	input := `AllowUsers ops alice carol`
	got := parseSSHDConfig(input)
	if got["allowusers"] != "ops alice carol" {
		t.Errorf("got %q, want %q", got["allowusers"], "ops alice carol")
	}
}

func TestParseSSHDConfig_LastWinsOnDuplicate(t *testing.T) {
	// OpenSSH applies the LAST matching directive when one repeats.
	// Our parser must do the same.
	input := `
HostKey /etc/ssh/key1
HostKey /etc/ssh/key2
HostKey /etc/ssh/key3
`
	got := parseSSHDConfig(input)
	if got["hostkey"] != "/etc/ssh/key3" {
		t.Errorf("last-wins violated: got %q", got["hostkey"])
	}
}

func TestParseSSHDConfig_SkipsCommentsAndBlanks(t *testing.T) {
	input := `
# Top comment
   # Indented comment

Port 22

# Mid comment
PermitRootLogin no
`
	got := parseSSHDConfig(input)
	if len(got) != 2 {
		t.Errorf("expected 2 directives, got %d: %v", len(got), got)
	}
}

func TestParseSSHDConfig_EmptyInputReturnsEmpty(t *testing.T) {
	if got := parseSSHDConfig(""); len(got) != 0 {
		t.Errorf("empty input should yield empty map, got %v", got)
	}
}

func TestTruncateForError(t *testing.T) {
	short := "abcdef"
	if got := truncateForError(short); got != short {
		t.Errorf("short string changed: %q", got)
	}
	long := make([]byte, errorOutputLimit+50)
	for i := range long {
		long[i] = 'x'
	}
	got := truncateForError(string(long))
	if len(got) != errorOutputLimit+3 { // limit + "..."
		t.Errorf("truncated length = %d, want %d", len(got), errorOutputLimit+3)
	}
}

func TestUnreachableResource_Shape(t *testing.T) {
	r := unreachableResource(Host{Host: "broken-01", Tags: []string{"prod"}}, "i/o timeout")
	if r.Type != HostType {
		t.Errorf("Type = %q, want %q", r.Type, HostType)
	}
	if r.ID != "linux.host.broken-01" {
		t.Errorf("ID = %q, want linux.host.broken-01", r.ID)
	}
	if r.AttrBool("reachable") {
		t.Errorf("reachable = true on unreachable resource: %v", r.Attributes)
	}
	if r.Attr("unreachable_reason") != "i/o timeout" {
		t.Errorf("unreachable_reason = %q, want i/o timeout", r.Attr("unreachable_reason"))
	}
	if !r.HasTag("prod") {
		t.Error("tag propagation broken")
	}
}
