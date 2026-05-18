package linux

import (
	"context"
	"testing"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// hostWithSSHD builds a linux.host Resource carrying the given parsed
// sshd_config map. Useful for compact check tests.
func hostWithSSHD(name string, sshd map[string]string) compliancekit.Resource {
	return compliancekit.Resource{
		ID:       "linux.host." + name,
		Type:     linuxcol.HostType,
		Name:     name,
		Provider: "linux",
		Attributes: map[string]any{
			"reachable":   true,
			"sshd_config": sshd,
		},
	}
}

func unreachableHost(name, reason string) compliancekit.Resource {
	return compliancekit.Resource{
		ID:       "linux.host." + name,
		Type:     linuxcol.HostType,
		Name:     name,
		Provider: "linux",
		Attributes: map[string]any{
			"reachable":          false,
			"unreachable_reason": reason,
		},
	}
}

func newGraph(t *testing.T, rs ...compliancekit.Resource) *compliancekit.ResourceGraph {
	t.Helper()
	g := compliancekit.NewResourceGraph()
	for _, r := range rs {
		g.Add(r)
	}
	return g
}

func TestSSHDNoRootLogin(t *testing.T) {
	g := newGraph(t,
		hostWithSSHD("good", map[string]string{"permitrootlogin": "no"}),
		hostWithSSHD("bad", map[string]string{"permitrootlogin": "yes"}),
		hostWithSSHD("missing", map[string]string{}),
		unreachableHost("offline", "i/o timeout"),
	)

	findings, err := SSHDNoRootLogin(context.Background(), g)
	if err != nil {
		t.Fatalf("SSHDNoRootLogin: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(findings))
	}

	byHost := map[string]compliancekit.Finding{}
	for _, f := range findings {
		byHost[f.Resource.Name] = f
	}
	if byHost["good"].Status != compliancekit.StatusPass {
		t.Errorf("good: %s, want pass", byHost["good"].Status)
	}
	if byHost["bad"].Status != compliancekit.StatusFail {
		t.Errorf("bad: %s, want fail", byHost["bad"].Status)
	}
	if byHost["missing"].Status != compliancekit.StatusFail {
		t.Errorf("missing: %s, want fail (absent directive is non-compliant)", byHost["missing"].Status)
	}
	if byHost["offline"].Status != compliancekit.StatusSkip {
		t.Errorf("offline: %s, want skip", byHost["offline"].Status)
	}
}

func TestSSHDNoPasswordAuth(t *testing.T) {
	g := newGraph(t,
		hostWithSSHD("good", map[string]string{"passwordauthentication": "no"}),
		hostWithSSHD("bad", map[string]string{"passwordauthentication": "yes"}),
	)
	findings, err := SSHDNoPasswordAuth(context.Background(), g)
	if err != nil {
		t.Fatalf("SSHDNoPasswordAuth: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Status != compliancekit.StatusPass {
		t.Errorf("good: %s, want pass", findings[0].Status)
	}
	if findings[1].Status != compliancekit.StatusFail {
		t.Errorf("bad: %s, want fail", findings[1].Status)
	}
}

func TestSSHDProtocol2_AbsentDirectiveIsPass(t *testing.T) {
	// Modern OpenSSH does not emit a Protocol line in `sshd -T` output;
	// we must not flag every modern host.
	g := newGraph(t,
		hostWithSSHD("modern", map[string]string{"permitrootlogin": "no"}),
		hostWithSSHD("explicit2", map[string]string{"protocol": "2"}),
		hostWithSSHD("legacy", map[string]string{"protocol": "1"}),
	)
	findings, err := SSHDProtocol2(context.Background(), g)
	if err != nil {
		t.Fatalf("SSHDProtocol2: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	want := map[string]compliancekit.Status{
		"modern":    compliancekit.StatusPass,
		"explicit2": compliancekit.StatusPass,
		"legacy":    compliancekit.StatusFail,
	}
	for _, f := range findings {
		if f.Status != want[f.Resource.Name] {
			t.Errorf("%s: %s, want %s", f.Resource.Name, f.Status, want[f.Resource.Name])
		}
	}
}

func TestSSHDMaxAuthTries(t *testing.T) {
	g := newGraph(t,
		hostWithSSHD("low", map[string]string{"maxauthtries": "3"}),
		hostWithSSHD("limit", map[string]string{"maxauthtries": "4"}),
		hostWithSSHD("high", map[string]string{"maxauthtries": "10"}),
		hostWithSSHD("absent", map[string]string{}),
		hostWithSSHD("garbage", map[string]string{"maxauthtries": "many"}),
	)
	findings, err := SSHDMaxAuthTries(context.Background(), g)
	if err != nil {
		t.Fatalf("SSHDMaxAuthTries: %v", err)
	}

	byHost := map[string]compliancekit.Status{}
	for _, f := range findings {
		byHost[f.Resource.Name] = f.Status
	}
	if byHost["low"] != compliancekit.StatusPass {
		t.Errorf("low (3): %s, want pass", byHost["low"])
	}
	if byHost["limit"] != compliancekit.StatusPass {
		t.Errorf("limit (4): %s, want pass", byHost["limit"])
	}
	if byHost["high"] != compliancekit.StatusFail {
		t.Errorf("high (10): %s, want fail", byHost["high"])
	}
	if byHost["absent"] != compliancekit.StatusFail {
		t.Errorf("absent: %s, want fail", byHost["absent"])
	}
	if byHost["garbage"] != compliancekit.StatusError {
		t.Errorf("garbage value: %s, want error", byHost["garbage"])
	}
}

func TestSSHDLoginGraceTime_DurationFormats(t *testing.T) {
	cases := []struct {
		raw      string
		seconds  int
		ok       bool
		wantPass bool
	}{
		{"60", 60, true, true},
		{"60s", 60, true, true},
		{"30s", 30, true, true},
		{"1m", 60, true, true},
		{"2m", 120, true, false}, // exceeds 60s ceiling
		{"1h", 3600, true, false},
		{"banana", 0, false, false},
	}
	for _, tc := range cases {
		got, err := parseSSHDDuration(tc.raw)
		if tc.ok {
			if err != nil {
				t.Errorf("parseSSHDDuration(%q): unexpected error: %v", tc.raw, err)
				continue
			}
			if got != tc.seconds {
				t.Errorf("parseSSHDDuration(%q) = %d, want %d", tc.raw, got, tc.seconds)
			}
		} else if err == nil {
			t.Errorf("parseSSHDDuration(%q): expected error, got %d", tc.raw, got)
		}
	}
}

func TestSSHDLoginGraceTime_Findings(t *testing.T) {
	g := newGraph(t,
		hostWithSSHD("good-int", map[string]string{"logingracetime": "30"}),
		hostWithSSHD("good-suffix", map[string]string{"logingracetime": "60s"}),
		hostWithSSHD("bad", map[string]string{"logingracetime": "2m"}),
		hostWithSSHD("absent", map[string]string{}),
	)
	findings, err := SSHDLoginGraceTime(context.Background(), g)
	if err != nil {
		t.Fatalf("SSHDLoginGraceTime: %v", err)
	}
	byHost := map[string]compliancekit.Status{}
	for _, f := range findings {
		byHost[f.Resource.Name] = f.Status
	}
	if byHost["good-int"] != compliancekit.StatusPass {
		t.Errorf("good-int: %s, want pass", byHost["good-int"])
	}
	if byHost["good-suffix"] != compliancekit.StatusPass {
		t.Errorf("good-suffix: %s, want pass", byHost["good-suffix"])
	}
	if byHost["bad"] != compliancekit.StatusFail {
		t.Errorf("bad: %s, want fail", byHost["bad"])
	}
	if byHost["absent"] != compliancekit.StatusFail {
		t.Errorf("absent: %s, want fail", byHost["absent"])
	}
}

func TestSSHDChecks_RegisterIntoDefaultRegistry(t *testing.T) {
	for _, id := range []string{
		CheckSSHDNoRootLogin.ID,
		CheckSSHDNoPasswordAuth.ID,
		CheckSSHDProtocol2.ID,
		CheckSSHDMaxAuthTries.ID,
		CheckSSHDLoginGraceTime.ID,
	} {
		if _, ok := compliancekit.Lookup(id); !ok {
			t.Errorf("check %q not registered", id)
		}
	}
}
