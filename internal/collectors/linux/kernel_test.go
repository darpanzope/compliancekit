package linux

import "testing"

// v0.20 phase 2 — kernel collector now uses `sysctl key1 key2 ...`
// (without -n) so output is `name = value` per line. ParseSysctlOutput
// converts that into a string-keyed integer map.

func TestParseSysctlOutput_HappyPath(t *testing.T) {
	output := `kernel.randomize_va_space = 2
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
`
	got := ParseSysctlOutput(output)
	if got["kernel.randomize_va_space"] != 2 {
		t.Errorf("randomize_va_space=%d want 2", got["kernel.randomize_va_space"])
	}
	if got["net.ipv4.tcp_syncookies"] != 1 {
		t.Errorf("tcp_syncookies=%d want 1", got["net.ipv4.tcp_syncookies"])
	}
}

func TestParseSysctlOutput_SkipsNonNumeric(t *testing.T) {
	// Tunables with comma-separated lists or non-integer payloads are
	// silently skipped — the v0.20 check surface only consults
	// integer-valued knobs.
	output := `kernel.dmesg_restrict = 1
kernel.osrelease = 5.15.0-generic
kernel.kptr_restrict = 2
`
	got := ParseSysctlOutput(output)
	if got["kernel.dmesg_restrict"] != 1 || got["kernel.kptr_restrict"] != 2 {
		t.Errorf("missing expected ints: %+v", got)
	}
	if _, ok := got["kernel.osrelease"]; ok {
		t.Errorf("non-integer value should be skipped: %+v", got)
	}
}

func TestParseSysctlOutput_EmptyInput(t *testing.T) {
	if got := ParseSysctlOutput(""); len(got) != 0 {
		t.Errorf("empty input should yield empty map, got %v", got)
	}
}

func TestParseSysctlOutput_MultiTokenValues(t *testing.T) {
	// `sysctl` sometimes emits keys with multi-token values
	// (net.core.somaxconn, etc.). The first integer token wins.
	output := "net.core.somaxconn = 4096 something_else\n"
	if got := ParseSysctlOutput(output); got["net.core.somaxconn"] != 4096 {
		t.Errorf("somaxconn=%d want 4096", got["net.core.somaxconn"])
	}
}

func TestSysctlKeys_NonEmpty(t *testing.T) {
	if len(SysctlKeys) < 30 {
		t.Errorf("SysctlKeys=%d entries; v0.20 expects ≥30", len(SysctlKeys))
	}
}
