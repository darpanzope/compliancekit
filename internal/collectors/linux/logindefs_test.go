package linux

import "testing"

const loginDefsFixture = `# /etc/login.defs - Configuration control definitions for the shadow package.

MAIL_DIR        /var/mail

PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_WARN_AGE   7

ENCRYPT_METHOD SHA512

UMASK           027
`

func TestParseLoginDefs(t *testing.T) {
	ld := ParseLoginDefs(loginDefsFixture)
	if !ld.HasPassMaxDays || ld.PassMaxDays != 90 {
		t.Errorf("PassMaxDays=%d has=%v", ld.PassMaxDays, ld.HasPassMaxDays)
	}
	if ld.PassMinDays != 1 || ld.PassWarnAge != 7 {
		t.Errorf("PassMinDays=%d PassWarnAge=%d", ld.PassMinDays, ld.PassWarnAge)
	}
	if ld.EncryptMethod != "SHA512" {
		t.Errorf("EncryptMethod=%q", ld.EncryptMethod)
	}
	if ld.Umask != "027" || !ld.HasUmask {
		t.Errorf("Umask=%q has=%v", ld.Umask, ld.HasUmask)
	}
}

func TestParseLoginDefs_Empty(t *testing.T) {
	ld := ParseLoginDefs("")
	if ld.HasPassMaxDays || ld.HasUmask {
		t.Errorf("empty input should yield zero-value LoginDefs: %+v", ld)
	}
}
