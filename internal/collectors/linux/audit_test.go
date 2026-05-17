package linux

import "testing"

func TestParseJournaldStorage_ExplicitPersistent(t *testing.T) {
	conf := `[Journal]
Storage=persistent
SystemMaxUse=200M
`
	if got := parseJournaldStorage(conf); got != "persistent" {
		t.Errorf("got %q, want persistent", got)
	}
}

func TestParseJournaldStorage_CommentedDefaultsToAuto(t *testing.T) {
	conf := `[Journal]
#Storage=auto
#SystemMaxUse=
`
	if got := parseJournaldStorage(conf); got != "auto" {
		t.Errorf("got %q, want auto (per journald.conf(5) default)", got)
	}
}

func TestParseJournaldStorage_EmptyFileDefaultsToAuto(t *testing.T) {
	if got := parseJournaldStorage(""); got != "auto" {
		t.Errorf("got %q, want auto", got)
	}
}

func TestParseJournaldStorage_HandlesValueWhitespace(t *testing.T) {
	conf := `Storage=  volatile  `
	if got := parseJournaldStorage(conf); got != "volatile" {
		t.Errorf("got %q, want volatile (whitespace stripped)", got)
	}
}

func TestParseJournaldStorage_OtherDirectivesIgnored(t *testing.T) {
	conf := `[Journal]
SystemMaxUse=200M
SyncIntervalSec=5m
`
	// No Storage= line at all -> default applies.
	if got := parseJournaldStorage(conf); got != "auto" {
		t.Errorf("got %q, want auto when Storage= absent", got)
	}
}

// v0.20 phase 11 — coverage for ParseAuditRules.

func TestParseAuditRules(t *testing.T) {
	body := `# auditctl -l output (typical)
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity

-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
   # trailing comment
`
	rules := ParseAuditRules(body)
	if len(rules) != 3 {
		t.Fatalf("ParseAuditRules: got %d rules, want 3 (%v)", len(rules), rules)
	}
	want := []string{
		"-w /etc/passwd -p wa -k identity",
		"-w /etc/shadow -p wa -k identity",
		"-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change",
	}
	for i, w := range want {
		if rules[i] != w {
			t.Errorf("rule[%d]=%q want %q", i, rules[i], w)
		}
	}
}

func TestParseAuditRules_Empty(t *testing.T) {
	if rules := ParseAuditRules(""); len(rules) != 0 {
		t.Errorf("ParseAuditRules(''): %v, want empty", rules)
	}
}

func TestParseAuditRules_OnlyComments(t *testing.T) {
	body := `# first
# second
   # third (indented)
`
	if rules := ParseAuditRules(body); len(rules) != 0 {
		t.Errorf("ParseAuditRules(comment-only): %v, want empty", rules)
	}
}
