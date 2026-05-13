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
