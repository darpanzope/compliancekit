package linux

import "testing"

func TestParseEmptyPasswordUsers(t *testing.T) {
	shadow := `root:$6$abc$hash:19000:0:99999:7:::
emptyuser::19000:0:99999:7:::
lockeduser:!:19000:0:99999:7:::
starlocked:*:19000:0:99999:7:::
`
	got := parseEmptyPasswordUsers(shadow)
	if !got["emptyuser"] {
		t.Error("emptyuser should be flagged with empty password")
	}
	if got["root"] {
		t.Error("root has a real hash; should not be flagged")
	}
	if got["lockeduser"] {
		t.Error("locked accounts (!) should not be flagged as empty")
	}
	if got["starlocked"] {
		t.Error("locked accounts (*) should not be flagged as empty")
	}
}

func TestParsePasswdAccounts(t *testing.T) {
	passwd := `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
evil:x:0:0:hidden root:/root:/bin/bash
`
	emptyShadow := map[string]bool{"alice": true}

	got := parsePasswdAccounts(passwd, emptyShadow)
	if len(got) != 4 {
		t.Fatalf("len(got) = %d, want 4", len(got))
	}

	byName := map[string]UserAccount{}
	for _, a := range got {
		byName[a.Name] = a
	}

	if byName["root"].UID != 0 {
		t.Errorf("root UID = %d, want 0", byName["root"].UID)
	}
	if byName["evil"].UID != 0 {
		t.Errorf("evil UID = %d, want 0 (test fixture)", byName["evil"].UID)
	}
	if !byName["alice"].HasEmptyPassword {
		t.Error("alice should be marked HasEmptyPassword=true")
	}
	if byName["root"].HasEmptyPassword {
		t.Error("root should not have empty password")
	}
}

func TestParsePasswdAccounts_SkipsMalformed(t *testing.T) {
	passwd := `not-enough-fields
root:x:0:0:root:/root:/bin/bash
root:x:NOTNUMERIC:0:root:/root:/bin/bash
`
	got := parsePasswdAccounts(passwd, nil)
	if len(got) != 1 {
		t.Errorf("expected 1 valid account, got %d", len(got))
	}
}
