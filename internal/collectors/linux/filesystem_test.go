package linux

import "testing"

func TestParseStatLines_HappyPath(t *testing.T) {
	output := `640 0 root 42 shadow /etc/shadow
644 0 root 0 root /etc/passwd
700 0 root 0 root /root
`
	got := parseStatLines(output)
	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3", len(got))
	}

	shadow := got["/etc/shadow"]
	if shadow.Mode != 0o640 {
		t.Errorf("shadow.Mode = %o, want 640", shadow.Mode)
	}
	if shadow.User != "root" || shadow.Group != "shadow" {
		t.Errorf("shadow owner = %s:%s, want root:shadow", shadow.User, shadow.Group)
	}

	passwd := got["/etc/passwd"]
	if passwd.Mode != 0o644 {
		t.Errorf("passwd.Mode = %o, want 644", passwd.Mode)
	}

	root := got["/root"]
	if root.Mode != 0o700 {
		t.Errorf("root.Mode = %o, want 700", root.Mode)
	}
}

func TestParseStatLines_SkipsMalformed(t *testing.T) {
	output := `garbage
640 0 root 42 shadow /etc/shadow
also garbage
`
	got := parseStatLines(output)
	if len(got) != 1 {
		t.Errorf("expected 1 valid entry, got %d", len(got))
	}
}

func TestParseStatLines_MasksTypeBits(t *testing.T) {
	// stat can include the file-type bits in the mode (e.g. 100640 for
	// a regular file with 0o640 perms). Some shells / busybox emit
	// these. We mask to permission bits only.
	output := `100640 0 root 42 shadow /etc/shadow`
	got := parseStatLines(output)
	if got["/etc/shadow"].Mode != 0o640 {
		t.Errorf("mode after mask = %o, want 640", got["/etc/shadow"].Mode)
	}
}
