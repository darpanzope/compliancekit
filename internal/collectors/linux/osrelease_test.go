package linux

import (
	"os"
	"path/filepath"
	"testing"
)

// v0.20 phase 1 — table-driven test for ParseOSRelease across the
// canonical fixtures. Each fixture is a verbatim /etc/os-release
// from a real install (no synthesis), so the parser handles every
// quote / spacing / field-ordering variant we encounter in the wild.

func TestParseOSRelease(t *testing.T) {
	cases := []struct {
		name        string
		fixture     string
		wantID      string
		wantIDLike  string
		wantVersion string
		isDebianFam bool
		isRHELFam   bool
		isAlpine    bool
		isAmazon    bool
	}{
		{
			name: "ubuntu 22.04", fixture: "ubuntu-22.04.txt",
			wantID: "ubuntu", wantIDLike: "debian", wantVersion: "22.04",
			isDebianFam: true,
		},
		{
			name: "debian 12 no id_like", fixture: "debian-12.txt",
			wantID: "debian", wantIDLike: "", wantVersion: "12",
			isDebianFam: true,
		},
		{
			name: "rhel 9", fixture: "rhel-9.txt",
			wantID: "rhel", wantIDLike: "fedora", wantVersion: "9.3",
			isRHELFam: true,
		},
		{
			name: "alpine 3.19", fixture: "alpine-3.19.txt",
			wantID: "alpine", wantIDLike: "", wantVersion: "3.19.1",
			isAlpine: true,
		},
		{
			name: "amazon linux 2023", fixture: "amzn-2023.txt",
			wantID: "amzn", wantIDLike: "fedora", wantVersion: "2023",
			isRHELFam: true, // amzn 2023 is in the fedora family
			isAmazon:  true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", "distros", c.fixture))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			rel, err := ParseOSRelease(string(body))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if rel.ID != c.wantID {
				t.Errorf("ID=%q want %q", rel.ID, c.wantID)
			}
			if rel.IDLike != c.wantIDLike {
				t.Errorf("IDLike=%q want %q", rel.IDLike, c.wantIDLike)
			}
			if rel.VersionID != c.wantVersion {
				t.Errorf("VersionID=%q want %q", rel.VersionID, c.wantVersion)
			}
			if rel.IsDebianFamily() != c.isDebianFam {
				t.Errorf("IsDebianFamily=%v want %v", rel.IsDebianFamily(), c.isDebianFam)
			}
			if rel.IsRHELFamily() != c.isRHELFam {
				t.Errorf("IsRHELFamily=%v want %v", rel.IsRHELFamily(), c.isRHELFam)
			}
			if rel.IsAlpine() != c.isAlpine {
				t.Errorf("IsAlpine=%v want %v", rel.IsAlpine(), c.isAlpine)
			}
			if rel.IsAmazonLinux() != c.isAmazon {
				t.Errorf("IsAmazonLinux=%v want %v", rel.IsAmazonLinux(), c.isAmazon)
			}
			if rel.PrettyName == "" {
				t.Errorf("PrettyName empty — every supported distro sets it")
			}
		})
	}
}

func TestParseOSRelease_Quotes(t *testing.T) {
	body := `ID=unquoted
ID_LIKE="double quoted"
VERSION_ID='single quoted'
PRETTY_NAME="My Distro 1.0"
# comment line
EMPTY=
NO_EQUALS_SIGN`
	rel, err := ParseOSRelease(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rel.ID != "unquoted" {
		t.Errorf("ID=%q", rel.ID)
	}
	if rel.IDLike != "double quoted" {
		t.Errorf("IDLike=%q", rel.IDLike)
	}
	if rel.VersionID != "single quoted" {
		t.Errorf("VersionID=%q", rel.VersionID)
	}
}
