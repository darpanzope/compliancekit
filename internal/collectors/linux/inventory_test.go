package linux

import (
	"strings"
	"testing"
)

func TestParseInventory_HappyPath(t *testing.T) {
	data := []byte(`
groups:
  web:
    hosts:
      - host: web-01.acme.com
      - host: web-02.acme.com
        user: ubuntu
        port: 2222
  db:
    hosts:
      - host: db-01.acme.com
        ssh:
          key_file: ~/.ssh/db_key

hosts:
  - host: bastion.acme.com
    tags: [prod, jump]
`)

	inv, err := ParseInventory(data)
	if err != nil {
		t.Fatalf("ParseInventory: %v", err)
	}

	if got, want := len(inv.Hosts), 1; got != want {
		t.Errorf("len(inv.Hosts) = %d, want %d", got, want)
	}
	if got, want := len(inv.Groups), 2; got != want {
		t.Errorf("len(inv.Groups) = %d, want %d", got, want)
	}

	// Per-host overrides parsed correctly.
	web02 := inv.Groups["web"].Hosts[1]
	if web02.User != "ubuntu" {
		t.Errorf("web-02 User = %q, want ubuntu", web02.User)
	}
	if web02.Port != 2222 {
		t.Errorf("web-02 Port = %d, want 2222", web02.Port)
	}

	// Per-host SSH overrides parsed correctly.
	db01 := inv.Groups["db"].Hosts[0]
	if db01.SSH == nil || db01.SSH.KeyFile != "~/.ssh/db_key" {
		t.Errorf("db-01 SSH.KeyFile = %+v, want ~/.ssh/db_key", db01.SSH)
	}

	// Tags preserved.
	bastion := inv.Hosts[0]
	if len(bastion.Tags) != 2 || bastion.Tags[0] != "prod" {
		t.Errorf("bastion.Tags = %v, want [prod jump]", bastion.Tags)
	}
}

func TestAllHosts_DeterministicOrder(t *testing.T) {
	data := []byte(`
groups:
  zebra:
    hosts:
      - host: zebra-1
      - host: zebra-2
  alpha:
    hosts:
      - host: alpha-1
hosts:
  - host: top-1
`)

	inv, err := ParseInventory(data)
	if err != nil {
		t.Fatalf("ParseInventory: %v", err)
	}

	got := inv.AllHosts()
	wantOrder := []string{"top-1", "alpha-1", "zebra-1", "zebra-2"}
	if len(got) != len(wantOrder) {
		t.Fatalf("AllHosts() length = %d, want %d", len(got), len(wantOrder))
	}
	for i, h := range got {
		if h.Host != wantOrder[i] {
			t.Errorf("AllHosts()[%d].Host = %q, want %q", i, h.Host, wantOrder[i])
		}
	}

	// Group is populated on grouped hosts, empty on top-level.
	if got[0].Group != "" {
		t.Errorf("top-1 Group = %q, want empty", got[0].Group)
	}
	if got[1].Group != "alpha" {
		t.Errorf("alpha-1 Group = %q, want alpha", got[1].Group)
	}
}

func TestValidate_RejectsEmpty(t *testing.T) {
	_, err := ParseInventory([]byte(`{}`))
	if err == nil {
		t.Error("expected error for empty inventory")
	}
	if !strings.Contains(err.Error(), "no hosts or groups") {
		t.Errorf("expected 'no hosts or groups', got: %v", err)
	}
}

func TestValidate_RejectsEmptyHost(t *testing.T) {
	data := []byte(`
hosts:
  - host: ""
`)
	_, err := ParseInventory(data)
	if err == nil {
		t.Error("expected error for empty host field")
	}
}

func TestValidate_RejectsDuplicate(t *testing.T) {
	data := []byte(`
hosts:
  - host: web-01
groups:
  web:
    hosts:
      - host: web-01
`)
	_, err := ParseInventory(data)
	if err == nil {
		t.Fatal("expected error for duplicate host")
	}
	if !strings.Contains(err.Error(), "duplicate") && !strings.Contains(err.Error(), "appears in both") {
		t.Errorf("expected duplicate-host error, got: %v", err)
	}
}

func TestValidate_RejectsMalformedYAML(t *testing.T) {
	_, err := ParseInventory([]byte(`{not: valid: yaml`))
	if err == nil {
		t.Error("expected parse error for malformed YAML")
	}
}

func TestHostSSH_StrictHostKeyPointer(t *testing.T) {
	// strict_host_key must be a *bool so "false" differs from "unset".
	data := []byte(`
hosts:
  - host: explicit-false
    ssh:
      strict_host_key: false
  - host: unset
    ssh:
      key_file: /tmp/x
`)
	inv, err := ParseInventory(data)
	if err != nil {
		t.Fatalf("ParseInventory: %v", err)
	}

	hf := inv.Hosts[0]
	if hf.SSH == nil || hf.SSH.StrictHostKey == nil {
		t.Fatalf("explicit-false SSH = %+v", hf.SSH)
	}
	if *hf.SSH.StrictHostKey {
		t.Errorf("explicit-false: StrictHostKey deref = true, want false")
	}

	un := inv.Hosts[1]
	if un.SSH == nil {
		t.Fatal("unset host SSH was nil but key_file set")
	}
	if un.SSH.StrictHostKey != nil {
		t.Errorf("unset host StrictHostKey = %v, want nil pointer", un.SSH.StrictHostKey)
	}
}
