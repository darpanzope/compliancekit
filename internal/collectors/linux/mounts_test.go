package linux

import "testing"

// v0.20 phase 3 — table tests for ParseProcMounts + MountEntry helpers.

const procMountsFixture = `proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
devtmpfs /dev devtmpfs rw,nosuid,size=4017028k,nr_inodes=1004257,mode=755 0 0
/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,size=2g 0 0
/dev/sda2 /var ext4 rw,nodev,noexec,relatime 0 0
/dev/sda3 /home ext4 rw,nodev,nosuid,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0
`

func TestParseProcMounts(t *testing.T) {
	mounts := ParseProcMounts(procMountsFixture)
	if len(mounts) != 8 {
		t.Fatalf("mounts=%d want 8", len(mounts))
	}
	tmp, ok := FindMount(mounts, "/tmp")
	if !ok {
		t.Fatal("missing /tmp mount")
	}
	if tmp.FSType != "tmpfs" {
		t.Errorf("/tmp fstype=%q want tmpfs", tmp.FSType)
	}
	for _, want := range []string{"nosuid", "nodev", "noexec"} {
		if !tmp.HasOption(want) {
			t.Errorf("/tmp missing %s", want)
		}
	}
	if tmp.HasOption("bogus") {
		t.Error("/tmp should not have bogus option")
	}
}

func TestParseProcMounts_Empty(t *testing.T) {
	if got := ParseProcMounts(""); len(got) != 0 {
		t.Errorf("empty input → %d entries", len(got))
	}
}

func TestParseProcMounts_MalformedSkipped(t *testing.T) {
	body := "complete /tmp tmpfs rw 0 0\nmalformed line here\n/dev/sda / ext4 rw\n"
	got := ParseProcMounts(body)
	if len(got) != 2 {
		t.Errorf("expected 2 valid lines, got %d", len(got))
	}
}

func TestFindMount_Missing(t *testing.T) {
	mounts := ParseProcMounts(procMountsFixture)
	_, ok := FindMount(mounts, "/nonexistent")
	if ok {
		t.Error("FindMount should report false for missing path")
	}
}
