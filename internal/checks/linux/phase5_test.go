package linux

import (
	"context"
	"testing"

	linuxcol "github.com/darpanzope/compliancekit/internal/collectors/linux"
	"github.com/darpanzope/compliancekit/internal/core"
)

// ============================================================
// filesystem checks
// ============================================================

func hostWithFS(name string, fs map[string]any) core.Resource {
	return hostWithAttrs(name, map[string]any{"filesystem": fs})
}

func TestShadowPerms(t *testing.T) {
	g := newGraph(t,
		hostWithFS("good", map[string]any{
			"/etc/shadow": linuxcol.FileFacts{Mode: 0o640, User: "root", Group: "shadow"},
		}),
		hostWithFS("loose-mode", map[string]any{
			"/etc/shadow": linuxcol.FileFacts{Mode: 0o644, User: "root", Group: "shadow"},
		}),
		hostWithFS("wrong-group", map[string]any{
			"/etc/shadow": linuxcol.FileFacts{Mode: 0o640, User: "root", Group: "root"},
		}),
		hostWithFS("missing", map[string]any{}),
	)
	findings, err := ShadowPerms(context.Background(), g)
	if err != nil {
		t.Fatalf("ShadowPerms: %v", err)
	}
	byHost := map[string]core.Status{}
	for _, f := range findings {
		byHost[f.Resource.Name] = f.Status
	}
	want := map[string]core.Status{
		"good":        core.StatusPass,
		"loose-mode":  core.StatusFail,
		"wrong-group": core.StatusFail,
		"missing":     core.StatusSkip,
	}
	for h, w := range want {
		if byHost[h] != w {
			t.Errorf("%s: %s, want %s", h, byHost[h], w)
		}
	}
}

func TestPasswdPerms(t *testing.T) {
	g := newGraph(t,
		hostWithFS("0644", map[string]any{
			"/etc/passwd": linuxcol.FileFacts{Mode: 0o644, User: "root"},
		}),
		hostWithFS("0640-stricter", map[string]any{
			"/etc/passwd": linuxcol.FileFacts{Mode: 0o640, User: "root"},
		}),
		hostWithFS("group-writable", map[string]any{
			"/etc/passwd": linuxcol.FileFacts{Mode: 0o664, User: "root"},
		}),
		hostWithFS("wrong-owner", map[string]any{
			"/etc/passwd": linuxcol.FileFacts{Mode: 0o644, User: "alice"},
		}),
	)
	findings, err := PasswdPerms(context.Background(), g)
	if err != nil {
		t.Fatalf("PasswdPerms: %v", err)
	}
	byHost := map[string]core.Status{}
	for _, f := range findings {
		byHost[f.Resource.Name] = f.Status
	}
	if byHost["0644"] != core.StatusPass {
		t.Errorf("0644: %s, want pass", byHost["0644"])
	}
	if byHost["0640-stricter"] != core.StatusPass {
		t.Errorf("0640: %s, want pass (stricter than 0644)", byHost["0640-stricter"])
	}
	if byHost["group-writable"] != core.StatusFail {
		t.Errorf("group-writable: %s, want fail", byHost["group-writable"])
	}
	if byHost["wrong-owner"] != core.StatusFail {
		t.Errorf("wrong-owner: %s, want fail", byHost["wrong-owner"])
	}
}

// ============================================================
// user checks
// ============================================================

func hostWithUsers(name string, accounts []linuxcol.UserAccount, shadowReadable bool) core.Resource {
	return hostWithAttrs(name, map[string]any{
		"users": map[string]any{
			"accounts":        accounts,
			"shadow_readable": shadowReadable,
		},
	})
}

func TestUIDZeroOnlyRoot(t *testing.T) {
	g := newGraph(t,
		hostWithUsers("clean", []linuxcol.UserAccount{
			{Name: "root", UID: 0},
			{Name: "alice", UID: 1000},
		}, true),
		hostWithUsers("backdoor", []linuxcol.UserAccount{
			{Name: "root", UID: 0},
			{Name: "evil", UID: 0},
		}, true),
	)
	findings, err := UIDZeroOnlyRoot(context.Background(), g)
	if err != nil {
		t.Fatalf("UIDZeroOnlyRoot: %v", err)
	}
	byHost := map[string]core.Status{}
	for _, f := range findings {
		byHost[f.Resource.Name] = f.Status
	}
	if byHost["clean"] != core.StatusPass {
		t.Errorf("clean: %s, want pass", byHost["clean"])
	}
	if byHost["backdoor"] != core.StatusFail {
		t.Errorf("backdoor: %s, want fail", byHost["backdoor"])
	}
}

func TestNoEmptyPasswords(t *testing.T) {
	g := newGraph(t,
		hostWithUsers("good", []linuxcol.UserAccount{
			{Name: "root", UID: 0, HasEmptyPassword: false},
			{Name: "alice", UID: 1000, HasEmptyPassword: false},
		}, true),
		hostWithUsers("bad", []linuxcol.UserAccount{
			{Name: "ghost", UID: 1001, HasEmptyPassword: true},
		}, true),
		hostWithUsers("shadow-locked", []linuxcol.UserAccount{
			{Name: "root", UID: 0},
		}, false), // shadow_readable=false
	)
	findings, err := NoEmptyPasswords(context.Background(), g)
	if err != nil {
		t.Fatalf("NoEmptyPasswords: %v", err)
	}
	byHost := map[string]core.Status{}
	for _, f := range findings {
		byHost[f.Resource.Name] = f.Status
	}
	if byHost["good"] != core.StatusPass {
		t.Errorf("good: %s, want pass", byHost["good"])
	}
	if byHost["bad"] != core.StatusFail {
		t.Errorf("bad: %s, want fail", byHost["bad"])
	}
	if byHost["shadow-locked"] != core.StatusSkip {
		t.Errorf("shadow-locked: %s, want skip (cannot confirm without shadow)", byHost["shadow-locked"])
	}
}

// ============================================================
// kernel checks
// ============================================================

func hostWithKernel(name string, k map[string]any) core.Resource {
	return hostWithAttrs(name, map[string]any{"kernel": k})
}

func TestASLREnabled(t *testing.T) {
	g := newGraph(t,
		hostWithKernel("good", map[string]any{"randomize_va_space": 2}),
		hostWithKernel("weak", map[string]any{"randomize_va_space": 1}),
		hostWithKernel("off", map[string]any{"randomize_va_space": 0}),
		hostWithKernel("missing", map[string]any{}),
	)
	findings, err := ASLREnabled(context.Background(), g)
	if err != nil {
		t.Fatalf("ASLREnabled: %v", err)
	}
	byHost := map[string]core.Status{}
	for _, f := range findings {
		byHost[f.Resource.Name] = f.Status
	}
	want := map[string]core.Status{
		"good":    core.StatusPass,
		"weak":    core.StatusFail,
		"off":     core.StatusFail,
		"missing": core.StatusSkip,
	}
	for h, w := range want {
		if byHost[h] != w {
			t.Errorf("%s: %s, want %s", h, byHost[h], w)
		}
	}
}

func TestNoSourceRouting(t *testing.T) {
	g := newGraph(t,
		hostWithKernel("good", map[string]any{"accept_source_route_all": 0}),
		hostWithKernel("bad", map[string]any{"accept_source_route_all": 1}),
	)
	findings, err := NoSourceRouting(context.Background(), g)
	if err != nil {
		t.Fatalf("NoSourceRouting: %v", err)
	}
	byHost := map[string]core.Status{}
	for _, f := range findings {
		byHost[f.Resource.Name] = f.Status
	}
	if byHost["good"] != core.StatusPass {
		t.Errorf("good: %s, want pass", byHost["good"])
	}
	if byHost["bad"] != core.StatusFail {
		t.Errorf("bad: %s, want fail", byHost["bad"])
	}
}

func TestPhase5Checks_RegisterIntoDefaultRegistry(t *testing.T) {
	for _, id := range []string{
		CheckShadowPerms.ID,
		CheckPasswdPerms.ID,
		CheckUIDZeroOnlyRoot.ID,
		CheckNoEmptyPasswords.ID,
		CheckASLREnabled.ID,
		CheckNoSourceRouting.ID,
	} {
		if _, ok := core.Lookup(id); !ok {
			t.Errorf("check %q not registered", id)
		}
	}
}
