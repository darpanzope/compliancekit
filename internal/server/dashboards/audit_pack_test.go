package dashboards

import (
	"context"
	"testing"
)

func TestCreateAuditPackProfile_HappyPath(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	d, _ := s.CreateDashboard(ctx, "", "", "Exec board", "", "")

	in := &AuditPackProfile{
		Name:        "SOC 2 Q3",
		Description: "Q3 SOC 2 audit pack",
		Artifacts:   []Artifact{ArtifactFindingsCSV, ArtifactWaiversJSON, ArtifactPoAMOSCAL},
		Dashboards:  []string{d.ID},
	}
	got, err := s.CreateAuditPackProfile(ctx, in)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got.ID == "" {
		t.Errorf("expected ID populated")
	}
	loaded, err := s.AuditPackProfileByID(ctx, got.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if len(loaded.Artifacts) != 3 {
		t.Errorf("artifacts roundtrip: got %d want 3", len(loaded.Artifacts))
	}
	if len(loaded.Dashboards) != 1 || loaded.Dashboards[0] != d.ID {
		t.Errorf("dashboards roundtrip: got %v", loaded.Dashboards)
	}
}

func TestCreateAuditPackProfile_UnknownArtifact(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	_, err := s.CreateAuditPackProfile(ctx, &AuditPackProfile{
		Name:      "x",
		Artifacts: []Artifact{Artifact("not-a-thing")},
	})
	if err == nil {
		t.Errorf("expected error on unknown artifact")
	}
}

func TestUpdateAuditPackProfile(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	p, _ := s.CreateAuditPackProfile(ctx, &AuditPackProfile{
		Name:      "first",
		Artifacts: []Artifact{ArtifactFindingsCSV},
	})
	p.Name = "second"
	p.Artifacts = []Artifact{ArtifactFindingsCSV, ArtifactVulnsCSV}
	if err := s.UpdateAuditPackProfile(ctx, p); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := s.AuditPackProfileByID(ctx, p.ID)
	if got.Name != "second" {
		t.Errorf("name update missed: %q", got.Name)
	}
	if len(got.Artifacts) != 2 {
		t.Errorf("artifacts update missed: %v", got.Artifacts)
	}
}

func TestListAuditPackProfiles(t *testing.T) {
	ctx := context.Background()
	_, s := newTestStore(t)
	for i := 0; i < 3; i++ {
		if _, err := s.CreateAuditPackProfile(ctx, &AuditPackProfile{Name: "p"}); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	got, _ := s.ListAuditPackProfiles(ctx)
	if len(got) != 3 {
		t.Errorf("list len = %d want 3", len(got))
	}
}

func TestCanonicalArtifactsCoverage(t *testing.T) {
	for _, a := range CanonicalArtifacts {
		if !isCanonicalArtifact(a) {
			t.Errorf("artifact %q in CanonicalArtifacts but not isCanonicalArtifact", a)
		}
	}
}
