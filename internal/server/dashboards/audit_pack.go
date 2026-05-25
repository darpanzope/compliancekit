package dashboards

// v1.14 phase 8 — audit-pack profile storage.
//
// A profile records which artifacts an auditor should receive for a
// given engagement. The artifact set is closed (CanonicalArtifacts)
// so a typo in the UI can't pin a dashboard at a non-existent
// artifact ID; the dashboard set is open — any saved dashboard can
// be PDF-rendered into the pack.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Artifact names the canonical evidence artifacts the v0.4 evidence
// pack already emits. The audit-pack profile picks which subset of
// these to include alongside the dashboard PDFs.
type Artifact string

// Artifact constants — the closed set the profile UI offers.
const (
	ArtifactFindingsCSV     Artifact = "findings.csv"
	ArtifactVulnsCSV        Artifact = "vulnerabilities.csv"
	ArtifactSecretsCSV      Artifact = "secrets.csv"
	ArtifactPoAMOSCAL       Artifact = "poam.oscal.json"
	ArtifactWaiversJSON     Artifact = "waivers.json"
	ArtifactScanJSON        Artifact = "scan.json"
	ArtifactSummaryMarkdown Artifact = "summary.md"
)

// CanonicalArtifacts is the iteration order the profile UI offers
// in its picker.
var CanonicalArtifacts = []Artifact{
	ArtifactFindingsCSV,
	ArtifactVulnsCSV,
	ArtifactSecretsCSV,
	ArtifactPoAMOSCAL,
	ArtifactWaiversJSON,
	ArtifactScanJSON,
	ArtifactSummaryMarkdown,
}

// AuditPackProfile is the row shape.
type AuditPackProfile struct {
	ID              string
	Name            string
	Description     string
	Artifacts       []Artifact
	Dashboards      []string // dashboard IDs to PDF-render
	CreatedByUserID string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// CreateAuditPackProfile persists a new profile. Validates every
// artifact is in CanonicalArtifacts so a malformed UI payload can't
// poison the table.
func (s *Store) CreateAuditPackProfile(ctx context.Context, in *AuditPackProfile) (*AuditPackProfile, error) {
	if in == nil || in.Name == "" {
		return nil, errors.New("dashboards: profile.Name required")
	}
	for _, a := range in.Artifacts {
		if !isCanonicalArtifact(a) {
			return nil, fmt.Errorf("dashboards: unknown artifact %q", a)
		}
	}
	in.ID = uuid.NewString()
	now := time.Now().UTC()
	in.CreatedAt = now
	in.UpdatedAt = now
	artifacts, _ := json.Marshal(in.Artifacts)
	dashboards, _ := json.Marshal(in.Dashboards)
	q := `INSERT INTO audit_pack_profiles
	      (id, name, description, artifacts_json, dashboards_json,
	       created_by_user_id, created_at, updated_at)
	      VALUES (` + s.phList(8) + `)`
	if _, err := s.store.DB().ExecContext(ctx, q,
		in.ID, in.Name, in.Description,
		string(artifacts), string(dashboards),
		nullable(in.CreatedByUserID),
		in.CreatedAt.Format(time.RFC3339),
		in.UpdatedAt.Format(time.RFC3339)); err != nil {
		return nil, fmt.Errorf("insert profile: %w", err)
	}
	return in, nil
}

// ListAuditPackProfiles returns every profile, newest first.
func (s *Store) ListAuditPackProfiles(ctx context.Context) ([]*AuditPackProfile, error) {
	rows, err := s.store.DB().QueryContext(ctx,
		`SELECT id, name, description, artifacts_json, dashboards_json,
		        COALESCE(created_by_user_id,''),
		        created_at, updated_at
		 FROM audit_pack_profiles ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*AuditPackProfile
	for rows.Next() {
		p := &AuditPackProfile{}
		var artifacts, dashboards, created, updated string
		if err := rows.Scan(&p.ID, &p.Name, &p.Description,
			&artifacts, &dashboards, &p.CreatedByUserID,
			&created, &updated); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(artifacts), &p.Artifacts)
		_ = json.Unmarshal([]byte(dashboards), &p.Dashboards)
		p.CreatedAt = parseTime(created)
		p.UpdatedAt = parseTime(updated)
		out = append(out, p)
	}
	return out, rows.Err()
}

// AuditPackProfileByID returns one row.
func (s *Store) AuditPackProfileByID(ctx context.Context, id string) (*AuditPackProfile, error) {
	row := s.store.DB().QueryRowContext(ctx,
		`SELECT id, name, description, artifacts_json, dashboards_json,
		        COALESCE(created_by_user_id,''),
		        created_at, updated_at
		 FROM audit_pack_profiles WHERE id = `+s.ph(1), id)
	p := &AuditPackProfile{}
	var artifacts, dashboards, created, updated string
	if err := row.Scan(&p.ID, &p.Name, &p.Description,
		&artifacts, &dashboards, &p.CreatedByUserID,
		&created, &updated); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(artifacts), &p.Artifacts)
	_ = json.Unmarshal([]byte(dashboards), &p.Dashboards)
	p.CreatedAt = parseTime(created)
	p.UpdatedAt = parseTime(updated)
	return p, nil
}

// UpdateAuditPackProfile rewrites a profile.
func (s *Store) UpdateAuditPackProfile(ctx context.Context, in *AuditPackProfile) error {
	if in == nil || in.ID == "" {
		return errors.New("dashboards: profile.ID required")
	}
	for _, a := range in.Artifacts {
		if !isCanonicalArtifact(a) {
			return fmt.Errorf("dashboards: unknown artifact %q", a)
		}
	}
	artifacts, _ := json.Marshal(in.Artifacts)
	dashboards, _ := json.Marshal(in.Dashboards)
	q := `UPDATE audit_pack_profiles SET name = ` + s.ph(1) +
		`, description = ` + s.ph(2) +
		`, artifacts_json = ` + s.ph(3) +
		`, dashboards_json = ` + s.ph(4) +
		`, updated_at = ` + s.ph(5) +
		` WHERE id = ` + s.ph(6)
	_, err := s.store.DB().ExecContext(ctx, q,
		in.Name, in.Description, string(artifacts), string(dashboards),
		time.Now().UTC().Format(time.RFC3339), in.ID)
	return err
}

// DeleteAuditPackProfile removes a row.
func (s *Store) DeleteAuditPackProfile(ctx context.Context, id string) error {
	_, err := s.store.DB().ExecContext(ctx,
		`DELETE FROM audit_pack_profiles WHERE id = `+s.ph(1), id)
	return err
}

func isCanonicalArtifact(a Artifact) bool {
	for _, k := range CanonicalArtifacts {
		if k == a {
			return true
		}
	}
	return false
}
