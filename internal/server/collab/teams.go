package collab

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// Team is one row in the teams table + (optionally) a member count
// for list-view rendering.
type Team struct {
	ID          string
	Slug        string
	Name        string
	Description string
	CreatedByID string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	MemberCount int
}

// TeamMember is one row in team_members + a JOIN against users.
type TeamMember struct {
	UserID      string
	Email       string
	DisplayName string
	Role        string
	AddedAt     time.Time
}

// Teams owns CRUD against teams + team_members.
type Teams struct{ store *store.Store }

// NewTeams wires the handle.
func NewTeams(s *store.Store) *Teams { return &Teams{store: s} }

// Create inserts a team row + returns it. slug must be 2+ chars,
// lowercase letters/digits/dashes only. Caller is responsible for
// uniqueness (slug is UNIQUE in the schema; a re-insert returns an
// error).
func (t *Teams) Create(ctx context.Context, slug, name, description, createdByID string) (Team, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if !validSlug(slug) {
		return Team{}, errors.New("invalid slug — use 2+ lowercase letters/digits/dashes")
	}
	if strings.TrimSpace(name) == "" {
		return Team{}, errors.New("name required")
	}
	id, err := newTeamID()
	if err != nil {
		return Team{}, err
	}
	now := nowFn().UTC().Format(time.RFC3339)
	q := "INSERT INTO teams (id, slug, name, description, created_by_user_id, created_at, updated_at) VALUES (" +
		ph(t.store, 1) + "," + ph(t.store, 2) + "," + ph(t.store, 3) + "," + ph(t.store, 4) + "," + ph(t.store, 5) + "," + ph(t.store, 6) + "," + ph(t.store, 7) + ")"
	if _, err := t.store.DB().ExecContext(ctx, q, id, slug, name, description, nullable(createdByID), now, now); err != nil {
		return Team{}, fmt.Errorf("insert team: %w", err)
	}
	return t.ByID(ctx, id)
}

// ByID loads a team by its primary key.
func (t *Teams) ByID(ctx context.Context, id string) (Team, error) {
	q := selectTeam + " WHERE t.id = " + ph(t.store, 1)
	row := t.store.DB().QueryRowContext(ctx, q, id)
	return scanTeam(row)
}

// BySlug loads a team by its slug (the @team-<slug> handle).
func (t *Teams) BySlug(ctx context.Context, slug string) (Team, error) {
	q := selectTeam + " WHERE t.slug = " + ph(t.store, 1)
	row := t.store.DB().QueryRowContext(ctx, q, strings.ToLower(slug))
	return scanTeam(row)
}

// All returns every team, sorted by name.
func (t *Teams) All(ctx context.Context) ([]Team, error) {
	q := selectTeam + " ORDER BY t.name COLLATE NOCASE"
	if t.store.Driver() == store.DriverPostgres {
		q = selectTeam + " ORDER BY LOWER(t.name)"
	}
	rows, err := t.store.DB().QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Team
	for rows.Next() {
		row, err := scanTeam(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// Update rewrites the team's name + description. Returns sql.ErrNoRows
// if nothing matched the id.
func (t *Teams) Update(ctx context.Context, id, name, description string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("name required")
	}
	now := nowFn().UTC().Format(time.RFC3339)
	q := "UPDATE teams SET name = " + ph(t.store, 1) +
		", description = " + ph(t.store, 2) +
		", updated_at = " + ph(t.store, 3) +
		" WHERE id = " + ph(t.store, 4)
	res, err := t.store.DB().ExecContext(ctx, q, name, description, now, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Delete removes the team. Members + cascades are handled by the
// FK ON DELETE CASCADE.
func (t *Teams) Delete(ctx context.Context, id string) error {
	q := "DELETE FROM teams WHERE id = " + ph(t.store, 1)
	res, err := t.store.DB().ExecContext(ctx, q, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// AddMember inserts a (team, user) row. role must be "member" or "lead".
// Idempotent via the composite PK ON CONFLICT DO NOTHING.
func (t *Teams) AddMember(ctx context.Context, teamID, userID, role string) error {
	if role == "" {
		role = "member"
	}
	if role != "member" && role != "lead" {
		return errors.New("role must be member or lead")
	}
	now := nowFn().UTC().Format(time.RFC3339)
	q := insertTeamMemberSQL(t.store)
	_, err := t.store.DB().ExecContext(ctx, q, teamID, userID, role, now)
	return err
}

// RemoveMember drops the (team, user) row.
func (t *Teams) RemoveMember(ctx context.Context, teamID, userID string) error {
	q := "DELETE FROM team_members WHERE team_id = " + ph(t.store, 1) +
		" AND user_id = " + ph(t.store, 2)
	_, err := t.store.DB().ExecContext(ctx, q, teamID, userID)
	return err
}

// Members returns every member of the team, sorted by display_name.
func (t *Teams) Members(ctx context.Context, teamID string) ([]TeamMember, error) {
	q := `SELECT tm.user_id, u.email, COALESCE(u.display_name, ''), tm.role, tm.added_at
	      FROM team_members tm
	      JOIN users u ON u.id = tm.user_id
	      WHERE tm.team_id = ` + ph(t.store, 1) + `
	      ORDER BY COALESCE(NULLIF(u.display_name, ''), u.email)`
	rows, err := t.store.DB().QueryContext(ctx, q, teamID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []TeamMember
	for rows.Next() {
		var (
			m       TeamMember
			addedAt string
		)
		if err := rows.Scan(&m.UserID, &m.Email, &m.DisplayName, &m.Role, &addedAt); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, addedAt); err == nil {
			m.AddedAt = t
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ─── helpers ───────────────────────────────────────────────────────────

const selectTeam = `SELECT t.id, t.slug, t.name, t.description,
       COALESCE(t.created_by_user_id, ''),
       t.created_at, t.updated_at,
       (SELECT COUNT(*) FROM team_members WHERE team_id = t.id)
FROM teams t`

func scanTeam(s rowScanner) (Team, error) {
	var (
		out                  Team
		createdAt, updatedAt string
	)
	if err := s.Scan(&out.ID, &out.Slug, &out.Name, &out.Description,
		&out.CreatedByID, &createdAt, &updatedAt, &out.MemberCount); err != nil {
		return out, err
	}
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		out.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, updatedAt); err == nil {
		out.UpdatedAt = t
	}
	return out, nil
}

func insertTeamMemberSQL(s *store.Store) string {
	if s.Driver() == store.DriverPostgres {
		return `INSERT INTO team_members (team_id, user_id, role, added_at)
		        VALUES ($1, $2, $3, $4)
		        ON CONFLICT DO NOTHING`
	}
	return `INSERT INTO team_members (team_id, user_id, role, added_at)
	        VALUES (?, ?, ?, ?)
	        ON CONFLICT DO NOTHING`
}

func newTeamID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "team_" + hex.EncodeToString(b[:]), nil
}

// validSlug accepts 2+ chars of [a-z0-9-], no leading/trailing dash.
func validSlug(s string) bool {
	if len(s) < 2 {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}
