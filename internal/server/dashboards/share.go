package dashboards

// v1.14 phase 7 — revocable live-share + per-recipient watermark.
//
// Share creation produces a 256-bit url-safe token. The recipient
// trades the token at /shared/{token} for a read-only dashboard
// render with their email stamped as the watermark on every page.
//
// Trade is gated three ways:
//   - revoked_at must be NULL
//   - expires_at, when set, must be in the future
//   - view_count is bumped on every successful trade (audit trail
//     without a separate access_log table)

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ErrShareGone is returned by TradeShare when the link has been
// revoked or has expired. The HTTP handler maps this to 410.
var ErrShareGone = errors.New("dashboards: share link gone")

// SharedLink is the row shape.
type SharedLink struct {
	Token              string
	DashboardID        string
	CreatedByUserID    string
	CreatedAt          time.Time
	ExpiresAt          time.Time // zero = no expiry
	RevokedAt          time.Time
	WatermarkRecipient string
	ViewCount          int
}

// CreateShare issues a new live-share token. expiresAt may be the
// zero time (no expiry); recipient is the watermark text (typically
// the email + a "for X — YYYY-MM-DD" suffix from the UI).
func (s *Store) CreateShare(ctx context.Context, dashboardID, createdBy string, expiresAt time.Time, recipient string) (*SharedLink, error) {
	if dashboardID == "" {
		return nil, errors.New("dashboards: dashboardID required")
	}
	token, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("share token: %w", err)
	}
	now := time.Now().UTC()
	var expArg any
	if !expiresAt.IsZero() {
		expArg = expiresAt.UTC().Format(time.RFC3339)
	}
	q := `INSERT INTO shared_links
	      (token, dashboard_id, created_by_user_id, created_at, expires_at, watermark_recipient)
	      VALUES (` + s.phList(6) + `)`
	if _, err := s.store.DB().ExecContext(ctx, q,
		token, dashboardID, nullable(createdBy), now.Format(time.RFC3339),
		expArg, recipient); err != nil {
		return nil, fmt.Errorf("insert shared_link: %w", err)
	}
	return &SharedLink{
		Token:              token,
		DashboardID:        dashboardID,
		CreatedByUserID:    createdBy,
		CreatedAt:          now,
		ExpiresAt:          expiresAt,
		WatermarkRecipient: recipient,
	}, nil
}

// TradeShare validates the token + returns the linked dashboard
// (loaded with its widgets) + the SharedLink row. Increments
// view_count on success.
func (s *Store) TradeShare(ctx context.Context, token string) (*SharedLink, *Dashboard, error) {
	link, err := s.ShareByToken(ctx, token)
	if err != nil {
		return nil, nil, err
	}
	if !link.RevokedAt.IsZero() {
		return nil, nil, ErrShareGone
	}
	if !link.ExpiresAt.IsZero() && time.Now().UTC().After(link.ExpiresAt) {
		return nil, nil, ErrShareGone
	}
	d, err := s.ByID(ctx, link.DashboardID)
	if err != nil {
		return nil, nil, err
	}
	// Best-effort view counter bump.
	_, _ = s.store.DB().ExecContext(ctx,
		`UPDATE shared_links SET view_count = view_count + 1 WHERE token = `+s.ph(1), token)
	link.ViewCount++
	return link, d, nil
}

// ShareByToken returns the row without trading. Useful for the
// admin UI listing.
func (s *Store) ShareByToken(ctx context.Context, token string) (*SharedLink, error) {
	row := s.store.DB().QueryRowContext(ctx,
		`SELECT token, dashboard_id, COALESCE(created_by_user_id,''), created_at,
		        COALESCE(expires_at,''), COALESCE(revoked_at,''),
		        watermark_recipient, view_count
		 FROM shared_links WHERE token = `+s.ph(1), token)
	link := &SharedLink{}
	var created, expires, revoked string
	if err := row.Scan(&link.Token, &link.DashboardID, &link.CreatedByUserID, &created,
		&expires, &revoked, &link.WatermarkRecipient, &link.ViewCount); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrShareGone
		}
		return nil, err
	}
	link.CreatedAt = parseTime(created)
	link.ExpiresAt = parseTime(expires)
	link.RevokedAt = parseTime(revoked)
	return link, nil
}

// ListShares returns every share for dashboardID, newest first.
func (s *Store) ListShares(ctx context.Context, dashboardID string) ([]*SharedLink, error) {
	rows, err := s.store.DB().QueryContext(ctx,
		`SELECT token, dashboard_id, COALESCE(created_by_user_id,''), created_at,
		        COALESCE(expires_at,''), COALESCE(revoked_at,''),
		        watermark_recipient, view_count
		 FROM shared_links WHERE dashboard_id = `+s.ph(1)+
			` ORDER BY created_at DESC`, dashboardID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*SharedLink
	for rows.Next() {
		link := &SharedLink{}
		var created, expires, revoked string
		if err := rows.Scan(&link.Token, &link.DashboardID, &link.CreatedByUserID, &created,
			&expires, &revoked, &link.WatermarkRecipient, &link.ViewCount); err != nil {
			return nil, err
		}
		link.CreatedAt = parseTime(created)
		link.ExpiresAt = parseTime(expires)
		link.RevokedAt = parseTime(revoked)
		out = append(out, link)
	}
	return out, rows.Err()
}

// RevokeShare marks the share gone. Idempotent.
func (s *Store) RevokeShare(ctx context.Context, token string) error {
	_, err := s.store.DB().ExecContext(ctx,
		`UPDATE shared_links SET revoked_at = `+s.ph(1)+` WHERE token = `+s.ph(2)+` AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339), token)
	return err
}

// WatermarkText formats the per-recipient watermark string the
// HTML/PDF render layers stamp into every page. Empty recipient
// returns empty string so the renderer can skip the overlay.
func WatermarkText(recipient string) string {
	if recipient == "" {
		return ""
	}
	return fmt.Sprintf("for %s — %s", recipient, time.Now().UTC().Format("2006-01-02"))
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
