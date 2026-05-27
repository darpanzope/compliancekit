// Package push implements VAPID-encrypted Web Push delivery for
// v1.16 phase 4. The daemon generates a single VAPID keypair at
// first boot (persisted in app_kv), users opt in per device via
// the PushManager.subscribe() browser API, and the daemon fans
// critical-finding alerts out as encrypted push payloads.
//
// No third-party push provider — Firebase / OneSignal would push
// payloads through their servers and need long-lived API keys.
// VAPID is the IETF-standard alternative: keys live in the daemon,
// pushes go directly to the browser push services (FCM, Mozilla,
// Apple). Honors the no-phone-home invariant (ADR-013 spirit).
package push

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/google/uuid"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// Subscription is the server-side record of a single browser/
// device push registration. Mirrors the wire shape browsers send
// when ServiceWorkerRegistration.pushManager.subscribe() returns.
type Subscription struct {
	ID         string
	UserID     string
	Endpoint   string
	P256dhKey  string
	AuthKey    string
	DeviceLbl  string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// Payload is the message envelope delivered to the client's service
// worker push handler. The browser's notification UI renders Title
// + Body; URL routes the user when they click the notification.
type Payload struct {
	Title    string `json:"title"`
	Body     string `json:"body"`
	URL      string `json:"url,omitempty"`
	Severity string `json:"severity,omitempty"`
	Tag      string `json:"tag,omitempty"` // browser dedupe key
}

// Store wraps the SQLite/Postgres push tables.
type Store struct {
	st *store.Store
}

func NewStore(st *store.Store) *Store { return &Store{st: st} }

// EnsureVAPID returns the daemon's VAPID keypair, generating + saving
// it on first call. Subsequent calls return the persisted pair.
// Returning the keys (rather than caching in memory) keeps the
// implementation stateless across daemon restarts + HA replicas.
func (s *Store) EnsureVAPID(ctx context.Context) (publicKey, privateKey string, err error) {
	row := s.st.DB().QueryRowContext(ctx, `SELECT v FROM app_kv WHERE k = 'vapid'`)
	var raw string
	if err := row.Scan(&raw); err == nil {
		var pair struct{ Public, Private string }
		if err := json.Unmarshal([]byte(raw), &pair); err == nil && pair.Public != "" {
			return pair.Public, pair.Private, nil
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", "", err
	}
	// First boot — generate + persist.
	priv, pub, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		return "", "", fmt.Errorf("generate vapid: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"public": pub, "private": priv})
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.st.DB().ExecContext(ctx,
		`INSERT INTO app_kv (k, v, updated_at) VALUES ('vapid', ?, ?)
		 ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at`,
		string(body), now); err != nil {
		return "", "", fmt.Errorf("persist vapid: %w", err)
	}
	return pub, priv, nil
}

// Save upserts a Subscription by (user_id, endpoint). Idempotent;
// a refresh-token / reinstall returns the same id.
func (s *Store) Save(ctx context.Context, sub Subscription) (Subscription, error) {
	now := time.Now().UTC()
	// Check existing.
	var existingID string
	err := s.st.DB().QueryRowContext(ctx,
		`SELECT id FROM push_subscriptions WHERE user_id = ? AND endpoint = ?`,
		sub.UserID, sub.Endpoint).Scan(&existingID)
	if err == nil {
		_, err := s.st.DB().ExecContext(ctx,
			`UPDATE push_subscriptions
			   SET p256dh_key = ?, auth_key = ?, device_label = ?, last_used_at = ?
			 WHERE id = ?`,
			sub.P256dhKey, sub.AuthKey, sub.DeviceLbl, now.Format(time.RFC3339), existingID)
		if err != nil {
			return sub, err
		}
		sub.ID = existingID
		sub.LastUsedAt = now
		return sub, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return sub, err
	}
	sub.ID = uuid.NewString()
	sub.CreatedAt = now
	sub.LastUsedAt = now
	_, err = s.st.DB().ExecContext(ctx,
		`INSERT INTO push_subscriptions
		  (id, user_id, endpoint, p256dh_key, auth_key, device_label, created_at, last_used_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sub.ID, sub.UserID, sub.Endpoint, sub.P256dhKey, sub.AuthKey,
		sub.DeviceLbl, sub.CreatedAt.Format(time.RFC3339), sub.LastUsedAt.Format(time.RFC3339))
	return sub, err
}

// DeleteByEndpoint removes a subscription matching the user + endpoint.
// Returns the number of rows deleted (0 if the user didn't have a
// subscription with that endpoint).
func (s *Store) DeleteByEndpoint(ctx context.Context, userID, endpoint string) (int64, error) {
	res, err := s.st.DB().ExecContext(ctx,
		`DELETE FROM push_subscriptions WHERE user_id = ? AND endpoint = ?`,
		userID, endpoint)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ListForUser returns every subscription the user has registered,
// most-recent first. Used by the /settings/notifications UI to
// render the per-device list.
func (s *Store) ListForUser(ctx context.Context, userID string) ([]Subscription, error) {
	rows, err := s.st.DB().QueryContext(ctx,
		`SELECT id, user_id, endpoint, p256dh_key, auth_key, device_label, created_at, last_used_at
		 FROM push_subscriptions
		 WHERE user_id = ?
		 ORDER BY last_used_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var subs []Subscription
	for rows.Next() {
		var s Subscription
		var createdAt, lastUsedAt string
		if err := rows.Scan(&s.ID, &s.UserID, &s.Endpoint, &s.P256dhKey, &s.AuthKey,
			&s.DeviceLbl, &createdAt, &lastUsedAt); err != nil {
			return nil, err
		}
		s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		s.LastUsedAt, _ = time.Parse(time.RFC3339, lastUsedAt)
		subs = append(subs, s)
	}
	return subs, rows.Err()
}

// Sender owns the HTTP client + VAPID keys used to push to every
// subscriber. Reused across calls — webpush-go's send is per-request
// so the sender itself stays cheap to construct.
type Sender struct {
	store        *Store
	publicKey    string
	privateKey   string
	contactEmail string
	timeout      time.Duration
}

// NewSender returns a Sender that signs every push with the
// daemon's VAPID keys. contactEmail goes into the JWT `sub` claim
// browsers use to identify the sender to push services. Empty
// email falls back to the deploy-time admin email or a placeholder.
func NewSender(ctx context.Context, st *Store, contactEmail string) (*Sender, error) {
	pub, priv, err := st.EnsureVAPID(ctx)
	if err != nil {
		return nil, err
	}
	if contactEmail == "" {
		contactEmail = "mailto:admin@compliancekit.local"
	}
	return &Sender{
		store:        st,
		publicKey:    pub,
		privateKey:   priv,
		contactEmail: contactEmail,
		timeout:      10 * time.Second,
	}, nil
}

// PublicKey returns the VAPID public key in URL-safe base64. The
// browser needs this to call PushManager.subscribe(applicationServerKey).
func (s *Sender) PublicKey() string { return s.publicKey }

// SendToUser dispatches the payload to every subscription belonging
// to userID. Returns (sent, failed) counts; failed deliveries are
// logged but don't abort the loop. A 404/410 response from the push
// service means the subscription is stale and gets deleted.
func (s *Sender) SendToUser(ctx context.Context, userID string, p Payload) (sent, failed int, err error) {
	subs, err := s.store.ListForUser(ctx, userID)
	if err != nil {
		return 0, 0, err
	}
	body, err := json.Marshal(p)
	if err != nil {
		return 0, 0, err
	}
	for _, sub := range subs {
		resp, err := webpush.SendNotificationWithContext(ctx, body, &webpush.Subscription{
			Endpoint: sub.Endpoint,
			Keys: webpush.Keys{
				P256dh: sub.P256dhKey,
				Auth:   sub.AuthKey,
			},
		}, &webpush.Options{
			Subscriber:      s.contactEmail,
			VAPIDPublicKey:  s.publicKey,
			VAPIDPrivateKey: s.privateKey,
			TTL:             60, // seconds; drop if undelivered after 1 min
		})
		if err != nil {
			failed++
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
			// Subscription is stale at the push service end — clean up.
			_, _ = s.store.DeleteByEndpoint(ctx, sub.UserID, sub.Endpoint)
			failed++
			continue
		}
		if resp.StatusCode >= 300 {
			failed++
			continue
		}
		sent++
	}
	return sent, failed, nil
}
