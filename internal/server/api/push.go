package api

// v1.16 phase 4 — Web Push API surface. Four endpoints:
//
//   GET  /api/v1/push/vapid-public-key   →  { "key": "<urlsafe-b64>" }
//   POST /api/v1/push/subscribe           accept the browser's
//                                         PushSubscription JSON; persists
//                                         to push_subscriptions keyed by
//                                         (user_id, endpoint). Idempotent.
//   POST /api/v1/push/unsubscribe         body: { "endpoint": "..." }
//                                         removes the row for the
//                                         current user + endpoint.
//   GET  /api/v1/push/subscriptions       list every subscription the
//                                         caller has registered (used
//                                         by /settings/notifications).

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/push"
)

// pushVAPIDPublic returns the daemon's VAPID public key so the
// browser can call pushManager.subscribe({applicationServerKey}).
// Unauthenticated: the public key is, by definition, public —
// gating it would just complicate the front-end bootstrap.
func (a *API) pushVAPIDPublic(w http.ResponseWriter, r *http.Request) {
	if a.pushSend == nil {
		http.Error(w, "push not configured", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"key": a.pushSend.PublicKey()})
}

// pushSubscribePayload mirrors the JSON shape the browser sends
// when posting a PushSubscription. The keys block holds p256dh +
// auth values returned by ServiceWorkerRegistration.pushManager.subscribe().
type pushSubscribePayload struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
	DeviceLabel string `json:"device_label,omitempty"`
}

func (a *API) pushSubscribe(w http.ResponseWriter, r *http.Request) {
	if a.push == nil {
		http.Error(w, "push not configured", http.StatusServiceUnavailable)
		return
	}
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "session required", http.StatusUnauthorized)
		return
	}
	var p pushSubscribePayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "invalid payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	if p.Endpoint == "" || p.Keys.P256dh == "" || p.Keys.Auth == "" {
		http.Error(w, "missing endpoint/keys", http.StatusBadRequest)
		return
	}
	if p.DeviceLabel == "" {
		// Default label: User-Agent fingerprint (the operator can
		// rename later via the /settings/notifications UI).
		p.DeviceLabel = userAgentLabel(r)
	}
	sub, err := a.push.Save(r.Context(), push.Subscription{
		UserID:    sess.UserID,
		Endpoint:  p.Endpoint,
		P256dhKey: p.Keys.P256dh,
		AuthKey:   p.Keys.Auth,
		DeviceLbl: p.DeviceLabel,
	})
	if err != nil {
		http.Error(w, "save subscription: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":           sub.ID,
		"device_label": sub.DeviceLbl,
		"created_at":   sub.CreatedAt.Format(time.RFC3339),
	})
}

type pushUnsubscribePayload struct {
	Endpoint string `json:"endpoint"`
}

func (a *API) pushUnsubscribe(w http.ResponseWriter, r *http.Request) {
	if a.push == nil {
		http.Error(w, "push not configured", http.StatusServiceUnavailable)
		return
	}
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "session required", http.StatusUnauthorized)
		return
	}
	var p pushUnsubscribePayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "invalid payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	if p.Endpoint == "" {
		http.Error(w, "missing endpoint", http.StatusBadRequest)
		return
	}
	n, err := a.push.DeleteByEndpoint(r.Context(), sess.UserID, p.Endpoint)
	if err != nil {
		http.Error(w, "delete: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int64{"deleted": n})
}

func (a *API) pushListSubscriptions(w http.ResponseWriter, r *http.Request) {
	if a.push == nil {
		http.Error(w, "push not configured", http.StatusServiceUnavailable)
		return
	}
	sess := auth.FromContext(r.Context())
	if sess == nil {
		http.Error(w, "session required", http.StatusUnauthorized)
		return
	}
	subs, err := a.push.ListForUser(r.Context(), sess.UserID)
	if err != nil {
		http.Error(w, "list: "+err.Error(), http.StatusInternalServerError)
		return
	}
	type row struct {
		ID          string    `json:"id"`
		Endpoint    string    `json:"endpoint"`
		DeviceLabel string    `json:"device_label"`
		CreatedAt   time.Time `json:"created_at"`
		LastUsedAt  time.Time `json:"last_used_at"`
	}
	out := make([]row, 0, len(subs))
	for _, s := range subs {
		out = append(out, row{
			ID:          s.ID,
			Endpoint:    truncEndpoint(s.Endpoint),
			DeviceLabel: s.DeviceLbl,
			CreatedAt:   s.CreatedAt,
			LastUsedAt:  s.LastUsedAt,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"items": out})
}

// userAgentLabel returns a short, human-readable description of the
// caller's browser/OS combo. Used as the default device_label when
// the client doesn't provide one explicitly.
func userAgentLabel(r *http.Request) string {
	ua := r.UserAgent()
	if ua == "" {
		return "Unknown device"
	}
	// Crude but useful: trim to the first parenthetical block which
	// usually contains the OS string. v1.16.x may swap in a real UA
	// parser if operators want richer labels in /settings/notifications.
	if len(ua) > 80 {
		ua = ua[:80] + "…"
	}
	return ua
}

// truncEndpoint shortens the long push-service endpoint URL to
// something a human can recognize without leaking the full token.
// The full endpoint stays in the DB; this is the wire-friendly form.
func truncEndpoint(ep string) string {
	if len(ep) <= 60 {
		return ep
	}
	return ep[:40] + "…" + ep[len(ep)-16:]
}
