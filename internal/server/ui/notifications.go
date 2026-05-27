package ui

// v1.16 phase 4 — /settings/notifications page. Lists every push
// subscription the current user has registered (per-device, per-
// browser) and gives them an Enable/Disable toggle that the Alpine
// factory `pushSubs()` wires into the v1.16 API endpoints. Server-
// side just renders the list + the page chrome; everything else is
// browser-side (the subscribe flow needs navigator.serviceWorker
// + PushManager + Notification.requestPermission which all live in
// the browser).

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/push"
)

// notificationsView wraps View with the per-user push subscription
// list. PushEnabled is true when the daemon was booted with push
// support (the Sender is non-nil); when false the page shows a
// "push not enabled by your admin" banner instead of the toggle.
type notificationsView struct {
	View
	PushEnabled bool
	Subs        []notificationsSub
}

type notificationsSub struct {
	ID          string
	DeviceLabel string
	Endpoint    string
	CreatedAt   time.Time
	LastUsedAt  time.Time
}

func (u *UI) mountNotificationsRoutes(r chi.Router) {
	r.Get("/settings/notifications", u.notificationsList)
}

func (u *UI) notificationsList(w http.ResponseWriter, r *http.Request) {
	view := notificationsView{
		View:        u.viewFor(r, "Notifications", "settings", View{}),
		PushEnabled: u.push != nil,
	}
	if u.push != nil {
		sess := auth.FromContext(r.Context())
		if sess != nil {
			subs, err := u.push.ListForUser(r.Context(), sess.UserID)
			if err == nil {
				for _, s := range subs {
					view.Subs = append(view.Subs, notificationsSub{
						ID:          s.ID,
						DeviceLabel: s.DeviceLbl,
						Endpoint:    truncEndpointUI(s.Endpoint),
						CreatedAt:   s.CreatedAt,
						LastUsedAt:  s.LastUsedAt,
					})
				}
			}
		}
	}
	u.render(w, "notifications.html", view)
}

// pushStore wires the push package into the UI so the route can list
// subscriptions per user. Optional — when nil, the page renders the
// "not enabled" state. Set via WithPush from the daemon boot path.
func (u *UI) WithPush(p *push.Store) *UI {
	u.push = p
	return u
}

func truncEndpointUI(ep string) string {
	if len(ep) <= 60 {
		return ep
	}
	return ep[:40] + "…" + ep[len(ep)-16:]
}
