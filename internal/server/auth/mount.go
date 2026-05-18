package auth

import "github.com/go-chi/chi/v5"

// Mount installs the auth HTTP routes onto r:
//
//	POST /api/auth/login   → LoginHandler (form + JSON)
//	POST /api/auth/logout  → LogoutHandler (destroy session, clear cookies)
//	GET  /api/auth/me      → MeHandler   (returns current session's user)
//
// /me sits behind RequireAuth; login + logout are intentionally
// unauthenticated. This helper was missing in v1.3.0 — the
// individual handlers shipped in phase 3 but never got wired onto
// the daemon's router; the bug surfaced as a 404 from the UI login
// form's POST. v1.3.1 closes the gap.
func Mount(r chi.Router, users *Users, sessions *Sessions) {
	r.Post("/api/auth/login", LoginHandler(users, sessions))
	r.Post("/api/auth/logout", LogoutHandler(sessions))
	r.Method("GET", "/api/auth/me", sessions.RequireAuth(MeHandler(users)))
}
