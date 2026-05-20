package compliancekit

import "time"

// User is the v1.8+ identity reference exposed on Finding for
// collaboration metadata. It is a deliberately thin shape — just
// enough for a Finding consumer to render "who commented" or "who is
// assigned" without forcing embedders to model an entire auth system.
//
// User values flow through reporters as part of Finding.Comments,
// Finding.Assignee, and Finding.Followers when the finding is loaded
// from the serve daemon. CLI-only embedders who never run the daemon
// will see zero-value users (the embedder may still construct them
// directly to plumb attribution through their own pipeline).
//
// Added in v1.8 alongside per-finding markdown comments and resource
// ownership. ADR-014 — additive-only changes preserve the v1.x
// API contract.
type User struct {
	// ID is the daemon's internal opaque user id. Embedders that need
	// to correlate against an external IdP should join on Email.
	ID string `json:"id"`

	// Email is the user's primary contact address. Required.
	Email string `json:"email"`

	// DisplayName is the operator-visible label ("Alex Lee"). Falls
	// back to the local-part of Email when unset.
	DisplayName string `json:"display_name,omitempty"`
}

// Label returns DisplayName when set, else the part of Email before
// the '@'. Reporters that need a one-token actor name read this; the
// CLI's --json output keeps the raw fields untouched.
func (u User) Label() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	for i := 0; i < len(u.Email); i++ {
		if u.Email[i] == '@' {
			return u.Email[:i]
		}
	}
	return u.Email
}

// Comment is one operator-authored message attached to a Finding.
// Comments thread by Finding.Fingerprint() — across scans, the same
// fingerprint surfaces the same comment history. v1.8 introduces the
// type; v1.9+ may extend it (reactions, replies) within the additive-
// only ADR-014 contract.
//
// Body is the markdown source as the author typed it. BodyHTML is the
// goldmark-rendered, sanitized HTML cached for fast list rendering;
// embedders that re-render markdown themselves can ignore it.
type Comment struct {
	// ID is the daemon's opaque identifier for this comment.
	ID string `json:"id"`

	// Author is the operator who wrote the comment. May be a zero
	// User if the original author was deleted from the daemon (the
	// comment text is preserved; Author.ID is empty in that case).
	Author User `json:"author"`

	// Body is the markdown source the author wrote.
	Body string `json:"body"`

	// BodyHTML is the rendered, sanitized HTML. Cached at write time
	// and refreshed only on Edit. Empty for embedders that don't
	// populate it.
	BodyHTML string `json:"body_html,omitempty"`

	// CreatedAt is the timestamp the comment was first persisted.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt tracks the most recent write, including edits.
	UpdatedAt time.Time `json:"updated_at"`

	// EditedAt is non-nil when the comment has been edited at least
	// once after creation. The UI renders "edited 3m ago" when set.
	EditedAt *time.Time `json:"edited_at,omitempty"`

	// Source records how the comment entered compliancekit: 'ui',
	// 'slack', 'teams', 'github-pr', 'jira', 'linear'. Empty string
	// is treated as 'ui' for backwards compatibility.
	Source string `json:"source,omitempty"`

	// ExternalID is the originating sink's native id (Slack thread
	// timestamp, GitHub comment id, Jira/Linear comment id) — populated
	// for non-UI comments so two-way sync can dedup re-delivery.
	ExternalID string `json:"external_id,omitempty"`
}

// IsEdited reports whether the comment has been edited after creation.
func (c Comment) IsEdited() bool { return c.EditedAt != nil }
