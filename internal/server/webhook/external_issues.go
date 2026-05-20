package webhook

// v1.8 phase 7 — Jira / Linear inbound webhook handlers.
//
// Both systems POST a JSON envelope when an issue transitions; the
// daemon picks it up, looks up which findings are linked, and emits
// an activity row + marks the mapping row closed. Future phases
// could flip the finding's status when every linked external issue
// closes — for now we record the signal + leave human review.
//
// Outbound (the daemon CREATING a Jira/Linear issue + persisting
// the mapping) is the next slot; this phase ships the inbound +
// the mapping table so the wiring is single-commit on the outbound
// side.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/darpanzope/compliancekit/internal/server/collab"
)

// handleJiraWebhook accepts the Jira webhook payload. Jira's
// out-of-the-box webhook signs with the system's shared secret in
// the X-Hub-Signature header (HMAC-SHA256). When jiraSecret is empty
// the route 503s.
func (rc *Receiver) handleJiraWebhook(w http.ResponseWriter, r *http.Request) {
	if rc.jiraSecret == "" {
		http.Error(w, "jira receiver not configured", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !VerifySignature(rc.jiraSecret, r.Header.Get("X-Hub-Signature"), body) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	var env struct {
		WebhookEvent string `json:"webhookEvent"`
		Issue        struct {
			Key    string `json:"key"`
			Fields struct {
				Status struct {
					Name           string `json:"name"`
					StatusCategory struct {
						Key string `json:"key"`
					} `json:"statusCategory"`
				} `json:"status"`
			} `json:"fields"`
		} `json:"issue"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	// jira:issue_updated is the most common event; only act when the
	// statusCategory transitions to "done".
	if env.Issue.Key == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !strings.EqualFold(env.Issue.Fields.Status.StatusCategory.Key, "done") {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rc.closeExternalIssue(r, collab.SystemJira, env.Issue.Key, env.Issue.Fields.Status.Name)
	w.WriteHeader(http.StatusOK)
}

// handleLinearWebhook accepts the Linear webhook payload. Linear
// signs with X-Linear-Signature (also HMAC-SHA256 over the body).
// The payload exposes `action: "update"` events with a state.type
// field; we act on type == "completed".
func (rc *Receiver) handleLinearWebhook(w http.ResponseWriter, r *http.Request) {
	if rc.linearSecret == "" {
		http.Error(w, "linear receiver not configured", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !VerifySignature(rc.linearSecret, r.Header.Get("X-Linear-Signature"), body) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	var env struct {
		Action string `json:"action"`
		Data   struct {
			Identifier string `json:"identifier"`
			State      struct {
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"state"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if env.Data.Identifier == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if env.Data.State.Type != "completed" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rc.closeExternalIssue(r, collab.SystemLinear, env.Data.Identifier, env.Data.State.Name)
	w.WriteHeader(http.StatusOK)
}

// externalIssuesRepo returns the lazy-constructed collab handle.
func (rc *Receiver) externalIssuesRepo() *collab.ExternalIssues {
	if rc.extIssues == nil {
		rc.extIssues = collab.NewExternalIssues(rc.store)
	}
	return rc.extIssues
}

// closeExternalIssue marks every mapping row for (system, externalID)
// as closed + emits an activity row per affected fingerprint so the
// timeline carries the transition.
func (rc *Receiver) closeExternalIssue(r *http.Request, system, externalID, statusLabel string) {
	rows, err := rc.externalIssuesRepo().ListByExternal(r.Context(), system, externalID)
	if err != nil {
		return
	}
	for _, row := range rows {
		_ = rc.externalIssuesRepo().MarkClosed(r.Context(), row.ID)
		actor := collab.ActorJira
		if system == collab.SystemLinear {
			actor = collab.ActorLinear
		}
		_, _ = rc.activitiesRepo().Record(r.Context(), row.Fingerprint, collab.ActivityWaiverRevoked, collab.RecordOptions{
			ActorSource: actor,
			Metadata: map[string]any{
				"system":      system,
				"external_id": externalID,
				"status":      statusLabel,
			},
		})
	}
}
