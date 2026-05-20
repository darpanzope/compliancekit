package webhook

// v1.8 phase 5 — Slack reply-in-thread receiver + slash commands.
//
// Two routes:
//   POST /webhooks/slack/events   — Slack Events API (URL verify +
//                                   message events in threads).
//   POST /webhooks/slack/commands — Slack slash commands (/ck ack,
//                                   /ck assign, /ck waive).
//
// Both verify the X-Slack-Signature + X-Slack-Request-Timestamp
// pair against the workspace signing secret; replay window is
// 5 minutes (Slack's documented recommendation).
//
// The reply-in-thread path reads slack_thread_mapping (populated
// by the v0.17 outbound notifier when daemon mode is configured)
// to resolve (channel, thread_ts) → finding fingerprint.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/darpanzope/compliancekit/internal/server/collab"
	"github.com/darpanzope/compliancekit/internal/server/comments"
)

// SlackSignaturePrefix is the version-prefix Slack puts on the
// signature header. v0 is the only spec'd value as of 2026.
const SlackSignaturePrefix = "v0="

// SlackReplayWindow is the maximum age of an inbound request,
// rejecting anything older to mitigate replay attacks.
const SlackReplayWindow = 5 * time.Minute

// VerifySlackSignature implements Slack's HMAC-SHA256-over-
// (v0:timestamp:body) recipe. Returns false on any structural error
// (missing/empty headers, stale timestamp, malformed hex). secret
// is the workspace signing-secret.
func VerifySlackSignature(secret string, headerSig string, timestamp string, body []byte) bool {
	if secret == "" || headerSig == "" || timestamp == "" {
		return false
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if time.Since(time.Unix(ts, 0)).Abs() > SlackReplayWindow {
		return false
	}
	if !strings.HasPrefix(headerSig, SlackSignaturePrefix) {
		return false
	}
	want, err := hex.DecodeString(headerSig[len(SlackSignaturePrefix):])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + timestamp + ":"))
	mac.Write(body)
	return hmac.Equal(want, mac.Sum(nil))
}

// handleSlackEvents handles the Events API callback. Two payload
// shapes matter: url_verification (returns the challenge so the
// workspace owner can confirm the URL) + event_callback (where a
// thread-reply lands as a "message" event).
func (rc *Receiver) handleSlackEvents(w http.ResponseWriter, r *http.Request) {
	if rc.slackSigningSecret == "" {
		http.Error(w, "slack receiver not configured", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !VerifySlackSignature(rc.slackSigningSecret, r.Header.Get("X-Slack-Signature"),
		r.Header.Get("X-Slack-Request-Timestamp"), body) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	var env struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Event     struct {
			Type     string `json:"type"`
			Channel  string `json:"channel"`
			ThreadTS string `json:"thread_ts"`
			TS       string `json:"ts"`
			User     string `json:"user"`
			Text     string `json:"text"`
			Subtype  string `json:"subtype"`
			BotID    string `json:"bot_id"`
		} `json:"event"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if env.Type == "url_verification" {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(env.Challenge))
		return
	}
	if env.Type != "event_callback" || env.Event.Type != "message" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Ignore bot-authored messages (compliancekit's own posts +
	// other integrations); we only want human replies.
	if env.Event.BotID != "" || env.Event.Subtype == "bot_message" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// thread_ts empty → top-level message in a channel, not a reply.
	if env.Event.ThreadTS == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	fingerprint, err := rc.lookupSlackThread(r.Context(), env.Event.Channel, env.Event.ThreadTS)
	if err != nil || fingerprint == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if _, err := rc.commentsRepo().Add(r.Context(), fingerprint, "", env.Event.Text, comments.AddOptions{
		Source:     comments.SourceSlack,
		ExternalID: env.Event.Channel + ":" + env.Event.TS,
	}); err != nil {
		http.Error(w, "persist: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = rc.activitiesRepo().Record(r.Context(), fingerprint, collab.ActivityCommentAdded, collab.RecordOptions{
		ActorSource: collab.ActorSlack,
		Metadata: map[string]any{
			"slack_channel":   env.Event.Channel,
			"slack_thread_ts": env.Event.ThreadTS,
		},
	})
	w.WriteHeader(http.StatusOK)
}

// handleSlackCommands handles the slash-command POST. Slack sends
// application/x-www-form-urlencoded with the command + text fields.
// Supported (so far): "/ck ack", "/ck assign", "/ck waive".
func (rc *Receiver) handleSlackCommands(w http.ResponseWriter, r *http.Request) {
	if rc.slackSigningSecret == "" {
		http.Error(w, "slack receiver not configured", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !VerifySlackSignature(rc.slackSigningSecret, r.Header.Get("X-Slack-Signature"),
		r.Header.Get("X-Slack-Request-Timestamp"), body) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		http.Error(w, "parse: "+err.Error(), http.StatusBadRequest)
		return
	}
	command := form.Get("command")
	text := strings.TrimSpace(form.Get("text"))
	channel := form.Get("channel_id")
	user := form.Get("user_name")
	// The command in our convention is "/ck" with a subcommand in the
	// text field: "/ck ack fp123", "/ck assign fp123 @alice",
	// "/ck waive fp123 reason here".
	if command != "/ck" && command != "/compliancekit" {
		respondSlackText(w, "unsupported command: "+command)
		return
	}
	tokens := strings.Fields(text)
	if len(tokens) < 2 {
		respondSlackText(w, "usage: /ck <ack|assign|waive> <fingerprint> [args]")
		return
	}
	sub := tokens[0]
	fp := tokens[1]
	rest := strings.TrimSpace(strings.Join(tokens[2:], " "))

	switch sub {
	case "ack":
		rc.slackCmdAck(r.Context(), w, fp, channel, user, rest, form.Get("trigger_id"))
	case "assign":
		rc.slackCmdAssign(r.Context(), w, fp, user, rest)
	case "waive":
		rc.slackCmdWaive(r.Context(), w, fp, channel, user, rest, form.Get("trigger_id"))
	default:
		respondSlackText(w, "unsupported subcommand: "+sub)
	}
}

// slackCmdAck records an "acknowledged" comment + activity row.
func (rc *Receiver) slackCmdAck(ctx context.Context, w http.ResponseWriter, fp, channel, user, rest, triggerID string) {
	ackBody := "Acknowledged by @" + user
	if rest != "" {
		ackBody += " — " + rest
	}
	if _, err := rc.commentsRepo().Add(ctx, fp, "", ackBody, comments.AddOptions{
		Source:     comments.SourceSlack,
		ExternalID: channel + ":ack:" + triggerID,
	}); err != nil {
		respondSlackText(w, "ack failed: "+err.Error())
		return
	}
	_, _ = rc.activitiesRepo().Record(ctx, fp, collab.ActivityCommentAdded, collab.RecordOptions{
		ActorSource: collab.ActorSlack,
		Metadata:    map[string]any{"slack_user": user, "kind": "ack"},
	})
	respondSlackText(w, fmt.Sprintf("✅ Acknowledged finding %s by @%s", fp, user))
}

// slackCmdAssign resolves @handle → userID + upserts assignment.
func (rc *Receiver) slackCmdAssign(ctx context.Context, w http.ResponseWriter, fp, user, rest string) {
	if rest == "" {
		respondSlackText(w, "usage: /ck assign <fingerprint> @user")
		return
	}
	handle := strings.TrimPrefix(strings.TrimSpace(rest), "@")
	uid := rc.resolveSlackHandleToUser(ctx, handle)
	if uid == "" {
		respondSlackText(w, "unknown user: @"+handle)
		return
	}
	if _, err := rc.assignmentsRepo().Set(ctx, fp, uid, ""); err != nil {
		respondSlackText(w, "assign failed: "+err.Error())
		return
	}
	_, _ = rc.activitiesRepo().Record(ctx, fp, collab.ActivityAssigned, collab.RecordOptions{
		ActorSource: collab.ActorSlack,
		Metadata:    map[string]any{"assignee_user_id": uid, "slack_user": user},
	})
	respondSlackText(w, "👤 Assigned "+fp+" → @"+handle)
}

// slackCmdWaive logs a waiver request (comment + activity); the row
// in the waivers table is left for the v1.9 rules-engine review flow.
func (rc *Receiver) slackCmdWaive(ctx context.Context, w http.ResponseWriter, fp, channel, user, rest, triggerID string) {
	if len(rest) < 17 {
		respondSlackText(w, "waive reason must be 17+ chars")
		return
	}
	waiveBody := "Waiver request from @" + user + " — " + rest
	if _, err := rc.commentsRepo().Add(ctx, fp, "", waiveBody, comments.AddOptions{
		Source:     comments.SourceSlack,
		ExternalID: channel + ":waive:" + triggerID,
	}); err != nil {
		respondSlackText(w, "waive log failed: "+err.Error())
		return
	}
	_, _ = rc.activitiesRepo().Record(ctx, fp, collab.ActivityWaiverApplied, collab.RecordOptions{
		ActorSource: collab.ActorSlack,
		Metadata:    map[string]any{"reason": rest, "slack_user": user, "pending": true},
	})
	respondSlackText(w, "⏳ Waiver requested for "+fp+" — awaiting approver")
}

// respondSlackText writes a single in_channel text reply. Slack
// accepts JSON or form-encoded; JSON keeps escaping clean.
func respondSlackText(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "application/json")
	payload := map[string]any{"response_type": "in_channel", "text": text}
	b, _ := json.Marshal(payload)
	_, _ = w.Write(b)
}

// lookupSlackThread resolves (channel, thread_ts) → fingerprint via
// the slack_thread_mapping table. Empty fingerprint means we didn't
// post that thread (the reply isn't ours to ingest).
func (rc *Receiver) lookupSlackThread(ctx context.Context, channel, threadTS string) (string, error) {
	q := "SELECT fingerprint FROM slack_thread_mapping WHERE channel = " + rc.ph(1) +
		" AND thread_ts = " + rc.ph(2)
	var fp string
	err := rc.store.DB().QueryRowContext(ctx, q, channel, threadTS).Scan(&fp)
	return fp, err
}

// resolveSlackHandleToUser maps a Slack handle to compliancekit
// user_id via the users table (display_name OR local-part of email).
// Returns "" when no match.
func (rc *Receiver) resolveSlackHandleToUser(ctx context.Context, handle string) string {
	rows, err := rc.store.DB().QueryContext(ctx, `SELECT id, email, COALESCE(display_name,'') FROM users LIMIT 500`)
	if err != nil {
		return ""
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, email, name string
		if err := rows.Scan(&id, &email, &name); err != nil {
			continue
		}
		local := email
		if at := strings.IndexByte(email, '@'); at > 0 {
			local = email[:at]
		}
		if strings.EqualFold(local, handle) || strings.EqualFold(name, handle) {
			return id
		}
	}
	return ""
}
