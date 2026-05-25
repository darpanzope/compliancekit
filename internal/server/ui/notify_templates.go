package ui

// v1.13 phase 6 — /settings/notify-templates UI.
//
// Operators pick a sink kind, edit the Go text/template body in the
// textarea, and a live-preview panel rerenders the template against a
// canned sample finding payload on every keystroke (htmx hx-post on
// keyup, debounced by Alpine on the form). Save persists the body to
// the notify_templates table; v1.13.x wires the dispatchers to read
// from this table instead of their hardcoded defaults.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

var notifyKinds = []string{"slack", "teams", "email", "webhook", "jira", "linear", "pagerduty", "discord", "github"}

func (u *UI) mountNotifyTemplatesRoutes(r chi.Router) {
	r.Get("/settings/notify-templates", u.adminOnly(u.notifyTemplatesList))
	r.Get("/settings/notify-templates/{kind}", u.adminOnly(u.notifyTemplatesEdit))
	r.Post("/settings/notify-templates/{kind}", u.adminOnly(u.notifyTemplatesSave))
	r.Post("/settings/notify-templates/preview", u.adminOnly(u.notifyTemplatesPreview))
}

type notifyTemplatesListView struct {
	View
	Templates []notifyTemplateRow
}

type notifyTemplateRow struct {
	Kind        string
	HasOverride bool
	UpdatedAgo  string
}

func (u *UI) notifyTemplatesList(w http.ResponseWriter, r *http.Request) {
	have := map[string]string{}
	rows, err := u.store.DB().QueryContext(r.Context(),
		`SELECT kind, updated_at FROM notify_templates WHERE name = 'default'`)
	if err != nil {
		u.fail(w, "list templates: "+err.Error())
		return
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k, ts string
		if err := rows.Scan(&k, &ts); err != nil {
			u.fail(w, "scan templates: "+err.Error())
			return
		}
		have[k] = ts
	}

	items := make([]notifyTemplateRow, 0, len(notifyKinds))
	for _, k := range notifyKinds {
		row := notifyTemplateRow{Kind: k}
		if ts, ok := have[k]; ok {
			row.HasOverride = true
			row.UpdatedAgo = humanizeAgo(ts)
		}
		items = append(items, row)
	}
	view := notifyTemplatesListView{
		View:      u.viewFor(r, "Notification templates", "settings", View{Flash: r.URL.Query().Get("flash")}),
		Templates: items,
	}
	u.render(w, "notify_templates_list.html", view)
}

type notifyTemplateEditView struct {
	View
	Kind          string
	Body          string
	SamplePayload string
	Preview       string
	PreviewErr    string
}

func (u *UI) notifyTemplatesEdit(w http.ResponseWriter, r *http.Request) {
	kind := chi.URLParam(r, "kind")
	if !isKnownNotifyKind(kind) {
		http.NotFound(w, r)
		return
	}
	body := u.loadTemplateBody(r.Context(), kind)
	if body == "" {
		body = defaultTemplate(kind)
	}
	sample := defaultSamplePayload()
	preview, perr := renderTemplate(body, sample)
	view := notifyTemplateEditView{
		View:          u.viewFor(r, "Edit "+kind+" template", "settings", View{Flash: r.URL.Query().Get("flash")}),
		Kind:          kind,
		Body:          body,
		SamplePayload: sample,
		Preview:       preview,
		PreviewErr:    perr,
	}
	u.render(w, "notify_templates_edit.html", view)
}

func (u *UI) notifyTemplatesSave(w http.ResponseWriter, r *http.Request) {
	kind := chi.URLParam(r, "kind")
	if !isKnownNotifyKind(kind) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	body := r.FormValue("body")
	if _, err := template.New(kind).Parse(body); err != nil {
		http.Redirect(w, r, "/settings/notify-templates/"+kind+"?flash=parse-error", http.StatusSeeOther)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	// UPSERT via DELETE + INSERT — portable across SQLite + Postgres
	// without dialect-specific ON CONFLICT clauses.
	q1 := `DELETE FROM notify_templates WHERE kind = ` + ph(u.store, 1) + ` AND name = 'default'`
	if _, err := u.store.DB().ExecContext(r.Context(), q1, kind); err != nil {
		u.fail(w, "delete template: "+err.Error())
		return
	}
	q2 := `INSERT INTO notify_templates (id, kind, name, body, created_at, updated_at) VALUES (` + phList(u.store, 6) + `)`
	if _, err := u.store.DB().ExecContext(r.Context(), q2, uuid.NewString(), kind, "default", body, now, now); err != nil {
		u.fail(w, "insert template: "+err.Error())
		return
	}
	u.AuditLog(r.Context(), "notify_template.save", "notify_template", kind, map[string]any{
		"size_bytes": len(body),
	})
	http.Redirect(w, r, "/settings/notify-templates/"+kind+"?flash=saved", http.StatusSeeOther)
}

// notifyTemplatesPreview is the htmx target that re-renders on every
// keystroke. Body comes from form value `body`; payload from `payload`
// (defaults to defaultSamplePayload when empty). Returns an HTML
// fragment with the rendered output or an error block.
func (u *UI) notifyTemplatesPreview(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	body := r.FormValue("body")
	payload := r.FormValue("payload")
	if strings.TrimSpace(payload) == "" {
		payload = defaultSamplePayload()
	}
	out, perr := renderTemplate(body, payload)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if perr != "" {
		fmt.Fprintf(w, `<div class="text-xs text-destructive font-mono whitespace-pre-wrap">%s</div>`,
			template.HTMLEscapeString(perr))
		return
	}
	fmt.Fprintf(w, `<pre class="font-mono text-xs whitespace-pre-wrap">%s</pre>`,
		template.HTMLEscapeString(out))
}

func (u *UI) loadTemplateBody(ctx context.Context, kind string) string {
	var body string
	_ = u.store.DB().QueryRowContext(ctx,
		`SELECT body FROM notify_templates WHERE kind = `+ph(u.store, 1)+` AND name = 'default'`,
		kind).Scan(&body)
	return body
}

func isKnownNotifyKind(k string) bool {
	for _, n := range notifyKinds {
		if n == k {
			return true
		}
	}
	return false
}

// renderTemplate executes body against the JSON in payload. Returns
// the rendered output OR an error string (parse / unmarshal / exec).
//
// The funcmap exposes upper/lower/title so the canonical sink
// templates can format severities without preprocessing the payload.
func renderTemplate(body, payload string) (rendered, errMsg string) {
	t, err := template.New("preview").
		Option("missingkey=zero").
		Funcs(notifyTemplateFuncs).
		Parse(body)
	if err != nil {
		return "", "template parse error: " + err.Error()
	}
	var data any
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return "", "payload not valid JSON: " + err.Error()
	}
	var sb strings.Builder
	if err := t.Execute(&sb, data); err != nil {
		return "", "template exec error: " + err.Error()
	}
	return sb.String(), ""
}

// notifyTemplateFuncs is the FuncMap notification templates execute
// against. Kept tiny — operators reach for the sink's native body
// shape (JSON for webhooks, markdown for Slack); upper/lower/title
// cover the format-the-severity case.
var notifyTemplateFuncs = template.FuncMap{
	"upper": strings.ToUpper,
	"lower": strings.ToLower,
	"title": func(s string) string {
		if s == "" {
			return s
		}
		return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
	},
}

// defaultSamplePayload is the canned finding the preview renders
// against when the operator hasn't supplied their own JSON.
func defaultSamplePayload() string {
	return `{
  "id": "f-12345",
  "check_id": "aws.iam.user.mfa-enabled",
  "severity": "high",
  "status": "fail",
  "message": "Root account does not have MFA enabled",
  "resource": {
    "id": "arn:aws:iam::123456789012:root",
    "name": "root",
    "type": "aws.iam.user"
  },
  "provider": "aws",
  "scan_id": "scan-2026-05-25",
  "created_at": "2026-05-25T10:00:00Z"
}`
}

// defaultTemplate returns the starter body the editor shows on first
// visit per kind. Operators iterate on it from there.
func defaultTemplate(kind string) string {
	switch kind {
	case "slack", "teams", "discord":
		return `:rotating_light: *{{.severity | upper}}* — {{.check_id}}
Resource: {{.resource.name}} ({{.resource.type}})
{{.message}}
<https://compliancekit.example.com/findings/{{.id}}|View in compliancekit>`
	case "email":
		return `Subject: [{{.severity | upper}}] {{.check_id}} on {{.resource.name}}

A new compliance finding requires attention.

  Severity:  {{.severity}}
  Status:    {{.status}}
  Resource:  {{.resource.name}} ({{.resource.type}})
  Provider:  {{.provider}}

{{.message}}

Open the finding: https://compliancekit.example.com/findings/{{.id}}
`
	case "webhook":
		return `{
  "kind": "compliancekit.finding",
  "severity": "{{.severity}}",
  "check_id": "{{.check_id}}",
  "resource_id": "{{.resource.id}}",
  "message": "{{.message}}"
}`
	case "jira", "linear":
		return `{{.check_id}} → {{.resource.name}}

*{{.severity | upper}}*: {{.message}}

Resource: {{.resource.id}}
Scan: {{.scan_id}}`
	case "pagerduty":
		return `{
  "incident_key": "{{.id}}",
  "description": "[{{.severity}}] {{.check_id}} on {{.resource.name}}",
  "details": {
    "message": "{{.message}}",
    "resource": "{{.resource.id}}",
    "scan": "{{.scan_id}}"
  }
}`
	case "github":
		return `### {{.severity | upper}}: {{.check_id}}

**Resource:** ` + "`{{.resource.id}}`" + `
**Provider:** {{.provider}}

{{.message}}

_Detected in scan {{.scan_id}}_`
	}
	return "Override me — pick a sink kind."
}
