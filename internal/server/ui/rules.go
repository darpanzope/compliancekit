package ui

// v1.9 phase 3 — Rules engine UI.
//
// /rules                 — list view (enabled + disabled side-by-side)
// GET  /rules/new        — blank editor
// GET  /rules/{id}       — load + edit
// POST /rules            — create
// POST /rules/{id}       — update
// POST /rules/{id}/delete — remove
// POST /rules/{id}/toggle — flip enabled
// GET  /rules/export.yaml — full ruleset for git versioning
//
// The form posts JSON-encoded condition + action blobs (the
// front-end Alpine component builds the tree as the operator
// adds rows); the handler unmarshals into rules.Condition +
// []rules.Action and persists via internal/rules.Repo.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	"github.com/darpanzope/compliancekit/internal/rules"
	"github.com/darpanzope/compliancekit/internal/rules/actions"
	"github.com/darpanzope/compliancekit/internal/rules/conditions"
	"github.com/darpanzope/compliancekit/internal/server/auth"
	rsdk "github.com/darpanzope/compliancekit/pkg/compliancekit/rules"
)

// rulesRepo lazily-constructs the engine repo.
func (u *UI) rulesRepoHandle() *rules.Repo {
	if u.rulesRepo == nil {
		u.rulesRepo = rules.NewRepo(u.store)
	}
	return u.rulesRepo
}

// ruleRow is the per-row payload the list view iterates.
type ruleRow struct {
	ID          string
	Name        string
	Description string
	Enabled     bool
	Priority    int
	Trigger     string
	CondSummary string
	ActSummary  string
	UpdatedIn   string
}

type rulesListView struct {
	View
	Rules   []ruleRow
	Total   int
	CanEdit bool
}

// ruleEditorView is the new/edit form payload.
type ruleEditorView struct {
	View
	Editing        bool
	Rule           rsdk.Rule
	ConditionJSON  string
	ActionsJSON    string
	ConditionKinds []string
	ActionKinds    []string
	Triggers       []string
	CanEdit        bool
}

// mountRulesRoutes wires the v1.9 phase 3 surface.
func (u *UI) mountRulesRoutes(r chi.Router) {
	r.Get("/rules", u.rulesList)
	r.Get("/rules/new", u.rulesEditor)
	r.Get("/rules/export.yaml", u.rulesExport)
	r.Get("/rules/{id}", u.rulesEditor)
	r.Post("/rules", u.rulesSave)
	r.Post("/rules/{id}", u.rulesSave)
	r.Post("/rules/{id}/delete", u.rulesDelete)
	r.Post("/rules/{id}/toggle", u.rulesToggle)
}

// rulesList renders /rules.
func (u *UI) rulesList(w http.ResponseWriter, r *http.Request) {
	rls, err := u.rulesRepoHandle().All(r.Context())
	if err != nil {
		u.fail(w, "load rules: "+err.Error())
		return
	}
	rows := make([]ruleRow, 0, len(rls))
	for _, rl := range rls {
		rows = append(rows, ruleRow{
			ID:          rl.ID,
			Name:        rl.Name,
			Description: rl.Description,
			Enabled:     rl.Enabled,
			Priority:    rl.Priority,
			Trigger:     string(rl.Trigger),
			CondSummary: summariseCondition(rl.Condition),
			ActSummary:  summariseActions(rl.Actions),
			UpdatedIn:   humanizeAgoStr(rl.UpdatedAt.Format("2006-01-02T15:04:05Z")),
		})
	}
	u.render(w, "rules.html", rulesListView{
		View:    u.viewFor(r, "Rules", "rules", View{}),
		Rules:   rows,
		Total:   len(rows),
		CanEdit: u.isAdmin(r.Context()),
	})
}

// rulesEditor renders /rules/new or /rules/{id}.
func (u *UI) rulesEditor(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var (
		rl   rules.Rule
		err  error
		edit bool
	)
	if id != "" {
		rl, err = u.rulesRepoHandle().ByID(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		edit = true
	} else {
		rl = rules.Rule{Rule: rsdk.Rule{
			Enabled: true, Priority: 100, Trigger: rsdk.TriggerFindingCreated, Timezone: "UTC",
		}}
	}
	condBytes, _ := rsdk.MarshalCondition(rl.Condition)
	actBytes, _ := rsdk.MarshalActions(rl.Actions)
	view := ruleEditorView{
		View:           u.viewFor(r, rl.Name, "rules", View{}),
		Editing:        edit,
		Rule:           rl.Rule,
		ConditionJSON:  string(condBytes),
		ActionsJSON:    string(actBytes),
		ConditionKinds: rules.DefaultRegistry.ConditionKinds(),
		ActionKinds:    rules.DefaultRegistry.ActionKinds(),
		Triggers: []string{
			string(rsdk.TriggerFindingCreated),
			string(rsdk.TriggerFindingResolved),
			string(rsdk.TriggerScanCompleted),
			string(rsdk.TriggerWaiverExpired),
			string(rsdk.TriggerCron),
		},
		CanEdit: u.isAdmin(r.Context()),
	}
	u.render(w, "rule_editor.html", view)
}

// rulesSave handles POST /rules + POST /rules/{id}.
func (u *UI) rulesSave(w http.ResponseWriter, r *http.Request) {
	if !u.isAdmin(r.Context()) {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form", http.StatusBadRequest)
		return
	}
	id := chi.URLParam(r, "id")
	rl, err := u.bindRuleForm(r, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if sess := auth.FromContext(r.Context()); sess != nil {
		rl.CreatedBy = sess.UserID
	}
	if id == "" {
		created, err := u.rulesRepoHandle().Create(r.Context(), rl)
		if err != nil {
			http.Error(w, "create: "+err.Error(), http.StatusBadRequest)
			return
		}
		u.AuditLog(r.Context(), "rule.create", "rule", created.ID, map[string]any{"name": created.Name})
		http.Redirect(w, r, "/rules/"+created.ID, http.StatusSeeOther)
		return
	}
	if err := u.rulesRepoHandle().Update(r.Context(), rl); err != nil {
		http.Error(w, "update: "+err.Error(), http.StatusBadRequest)
		return
	}
	u.AuditLog(r.Context(), "rule.update", "rule", rl.ID, map[string]any{"name": rl.Name})
	http.Redirect(w, r, "/rules/"+rl.ID, http.StatusSeeOther)
}

// bindRuleForm parses the form fields into a rules.Rule. Splits out
// of rulesSave to keep cyclomatic complexity manageable.
func (u *UI) bindRuleForm(r *http.Request, id string) (rules.Rule, error) {
	priority, _ := strconv.Atoi(r.FormValue("priority"))
	enabled := r.FormValue("enabled") == "on"
	cond, err := rsdk.UnmarshalCondition([]byte(strings.TrimSpace(r.FormValue("condition_json"))))
	if err != nil {
		return rules.Rule{}, fmt.Errorf("condition_json: %w", err)
	}
	acts, err := rsdk.UnmarshalActions([]byte(strings.TrimSpace(r.FormValue("actions_json"))))
	if err != nil {
		return rules.Rule{}, fmt.Errorf("actions_json: %w", err)
	}
	if len(acts) == 0 {
		return rules.Rule{}, errors.New("rule needs at least one action")
	}
	return rules.Rule{Rule: rsdk.Rule{
		ID:          id,
		Name:        strings.TrimSpace(r.FormValue("name")),
		Description: strings.TrimSpace(r.FormValue("description")),
		Enabled:     enabled,
		Priority:    priority,
		Trigger:     rsdk.Trigger(r.FormValue("trigger")),
		CronExpr:    strings.TrimSpace(r.FormValue("cron_expr")),
		Timezone:    r.FormValue("timezone"),
		Condition:   cond,
		Actions:     acts,
	}}, nil
}

// rulesDelete handles POST /rules/{id}/delete.
func (u *UI) rulesDelete(w http.ResponseWriter, r *http.Request) {
	if !u.isAdmin(r.Context()) {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	if err := u.rulesRepoHandle().Delete(r.Context(), id); err != nil {
		http.Error(w, "delete: "+err.Error(), http.StatusInternalServerError)
		return
	}
	u.AuditLog(r.Context(), "rule.delete", "rule", id, nil)
	http.Redirect(w, r, "/rules", http.StatusSeeOther)
}

// rulesToggle flips the enabled flag.
func (u *UI) rulesToggle(w http.ResponseWriter, r *http.Request) {
	if !u.isAdmin(r.Context()) {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	rl, err := u.rulesRepoHandle().ByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rl.Enabled = !rl.Enabled
	if err := u.rulesRepoHandle().Update(r.Context(), rl); err != nil {
		http.Error(w, "toggle: "+err.Error(), http.StatusInternalServerError)
		return
	}
	u.AuditLog(r.Context(), "rule.toggle", "rule", id, map[string]any{"enabled": rl.Enabled})
	http.Redirect(w, r, "/rules", http.StatusSeeOther)
}

// rulesExport renders the full ruleset as YAML for git versioning.
// Operators can pipe this back via the CLI (next slot) to round-trip.
func (u *UI) rulesExport(w http.ResponseWriter, r *http.Request) {
	rls, err := u.rulesRepoHandle().All(r.Context())
	if err != nil {
		http.Error(w, "load rules: "+err.Error(), http.StatusInternalServerError)
		return
	}
	type exported struct {
		Version int         `yaml:"version"`
		Rules   []rsdk.Rule `yaml:"rules"`
	}
	out := exported{Version: 1, Rules: make([]rsdk.Rule, 0, len(rls))}
	for _, rl := range rls {
		out.Rules = append(out.Rules, rl.Rule)
	}
	body, err := yaml.Marshal(out)
	if err != nil {
		http.Error(w, "marshal: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="rules.yaml"`)
	_, _ = w.Write(body)
}

// ─── helpers ───────────────────────────────────────────────────────────

// summariseCondition walks the condition tree and renders a compact
// AND/OR string suitable for list views. Empty trees render as "any
// event" so the operator sees the action-only rule case.
func summariseCondition(c rsdk.Condition) string {
	if c.IsAlwaysMatch() {
		return "any event"
	}
	return walkCondition(c)
}

func walkCondition(c rsdk.Condition) string {
	if c.Term != nil {
		got := conditions.Describe(c.Term.Kind, c.Term.Params)
		if c.Term.Negate {
			got = "NOT (" + got + ")"
		}
		return got
	}
	parts := make([]string, 0, len(c.Children))
	for _, child := range c.Children {
		parts = append(parts, walkCondition(child))
	}
	join := " AND "
	if c.Op == rsdk.OpOr {
		join = " OR "
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, join) + ")"
}

// summariseActions joins per-action Describe outputs with arrows.
func summariseActions(as []rsdk.Action) string {
	if len(as) == 0 {
		return "(no actions)"
	}
	parts := make([]string, 0, len(as))
	for _, a := range as {
		parts = append(parts, actions.Describe(a.Kind, a.Params))
	}
	return strings.Join(parts, " → ")
}

// humanizeAgoStr accepts an RFC3339 string + delegates to the
// existing humanizeAgo helper from audit.go.
func humanizeAgoStr(s string) string {
	if s == "" {
		return ""
	}
	return humanizeAgo(s)
}

// avoid unused-import warning when only one of the imports is used
// during partial wiring.
var _ = json.Marshal
