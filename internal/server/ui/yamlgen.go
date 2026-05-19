package ui

// v1.4 Phase 6 — Live compliancekit.yaml preview.
//
// Builds the equivalent compliancekit.yaml from the current DB state
// (providers, checks_state, framework_tailoring). Lets the operator
// copy/download the file that matches what they've toggled in the
// Studio without ever hand-editing YAML.
//
// Phase 7 (CI workflow generator) layers on top — the same generated
// config gets embedded into the generated .github/workflows/*.yaml.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// generatedConfig is the YAML shape we emit. Keys match the v0.x
// compliancekit.yaml format so the file can be committed as-is.
// Omitted-when-empty across the board so the output stays tight.
type generatedConfig struct {
	Providers  map[string]providerYAML  `yaml:"providers,omitempty"`
	Checks     *checksYAML              `yaml:"checks,omitempty"`
	Frameworks map[string]frameworkYAML `yaml:"frameworks,omitempty"`
}

type providerYAML struct {
	Enabled    bool     `yaml:"enabled"`
	Region     string   `yaml:"region,omitempty"`
	Services   []string `yaml:"services,omitempty"`
	Exclusions []string `yaml:"exclusions,omitempty"`
}

type checksYAML struct {
	Disabled []string `yaml:"disabled,omitempty"`
}

type frameworkYAML struct {
	Tailoring []tailoredControlYAML `yaml:"tailoring,omitempty"`
}

type tailoredControlYAML struct {
	Control       string `yaml:"control"`
	Included      bool   `yaml:"included"`
	Justification string `yaml:"justification,omitempty"`
}

// buildGeneratedConfig assembles the YAML shape from DB state.
func (u *UI) buildGeneratedConfig(ctx context.Context) (generatedConfig, error) {
	cfg := generatedConfig{}

	// Providers — every configured row gets a YAML entry.
	rows, err := u.loadProviderRows(ctx)
	if err != nil {
		return cfg, err
	}
	providers := map[string]providerYAML{}
	for _, row := range rows {
		if !row.Configured {
			continue
		}
		py := providerYAML{Enabled: row.Enabled}
		// We need the parsed config — reach back to the DB for the raw
		// JSON column.
		raw, _ := u.providerRawConfig(ctx, row.ID)
		var pc providerConfig
		if raw != "" {
			_ = json.Unmarshal([]byte(raw), &pc)
		}
		py.Region = pc.Region
		py.Services = pc.Services
		py.Exclusions = pc.Exclusions
		providers[row.ID] = py
	}
	if len(providers) > 0 {
		cfg.Providers = providers
	}

	// Checks — every checks_state row with enabled=0 lands in the
	// disabled list. Enabled overrides are no-ops since shipped
	// default is "on".
	overrides := u.loadCheckOverrides(ctx)
	disabled := []string{}
	for id, on := range overrides {
		if !on {
			disabled = append(disabled, id)
		}
	}
	if len(disabled) > 0 {
		sort.Strings(disabled)
		cfg.Checks = &checksYAML{Disabled: disabled}
	}

	// Framework tailoring — every framework_tailoring row.
	fwRows, _ := u.allTailoringDecisions(ctx)
	if len(fwRows) > 0 {
		cfg.Frameworks = map[string]frameworkYAML{}
		for fwID, decisions := range fwRows {
			items := []tailoredControlYAML{}
			for ctrlID, d := range decisions {
				items = append(items, tailoredControlYAML{
					Control:       ctrlID,
					Included:      d.included,
					Justification: d.justification,
				})
			}
			sort.Slice(items, func(i, j int) bool { return items[i].Control < items[j].Control })
			cfg.Frameworks[fwID] = frameworkYAML{Tailoring: items}
		}
	}

	return cfg, nil
}

// providerRawConfig fetches just the config_json column. Avoids
// re-querying via loadProviderRow when only the JSON is needed.
func (u *UI) providerRawConfig(ctx context.Context, id string) (string, error) {
	var raw string
	err := u.store.DB().QueryRowContext(ctx,
		`SELECT COALESCE(config_json,'{}') FROM providers WHERE id = `+ph(u.store, 1),
		id).Scan(&raw)
	return raw, err
}

// allTailoringDecisions returns every framework_tailoring row,
// indexed framework_id → control_id → decision.
func (u *UI) allTailoringDecisions(ctx context.Context) (map[string]map[string]tailoringDecision, error) {
	rows, err := u.store.DB().QueryContext(ctx,
		`SELECT framework_id, control_id, included, COALESCE(justification,'') FROM framework_tailoring`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]map[string]tailoringDecision{}
	for rows.Next() {
		var fwID, ctrlID, just string
		var inc int
		if err := rows.Scan(&fwID, &ctrlID, &inc, &just); err != nil {
			return out, err
		}
		if _, ok := out[fwID]; !ok {
			out[fwID] = map[string]tailoringDecision{}
		}
		out[fwID][ctrlID] = tailoringDecision{included: inc != 0, justification: just}
	}
	return out, rows.Err()
}

// renderGeneratedYAML returns the YAML serialization of the current
// DB state, with a header comment block linking back to the Studio.
func (u *UI) renderGeneratedYAML(ctx context.Context) (string, error) {
	cfg, err := u.buildGeneratedConfig(ctx)
	if err != nil {
		return "", err
	}
	body, err := yaml.Marshal(cfg)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# compliancekit.yaml — generated by the Studio (v1.4)\n")
	b.WriteString("#\n")
	b.WriteString("# This file matches the current state of /settings/providers,\n")
	b.WriteString("# /checks, and /settings/frameworks. Commit it to your repo and\n")
	b.WriteString("# the CLI scans against the same configuration.\n")
	b.WriteString("#\n")
	b.WriteString("# Sections omitted when empty.\n\n")
	if len(body) == 0 || strings.TrimSpace(string(body)) == "{}" {
		b.WriteString("# (no providers configured yet — visit /setup to onboard one)\n")
		return b.String(), nil
	}
	b.Write(body)
	return b.String(), nil
}

// mountYAMLRoutes registers the Phase 6 endpoints.
func (u *UI) mountYAMLRoutes(r interface {
	Get(pattern string, h http.HandlerFunc)
}) {
	r.Get("/settings/yaml", u.settingsYAMLView)
	r.Get("/settings/yaml/raw", u.settingsYAMLRaw)
	r.Get("/settings/yaml/download", u.settingsYAMLDownload)
}

// settingsYAMLView renders the YAML inside the daemon chrome with a
// copy + download button row.
func (u *UI) settingsYAMLView(w http.ResponseWriter, r *http.Request) {
	body, err := u.renderGeneratedYAML(r.Context())
	if err != nil {
		u.fail(w, "render yaml: "+err.Error())
		return
	}
	v := struct {
		View
		YAML string
	}{
		View: u.viewFor(r, "compliancekit.yaml · Settings", "settings", View{}),
		YAML: body,
	}
	u.render(w, "settings_yaml.html", v)
}

// settingsYAMLRaw returns the YAML as text/plain. Used by the
// "live preview" iframe / pre block on the settings landing page —
// any client that wants the raw file can hit this endpoint without
// the daemon chrome.
func (u *UI) settingsYAMLRaw(w http.ResponseWriter, r *http.Request) {
	body, err := u.renderGeneratedYAML(r.Context())
	if err != nil {
		http.Error(w, "render yaml: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, body)
}

// settingsYAMLDownload returns the YAML with a Content-Disposition
// attachment header so the browser saves it as compliancekit.yaml.
func (u *UI) settingsYAMLDownload(w http.ResponseWriter, r *http.Request) {
	body, err := u.renderGeneratedYAML(r.Context())
	if err != nil {
		http.Error(w, "render yaml: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="compliancekit.yaml"`)
	fmt.Fprint(w, body)
}
