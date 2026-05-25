// Package dashboards is the v1.14 reporting-renaissance persistence
// layer. Dashboards compose typed widgets over a 12-column grid;
// each widget carries a query (the v1.5 explorer filter DSL) + a
// per-kind config bag.
//
// The public-facing UI lives under internal/server/ui; the
// chart-rendering helpers under internal/report. This package
// owns the SQL and the canonical types both consume.
package dashboards

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/darpanzope/compliancekit/internal/server/store"
)

// ErrNotFound is returned by ByID when the dashboard doesn't exist.
var ErrNotFound = errors.New("dashboards: not found")

// Kind names the widget visualization. Mirrors the CHECK constraint
// in migration 0022 — adding a kind requires bumping both.
type Kind string

// Kind constants.
const (
	KindScoreGauge       Kind = "score_gauge"
	KindSeverityDonut    Kind = "severity_donut"
	KindFrameworkBar     Kind = "framework_bar"
	KindFrameworkRadar   Kind = "framework_radar"
	KindFindingList      Kind = "finding_list"
	KindResourceTable    Kind = "resource_table"
	KindSparkline        Kind = "sparkline"
	KindHeatmap          Kind = "heatmap"
	KindTreemap          Kind = "treemap"
	KindSankey           Kind = "sankey"
	KindMarkdown         Kind = "markdown"
	KindExecutiveSummary Kind = "executive_summary"
)

// AllKinds is the canonical iteration order the palette UI uses.
var AllKinds = []Kind{
	KindScoreGauge,
	KindSeverityDonut,
	KindFrameworkBar,
	KindFrameworkRadar,
	KindFindingList,
	KindResourceTable,
	KindSparkline,
	KindHeatmap,
	KindTreemap,
	KindSankey,
	KindMarkdown,
	KindExecutiveSummary,
}

// Dashboard is the canvas. Widgets are loaded eagerly via
// Store.ByID — typical dashboards carry 6-12 widgets so the N+1
// concern doesn't apply.
type Dashboard struct {
	ID              string    `json:"id"`
	OwnerUserID     string    `json:"owner_user_id,omitempty"`
	CreatedByUserID string    `json:"created_by_user_id,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	Template        string    `json:"template,omitempty"`
	Favorite        bool      `json:"favorite"`
	Widgets         []*Widget `json:"widgets,omitempty"`
}

// Widget is one tile on the canvas. Coordinates are on a 12-col
// grid; the UI clamps to legal ranges before saving.
type Widget struct {
	ID          string `json:"id"`
	DashboardID string `json:"dashboard_id,omitempty"`
	Kind        Kind   `json:"kind"`
	Title       string `json:"title,omitempty"`
	QueryJSON   string `json:"query_json"`
	ConfigJSON  string `json:"config_json"`
	GridX       int    `json:"grid_x"`
	GridY       int    `json:"grid_y"`
	GridW       int    `json:"grid_w"`
	GridH       int    `json:"grid_h"`
	OrderIdx    int    `json:"order_idx"`
}

// Store is the SQL-side handle.
type Store struct {
	store *store.Store
}

// New constructs a Store bound to st.
func New(st *store.Store) *Store { return &Store{store: st} }

// CreateDashboard inserts a new dashboard. ownerUserID may be empty
// (team-wide); createdBy is the session user.
func (s *Store) CreateDashboard(ctx context.Context, ownerUserID, createdBy, name, description, template string) (*Dashboard, error) {
	if name == "" {
		return nil, errors.New("dashboards: name is required")
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	q := `INSERT INTO dashboards (id, owner_user_id, created_by_user_id, created_at, updated_at, name, description, template)
	      VALUES (` + s.phList(8) + `)`
	if _, err := s.store.DB().ExecContext(ctx, q,
		id, nullable(ownerUserID), nullable(createdBy),
		now.Format(time.RFC3339), now.Format(time.RFC3339),
		name, description, template); err != nil {
		return nil, fmt.Errorf("insert dashboard: %w", err)
	}
	return &Dashboard{
		ID:              id,
		OwnerUserID:     ownerUserID,
		CreatedByUserID: createdBy,
		CreatedAt:       now,
		UpdatedAt:       now,
		Name:            name,
		Description:     description,
		Template:        template,
	}, nil
}

// ListVisible returns every dashboard the userID can view: team-wide
// (owner NULL) + user's own. Empty userID returns only team-wide.
func (s *Store) ListVisible(ctx context.Context, userID string) ([]*Dashboard, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if userID == "" {
		rows, err = s.store.DB().QueryContext(ctx,
			`SELECT id, COALESCE(owner_user_id,''), COALESCE(created_by_user_id,''),
			        created_at, updated_at, name, description, template, favorite
			 FROM dashboards WHERE owner_user_id IS NULL
			 ORDER BY favorite DESC, name`)
	} else {
		rows, err = s.store.DB().QueryContext(ctx,
			`SELECT id, COALESCE(owner_user_id,''), COALESCE(created_by_user_id,''),
			        created_at, updated_at, name, description, template, favorite
			 FROM dashboards
			 WHERE owner_user_id IS NULL OR owner_user_id = `+s.ph(1)+
				` ORDER BY favorite DESC, name`,
			userID)
	}
	if err != nil {
		return nil, fmt.Errorf("list dashboards: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Dashboard
	for rows.Next() {
		d := &Dashboard{}
		var (
			fav                  int
			created, updated     string
			ownerID, createdByID string
		)
		if err := rows.Scan(&d.ID, &ownerID, &createdByID, &created, &updated,
			&d.Name, &d.Description, &d.Template, &fav); err != nil {
			return nil, err
		}
		d.OwnerUserID = ownerID
		d.CreatedByUserID = createdByID
		d.CreatedAt = parseTime(created)
		d.UpdatedAt = parseTime(updated)
		d.Favorite = fav != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

// ByID returns the dashboard with its widgets loaded.
func (s *Store) ByID(ctx context.Context, id string) (*Dashboard, error) {
	row := s.store.DB().QueryRowContext(ctx,
		`SELECT id, COALESCE(owner_user_id,''), COALESCE(created_by_user_id,''),
		        created_at, updated_at, name, description, template, favorite
		 FROM dashboards WHERE id = `+s.ph(1), id)
	d := &Dashboard{}
	var (
		fav              int
		created, updated string
	)
	if err := row.Scan(&d.ID, &d.OwnerUserID, &d.CreatedByUserID, &created, &updated,
		&d.Name, &d.Description, &d.Template, &fav); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("dashboard: %w", err)
	}
	d.CreatedAt = parseTime(created)
	d.UpdatedAt = parseTime(updated)
	d.Favorite = fav != 0
	widgets, err := s.WidgetsFor(ctx, id)
	if err != nil {
		return nil, err
	}
	d.Widgets = widgets
	return d, nil
}

// WidgetsFor returns every widget on dashboardID, ordered by
// order_idx then grid_y, grid_x.
func (s *Store) WidgetsFor(ctx context.Context, dashboardID string) ([]*Widget, error) {
	rows, err := s.store.DB().QueryContext(ctx,
		`SELECT id, dashboard_id, kind, title, query_json, config_json,
		        grid_x, grid_y, grid_w, grid_h, order_idx
		 FROM dashboard_widgets WHERE dashboard_id = `+s.ph(1)+
			` ORDER BY order_idx, grid_y, grid_x`, dashboardID)
	if err != nil {
		return nil, fmt.Errorf("widgets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Widget
	for rows.Next() {
		var w Widget
		var kind string
		if err := rows.Scan(&w.ID, &w.DashboardID, &kind, &w.Title,
			&w.QueryJSON, &w.ConfigJSON,
			&w.GridX, &w.GridY, &w.GridW, &w.GridH, &w.OrderIdx); err != nil {
			return nil, err
		}
		w.Kind = Kind(kind)
		out = append(out, &w)
	}
	return out, rows.Err()
}

// AddWidget appends a widget. Clamps grid_w to [1,12] and grid_h
// to [1,24] so a malformed UI payload can't corrupt the canvas.
func (s *Store) AddWidget(ctx context.Context, w *Widget) (*Widget, error) {
	if w.DashboardID == "" {
		return nil, errors.New("dashboards: widget.DashboardID required")
	}
	if !isKnownKind(w.Kind) {
		return nil, fmt.Errorf("dashboards: unknown widget kind %q", w.Kind)
	}
	w.ID = uuid.NewString()
	w.GridW = clamp(w.GridW, 1, 12)
	w.GridH = clamp(w.GridH, 1, 24)
	if w.QueryJSON == "" {
		w.QueryJSON = "{}"
	}
	if w.ConfigJSON == "" {
		w.ConfigJSON = "{}"
	}
	q := `INSERT INTO dashboard_widgets (id, dashboard_id, kind, title, query_json, config_json,
	                                      grid_x, grid_y, grid_w, grid_h, order_idx)
	      VALUES (` + s.phList(11) + `)`
	if _, err := s.store.DB().ExecContext(ctx, q,
		w.ID, w.DashboardID, string(w.Kind), w.Title,
		w.QueryJSON, w.ConfigJSON,
		w.GridX, w.GridY, w.GridW, w.GridH, w.OrderIdx); err != nil {
		return nil, fmt.Errorf("insert widget: %w", err)
	}
	if err := s.touchDashboard(ctx, w.DashboardID); err != nil {
		return nil, err
	}
	return w, nil
}

// UpdateWidget rewrites a widget's grid coords + title + queries.
// Kind is immutable — drop + add to change shape.
func (s *Store) UpdateWidget(ctx context.Context, w *Widget) error {
	if w.ID == "" {
		return errors.New("dashboards: widget.ID required")
	}
	w.GridW = clamp(w.GridW, 1, 12)
	w.GridH = clamp(w.GridH, 1, 24)
	q := `UPDATE dashboard_widgets SET title = ` + s.ph(1) + `, query_json = ` + s.ph(2) +
		`, config_json = ` + s.ph(3) +
		`, grid_x = ` + s.ph(4) + `, grid_y = ` + s.ph(5) +
		`, grid_w = ` + s.ph(6) + `, grid_h = ` + s.ph(7) +
		`, order_idx = ` + s.ph(8) + ` WHERE id = ` + s.ph(9)
	if _, err := s.store.DB().ExecContext(ctx, q,
		w.Title, w.QueryJSON, w.ConfigJSON,
		w.GridX, w.GridY, w.GridW, w.GridH, w.OrderIdx, w.ID); err != nil {
		return fmt.Errorf("update widget: %w", err)
	}
	if w.DashboardID != "" {
		_ = s.touchDashboard(ctx, w.DashboardID)
	}
	return nil
}

// DeleteWidget removes a widget; cascade-friendly when the
// dashboard itself is removed.
func (s *Store) DeleteWidget(ctx context.Context, widgetID string) error {
	_, err := s.store.DB().ExecContext(ctx,
		`DELETE FROM dashboard_widgets WHERE id = `+s.ph(1), widgetID)
	return err
}

// SaveLayout persists a layout slice [{widget_id,x,y,w,h}] for the
// (user, dashboard) pair. v1.14 phase 1 — users override the team
// default layout without forking the dashboard.
func (s *Store) SaveLayout(ctx context.Context, userID, dashboardID string, layoutJSON string) error {
	if layoutJSON == "" {
		layoutJSON = "[]"
	}
	// Validate the JSON parses to a slice of position records.
	var positions []layoutPosition
	if err := json.Unmarshal([]byte(layoutJSON), &positions); err != nil {
		return fmt.Errorf("invalid layout_json: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	// UPSERT via DELETE + INSERT — portable across drivers.
	q1 := `DELETE FROM dashboard_layouts WHERE user_id = ` + s.ph(1) + ` AND dashboard_id = ` + s.ph(2)
	if _, err := s.store.DB().ExecContext(ctx, q1, userID, dashboardID); err != nil {
		return err
	}
	q2 := `INSERT INTO dashboard_layouts (user_id, dashboard_id, layout_json, updated_at) VALUES (` + s.phList(4) + `)`
	_, err := s.store.DB().ExecContext(ctx, q2, userID, dashboardID, layoutJSON, now)
	return err
}

type layoutPosition struct {
	WidgetID string `json:"widget_id"`
	X        int    `json:"x"`
	Y        int    `json:"y"`
	W        int    `json:"w"`
	H        int    `json:"h"`
}

// LayoutFor returns the per-user layout override or empty when none
// exists (caller falls back to the widget's saved grid coords).
func (s *Store) LayoutFor(ctx context.Context, userID, dashboardID string) (string, error) {
	var body string
	err := s.store.DB().QueryRowContext(ctx,
		`SELECT layout_json FROM dashboard_layouts WHERE user_id = `+s.ph(1)+` AND dashboard_id = `+s.ph(2),
		userID, dashboardID).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return body, err
}

// DeleteDashboard removes the dashboard + cascades widgets +
// layouts.
func (s *Store) DeleteDashboard(ctx context.Context, id string) error {
	_, err := s.store.DB().ExecContext(ctx,
		`DELETE FROM dashboards WHERE id = `+s.ph(1), id)
	return err
}

// ToggleFavorite flips the pin state.
func (s *Store) ToggleFavorite(ctx context.Context, id string) error {
	_, err := s.store.DB().ExecContext(ctx,
		`UPDATE dashboards SET favorite = (CASE favorite WHEN 1 THEN 0 ELSE 1 END) WHERE id = `+s.ph(1), id)
	return err
}

// UpdateMetadata edits name + description.
func (s *Store) UpdateMetadata(ctx context.Context, id, name, description string) error {
	q := `UPDATE dashboards SET name = ` + s.ph(1) + `, description = ` + s.ph(2) +
		`, updated_at = ` + s.ph(3) + ` WHERE id = ` + s.ph(4)
	_, err := s.store.DB().ExecContext(ctx, q,
		name, description, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

func (s *Store) touchDashboard(ctx context.Context, id string) error {
	_, err := s.store.DB().ExecContext(ctx,
		`UPDATE dashboards SET updated_at = `+s.ph(1)+` WHERE id = `+s.ph(2),
		time.Now().UTC().Format(time.RFC3339), id)
	return err
}

func isKnownKind(k Kind) bool {
	for _, known := range AllKinds {
		if known == k {
			return true
		}
	}
	return false
}

// clamp keeps grid coordinates within the (1, hi) legal range so a
// malformed UI payload can't corrupt the canvas. lo is always 1 by
// design — a widget with width 0 doesn't render. (The signature
// keeps `lo` parameterized for documentation symmetry with future
// hi-varying callers; revisit when more constraints land.)
//
//nolint:unparam // lo always 1; kept for future call sites + symmetry
func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Store) ph(n int) string {
	if s.store.Driver() == store.DriverPostgres {
		return "$" + strconv.Itoa(n)
	}
	return "?"
}

func (s *Store) phList(n int) string {
	out := make([]byte, 0, n*3)
	for i := 1; i <= n; i++ {
		if i > 1 {
			out = append(out, ',')
		}
		out = append(out, []byte(s.ph(i))...)
	}
	return string(out)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, s)
	return t
}
