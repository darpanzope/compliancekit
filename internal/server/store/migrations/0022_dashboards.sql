-- v1.14 phase 0 — dashboard storage.
--
-- Dashboards are the v1.14 reporting primitive: a named canvas
-- composed of N widgets. Each widget is a typed visualization
-- (score gauge, severity donut, framework bar, finding list, ...)
-- with a query_json blob (the v1.5 explorer filter DSL) + grid
-- coordinates (x, y, w, h on a 12-col grid).
--
-- Scope: owner_user_id NULL = team-wide (admin-only create); a
-- populated owner_user_id makes the dashboard private to that user
-- (other users can view via live-share links from v1.14 phase 7
-- but not edit). The same shape as v1.5.1 saved_views — keeps the
-- access pattern familiar.
--
-- dashboard_layouts is the per-(dashboard, user) layout override:
-- one user might prefer the donut on the left, another wants it
-- on the right. The base dashboard_widgets row is the team
-- default; layouts let individuals customize without forking the
-- whole dashboard.

CREATE TABLE dashboards (
    id              TEXT PRIMARY KEY,
    owner_user_id   TEXT REFERENCES users(id) ON DELETE SET NULL, -- NULL = team-wide
    created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    template        TEXT NOT NULL DEFAULT '',                      -- non-empty when cloned from a built-in
    favorite        INTEGER NOT NULL DEFAULT 0                     -- 0/1; pin to nav
);
CREATE INDEX idx_dashboards_owner ON dashboards (owner_user_id);
CREATE INDEX idx_dashboards_template ON dashboards (template);

CREATE TABLE dashboard_widgets (
    id              TEXT PRIMARY KEY,
    dashboard_id    TEXT NOT NULL REFERENCES dashboards(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL
                        CHECK (kind IN (
                            'score_gauge', 'severity_donut',
                            'framework_bar', 'framework_radar',
                            'finding_list', 'resource_table',
                            'sparkline', 'heatmap',
                            'treemap', 'sankey',
                            'markdown', 'executive_summary')),
    title           TEXT NOT NULL DEFAULT '',
    query_json      TEXT NOT NULL DEFAULT '{}',  -- v1.5 explorer filter DSL
    config_json     TEXT NOT NULL DEFAULT '{}',  -- widget-specific options
    -- 12-col grid coordinates; w must be 1..12, h must be 1..24.
    grid_x          INTEGER NOT NULL DEFAULT 0,
    grid_y          INTEGER NOT NULL DEFAULT 0,
    grid_w          INTEGER NOT NULL DEFAULT 4,
    grid_h          INTEGER NOT NULL DEFAULT 4,
    order_idx       INTEGER NOT NULL DEFAULT 0   -- stable iteration when grids collide
);
CREATE INDEX idx_dashboard_widgets_dashboard ON dashboard_widgets (dashboard_id, order_idx);

-- Per-user layout override. user_id + dashboard_id is unique so
-- each user has at most one override per dashboard.
CREATE TABLE dashboard_layouts (
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    dashboard_id    TEXT NOT NULL REFERENCES dashboards(id) ON DELETE CASCADE,
    layout_json     TEXT NOT NULL DEFAULT '[]', -- [{widget_id, x, y, w, h}, ...]
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (user_id, dashboard_id)
);
