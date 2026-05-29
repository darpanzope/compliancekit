-- v1.19 phase 7 — per-user Table 2.0 column layout.
--
-- One row per (user, table) storing the operator's column layout as a
-- JSON blob: { "order":[keys], "hidden":[keys], "widths":{key:px},
-- "pinLeft":[keys], "pinRight":[keys] }. table_id is the data-ck-table2
-- attribute on the <table> (e.g. "findings", "resources", "scans").
-- table2.js loads this on page render + persists it (debounced) on every
-- resize / reorder / pin / show-hide.
CREATE TABLE user_table_state (
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    table_id     TEXT NOT NULL,
    layout_json  TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    PRIMARY KEY (user_id, table_id)
);
