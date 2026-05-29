-- v1.19 phase 0 — per-user feature-tour dismissal state.
--
-- One row per (user, tour) the operator has dismissed or completed.
-- The feature-tour overlay (tour.js) reads the dismissed set from a
-- body data-attribute the daemon stamps per render + skips auto-
-- prompting tours already in this table. /onboarding lets the operator
-- replay a tour (re-runs it without clearing the row) or reset all
-- (DELETE the user's rows so every tour auto-prompts again).
CREATE TABLE user_tour_state (
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tour_id      TEXT NOT NULL,
    dismissed_at TEXT NOT NULL,
    PRIMARY KEY (user_id, tour_id)
);
