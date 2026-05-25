package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newReadyServer(t *testing.T) *Server {
	t.Helper()
	cfg := Default()
	cfg.Port = 0
	return New(cfg)
}

func TestHealthReady_NoChecksRegistered(t *testing.T) {
	s := newReadyServer(t)
	rec := httptest.NewRecorder()
	s.healthReadyHandler()(rec, httptest.NewRequest("GET", "/health/ready", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d want 200", rec.Code)
	}
	var body readinessReport
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status field = %q want ok", body.Status)
	}
}

func TestHealthReady_AllPass(t *testing.T) {
	s := newReadyServer(t)
	s.WithReadiness(ReadinessCheck{Name: "db", Check: func(context.Context) error { return nil }})
	s.WithReadiness(ReadinessCheck{Name: "queue", Check: func(context.Context) error { return nil }})

	rec := httptest.NewRecorder()
	s.healthReadyHandler()(rec, httptest.NewRequest("GET", "/health/ready", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d want 200", rec.Code)
	}
	var body readinessReport
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if body.Status != "ok" || len(body.Checks) != 2 {
		t.Errorf("body = %+v", body)
	}
}

func TestHealthReady_SingleFailure503s(t *testing.T) {
	s := newReadyServer(t)
	s.WithReadiness(ReadinessCheck{Name: "db", Check: func(context.Context) error { return nil }})
	s.WithReadiness(ReadinessCheck{Name: "queue", Check: func(context.Context) error { return errors.New("queue heartbeat stale") }})

	rec := httptest.NewRecorder()
	s.healthReadyHandler()(rec, httptest.NewRequest("GET", "/health/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d want 503", rec.Code)
	}
	var body readinessReport
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if body.Status != "fail" {
		t.Errorf("status field = %q want fail", body.Status)
	}
	var failures int
	for _, c := range body.Checks {
		if c.Status == "fail" {
			failures++
			if c.Name != "queue" || c.Err == "" {
				t.Errorf("expected queue:fail with err set, got %+v", c)
			}
		}
	}
	if failures != 1 {
		t.Errorf("expected exactly 1 failure, got %d", failures)
	}
}
