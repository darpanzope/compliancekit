package digitalocean

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbe_Success(t *testing.T) {
	server := newFixtureServer(t, map[string]string{
		"/v2/account": "testdata/account.json",
	})
	defer server.Close()

	client, err := newClient("test-token", server.URL)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}

	dur, err := probe(context.Background(), client)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if dur <= 0 {
		t.Errorf("probe duration = %v, want > 0", dur)
	}
}

func TestProbe_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"id":"unauthorized","message":"Unable to authenticate you"}`))
	}))
	defer server.Close()

	client, err := newClient("bad-token", server.URL)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}

	if _, err := probe(context.Background(), client); err == nil {
		t.Error("expected error on 401 unauthorized")
	}
}
