package plugins

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	pubplugin "github.com/darpanzope/compliancekit/pkg/compliancekit/plugin"
)

func TestSandboxMatchRule(t *testing.T) {
	cases := []struct {
		rule string
		host string
		want bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "evil.com", false},
		{"EXAMPLE.com", "example.com", true}, // case-insensitive host match
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "deep.api.example.com", false}, // single label only
		{"*.example.com", "example.com", false},
		{"example.com:443", "example.com", true},
		{"", "example.com", false},
	}
	for _, c := range cases {
		if got := matchRule(c.rule, c.host); got != c.want {
			t.Errorf("matchRule(%q,%q)=%v want %v", c.rule, c.host, got, c.want)
		}
	}
}

func TestSandboxCheckHost(t *testing.T) {
	s := NewSandbox(&pubplugin.Manifest{
		Name:           "p",
		DeclaredEgress: []string{"example.com", "*.api.com"},
	}, nil)
	if !s.CheckHost("example.com") {
		t.Errorf("example.com should be allowed")
	}
	if !s.CheckHost("v1.api.com") {
		t.Errorf("v1.api.com should be allowed (wildcard)")
	}
	if s.CheckHost("evil.example.com") {
		t.Errorf("evil.example.com should be denied")
	}
}

func TestSandbox_HTTPDenyAuditFires(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())

	var mu sync.Mutex
	denied := []string{}
	audit := func(pluginName, host string) {
		mu.Lock()
		denied = append(denied, pluginName+":"+host)
		mu.Unlock()
	}

	s := NewSandbox(&pubplugin.Manifest{Name: "blocked", DeclaredEgress: nil}, audit)
	client := s.HTTPClient()
	_, err := client.Get(srv.URL) //nolint:bodyclose,noctx // expected to fail at dial
	if err == nil {
		t.Fatalf("expected dial error, got nil")
	}
	if !strings.Contains(err.Error(), "egress denied") && !errors.Is(err, ErrEgressDenied) {
		t.Errorf("expected egress denied error, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(denied) == 0 || !strings.HasPrefix(denied[0], "blocked:") {
		t.Errorf("audit not fired or wrong shape: %v", denied)
	}
	_ = host // host is the localhost the test server bound; useful when extending the assertion
}

func TestSandbox_HTTPAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()
	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())

	s := NewSandbox(&pubplugin.Manifest{Name: "ok", DeclaredEgress: []string{host}}, nil)
	client := s.HTTPClient()
	resp, err := client.Get(srv.URL) //nolint:noctx // test
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 204 {
		t.Errorf("status=%d want 204", resp.StatusCode)
	}
}
