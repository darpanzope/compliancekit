package ingest

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// stubIngester is a minimal Ingester for exercising the registry. It
// records calls into a captured slice and returns whatever Result it
// was constructed with so tests can assert the plumbing path without
// depending on a real wire-format parser.
type stubIngester struct {
	format string
	desc   string
	result Result
	err    error
	calls  []string
}

func (s *stubIngester) Format() string      { return s.format }
func (s *stubIngester) Description() string { return s.desc }
func (s *stubIngester) Ingest(_ context.Context, r io.Reader, _ Options) (Result, error) {
	b, _ := io.ReadAll(r)
	s.calls = append(s.calls, string(b))
	if s.err != nil {
		return Result{}, s.err
	}
	return s.result, nil
}

func TestRegistry_RegisterLookupFormats(t *testing.T) {
	reg := NewRegistry()

	a := &stubIngester{format: "alpha", desc: "alpha format"}
	b := &stubIngester{format: "beta", desc: "beta format"}
	reg.Register(a)
	reg.Register(b)

	got, ok := reg.Lookup("alpha")
	if !ok || got.Format() != "alpha" {
		t.Fatalf("Lookup(alpha): got=%v ok=%v", got, ok)
	}
	if _, ok := reg.Lookup("missing"); ok {
		t.Fatalf("Lookup(missing): expected !ok")
	}

	formats := reg.Formats()
	if len(formats) != 2 || formats[0] != "alpha" || formats[1] != "beta" {
		t.Fatalf("Formats(): want [alpha beta], got %v", formats)
	}
}

func TestRegistry_DuplicateRegistrationPanics(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&stubIngester{format: "x"})

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on duplicate registration")
		}
	}()
	reg.Register(&stubIngester{format: "x"})
}

func TestRegistry_EmptyFormatPanics(t *testing.T) {
	reg := NewRegistry()
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on empty format")
		}
	}()
	reg.Register(&stubIngester{format: ""})
}

func TestRegistry_ConcurrentSafe(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&stubIngester{format: "alpha"})

	// Concurrent readers should not race. Run a handful of
	// goroutines doing Lookup + Formats while another writes.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			_ = reg.Formats()
			_, _ = reg.Lookup("alpha")
		}
		close(done)
	}()
	reg.Register(&stubIngester{format: "beta"})
	<-done
}

func TestIngester_StubIngestCall(t *testing.T) {
	want := Result{
		Findings: []compliancekit.Finding{{CheckID: "stub.example", Severity: compliancekit.SeverityHigh}},
	}
	s := &stubIngester{format: "stub", result: want}

	r := strings.NewReader("payload")
	got, err := s.Ingest(context.Background(), r, Options{})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(got.Findings) != 1 || got.Findings[0].CheckID != "stub.example" {
		t.Fatalf("Findings: %+v", got.Findings)
	}
	if len(s.calls) != 1 || s.calls[0] != "payload" {
		t.Fatalf("calls: %v", s.calls)
	}
}

func TestIngester_StubError(t *testing.T) {
	want := errors.New("parse boom")
	s := &stubIngester{format: "stub", err: want}

	_, err := s.Ingest(context.Background(), strings.NewReader(""), Options{})
	if !errors.Is(err, want) {
		t.Fatalf("Ingest: want err=%v, got %v", want, err)
	}
}

func TestMappingTable_Lookup(t *testing.T) {
	tab := &MappingTable{
		Tool: "trivy",
		Rules: map[string]MappingRule{
			"CKV_AWS_18": {
				Controls: []ControlMapping{{Framework: "soc2", Control: "CC6.1"}},
				Severity: "high",
				Tags:     []string{"s3"},
			},
		},
	}

	got, ok := tab.Lookup("CKV_AWS_18")
	if !ok || got.Severity != "high" || len(got.Controls) != 1 {
		t.Fatalf("Lookup(CKV_AWS_18): got=%+v ok=%v", got, ok)
	}
	if _, ok := tab.Lookup("MISSING"); ok {
		t.Fatalf("Lookup(MISSING): expected !ok")
	}

	// nil-safe.
	var nilTab *MappingTable
	if _, ok := nilTab.Lookup("anything"); ok {
		t.Fatalf("nil table Lookup: expected !ok")
	}
}
