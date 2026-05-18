package remediate

import (
	"errors"
	"strings"
	"testing"

	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

// stubStrategy is a minimal Strategy implementation tests use to
// exercise the registry. The fields name/ids/formats/render let
// each test parameterize what the strategy does without having to
// declare a new type.
type stubStrategy struct {
	name    string
	ids     []string
	formats []Format
	render  func(compliancekit.Finding, Format) (Snippet, error)
}

func (s stubStrategy) Name() string       { return s.name }
func (s stubStrategy) CheckIDs() []string { return s.ids }
func (s stubStrategy) Formats() []Format  { return s.formats }
func (s stubStrategy) Render(f compliancekit.Finding, format Format) (Snippet, error) {
	return s.render(f, format)
}

func TestParseFormat(t *testing.T) {
	cases := []struct {
		in   string
		want Format
		err  bool
	}{
		{"terraform", FormatTerraform, false},
		{"tf", FormatTerraform, false},
		{"k8s", FormatKubectl, false},
		{"aws", FormatAWSCLI, false},
		{"az", FormatAzureCLI, false},
		{"do", FormatDoctl, false},
		{"hetzner", FormatHcloud, false},
		{"helm", FormatHelm, false},
		{"ansible", FormatAnsible, false},
		{"bash", FormatBash, false},
		{"nonsense", "", true},
	}
	for _, c := range cases {
		got, err := ParseFormat(c.in)
		if (err != nil) != c.err {
			t.Errorf("ParseFormat(%q) err=%v want_err=%v", c.in, err, c.err)
		}
		if got != c.want {
			t.Errorf("ParseFormat(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	if _, err := ParseFormat("nope"); !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("ParseFormat unknown should wrap ErrUnknownFormat; got %v", err)
	}
}

func TestRegistry_ExactMatch(t *testing.T) {
	r := NewRegistry()
	r.Register(stubStrategy{
		name:    "test-exact",
		ids:     []string{"aws-s3-public"},
		formats: []Format{FormatTerraform},
		render: func(f compliancekit.Finding, _ Format) (Snippet, error) {
			return Snippet{Content: "resource " + f.Resource.ID, Risk: RiskSafe}, nil
		},
	})

	got, err := r.Render(compliancekit.Finding{
		CheckID:  "aws-s3-public",
		Resource: compliancekit.ResourceRef{ID: "aws.s3.bucket.foo"},
	}, FormatTerraform)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(got.Content, "aws.s3.bucket.foo") {
		t.Errorf("Content = %q; want resource ID embedded", got.Content)
	}
	if got.CheckID != "aws-s3-public" {
		t.Errorf("CheckID defaulting failed: %q", got.CheckID)
	}
	if got.Format != FormatTerraform {
		t.Errorf("Format defaulting failed: %q", got.Format)
	}
	if got.Resource.ID != "aws.s3.bucket.foo" {
		t.Errorf("Resource defaulting failed: %+v", got.Resource)
	}
}

func TestRegistry_NoStrategy(t *testing.T) {
	r := NewRegistry()
	_, err := r.Render(compliancekit.Finding{CheckID: "unknown"}, FormatTerraform)
	if !errors.Is(err, ErrNoStrategy) {
		t.Errorf("err = %v, want ErrNoStrategy wrapper", err)
	}
}

func TestRegistry_FormatFallback(t *testing.T) {
	r := NewRegistry()
	// Strategy 1 supports TF only.
	r.Register(stubStrategy{
		name:    "s1",
		ids:     []string{"check-x"},
		formats: []Format{FormatTerraform},
		render:  func(compliancekit.Finding, Format) (Snippet, error) { return Snippet{Content: "tf"}, nil },
	})
	// Strategy 2 supports AWS-CLI only for the SAME CheckID.
	r.Register(stubStrategy{
		name:    "s2",
		ids:     []string{"check-x"},
		formats: []Format{FormatAWSCLI},
		render:  func(compliancekit.Finding, Format) (Snippet, error) { return Snippet{Content: "aws"}, nil },
	})

	// Asking for TF picks s1.
	tf, err := r.Render(compliancekit.Finding{CheckID: "check-x"}, FormatTerraform)
	if err != nil || tf.Content != "tf" {
		t.Errorf("TF render = (%q, %v); want (tf, nil)", tf.Content, err)
	}
	// Asking for AWS-CLI picks s2 — registry iterates past s1.
	aws, err := r.Render(compliancekit.Finding{CheckID: "check-x"}, FormatAWSCLI)
	if err != nil || aws.Content != "aws" {
		t.Errorf("AWS-CLI render = (%q, %v); want (aws, nil)", aws.Content, err)
	}
	// Asking for an unsupported format → ErrFormatUnsupported.
	_, err = r.Render(compliancekit.Finding{CheckID: "check-x"}, FormatHelm)
	if !errors.Is(err, ErrFormatUnsupported) {
		t.Errorf("Helm render err = %v, want ErrFormatUnsupported", err)
	}
}

func TestRegistry_Wildcard(t *testing.T) {
	r := NewRegistry()
	r.Register(stubStrategy{
		name:    "fallback",
		ids:     []string{"*"},
		formats: []Format{FormatBash},
		render:  func(compliancekit.Finding, Format) (Snippet, error) { return Snippet{Content: "# manual review"}, nil },
	})
	got, err := r.Render(compliancekit.Finding{CheckID: "anything"}, FormatBash)
	if err != nil {
		t.Fatalf("wildcard render: %v", err)
	}
	if got.Content != "# manual review" {
		t.Errorf("wildcard render content = %q", got.Content)
	}
}

func TestRegistry_DuplicateNamePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("duplicate Name registration should panic")
		}
	}()
	r := NewRegistry()
	r.Register(stubStrategy{name: "dup", ids: []string{"a"}, formats: []Format{FormatBash},
		render: func(compliancekit.Finding, Format) (Snippet, error) { return Snippet{}, nil }})
	r.Register(stubStrategy{name: "dup", ids: []string{"b"}, formats: []Format{FormatBash},
		render: func(compliancekit.Finding, Format) (Snippet, error) { return Snippet{}, nil }})
}

func TestRegistry_RenderAll(t *testing.T) {
	r := NewRegistry()
	r.Register(stubStrategy{
		name:    "covers-tf-and-aws",
		ids:     []string{"check-y"},
		formats: []Format{FormatTerraform, FormatAWSCLI},
		render: func(_ compliancekit.Finding, f Format) (Snippet, error) {
			return Snippet{Content: string(f)}, nil
		},
	})
	findings := []compliancekit.Finding{
		{CheckID: "check-y", Resource: compliancekit.ResourceRef{ID: "x"}},
		{CheckID: "unknown-check"},
	}
	snippets, unmatched := r.RenderAll(findings)
	if len(snippets) != 2 {
		t.Errorf("snippets = %d, want 2 (tf+aws)", len(snippets))
	}
	if len(unmatched) != 1 || unmatched[0].CheckID != "unknown-check" {
		t.Errorf("unmatched = %+v; want unknown-check", unmatched)
	}
}

func TestRegistry_RegisterPanicsOnEmptyFormats(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("empty Formats() should panic at Register time")
		}
	}()
	r := NewRegistry()
	r.Register(stubStrategy{name: "no-formats", ids: []string{"a"}, formats: nil,
		render: func(compliancekit.Finding, Format) (Snippet, error) { return Snippet{}, nil }})
}

func TestRegistry_RegisteredCheckIDs(t *testing.T) {
	r := NewRegistry()
	r.Register(stubStrategy{
		name:    "multi",
		ids:     []string{"b", "a", "c"},
		formats: []Format{FormatBash},
		render:  func(compliancekit.Finding, Format) (Snippet, error) { return Snippet{}, nil },
	})
	ids := r.RegisteredCheckIDs()
	if len(ids) != 3 || ids[0] != "a" || ids[1] != "b" || ids[2] != "c" {
		t.Errorf("RegisteredCheckIDs = %v; want sorted [a b c]", ids)
	}
}
