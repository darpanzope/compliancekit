package plugin

import (
	"errors"
	"testing"
)

func TestManifestValidate_HappyPath(t *testing.T) {
	m := &Manifest{
		APIVersion: APIVersion,
		Name:       "hello",
		Version:    "v0.1.0",
		Kinds:      []Kind{KindCheck},
		Entrypoint: "./bin/hello",
	}
	if err := m.Validate(); err != nil {
		t.Errorf("expected nil err, got %v", err)
	}
}

func TestManifestValidate_RegoOnly(t *testing.T) {
	m := &Manifest{
		APIVersion: APIVersion,
		Name:       "aws-iam-pack",
		Version:    "v0.1.0",
		Kinds:      []Kind{KindCheck},
		RegoPacks:  []string{"iam.rego"},
	}
	if err := m.Validate(); err != nil {
		t.Errorf("rego-only manifest should validate, got %v", err)
	}
}

func TestManifestValidate_Errors(t *testing.T) {
	cases := map[string]struct {
		m       *Manifest
		wantErr error
	}{
		"nil":             {nil, ErrManifestNil},
		"missing-name":    {&Manifest{APIVersion: APIVersion, Version: "v0.1", Kinds: []Kind{KindCheck}, Entrypoint: "x"}, ErrManifestMissingName},
		"missing-version": {&Manifest{APIVersion: APIVersion, Name: "x", Kinds: []Kind{KindCheck}, Entrypoint: "x"}, ErrManifestMissingVersion},
		"missing-kinds":   {&Manifest{APIVersion: APIVersion, Name: "x", Version: "v0.1", Entrypoint: "x"}, ErrManifestMissingKinds},
		"empty-body":      {&Manifest{APIVersion: APIVersion, Name: "x", Version: "v0.1", Kinds: []Kind{KindCheck}}, ErrManifestEmpty},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := c.m.Validate()
			if !errors.Is(got, c.wantErr) {
				t.Errorf("got %v, want %v", got, c.wantErr)
			}
		})
	}
}

func TestManifestValidate_UnsupportedAPIVersion(t *testing.T) {
	m := &Manifest{
		APIVersion: "compliancekit.io/v999",
		Name:       "x",
		Version:    "v0.1",
		Kinds:      []Kind{KindCheck},
		Entrypoint: "x",
	}
	var got *ErrUnsupportedAPIVersion
	if !errors.As(m.Validate(), &got) {
		t.Fatalf("want ErrUnsupportedAPIVersion, got %v", m.Validate())
	}
	if got.Got != "compliancekit.io/v999" || got.Want != APIVersion {
		t.Errorf("ErrUnsupportedAPIVersion fields wrong: %+v", got)
	}
}

func TestManifestValidate_UnknownKind(t *testing.T) {
	m := &Manifest{
		APIVersion: APIVersion,
		Name:       "x",
		Version:    "v0.1",
		Kinds:      []Kind{Kind("frobnicator")},
		Entrypoint: "x",
	}
	var got *ErrUnknownKind
	if !errors.As(m.Validate(), &got) {
		t.Fatalf("want ErrUnknownKind, got %v", m.Validate())
	}
}

func TestAllKindsIterationOrder(t *testing.T) {
	want := []Kind{KindCheck, KindProvider, KindNotifier, KindReporter}
	if len(AllKinds) != len(want) {
		t.Fatalf("len(AllKinds)=%d want %d", len(AllKinds), len(want))
	}
	for i, k := range AllKinds {
		if k != want[i] {
			t.Errorf("AllKinds[%d]=%q want %q", i, k, want[i])
		}
	}
}
