package auth

import (
	"strings"
	"testing"

	"github.com/crewjam/saml"
)

func TestNewSAML_ValidationErrors(t *testing.T) {
	for name, cfg := range map[string]SAMLConfig{
		"missing-id":       {RootURL: "https://x", EntryPoint: "https://idp/sso"},
		"missing-idp-mat":  {ID: "x", RootURL: "https://x", EntryPoint: "https://idp/sso", SPCertPEM: "x", SPKeyPEM: "y"},
		"missing-sp-keys":  {ID: "x", RootURL: "https://x", EntryPoint: "https://idp/sso", IDPCertPEM: "x"},
		"missing-entry-pt": {ID: "x", RootURL: "https://x"},
		"missing-root-url": {ID: "x", EntryPoint: "https://idp/sso", IDPCertPEM: "x", SPCertPEM: "x", SPKeyPEM: "y"},
		"bad-sp-keypair":   {ID: "x", RootURL: "https://x", EntryPoint: "https://idp/sso", IDPCertPEM: "x", SPCertPEM: "junk", SPKeyPEM: "junk"},
	} {
		_, err := NewSAML(t.Context(), cfg, nil, nil, nil)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestExtractAssertionIdentity(t *testing.T) {
	cases := []struct {
		name        string
		assertion   *saml.Assertion
		wantEmail   string
		wantDisplay string
	}{
		{
			name: "email + displayName attrs",
			assertion: &saml.Assertion{
				Subject: &saml.Subject{NameID: &saml.NameID{Value: "alice@example.com"}},
				AttributeStatements: []saml.AttributeStatement{{
					Attributes: []saml.Attribute{
						{Name: "email", Values: []saml.AttributeValue{{Value: "alice@example.com"}}},
						{Name: "displayName", Values: []saml.AttributeValue{{Value: "Alice Smith"}}},
					},
				}},
			},
			wantEmail:   "alice@example.com",
			wantDisplay: "Alice Smith",
		},
		{
			name: "nameid only",
			assertion: &saml.Assertion{
				Subject: &saml.Subject{NameID: &saml.NameID{Value: "bob@example.com"}},
			},
			wantEmail:   "bob@example.com",
			wantDisplay: "bob@example.com",
		},
		{
			name:        "nil subject",
			assertion:   &saml.Assertion{},
			wantEmail:   "",
			wantDisplay: "",
		},
		{
			name: "xmlsoap schema attr names",
			assertion: &saml.Assertion{
				Subject: &saml.Subject{NameID: &saml.NameID{Value: "x"}},
				AttributeStatements: []saml.AttributeStatement{{
					Attributes: []saml.Attribute{
						{Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", Values: []saml.AttributeValue{{Value: "carol@example.com"}}},
					},
				}},
			},
			wantEmail:   "carol@example.com",
			wantDisplay: "carol@example.com",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotEmail, gotDisplay := extractAssertionIdentity(c.assertion)
			if gotEmail != c.wantEmail || gotDisplay != c.wantDisplay {
				t.Errorf("got (%q,%q), want (%q,%q)", gotEmail, gotDisplay, c.wantEmail, c.wantDisplay)
			}
		})
	}
}

func TestRandomPasswordPrefix(t *testing.T) {
	got := randomPassword()
	if !strings.HasPrefix(got, "saml-auto-") {
		t.Errorf("randomPassword should start with saml-auto- (got %q)", got)
	}
	if len(got) < 20 {
		t.Errorf("randomPassword too short: %q", got)
	}
}
