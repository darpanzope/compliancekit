package cli

// v1.12 phase 3 — wire SAML SSO from env vars, mirroring the OIDC
// shape from serve_oidc.go. Operators bring one or more IdPs by
// setting CK_SAML_<TAG>_* groups; each group spins up
// /saml/<id>/{login,acs,metadata} and surfaces a button on /login.
//
// Required env vars per group (suffix on CK_SAML_<TAG>_):
//
//	ID                     URL-safe identifier; defaults to lowercase TAG
//	LABEL                  Button label, "Sign in with Okta"
//	ROOT_URL               Daemon root, "https://compliancekit.example.com"
//	ENTRY_POINT            IdP SSO URL
//	IDP_METADATA_XML       OR IDP_CERT_PEM — IdP signing material
//	IDP_CERT_PEM
//	SP_CERT_PEM            SP signing cert
//	SP_KEY_PEM             SP signing private key
//	ENTITY_ID              optional; defaults to /metadata URL
//	ALLOW_IDP_INITIATED    "true" / "false" (default true)
//	SIGN_REQUESTS          "true" / "false" (default false)
//
// TAGs discovered: OKTA, AZURE, GOOGLE, CUSTOM (additive — operators
// can add new tags by extending the table below).

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/store"
)

func loadSAMLFromEnv(ctx context.Context, r chi.Router, users *auth.Users, sessions *auth.Sessions, st *store.Store) ([]auth.SAMLProviderButton, error) {
	tags := []string{"OKTA", "AZURE", "GOOGLE", "CUSTOM"}
	out := make([]auth.SAMLProviderButton, 0, len(tags))
	for _, tag := range tags {
		prefix := "CK_SAML_" + tag
		entry := os.Getenv(prefix + "_ENTRY_POINT")
		spCert := os.Getenv(prefix + "_SP_CERT_PEM")
		spKey := os.Getenv(prefix + "_SP_KEY_PEM")
		idpMeta := os.Getenv(prefix + "_IDP_METADATA_XML")
		idpCert := os.Getenv(prefix + "_IDP_CERT_PEM")
		if entry == "" && spCert == "" && spKey == "" && idpMeta == "" && idpCert == "" {
			continue
		}
		if entry == "" || spCert == "" || spKey == "" {
			return nil, fmt.Errorf("%s: incomplete SAML config (need ENTRY_POINT + SP_CERT_PEM + SP_KEY_PEM)", prefix)
		}
		if idpMeta == "" && idpCert == "" {
			return nil, fmt.Errorf("%s: missing %s_IDP_METADATA_XML or %s_IDP_CERT_PEM", prefix, prefix, prefix)
		}
		cfg := auth.SAMLConfig{
			ID:                envOr(prefix+"_ID", strings.ToLower(tag)),
			Label:             envOr(prefix+"_LABEL", "Sign in with "+strings.Title(strings.ToLower(tag))), //nolint:staticcheck // strings.Title is fine for short ASCII tags
			RootURL:           os.Getenv(prefix + "_ROOT_URL"),
			EntryPoint:        entry,
			IDPMetadataXML:    idpMeta,
			IDPCertPEM:        idpCert,
			SPCertPEM:         spCert,
			SPKeyPEM:          spKey,
			EntityID:          os.Getenv(prefix + "_ENTITY_ID"),
			AllowIDPInitiated: envBool(prefix+"_ALLOW_IDP_INITIATED", true),
			SignRequests:      envBool(prefix+"_SIGN_REQUESTS", false),
		}
		if cfg.RootURL == "" {
			return nil, fmt.Errorf("%s: missing %s_ROOT_URL", prefix, prefix)
		}
		h, err := auth.NewSAML(ctx, cfg, users, sessions, st)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", prefix, err)
		}
		h.Mount(r)
		out = append(out, h.Button())
	}
	return out, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}
