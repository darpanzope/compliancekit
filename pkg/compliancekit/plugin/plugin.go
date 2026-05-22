// Package plugin is the v1.13+ public surface for compliancekit
// plugins. A plugin extends the daemon with one or more checks,
// providers, notifiers, or reporters; the daemon discovers them
// under $XDG_DATA/compliancekit/plugins/ and loads them with cosign
// signature verification + a per-plugin egress allow-list.
//
// The types here describe the on-disk manifest shape + the loaded
// runtime view. Implementations of the actual plugin protocol
// (subprocess gRPC via hashicorp/go-plugin) live under
// internal/server/plugins/.
//
// Like every type in pkg/compliancekit, this surface is covered by
// SemVer 2.0 + the api.txt CI gate. Additive changes only inside
// the v1.x line per ADR-014; ABI breaks land at v2.9 when the
// marketplace layer goes live.
package plugin

import "time"

// APIVersion is the current manifest schema version. Plugins must
// declare an apiVersion in their manifest; the daemon refuses to load
// any manifest whose apiVersion is unknown to the running binary so
// a v2.x plugin can't accidentally drift into a v1.x daemon and
// silently misbehave.
const APIVersion = "compliancekit.io/v1"

// Kind classifies what the plugin contributes to the daemon. Plugins
// may declare multiple kinds (e.g. a plugin that ships both a check
// and a custom notifier).
type Kind string

// Kind constants.
const (
	// KindCheck contributes one or more Check IDs registered in the
	// global check registry.
	KindCheck Kind = "check"

	// KindProvider contributes a Collector implementation under a new
	// provider name.
	KindProvider Kind = "provider"

	// KindNotifier contributes a Notifier implementation hooked into
	// the v0.17 sink registry.
	KindNotifier Kind = "notifier"

	// KindReporter contributes a Reporter implementation for the
	// scan output formats.
	KindReporter Kind = "reporter"
)

// AllKinds is the canonical iteration order used by the catalog UI
// + the CLI's `plugins list` formatter.
var AllKinds = []Kind{
	KindCheck,
	KindProvider,
	KindNotifier,
	KindReporter,
}

// Manifest is the on-disk plugin descriptor. One manifest.yaml lives
// at the root of each plugin directory; the daemon parses it during
// discovery, validates the cosign signature against signature.sig,
// and registers the declared contributions.
type Manifest struct {
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`
	Name       string `json:"name" yaml:"name"`
	Version    string `json:"version" yaml:"version"`
	Author     string `json:"author,omitempty" yaml:"author,omitempty"`
	Homepage   string `json:"homepage,omitempty" yaml:"homepage,omitempty"`
	License    string `json:"license,omitempty" yaml:"license,omitempty"`

	Kinds []Kind `json:"kinds" yaml:"kinds"`

	// RequiredScopes is the auth.Scope set the plugin must hold to
	// run. Plugins requesting ScopeAdmin must be re-confirmed at
	// install time — the daemon's installer prompts the operator
	// before granting wildcard scope to third-party code.
	RequiredScopes []string `json:"required_scopes,omitempty" yaml:"required_scopes,omitempty"`

	// DeclaredEgress is the per-plugin allow-list of upstream hosts
	// the plugin is permitted to dial. Empty list = no egress
	// permitted (the plugin must run fully against in-process state
	// the daemon hands it). Each entry is a host[:port] string;
	// wildcard subdomains via "*.example.com" are honored.
	DeclaredEgress []string `json:"declared_egress,omitempty" yaml:"declared_egress,omitempty"`

	// Entrypoint is the relative path to the plugin's executable
	// inside the plugin directory. The daemon execs it with the
	// hashicorp/go-plugin handshake; absence + a Rego-only plugin
	// means the daemon hot-loads the Rego packs from rego/*.rego
	// directly without spinning a subprocess.
	Entrypoint string `json:"entrypoint,omitempty" yaml:"entrypoint,omitempty"`

	// RegoPacks lists the relative paths under rego/ that contain
	// Rego policies the daemon should load. When set, the plugin
	// extends the v0.16 policy registry without a subprocess.
	RegoPacks []string `json:"rego_packs,omitempty" yaml:"rego_packs,omitempty"`

	// Description is operator-facing copy displayed in the catalog UI
	// + the CLI's `plugins list` command.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// Validate reports the first manifest invariant the receiver fails.
// Returns nil when every required field is populated + sane.
//
// Validate intentionally does NOT verify the cosign signature — that
// step is the loader's job and requires the signature file alongside
// the manifest.
func (m *Manifest) Validate() error {
	if m == nil {
		return ErrManifestNil
	}
	if m.APIVersion != APIVersion {
		return &ErrUnsupportedAPIVersion{Got: m.APIVersion, Want: APIVersion}
	}
	if m.Name == "" {
		return ErrManifestMissingName
	}
	if m.Version == "" {
		return ErrManifestMissingVersion
	}
	if len(m.Kinds) == 0 {
		return ErrManifestMissingKinds
	}
	for _, k := range m.Kinds {
		if !isKnownKind(k) {
			return &ErrUnknownKind{Got: k}
		}
	}
	if m.Entrypoint == "" && len(m.RegoPacks) == 0 {
		return ErrManifestEmpty
	}
	return nil
}

// Plugin is the loaded, signature-verified runtime view of a plugin.
// Embedders receive these from PluginCatalog.All(); the daemon
// constructs them after discovery + manifest parse + signature
// verification + sandbox setup.
type Plugin struct {
	Manifest Manifest

	// Path is the absolute filesystem path of the plugin directory
	// the manifest was loaded from. Useful for the catalog UI's
	// "open in finder" affordance.
	Path string

	// SignatureValid is true when the plugin's signature.sig
	// validated against either the keyless Sigstore trust root or a
	// pinned operator-supplied verifier key. False when the daemon
	// was launched with --allow-unsigned-plugins.
	SignatureValid bool

	// InstalledAt is the wall-clock time the daemon first observed
	// the plugin on disk.
	InstalledAt time.Time

	// Generation increments on every hot-reload of the plugin's Rego
	// packs. In-flight scans cache the generation they started with
	// so a mid-scan reload doesn't shuffle their policy set.
	Generation int
}

// Catalog is the read-side interface the daemon's catalog exposes to
// embedders. Internal/server/plugins owns the implementation.
type Catalog interface {
	All() []*Plugin
	ByName(name string) (*Plugin, bool)
}

func isKnownKind(k Kind) bool {
	for _, known := range AllKinds {
		if known == k {
			return true
		}
	}
	return false
}
