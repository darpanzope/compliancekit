package plugin

import (
	"errors"
	"fmt"
)

// ErrManifestNil is returned by Manifest.Validate when called on a
// nil receiver. Callers should never see this in practice, but the
// guard keeps the validator panic-free.
var ErrManifestNil = errors.New("plugin: manifest is nil")

// ErrManifestMissingName is returned when the manifest's Name field
// is empty. The daemon uses Name as the catalog key + the
// audit_log entity_id, so it must be set.
var ErrManifestMissingName = errors.New("plugin: manifest.name is required")

// ErrManifestMissingVersion is returned when the manifest's Version
// field is empty.
var ErrManifestMissingVersion = errors.New("plugin: manifest.version is required")

// ErrManifestMissingKinds is returned when the manifest declares
// no Kinds. A plugin that contributes nothing is invalid.
var ErrManifestMissingKinds = errors.New("plugin: manifest.kinds must list at least one kind")

// ErrManifestEmpty is returned when the manifest declares no
// entrypoint AND no rego_packs. Such a plugin has nothing to load.
var ErrManifestEmpty = errors.New("plugin: manifest must declare entrypoint or rego_packs")

// ErrUnsupportedAPIVersion is returned when the manifest's
// apiVersion doesn't match the running binary's APIVersion constant.
type ErrUnsupportedAPIVersion struct {
	Got  string
	Want string
}

// Error implements error.
func (e *ErrUnsupportedAPIVersion) Error() string {
	return fmt.Sprintf("plugin: manifest.apiVersion %q is not supported by this daemon (want %q)", e.Got, e.Want)
}

// ErrUnknownKind is returned when the manifest lists a kind that
// isn't in AllKinds.
type ErrUnknownKind struct {
	Got Kind
}

// Error implements error.
func (e *ErrUnknownKind) Error() string {
	return fmt.Sprintf("plugin: manifest declares unknown kind %q (must be one of: check, provider, notifier, reporter)", e.Got)
}
