package plugins

import "errors"

// ErrUnsigned is returned by Catalog.loadOne when the plugin has no
// valid signature + the catalog was not opted into
// --allow-unsigned-plugins.
var ErrUnsigned = errors.New("plugins: unsigned plugin refused (operators may opt in with --allow-unsigned-plugins)")

// ErrEgressDenied is returned by the sandbox dialer when a plugin
// tries to reach a host outside its DeclaredEgress allow-list.
var ErrEgressDenied = errors.New("plugins: egress denied — host not in manifest.declared_egress")
