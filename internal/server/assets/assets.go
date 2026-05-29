// Package assets embeds the compiled UI bundle (Tailwind output +
// vendored htmx, Alpine, Preline) produced by `make ui`. The files
// are committed under internal/server/assets/ and re-generated from
// internal/server/ui/src/ + internal/server/ui/vendor/ by the build
// pipeline. CI gates on `make ui-check`.
//
// Why a separate package: go:embed paths cannot traverse upward
// (no ".."), so the embed.FS lives next to the bundled files. The
// UI package imports this FS and serves it at /assets/*.
package assets

import "embed"

// FS holds the daemon's compiled UI bundle: Tailwind output + vendored
// JS libraries + v1.16 PWA artifacts (manifest + icons + service
// worker). Served at /assets/* by the ui package.
//
//go:embed app.css app.js a11y.js htmx.min.js alpine.min.js preline.js tour.js
//go:embed manifest.webmanifest sw.js sprite.svg
//go:embed icon-192.png icon-512.png icon-maskable-512.png apple-touch-icon.png favicon-32.png
var FS embed.FS
