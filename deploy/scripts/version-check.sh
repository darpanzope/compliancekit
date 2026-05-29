#!/usr/bin/env bash
# v1.19.1 (AUDIT-2) — deploy-manifest version drift guard.
#
# Every artifact under deploy/ that pins a compliancekit release must
# track the version being released. They drifted to 1.15.x across the
# v1.16–v1.19 cycle because nothing checked them; this script is wired
# into release.yaml so a tag push fails loudly when a ref wasn't bumped.
#
# Usage:  VERSION=1.19.0 ./deploy/scripts/version-check.sh
#         (VERSION is the no-`v` image tag; the script also accepts the
#          v-prefixed form for the Terraform release-tag defaults.)
#
# Image tags / Helm appVersion / Kustomize newTag use the no-`v` form
# (goreleaser's `.Version` strips the prefix → real image is
# `compliancekit:1.19.0`). Terraform `release_tag` variable defaults use
# the v-prefixed form (Terraform downloads the GitHub release archive by
# its `v`-prefixed tag). The `dev` kustomize overlay intentionally pins
# `latest` and is exempt.
set -euo pipefail

VERSION="${VERSION:?set VERSION (no-v, e.g. 1.19.0)}"
VERSION="${VERSION#v}"           # normalise: accept v1.19.0 or 1.19.0
VTAG="v${VERSION}"               # v-prefixed form for Terraform
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
fail=0

note() { printf '  %s\n' "$1"; }
bad()  { printf '  ✗ %s\n' "$1"; fail=1; }

echo "deploy version check — expecting ${VERSION} (Terraform: ${VTAG})"

# Helm chart: version + appVersion must equal the no-v VERSION.
chart="${ROOT}/deploy/helm/Chart.yaml"
if grep -qE "^version: ${VERSION}\$" "$chart"; then note "helm version ✓"; else bad "helm Chart.yaml version != ${VERSION}"; fi
if grep -qE "^appVersion: \"${VERSION}\"\$" "$chart"; then note "helm appVersion ✓"; else bad "helm Chart.yaml appVersion != ${VERSION}"; fi

# Kustomize: every newTag except the dev overlay must equal VERSION.
while IFS= read -r f; do
  case "$f" in *overlays/dev/*) continue;; esac   # dev pins :latest by design
  tag="$(grep -E '^\s*newTag:' "$f" | awk '{print $2}')"
  if [ "$tag" = "$VERSION" ]; then note "kustomize $(basename "$(dirname "$f")")/newTag ✓"; else bad "$f newTag=${tag} != ${VERSION}"; fi
done < <(grep -rlE '^\s*newTag:' "${ROOT}/deploy/kustomize" 2>/dev/null)

# Image refs (daemon + operator) across deploy/*.yaml that pin a numeric
# tag must carry :VERSION. (`:latest` and templated tags are exempt.)
while IFS= read -r f; do
  while IFS= read -r ref; do
    tag="${ref##*:}"
    if [ "$tag" = "$VERSION" ]; then note "image $(basename "$f") :${tag} ✓"; else bad "${f} image tag :${tag} != ${VERSION}"; fi
  done < <(grep -oE 'ghcr\.io/darpanzope/compliancekit(-operator)?:[0-9][0-9.]*' "$f")
done < <(grep -rlE 'ghcr\.io/darpanzope/compliancekit(-operator)?:[0-9]' "${ROOT}/deploy" --include='*.yaml' --include='*.yml' 2>/dev/null)

# Terraform release-tag variable defaults must equal the v-prefixed VTAG.
while IFS= read -r f; do
  def="$(grep -E 'default *= *"v[0-9]' "$f" | head -1 | grep -oE 'v[0-9.]+')"
  if [ "$def" = "$VTAG" ]; then note "terraform $(basename "$(dirname "$f")") default ✓"; else bad "$f release-tag default=${def} != ${VTAG}"; fi
done < <(grep -rlE 'default *= *"v[0-9]' "${ROOT}/deploy/terraform" 2>/dev/null)

if [ "$fail" -ne 0 ]; then
  echo "deploy version check FAILED — bump the refs above to ${VERSION} (see deploy/scripts/version-check.sh)"
  exit 1
fi
echo "deploy version check OK — every ref tracks ${VERSION}"
