#!/usr/bin/env bash
#
# v1.15 phase 0 — guard the distroless image size budget.
# v1.15.1 phase 3 — bumped to a realistic measured ceiling and
# actually wired into .github/workflows/release.yaml as a post-
# publish gate. Before v1.15.1 this script was hand-run only and
# the 30 MiB budget was unreachable (measured was 45 MiB at v1.15.0).
#
# Fails when the published manifest exceeds the configured byte limit.
# CI invokes this against the release tag after every successful
# goreleaser run so a careless dependency bump (or a misconfigured
# Dockerfile layer) can't silently bloat the image.
#
# Defaults: 60 MiB. v1.15.0 measured at 45 MiB compressed (Go
# binary + K8s SDKs + OPA + chromedp + crewjam/saml + Preline + i18n
# all roll into a single ~45 MiB gzipped layer). 60 MiB gives 15 MiB
# of headroom for v1.15.x dep additions and the new operator image.
# The original "~25 MB" ROADMAP claim was aspirational; the v2.15
# code-health pass may shrink the binary back toward it by moving
# chromedp / OPA to v1.13 plugins.
#
# Usage:
#   IMAGE_TAG=1.15.1 ./deploy/scripts/image-size-budget.sh
#   IMAGE_TAG=latest BUDGET_MB=80 ./deploy/scripts/image-size-budget.sh
#   REGISTRY=ghcr.io/darpanzope/compliancekit-operator \
#     IMAGE_TAG=1.15.1 ./deploy/scripts/image-size-budget.sh
#
# Note the IMAGE_TAG has no `v` prefix — goreleaser publishes
# {{ .Version }} which strips it.

set -euo pipefail

REGISTRY="${REGISTRY:-ghcr.io/darpanzope/compliancekit}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
BUDGET_MB="${BUDGET_MB:-60}"
ARCH="${ARCH:-linux/amd64}"

if ! command -v crane >/dev/null 2>&1; then
  echo "image-size-budget: crane not on PATH; install via 'go install github.com/google/go-containerregistry/cmd/crane@latest'" >&2
  exit 2
fi

ref="${REGISTRY}:${IMAGE_TAG}"
echo "image-size-budget: measuring ${ref} (${ARCH}) against ${BUDGET_MB}MiB budget"

# Sum the manifest's per-layer sizes for the requested architecture.
bytes=$(crane manifest "${ref}" --platform="${ARCH}" \
  | jq '[.layers[].size, .config.size] | add')
mib=$(( bytes / 1024 / 1024 ))
budget_bytes=$(( BUDGET_MB * 1024 * 1024 ))

echo "image-size-budget: actual=${mib}MiB (${bytes}B) budget=${BUDGET_MB}MiB"

if [ "${bytes}" -gt "${budget_bytes}" ]; then
  echo "image-size-budget: FAIL — ${ref} (${ARCH}) is ${mib}MiB, exceeds ${BUDGET_MB}MiB" >&2
  exit 1
fi
echo "image-size-budget: ok"
