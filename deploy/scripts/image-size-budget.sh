#!/usr/bin/env bash
#
# v1.15 phase 0 — guard the distroless image size budget.
#
# Fails when the published amd64 manifest exceeds the configured
# byte limit. CI invokes this against the release tag after every
# successful goreleaser run so a careless dependency bump (or a
# misconfigured Dockerfile layer) can't silently bloat the image.
#
# Defaults: 30 MiB (the ROADMAP "~25 MB" target with 5 MiB of
# headroom for cosign / ca-cert metadata layers that ride along).
#
# Usage:
#   IMAGE_TAG=v1.15.0 ./deploy/scripts/image-size-budget.sh
#   IMAGE_TAG=latest BUDGET_MB=40 ./deploy/scripts/image-size-budget.sh

set -euo pipefail

REGISTRY="${REGISTRY:-ghcr.io/darpanzope/compliancekit}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
BUDGET_MB="${BUDGET_MB:-30}"
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
