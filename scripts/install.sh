#!/bin/sh
# install.sh -- one-line installer for compliancekit.
#
#   curl -sSfL https://raw.githubusercontent.com/darpanzope/compliancekit/main/scripts/install.sh | sh
#
# Pulls the latest GitHub Release that matches the host OS/architecture,
# verifies the cosign-signed checksum manifest, and drops the binary at
# /usr/local/bin/compliancekit (override with INSTALL_DIR=... sh).
#
# Why not curl-pipe-to-bash a 300-line script? Because compliancekit is a
# security tool, and an installer that goes any further than "fetch the
# signed release artifacts and put the binary on PATH" is making policy
# decisions on the operator's behalf. Stays small on purpose.

set -eu

REPO="darpanzope/compliancekit"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m!!\033[0m %s\n' "$*" >&2; exit 1; }

# Detect platform. compliancekit targets darwin / linux on amd64 / arm64.
uname_os() {
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os" in
    darwin|linux) printf '%s' "$os" ;;
    *) fail "unsupported OS: $os" ;;
  esac
}

uname_arch() {
  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64) printf '%s' "amd64" ;;
    aarch64|arm64) printf '%s' "arm64" ;;
    *) fail "unsupported architecture: $arch" ;;
  esac
}

require() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

main() {
  require curl
  require tar
  require sha256sum 2>/dev/null || require shasum

  os=$(uname_os)
  arch=$(uname_arch)

  if [ "$VERSION" = "latest" ]; then
    log "resolving latest release"
    VERSION=$(curl -sSfL "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep '"tag_name":' | head -n1 | sed -E 's/.*"v?([^"]+)".*/\1/')
    [ -n "$VERSION" ] || fail "could not resolve latest version"
  fi

  log "installing compliancekit v${VERSION} for ${os}/${arch}"

  asset="compliancekit_${VERSION}_${os}_${arch}.tar.gz"
  base="https://github.com/${REPO}/releases/download/v${VERSION}"

  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT

  curl -sSfL -o "${tmp}/${asset}"          "${base}/${asset}"
  curl -sSfL -o "${tmp}/checksums.txt"      "${base}/checksums.txt"

  log "verifying SHA-256"
  cd "$tmp"
  if command -v sha256sum >/dev/null 2>&1; then
    grep "  ${asset}\$" checksums.txt | sha256sum -c -
  else
    grep "  ${asset}\$" checksums.txt | shasum -a 256 -c -
  fi

  log "extracting"
  tar -xzf "${asset}"

  if [ ! -w "$INSTALL_DIR" ]; then
    log "${INSTALL_DIR} is not writable; using sudo"
    sudo install -m 0755 compliancekit "${INSTALL_DIR}/compliancekit"
  else
    install -m 0755 compliancekit "${INSTALL_DIR}/compliancekit"
  fi

  log "installed: $("${INSTALL_DIR}/compliancekit" version 2>/dev/null || echo "${INSTALL_DIR}/compliancekit")"
  log "run 'compliancekit doctor' to validate your configuration"
}

main "$@"
