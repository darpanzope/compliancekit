#!/usr/bin/env bash
#
# v1.15 phase 9 — one-line installer for compliancekit.
#
# Pipe-from-curl usage:
#
#   curl -sSf https://compliancekit.dev/install.sh | sh
#   curl -sSf https://raw.githubusercontent.com/darpanzope/compliancekit/main/deploy/install.sh | sh
#
# What it does:
#   1. Detects OS (linux / darwin) + arch (amd64 / arm64).
#   2. Resolves the latest release tag from the GitHub API (or
#      honors CK_VERSION when set).
#   3. Downloads the matching release tarball + checksum + cosign
#      bundle from github.com/darpanzope/compliancekit/releases.
#   4. Verifies the checksum + the cosign signature (keyless via
#      Sigstore Fulcio + Rekor, matching the goreleaser pipeline).
#   5. Installs the binary to /usr/local/bin/compliancekit
#      (CK_PREFIX overrides the destination dir).
#   6. On Linux with systemd present + run as root: drops the
#      deploy/systemd/compliancekit.service unit + creates the
#      compliancekit user + enables the service. CK_NO_SERVICE=1
#      skips this.
#   7. On macOS: prints next-step instructions (brew tap is the
#      preferred path on macOS; this installer is the fallback).
#
# Environment knobs:
#   CK_VERSION      tag to install (default: latest release).
#   CK_PREFIX       destination dir (default: /usr/local/bin).
#   CK_NO_SERVICE   1 to skip the systemd unit install.
#   CK_NO_VERIFY    1 to skip the cosign verification (NOT recommended).

set -euo pipefail

# ─── pretty-print helpers ─────────────────────────────────────────
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  BOLD=$(tput bold); DIM=$(tput dim); RESET=$(tput sgr0)
  RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3); CYAN=$(tput setaf 6)
else
  BOLD=""; DIM=""; RESET=""; RED=""; GREEN=""; YELLOW=""; CYAN=""
fi

step()  { printf "%s==>%s %s\n" "$CYAN" "$RESET" "$1"; }
done_() { printf "%s ok%s %s\n" "$GREEN" "$RESET" "$1"; }
warn()  { printf "%swarn%s %s\n" "$YELLOW" "$RESET" "$1" >&2; }
die()   { printf "%serror%s %s\n" "$RED" "$RESET" "$1" >&2; exit 1; }

# ─── 1. detect OS + arch ──────────────────────────────────────────
OS=""
case "$(uname -s)" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  *) die "unsupported OS: $(uname -s)" ;;
esac

ARCH=""
case "$(uname -m)" in
  x86_64|amd64)        ARCH=amd64 ;;
  aarch64|arm64)       ARCH=arm64 ;;
  *) die "unsupported arch: $(uname -m)" ;;
esac

step "detected ${BOLD}${OS}/${ARCH}${RESET}"

# ─── 2. resolve version ───────────────────────────────────────────
VERSION="${CK_VERSION:-}"
if [ -z "$VERSION" ]; then
  step "resolving latest release"
  if command -v curl >/dev/null 2>&1; then
    VERSION=$(curl -fsSL https://api.github.com/repos/darpanzope/compliancekit/releases/latest \
      | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
  elif command -v wget >/dev/null 2>&1; then
    VERSION=$(wget -qO- https://api.github.com/repos/darpanzope/compliancekit/releases/latest \
      | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
  else
    die "neither curl nor wget available"
  fi
  [ -n "$VERSION" ] || die "could not resolve latest release tag"
fi
done_ "version $VERSION"

VNUM="${VERSION#v}"
TAR="compliancekit_${VNUM}_${OS}_${ARCH}.tar.gz"
BASE="https://github.com/darpanzope/compliancekit/releases/download/${VERSION}"
SUMS="compliancekit_${VNUM}_checksums.txt"

# ─── 3. download ──────────────────────────────────────────────────
TMP=$(mktemp -d 2>/dev/null || mktemp -d -t compliancekit-install)
trap 'rm -rf "$TMP"' EXIT

step "downloading ${TAR}"
fetch() { curl -fsSL "$1" -o "$2"; }
if ! command -v curl >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
fi
fetch "${BASE}/${TAR}"  "${TMP}/${TAR}"
fetch "${BASE}/${SUMS}" "${TMP}/${SUMS}"

# ─── 4. verify checksum + cosign ──────────────────────────────────
step "verifying checksum"
EXPECTED=$(grep " ${TAR}\$" "${TMP}/${SUMS}" | awk '{print $1}')
[ -n "$EXPECTED" ] || die "${TAR} not listed in ${SUMS}"

ACTUAL=""
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "${TMP}/${TAR}" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL=$(shasum -a 256 "${TMP}/${TAR}" | awk '{print $1}')
else
  die "no sha256sum / shasum tool available"
fi
[ "$EXPECTED" = "$ACTUAL" ] || die "checksum mismatch: expected $EXPECTED got $ACTUAL"
done_ "checksum $ACTUAL"

if [ "${CK_NO_VERIFY:-0}" = "1" ]; then
  warn "skipping cosign verification (CK_NO_VERIFY=1)"
else
  step "verifying cosign signature"
  if ! command -v cosign >/dev/null 2>&1; then
    warn "cosign not on PATH; checksum verified but signature skipped — install cosign from https://docs.sigstore.dev/ to enforce"
  else
    fetch "${BASE}/${SUMS}.sig" "${TMP}/${SUMS}.sig" || true
    fetch "${BASE}/${SUMS}.pem" "${TMP}/${SUMS}.pem" || true
    if [ -s "${TMP}/${SUMS}.sig" ] && [ -s "${TMP}/${SUMS}.pem" ]; then
      cosign verify-blob \
        --certificate-identity-regexp 'https://github.com/darpanzope/compliancekit/' \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        --certificate "${TMP}/${SUMS}.pem" \
        --signature  "${TMP}/${SUMS}.sig" \
        "${TMP}/${SUMS}" >/dev/null
      done_ "cosign keyless signature ok"
    else
      warn "release did not ship cosign signature artifacts — proceeding without signature verification"
    fi
  fi
fi

# ─── 5. install ───────────────────────────────────────────────────
PREFIX="${CK_PREFIX:-/usr/local/bin}"
step "extracting + installing to ${PREFIX}/compliancekit"
tar -xzf "${TMP}/${TAR}" -C "${TMP}"

SUDO=""
if [ ! -w "${PREFIX}" ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO=sudo
  else
    die "${PREFIX} not writable + sudo unavailable — re-run as root or set CK_PREFIX"
  fi
fi
$SUDO install -m 0755 "${TMP}/compliancekit" "${PREFIX}/compliancekit"
done_ "installed ${PREFIX}/compliancekit"

# ─── 6. optional systemd unit on Linux ────────────────────────────
if [ "$OS" = "linux" ] && [ "${CK_NO_SERVICE:-0}" != "1" ] && [ "$(id -u)" = "0" ] && command -v systemctl >/dev/null 2>&1; then
  step "installing systemd unit"

  # User + state dir.
  if ! id compliancekit >/dev/null 2>&1; then
    useradd --system --user-group --create-home \
      --home-dir /var/lib/compliancekit \
      --shell /usr/sbin/nologin compliancekit
  fi
  install -d -o compliancekit -g compliancekit /var/lib/compliancekit

  # Inline the unit so the installer is self-contained (no second
  # download). Mirrors deploy/systemd/compliancekit.service verbatim.
  cat > /etc/systemd/system/compliancekit.service <<'UNIT'
[Unit]
Description=compliancekit daemon
Documentation=https://github.com/darpanzope/compliancekit
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=compliancekit
Group=compliancekit
WorkingDirectory=/var/lib/compliancekit
Environment=CK_DB=/var/lib/compliancekit/serve.db
ExecStart=/usr/local/bin/compliancekit serve --addr 127.0.0.1 --port 8080 --db ${CK_DB}
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s

NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/compliancekit
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0027
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now compliancekit
  done_ "systemd unit installed + enabled"
  printf "\n%scompliancekit is running on http://127.0.0.1:8080%s\n" "$BOLD" "$RESET"
  printf "  status:  systemctl status compliancekit\n"
  printf "  logs:    journalctl -u compliancekit -f\n"
  printf "  bootstrap admin: compliancekit serve users create --admin --email=…\n"
  exit 0
fi

# ─── 7. macOS / non-root / opt-out next steps ─────────────────────
printf "\n%sinstalled — next steps:%s\n" "$BOLD" "$RESET"
if [ "$OS" = "darwin" ]; then
  printf "  brew install darpanzope/tap/compliancekit   %s# preferred macOS path%s\n" "$DIM" "$RESET"
fi
printf "  compliancekit serve --db ./.compliancekit/serve.db\n"
printf "  compliancekit --help\n"
printf "\nDocs: https://github.com/darpanzope/compliancekit\n"
