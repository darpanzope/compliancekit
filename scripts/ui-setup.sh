#!/usr/bin/env bash
# scripts/ui-setup.sh — fetch the pinned Tailwind standalone CLI
# binary into .cache/ for the host OS+arch. One-time per developer;
# no Node toolchain required.
#
# Called via `make ui-setup`. Versions pinned here so every contributor
# compiles the same CSS bit-for-bit.
set -euo pipefail

TAILWIND_VERSION="${TAILWIND_VERSION:-3.4.17}"
CACHE_DIR=".cache"
BIN_PATH="${CACHE_DIR}/tailwindcss-${TAILWIND_VERSION}"

if [[ -x "${BIN_PATH}" ]]; then
  echo "tailwindcss v${TAILWIND_VERSION} already installed at ${BIN_PATH}"
  exit 0
fi

mkdir -p "${CACHE_DIR}"

uname_s=$(uname -s)
uname_m=$(uname -m)

case "${uname_s}/${uname_m}" in
  Darwin/x86_64)  asset="tailwindcss-macos-x64" ;;
  Darwin/arm64)   asset="tailwindcss-macos-arm64" ;;
  Linux/x86_64)   asset="tailwindcss-linux-x64" ;;
  Linux/aarch64)  asset="tailwindcss-linux-arm64" ;;
  Linux/armv7l)   asset="tailwindcss-linux-armv7" ;;
  *)
    echo "unsupported host: ${uname_s}/${uname_m}" >&2
    echo "see https://github.com/tailwindlabs/tailwindcss/releases for full list" >&2
    exit 1
    ;;
esac

url="https://github.com/tailwindlabs/tailwindcss/releases/download/v${TAILWIND_VERSION}/${asset}"
echo "downloading ${asset} v${TAILWIND_VERSION}..."
curl -fsSL -o "${BIN_PATH}" "${url}"
chmod +x "${BIN_PATH}"
echo "tailwindcss v${TAILWIND_VERSION} ready at ${BIN_PATH}"
