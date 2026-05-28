#!/bin/sh
# wotw-verify install script.
#
# Detects platform, downloads the latest GitHub Release artifact,
# verifies its cosign signature, and installs to /usr/local/bin (or
# $HOME/.local/bin if /usr/local/bin is not writable).
#
# Hosted at: https://install.wotw.dev/verify
#
# Usage:
#   curl -fsSL https://install.wotw.dev/verify | sh
#   curl -fsSL https://install.wotw.dev/verify | sh -s -- v0.1.0
#
# This script REQUIRES `curl`, `tar` (or `unzip` for Windows), and
# `cosign`. cosign is installed via your package manager:
#   macOS:   brew install cosign
#   Linux:   see https://docs.sigstore.dev/system_config/installation
#   Windows: scoop install cosign  (or chocolatey)
#
# If cosign is missing the script aborts BEFORE any binary touches
# disk. We do not silently fall back to unsigned downloads.

set -eu

REPO="3030-Labs/wotw-verify"
# Primary pubkey URL: served from wotw.dev once DNS+hosting is up.
# Until then, the fallback (raw.githubusercontent.com) is authoritative.
PUBKEY_URL="https://raw.githubusercontent.com/3030-Labs/wotw-verify/main/cosign.pub"
PUBKEY_URL_FALLBACK="https://wotw.dev/keys/wotw-verify.pub"

TAG="${1:-latest}"

# --- platform detection ---

uname_os=$(uname -s | tr '[:upper:]' '[:lower:]')
uname_arch=$(uname -m)

case "$uname_os" in
  linux)   os="linux" ;;
  darwin)  os="darwin" ;;
  *)
    echo "wotw-verify install: unsupported OS '$uname_os'" >&2
    exit 1
    ;;
esac

case "$uname_arch" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="arm64" ;;
  *)
    echo "wotw-verify install: unsupported arch '$uname_arch'" >&2
    exit 1
    ;;
esac

# --- prerequisites ---

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "wotw-verify install: missing required command: $1" >&2
    echo "" >&2
    echo "Install it first, then re-run." >&2
    exit 1
  fi
}

require curl
require tar
require cosign

# --- resolve tag ---

if [ "$TAG" = "latest" ]; then
  TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' \
        | head -1)
  if [ -z "$TAG" ]; then
    echo "wotw-verify install: could not resolve latest release tag" >&2
    exit 1
  fi
fi

VERSION="${TAG#v}"
ASSET="wotw-verify_${VERSION}_${os}_${arch}.tar.gz"
ASSET_URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
SIG_URL="${ASSET_URL}.sig"

echo "wotw-verify install: target = ${TAG} (${os}/${arch})"
echo "wotw-verify install: asset  = ${ASSET}"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

cd "$tmpdir"

# --- download ---

echo "wotw-verify install: downloading archive..."
curl -fsSL -o "$ASSET" "$ASSET_URL"
echo "wotw-verify install: downloading signature..."
curl -fsSL -o "${ASSET}.sig" "$SIG_URL"

# --- fetch cosign public key ---

echo "wotw-verify install: fetching cosign public key..."
if ! curl -fsSL -o cosign.pub "$PUBKEY_URL" 2>/dev/null; then
  echo "wotw-verify install: primary pubkey URL failed, trying fallback..." >&2
  curl -fsSL -o cosign.pub "$PUBKEY_URL_FALLBACK"
fi

# --- verify signature ---

echo "wotw-verify install: verifying cosign signature..."
if ! cosign verify-blob --key cosign.pub --signature "${ASSET}.sig" "$ASSET" >/dev/null 2>&1; then
  echo "" >&2
  echo "wotw-verify install: COSIGN SIGNATURE VERIFICATION FAILED" >&2
  echo "wotw-verify install: aborting — refusing to install unverified binary" >&2
  exit 1
fi
echo "wotw-verify install: ✓ signature verified"

# --- extract + install ---

tar -xzf "$ASSET"
test -f wotw-verify || {
  echo "wotw-verify install: archive did not contain a wotw-verify binary" >&2
  exit 1
}
chmod +x wotw-verify

# Pick install location: /usr/local/bin if writable, else ~/.local/bin
if [ -w /usr/local/bin ] || ( [ ! -e /usr/local/bin ] && [ -w /usr/local ] ); then
  install_dir="/usr/local/bin"
elif command -v sudo >/dev/null 2>&1 && [ -d /usr/local/bin ]; then
  install_dir="/usr/local/bin"
  echo "wotw-verify install: /usr/local/bin requires sudo; will run sudo install..."
  sudo install -m 0755 wotw-verify "$install_dir/wotw-verify"
  echo "wotw-verify install: installed to $install_dir/wotw-verify"
  "$install_dir/wotw-verify" --version
  exit 0
else
  install_dir="$HOME/.local/bin"
  mkdir -p "$install_dir"
fi

install -m 0755 wotw-verify "$install_dir/wotw-verify"
echo "wotw-verify install: installed to $install_dir/wotw-verify"
echo ""
"$install_dir/wotw-verify" --version
echo ""
echo "Add $install_dir to your PATH if not already, then run:"
echo "  wotw-verify --self-test"
