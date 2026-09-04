#!/bin/sh
# agentkeychain installer — one command, any platform.
#
#   curl -fsSL https://raw.githubusercontent.com/linsipeng/agentkeychain/main/install.sh | sh
#
# Or review first, then run:
#   curl -fsSLO https://raw.githubusercontent.com/linsipeng/agentkeychain/main/install.sh
#   less install.sh && sh install.sh
#
# Flags:
#   --version v0.3.0   install a specific release (default: latest)
#   --dir <path>       install directory (default: ~/.local/bin)
#   --uninstall        remove the binary
#
# Verifies the SHA256 checksum from the release's SHA256SUMS before installing.

set -eu

REPO="linsipeng/agentkeychain"
BIN_NAME="agentkeychain"
DEFAULT_DIR="$HOME/.local/bin"

VERSION=""
INSTALL_DIR="$DEFAULT_DIR"
UNINSTALL=0

say() { printf '%s\n' "$*"; }
err() { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || err "--version requires a value"; VERSION="$2"; shift 2 ;;
    --dir)     [ $# -ge 2 ] || err "--dir requires a value";     INSTALL_DIR="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) err "unknown flag: $1 (try --help)" ;;
  esac
done

# ---- uninstall -------------------------------------------------------------
if [ "$UNINSTALL" = "1" ]; then
  TARGET="$INSTALL_DIR/$BIN_NAME"
  if [ -f "$TARGET" ]; then
    rm -f "$TARGET"
    say "✓ removed $TARGET"
  else
    say "not found: $TARGET (nothing to do)"
  fi
  exit 0
fi

# ---- platform detection ----------------------------------------------------
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin) OS_TAG="darwin" ;;
  Linux)  OS_TAG="linux" ;;
  *) err "unsupported OS: $OS (supported: macOS, Linux)" ;;
esac

case "$ARCH" in
  arm64|aarch64) ARCH_TAG="arm64" ;;
  x86_64|amd64)  ARCH_TAG="x64" ;;
  *) err "unsupported architecture: $ARCH (supported: arm64, x86_64)" ;;
esac

ASSET="agentkeychain-${OS_TAG}-${ARCH_TAG}"

# ---- fetch tooling ----------------------------------------------------------
if command -v curl > /dev/null 2>&1; then
  FETCH="curl -fsSL"
  FETCH_O="curl -fsSL -o"
elif command -v wget > /dev/null 2>&1; then
  FETCH="wget -qO-"
  FETCH_O="wget -qO"
else
  err "need curl or wget to download"
fi

# ---- resolve version ----------------------------------------------------------
if [ -z "$VERSION" ]; then
  LATEST_URL="https://github.com/$REPO/releases/latest/download/SHA256SUMS"
  # Latest release assets carry no version in the path; use the /releases/latest redirect.
  VERSION="$($FETCH "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)"
  [ -n "$VERSION" ] || err "cannot determine latest release — specify --version v0.3.0"
fi
say "installing $BIN_NAME $VERSION ($ASSET) → $INSTALL_DIR"

BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---- download + verify --------------------------------------------------------
$FETCH_O "$TMP/$ASSET" "$BASE_URL/$ASSET" || err "download failed: $BASE_URL/$ASSET"
$FETCH_O "$TMP/SHA256SUMS" "$BASE_URL/SHA256SUMS" || err "download failed: SHA256SUMS"

EXPECTED="$(grep " $ASSET\$" "$TMP/SHA256SUMS" | cut -d' ' -f1)"
[ -n "$EXPECTED" ] || err "$ASSET not listed in SHA256SUMS (release packaging bug?)"

if command -v shasum > /dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "$TMP/$ASSET" | cut -d' ' -f1)"
elif command -v sha256sum > /dev/null 2>&1; then
  ACTUAL="$(sha256sum "$TMP/$ASSET" | cut -d' ' -f1)"
else
  err "need shasum or sha256sum to verify checksum"
fi

[ "$ACTUAL" = "$EXPECTED" ] || err "checksum mismatch!
  expected: $EXPECTED
  actual:   $ACTUAL
The download may be corrupted or tampered. Do NOT install."
say "✓ checksum verified"

# ---- install ------------------------------------------------------------------
mkdir -p "$INSTALL_DIR"
mv "$TMP/$ASSET" "$INSTALL_DIR/$BIN_NAME"
chmod +x "$INSTALL_DIR/$BIN_NAME"

# ---- PATH check ----------------------------------------------------------------
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    say ""
    say "⚠ $INSTALL_DIR is not in your PATH."
    say "  Add this line to your ~/.zshrc (or ~/.bashrc):"
    say ""
    say "    export PATH=\"$INSTALL_DIR:\$PATH\""
    say ""
    say "  Then run: source ~/.zshrc"
    ;;
esac

say ""
say "✓ installed: $INSTALL_DIR/$BIN_NAME"
say "next: $BIN_NAME --version"
