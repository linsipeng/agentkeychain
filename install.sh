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
CANDIDATE=""
HELPER_STAGE=""
PAIR=""
PUBLISHING=0
RESTART_CLOUD=0
SUCCESS=0
cleanup() {
  status=$?
  trap - EXIT
  if [ "$SUCCESS" != 1 ] && [ "$PUBLISHING" = 1 ]; then
    failed=0
    for name in agentkeychain agentkeychain-secure-store; do
      if [ -f "$PAIR/previous-$name" ]; then
        cp "$PAIR/previous-$name" "$PAIR/restore-$name" && mv -f "$PAIR/restore-$name" "$INSTALL_DIR/$name" || failed=1
      elif [ -f "$PAIR/absent-$name" ]; then
        rm -f "$INSTALL_DIR/$name" || failed=1
      fi
    done
    if [ "$failed" = 0 ] && [ "$RESTART_CLOUD" = 1 ]; then
      "$INSTALL_DIR/$BIN_NAME" cloud service start || failed=1
    fi
    if [ "$failed" = 1 ]; then printf 'error: rollback failed; service requires repair; retained pair backup: %s\n' "$PAIR" >&2; fi
  fi
  rm -rf "$TMP"
  [ -z "$CANDIDATE" ] || rm -f "$CANDIDATE"
  [ -z "$HELPER_STAGE" ] || rm -f "$HELPER_STAGE"
  exit "$status"
}
trap cleanup EXIT

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
INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd -P)"
# Stage on the destination filesystem. chmod and metadata checks happen before
# rename, so concurrent readers observe either the old or the executable new file.
CANDIDATE="$(mktemp "$INSTALL_DIR/.agentkeychain-install.XXXXXX")"
cp "$TMP/$ASSET" "$CANDIDATE"
chmod 755 "$CANDIDATE"
COMPATIBILITY="$("$CANDIDATE" cloud compatibility --json 2>/dev/null || true)"
if printf '%s' "$COMPATIBILITY" | grep -q '"nativeHelper":"required"'; then
  HELPER_ASSET="agentkeychain-secure-store-${OS_TAG}-${ARCH_TAG}"
  HELPER_EXPECTED="$(grep " $HELPER_ASSET\$" "$TMP/SHA256SUMS" | cut -d' ' -f1)"
  [ -n "$HELPER_EXPECTED" ] || err "missing native secure-store checksum"
  $FETCH_O "$TMP/$HELPER_ASSET" "$BASE_URL/$HELPER_ASSET" || err "native secure-store download failed"
  if command -v shasum > /dev/null 2>&1; then
    HELPER_ACTUAL="$(shasum -a 256 "$TMP/$HELPER_ASSET" | cut -d' ' -f1)"
  else
    HELPER_ACTUAL="$(sha256sum "$TMP/$HELPER_ASSET" | cut -d' ' -f1)"
  fi
  [ "$HELPER_ACTUAL" = "$HELPER_EXPECTED" ] || err "native secure-store checksum mismatch"
  HELPER_STAGE="$(mktemp "$INSTALL_DIR/.agentkeychain-helper.XXXXXX")"
  cp "$TMP/$HELPER_ASSET" "$HELPER_STAGE"
  chmod 755 "$HELPER_STAGE"
  HELPER_COMPATIBILITY="$("$HELPER_STAGE" --compatibility 2>/dev/null)" || err "native helper metadata probe failed"
  for field in '"helperABI":1' '"helperVersion":"1"'; do
    printf '%s' "$COMPATIBILITY" | grep -q "$field" || err "unsupported binary helper compatibility"
    printf '%s' "$HELPER_COMPATIBILITY" | grep -q "$field" || err "incompatible native helper"
  done
fi
# Keep the exact staged version and both previous members for recovery.
PAIR="$(mktemp -d "$INSTALL_DIR/.agentkeychain-pair.XXXXXX")"
printf '%s\n' "$VERSION" > "$PAIR/version"
printf '%s\n' "$COMPATIBILITY" > "$PAIR/compatibility.json"
cp "$CANDIDATE" "$PAIR/agentkeychain"
[ -z "$HELPER_STAGE" ] || cp "$HELPER_STAGE" "$PAIR/agentkeychain-secure-store"
for name in agentkeychain agentkeychain-secure-store; do
  if [ -f "$INSTALL_DIR/$name" ]; then cp -p "$INSTALL_DIR/$name" "$PAIR/previous-$name"; else touch "$PAIR/absent-$name"; fi
done
if printf '%s' "$COMPATIBILITY" | grep -q '"cloudSchema":1' && [ -x "$INSTALL_DIR/$BIN_NAME" ]; then
  CLOUD_SERVICE_STATUS="$("$INSTALL_DIR/$BIN_NAME" cloud service status --json 2>/dev/null || true)"
  if printf '%s' "$CLOUD_SERVICE_STATUS" | grep -q '"installed":true' && printf '%s' "$CLOUD_SERVICE_STATUS" | grep -q '"running":true'; then
    RESTART_CLOUD=1
    PUBLISHING=1
    "$INSTALL_DIR/$BIN_NAME" cloud service stop || err "could not stop managed background service"
  fi
fi
PUBLISHING=1
# Both facades resolve through one directory pointer. Stage the previous pair
# first for an upgrade from flat files; the final pointer rename publishes both.
mkdir "$PAIR/previous"
for name in agentkeychain agentkeychain-secure-store; do
  [ ! -f "$PAIR/previous-$name" ] || cp -p "$PAIR/previous-$name" "$PAIR/previous/$name"
done
ln -s "$PAIR/previous" "$PAIR/current-previous"
if [ "$OS_TAG" = darwin ]; then mv -fh "$PAIR/current-previous" "$INSTALL_DIR/.agentkeychain-current" || err "previous pair staging failed"; else mv -fT "$PAIR/current-previous" "$INSTALL_DIR/.agentkeychain-current" || err "previous pair staging failed"; fi
if [ -n "$HELPER_STAGE" ]; then
  rm -f "$HELPER_STAGE"
  ln -s .agentkeychain-current/agentkeychain-secure-store "$HELPER_STAGE"
  mv -f "$HELPER_STAGE" "$INSTALL_DIR/agentkeychain-secure-store" || err "helper publish failed"
  HELPER_STAGE=""
fi
rm -f "$CANDIDATE"
ln -s .agentkeychain-current/agentkeychain "$CANDIDATE"
mv -f "$CANDIDATE" "$INSTALL_DIR/$BIN_NAME" || err "binary publish failed"
CANDIDATE=""
ln -s "$PAIR" "$PAIR/current-next"
# -h is needed on BSD mv to replace a directory symlink instead of following it.
if [ "$OS_TAG" = darwin ]; then mv -fh "$PAIR/current-next" "$INSTALL_DIR/.agentkeychain-current" || err "pair publish failed";
else mv -fT "$PAIR/current-next" "$INSTALL_DIR/.agentkeychain-current" || err "pair publish failed"; fi
if [ "$RESTART_CLOUD" = 1 ]; then
  "$INSTALL_DIR/$BIN_NAME" cloud service start || err "new pair restart failed; restoring previous pair"
fi

SUCCESS=1

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
