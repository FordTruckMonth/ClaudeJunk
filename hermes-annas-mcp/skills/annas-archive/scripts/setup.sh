#!/usr/bin/env bash
#
# setup.sh — install the annas-mcp binary into this skill's bin/ directory.
# Run once. Tries, in order: build from a local source checkout, `go install`,
# then downloading the matching release archive.

set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$SKILL_DIR/bin"
BIN="$BIN_DIR/annas-mcp"
REPO="github.com/iosifache/annas-mcp"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

mkdir -p "$BIN_DIR"

# 1) Build from a local source checkout if one sits next to the skill tree.
for src in "$SKILL_DIR/../../.." "$HOME/annas-mcp" "/workspace/iosifache/annas-mcp"; do
  if [[ -f "$src/go.mod" ]] && grep -q "$REPO" "$src/go.mod" 2>/dev/null && command -v go >/dev/null 2>&1; then
    log "Building from local source: $src"
    ( cd "$src" && go build -o "$BIN" ./cmd/annas-mcp )
    "$BIN" --version >/dev/null 2>&1 && { log "Installed -> $BIN"; exit 0; }
  fi
done

# 2) go install
if command -v go >/dev/null 2>&1; then
  log "Installing via go install ${REPO}/cmd/annas-mcp@latest"
  if GOBIN="$BIN_DIR" go install "${REPO}/cmd/annas-mcp@latest"; then
    log "Installed -> $BIN"; exit 0
  fi
fi

# 3) Download a prebuilt release archive.
command -v curl >/dev/null 2>&1 || die "need Go or curl to install annas-mcp"
case "$(uname -s)" in
  Linux) os=linux ;; Darwin) os=darwin ;; FreeBSD) os=freebsd ;;
  *) die "unsupported OS $(uname -s); install Go and re-run, or grab a binary from https://${REPO}/releases" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; armv7l|armv7) arch=arm ;;
  *) die "unsupported arch $(uname -m); install Go and re-run" ;;
esac
tag="$(curl -fsSL "https://api.github.com/repos/iosifache/annas-mcp/releases/latest" \
      | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
[[ -n "$tag" ]] || die "could not determine latest release tag"
asset="annas-mcp_${tag#v}_${os}_${arch}.tar.xz"
tmp="$(mktemp -d)"
log "Downloading $asset ($tag)"
curl -fsSL -o "$tmp/$asset" \
  "https://github.com/iosifache/annas-mcp/releases/download/${tag}/${asset}" \
  || die "download failed; asset name may differ — check https://${REPO}/releases"
tar -xJf "$tmp/$asset" -C "$tmp"
found="$(find "$tmp" -type f -name annas-mcp | head -n1)"
[[ -n "$found" ]] || die "annas-mcp binary not found inside archive"
install -m 0755 "$found" "$BIN"
rm -rf "$tmp"
log "Installed -> $BIN"
