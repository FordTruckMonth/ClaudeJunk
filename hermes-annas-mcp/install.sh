#!/usr/bin/env bash
#
# install.sh — install the Anna's Archive MCP server (annas-mcp) and wire it
# into Nous Research's Hermes Agent (~/.hermes/config.yaml).
#
# Usage:
#   ./install.sh                # interactive; prompts for missing values
#   ANNAS_SECRET_KEY=... ANNAS_DOWNLOAD_PATH=/abs/path ./install.sh
#
# Reads defaults from a sibling .env if present. Idempotent: re-running
# updates the binary and the `annas-archive` server entry in place.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HERMES_DIR="${HERMES_DIR:-$HOME/.hermes}"
HERMES_CONFIG="$HERMES_DIR/config.yaml"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
BINARY_PATH="$INSTALL_DIR/annas-mcp"
REPO="github.com/iosifache/annas-mcp"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --- 1. Load .env defaults ---------------------------------------------------
if [[ -f "$SCRIPT_DIR/.env" ]]; then
  log "Loading defaults from $SCRIPT_DIR/.env"
  set -a; # shellcheck disable=SC1091
  source "$SCRIPT_DIR/.env"; set +a
fi

# --- 2. Install the annas-mcp binary ----------------------------------------
install_via_go() {
  command -v go >/dev/null 2>&1 || return 1
  log "Installing via 'go install ${REPO}/cmd/annas-mcp@latest'"
  GOBIN="$INSTALL_DIR" go install "${REPO}/cmd/annas-mcp@latest"
}

install_via_release() {
  command -v curl >/dev/null 2>&1 || die "need curl (or Go) to install annas-mcp"
  local os arch asset ext tag tmp
  case "$(uname -s)" in
    Linux)  os=linux ;;
    Darwin) os=darwin ;;
    FreeBSD) os=freebsd ;;
    *) die "unsupported OS $(uname -s); install Go and re-run, or grab a binary from https://${REPO}/releases" ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    armv7l|armv7) arch=arm ;;
    *) die "unsupported arch $(uname -m); install Go and re-run" ;;
  esac
  ext=tar.xz
  tag="$(curl -fsSL "https://api.github.com/repos/iosifache/annas-mcp/releases/latest" \
        | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  [[ -n "$tag" ]] || die "could not determine latest release tag"
  local ver="${tag#v}"
  asset="annas-mcp_${ver}_${os}_${arch}.${ext}"
  tmp="$(mktemp -d)"
  log "Downloading $asset ($tag)"
  curl -fsSL -o "$tmp/$asset" \
    "https://github.com/iosifache/annas-mcp/releases/download/${tag}/${asset}" \
    || die "download failed; asset name may differ — check https://${REPO}/releases"
  tar -xJf "$tmp/$asset" -C "$tmp"
  local bin
  bin="$(find "$tmp" -type f -name annas-mcp | head -n1)"
  [[ -n "$bin" ]] || die "annas-mcp binary not found inside archive"
  install -m 0755 "$bin" "$BINARY_PATH"
  rm -rf "$tmp"
}

mkdir -p "$INSTALL_DIR"
if install_via_go; then
  :
else
  warn "Go toolchain not found; falling back to release download"
  install_via_release
fi
[[ -x "$BINARY_PATH" ]] || die "installation did not produce $BINARY_PATH"
log "Installed: $("$BINARY_PATH" --version 2>/dev/null || echo annas-mcp)  ->  $BINARY_PATH"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) : ;;
  *) warn "$INSTALL_DIR is not on your PATH; the config below uses the absolute path so Hermes will still find it." ;;
esac

# --- 3. Resolve required config values --------------------------------------
: "${ANNAS_SECRET_KEY:=}"
: "${ANNAS_DOWNLOAD_PATH:=}"
: "${ANNAS_BASE_URL:=annas-archive.gl}"

if [[ -z "$ANNAS_DOWNLOAD_PATH" ]]; then
  read -r -p "Absolute download path [$HOME/Downloads/annas]: " ANNAS_DOWNLOAD_PATH
  ANNAS_DOWNLOAD_PATH="${ANNAS_DOWNLOAD_PATH:-$HOME/Downloads/annas}"
fi
[[ "$ANNAS_DOWNLOAD_PATH" = /* ]] || die "ANNAS_DOWNLOAD_PATH must be absolute, got: $ANNAS_DOWNLOAD_PATH"
mkdir -p "$ANNAS_DOWNLOAD_PATH"

if [[ -z "$ANNAS_SECRET_KEY" ]]; then
  read -r -p "Anna's Archive donor API key (blank = search only): " ANNAS_SECRET_KEY
  ANNAS_SECRET_KEY="${ANNAS_SECRET_KEY:-REPLACE_WITH_YOUR_ANNAS_DONOR_KEY}"
fi

# --- 4. Merge into ~/.hermes/config.yaml ------------------------------------
mkdir -p "$HERMES_DIR"
[[ -f "$HERMES_CONFIG" ]] || : > "$HERMES_CONFIG"

merged=0
if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' 2>/dev/null; then
  ANNAS_MCP_BIN="$BINARY_PATH" \
  ANNAS_SECRET_KEY="$ANNAS_SECRET_KEY" \
  ANNAS_DOWNLOAD_PATH="$ANNAS_DOWNLOAD_PATH" \
  ANNAS_BASE_URL="$ANNAS_BASE_URL" \
  HERMES_CONFIG="$HERMES_CONFIG" \
  python3 - <<'PY' && merged=1
import os, yaml

path = os.environ["HERMES_CONFIG"]
with open(path) as f:
    cfg = yaml.safe_load(f) or {}
if not isinstance(cfg, dict):
    raise SystemExit(f"{path} is not a YAML mapping; refusing to edit")

servers = cfg.setdefault("mcp_servers", {})
servers["annas-archive"] = {
    "command": os.environ["ANNAS_MCP_BIN"],
    "args": ["mcp"],
    "env": {
        "ANNAS_SECRET_KEY": os.environ["ANNAS_SECRET_KEY"],
        "ANNAS_DOWNLOAD_PATH": os.environ["ANNAS_DOWNLOAD_PATH"],
        "ANNAS_BASE_URL": os.environ["ANNAS_BASE_URL"],
    },
}
with open(path, "w") as f:
    yaml.safe_dump(cfg, f, sort_keys=False, default_flow_style=False)
print("merged annas-archive into", path)
PY
fi

if [[ "$merged" -ne 1 ]]; then
  warn "PyYAML not available — could not auto-merge. Add this block to $HERMES_CONFIG:"
  cat <<YAML

mcp_servers:
  annas-archive:
    command: "$BINARY_PATH"
    args: ["mcp"]
    env:
      ANNAS_SECRET_KEY: "$ANNAS_SECRET_KEY"
      ANNAS_DOWNLOAD_PATH: "$ANNAS_DOWNLOAD_PATH"
      ANNAS_BASE_URL: "$ANNAS_BASE_URL"
YAML
fi

# --- 5. Done ----------------------------------------------------------------
log "Done. In a Hermes session run /reload-mcp (or restart Hermes), then try:"
echo "      book_search  query=\"the pragmatic programmer\""
echo "      book_download hash=<md5-from-search>"
