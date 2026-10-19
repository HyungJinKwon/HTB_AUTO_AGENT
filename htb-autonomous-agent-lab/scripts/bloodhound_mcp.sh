#!/usr/bin/env bash
# Pinned setup for the community BloodHound MCP server. It is deliberately
# separate from htb-agent: upstream currently exposes mutation-capable tools.
set -euo pipefail

BH_MCP_HOME="${BH_MCP_HOME:-$HOME/bloodhound_mcp}"
BH_MCP_REPO="${BH_MCP_REPO:-https://github.com/mwnickerson/bloodhound_mcp.git}"
BH_MCP_REF="${BH_MCP_REF:-cdb17097e761c8a8622cb93bc3ba49a9e150bb6e}"
BH_MCP_VENV="${BH_MCP_HOME}/.venv"

die() { printf '⛔ %s\n' "$*" >&2; exit 2; }

checkout() {
  if [[ -d "$BH_MCP_HOME/.git" ]]; then
    [[ -z "$(git -C "$BH_MCP_HOME" status --porcelain)" ]] ||
      die "BloodHound MCP checkout has local changes: $BH_MCP_HOME"
    [[ "$(git -C "$BH_MCP_HOME" config --get remote.origin.url)" == "$BH_MCP_REPO" ]] ||
      die "BloodHound MCP checkout remote differs; set BH_MCP_REPO explicitly"
  else
    git clone "$BH_MCP_REPO" "$BH_MCP_HOME"
  fi
  git -C "$BH_MCP_HOME" fetch -q origin
  git -C "$BH_MCP_HOME" checkout -q "$BH_MCP_REF"
}

setup() {
  checkout
  [[ -x "$BH_MCP_VENV/bin/python" ]] || python3 -m venv "$BH_MCP_VENV"
  "$BH_MCP_VENV/bin/pip" install "$BH_MCP_HOME"
  printf '✅ BloodHound MCP ready at %s\n' "$BH_MCP_HOME"
  printf '   Configure BLOODHOUND_DOMAIN, BLOODHOUND_TOKEN_ID, and BLOODHOUND_TOKEN_KEY before run.\n'
}

run() {
  [[ "$1" == "--allow-upstream-mutations" ]] ||
    die "Upstream exposes custom_nodes and file_upload; no documented read-only mode exists. Use a least-privilege lab token and pass --allow-upstream-mutations only after review."
  [[ -x "$BH_MCP_VENV/bin/bloodhound-mcp" ]] || setup
  [[ -n "${BLOODHOUND_DOMAIN:-}" && -n "${BLOODHOUND_TOKEN_ID:-}" && -n "${BLOODHOUND_TOKEN_KEY:-}" ]] ||
    die "BLOODHOUND_DOMAIN, BLOODHOUND_TOKEN_ID, and BLOODHOUND_TOKEN_KEY are required"
  exec "$BH_MCP_VENV/bin/bloodhound-mcp"
}

case "${1:-}" in
  setup) setup ;;
  run) shift; [[ $# -eq 1 ]] || die "Usage: $0 run --allow-upstream-mutations"; run "$@" ;;
  *) echo "Usage: $0 setup | run --allow-upstream-mutations" >&2; exit 2 ;;
esac
