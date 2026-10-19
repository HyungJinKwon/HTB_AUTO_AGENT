#!/usr/bin/env bash
# Kali-only launcher for one assigned HTB target. It owns only the OpenVPN
# process it starts and keeps every agent command bound to this one IP.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"
VPN_DIR=""
VPN_PIDFILE=""
OWNED_VPN=0
AUTO=1
ONLINE_CVE=0
NO_ONE_DAY=0
VALIDATE_ONLY=0
FRAMEWORK="core"
LLM=""
USERNAME=""
DOMAIN=""
CREDENTIALS_FILE=""

usage() {
  cat <<'EOF'
Usage: bash scripts/htb-kali.sh <htb.ovpn> <target-ip> [options]

Required:
  htb.ovpn                 Official HTB OpenVPN profile without executable hooks
  target-ip                Assigned target in the standard HTB 10.10.10.0/23 or
                           10.129.0.0/16 range

Options:
  --username USER          Prompt once for the target credential password
  --domain DOMAIN          AD domain (requires --username)
  --credentials-file FILE  Credential JSON; keep it mode 600
  --llm none|claude|ollama|hybrid
                           Default: claude when ANTHROPIC_API_KEY exists, else none
  --framework core|artex|pentestgpt|bloodhound-mcp
                           Set up the selected local framework before native run
  --online-cve             One bounded NVD metadata lookup; no target IP is sent
  --no-one-day             Disable local SearchSploit metadata lookup
  --interactive            Ask before each in-scope action instead of --auto
  --validate-only          Validate inputs without installing, connecting, or scanning
EOF
}

die() { printf '⛔ %s\n' "$*" >&2; exit 2; }

cleanup() {
  local pid=""
  set +e
  if [[ "$OWNED_VPN" == "1" && -r "$VPN_PIDFILE" ]]; then
    pid="$(<"$VPN_PIDFILE")"
    if [[ "$pid" =~ ^[0-9]+$ ]] && ps -p "$pid" -o comm= 2>/dev/null | grep -q 'openvpn'; then
      sudo kill "$pid" 2>/dev/null
    fi
  fi
  if [[ -n "$VPN_DIR" && -d "$VPN_DIR" ]]; then
    rm -rf -- "$VPN_DIR"
  fi
}
trap cleanup EXIT INT TERM

is_kali() {
  [[ -r /etc/os-release ]] && . /etc/os-release && [[ "${ID:-}" == "kali" ]]
}

validate_target() {
  python3 - "$1" <<'PY'
import ipaddress
import sys

target = ipaddress.ip_address(sys.argv[1])
allowed = (ipaddress.ip_network("10.10.10.0/23"),
           ipaddress.ip_network("10.129.0.0/16"))
if target.version != 4 or not any(target in network for network in allowed):
    raise SystemExit("target is outside the standard HTB ranges")
PY
}

validate_profile() {
  [[ -f "$1" && -r "$1" ]] || die "OpenVPN profile cannot be read: $1"
  # A downloaded profile is input. Do not let it run local helper scripts/plugins.
  if grep -Eiq '^[[:space:]]*(up|down|route-up|route-pre-down|client-connect|client-disconnect|learn-address|ipchange|plugin|script-security)([[:space:]]|$)' "$1"; then
    die "OpenVPN profile contains executable hooks/plugins; use a clean official HTB profile"
  fi
  if grep -Eiq '^[[:space:]]*auth-user-pass([[:space:]]|$)' "$1"; then
    die "This profile needs VPN credentials. Connect it manually, then use the native htb-agent command."
  fi
}

install_base() {
  local missing=()
  command -v openvpn >/dev/null || missing+=(openvpn)
  command -v nmap >/dev/null || missing+=(nmap)
  command -v searchsploit >/dev/null || missing+=(exploitdb)
  [[ -x "$VENV_DIR/bin/python" ]] || missing+=(python3-venv python3-pip)
  if ((${#missing[@]})); then
    sudo apt-get update
    sudo apt-get install -y "${missing[@]}"
  fi
}

install_core() {
  local extras="[session]"
  [[ "$LLM" == "claude" || "$LLM" == "hybrid" ]] && extras="[session,claude]"
  [[ -x "$VENV_DIR/bin/python" ]] || python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install -e "${ROOT_DIR}${extras}"
}

setup_framework() {
  case "$FRAMEWORK" in
    core) ;;
    artex) bash "$ROOT_DIR/scripts/artex.sh" setup ;;
    pentestgpt) bash "$ROOT_DIR/scripts/pentestgpt.sh" setup ;;
    bloodhound-mcp) bash "$ROOT_DIR/scripts/bloodhound_mcp.sh" setup ;;
    *) die "Unknown framework: $FRAMEWORK" ;;
  esac
}

start_vpn() {
  VPN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/htb-agent-vpn.XXXXXX")"
  chmod 700 "$VPN_DIR"
  VPN_PIDFILE="$VPN_DIR/openvpn.pid"
  local log="$VPN_DIR/openvpn.log"
  sudo openvpn --config "$OVPN" --auth-nocache --writepid "$VPN_PIDFILE" \
    --log "$log" --daemon htb-agent-vpn
  OWNED_VPN=1
  for _ in $(seq 1 30); do
    grep -q 'Initialization Sequence Completed' "$log" 2>/dev/null && break
    [[ -r "$VPN_PIDFILE" ]] || true
    sleep 1
  done
  grep -q 'Initialization Sequence Completed' "$log" 2>/dev/null ||
    { tail -n 20 "$log" >&2 || true
      die "HTB VPN did not become ready within 30 seconds"; }
  local route
  route="$(ip -4 route get "$TARGET" 2>&1 || true)"
  [[ "$route" =~ dev[[:space:]]+(tun|tap)[[:alnum:]_.-]* ]] ||
    die "Target route is not through the VPN tunnel: $route"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
[[ $# -ge 2 ]] || { usage; exit 2; }
OVPN="$1"
TARGET="$2"
shift 2

while (($#)); do
  case "$1" in
    --username) [[ $# -ge 2 ]] || die "--username needs a value"; USERNAME="$2"; shift 2 ;;
    --domain) [[ $# -ge 2 ]] || die "--domain needs a value"; DOMAIN="$2"; shift 2 ;;
    --credentials-file) [[ $# -ge 2 ]] || die "--credentials-file needs a value"; CREDENTIALS_FILE="$2"; shift 2 ;;
    --llm) [[ $# -ge 2 ]] || die "--llm needs a value"; LLM="$2"; shift 2 ;;
    --framework) [[ $# -ge 2 ]] || die "--framework needs a value"; FRAMEWORK="$2"; shift 2 ;;
    --online-cve) ONLINE_CVE=1; shift ;;
    --no-one-day) NO_ONE_DAY=1; shift ;;
    --interactive) AUTO=0; shift ;;
    --validate-only) VALIDATE_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

is_kali || die "Run this launcher inside Kali Linux (Kali WSL is supported)"
validate_target "$TARGET" || die "Target must be an assigned IP in the standard HTB ranges"
validate_profile "$OVPN"
[[ -z "$DOMAIN" || -n "$USERNAME" ]] || die "--domain requires --username"
[[ -z "$CREDENTIALS_FILE" || -r "$CREDENTIALS_FILE" ]] ||
  die "Credential file cannot be read: $CREDENTIALS_FILE"
[[ "$ONLINE_CVE" == "0" || "$NO_ONE_DAY" == "0" ]] ||
  die "--online-cve cannot be used with --no-one-day"
case "${LLM:-auto}" in auto|none|claude|ollama|hybrid) ;; *) die "Invalid --llm value: $LLM" ;; esac
case "$FRAMEWORK" in core|artex|pentestgpt|bloodhound-mcp) ;; *) die "Invalid --framework value: $FRAMEWORK" ;; esac

if [[ "$VALIDATE_ONLY" == "1" ]]; then
  printf '✅ valid HTB profile and target: %s\n' "$TARGET"
  printf '   framework=%s, local SearchSploit=%s, NVD=%s\n' "$FRAMEWORK" \
    "$([[ "$NO_ONE_DAY" == 1 ]] && echo off || echo on)" \
    "$([[ "$ONLINE_CVE" == 1 ]] && echo on || echo off)"
  exit 0
fi

if [[ -z "$LLM" ]]; then
  LLM="none"
  [[ -n "${ANTHROPIC_API_KEY:-}" ]] && LLM="claude"
fi
if [[ "$LLM" == "claude" || "$LLM" == "hybrid" ]]; then
  [[ -n "${ANTHROPIC_API_KEY:-}" ]] || die "ANTHROPIC_API_KEY is required for --llm $LLM"
fi

install_base
install_core
setup_framework
start_vpn

cmd=("$VENV_DIR/bin/htb-agent" "$TARGET" "--range" "$TARGET/32" "--llm" "$LLM" "--writeup")
[[ "$AUTO" == "1" ]] && cmd+=("--auto")
[[ "$ONLINE_CVE" == "1" ]] && cmd+=("--online-cve")
[[ "$NO_ONE_DAY" == "1" ]] && cmd+=("--no-one-day")
[[ -n "$USERNAME" ]] && cmd+=("--username" "$USERNAME")
[[ -n "$DOMAIN" ]] && cmd+=("--domain" "$DOMAIN")
[[ -n "$CREDENTIALS_FILE" ]] && cmd+=("--credentials-file" "$CREDENTIALS_FILE")

printf '▶ native HTB agent: target=%s llm=%s framework=%s\n' "$TARGET" "$LLM" "$FRAMEWORK"
cd "$ROOT_DIR"
"${cmd[@]}"
