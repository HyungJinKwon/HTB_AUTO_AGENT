#!/usr/bin/env bash
# =============================================================================
# HTB 에이전트 도구 설치 스크립트 — Kali / Ubuntu(Debian계) 대상
# =============================================================================
# 이 스크립트는 '사용자의 실제 작업 머신(Kali/Ubuntu + HTB VPN)'에서 실행한다.
# ⚠️ 클라우드 컨테이너용이 아님: 거기선 HTB 에 도달할 수 없고 비영속이다.
#
# 설계: 하나가 실패해도 멈추지 않고 계속 진행한다(경우의 수 확보). 마지막에
#       성공/실패 요약을 출력한다. 재실행해도 안전(apt/pipx 는 멱등적).
#
# 사용법:
#   sudo ./install_tools.sh            # 전체 설치
#   sudo ./install_tools.sh ad cloud   # 지정 카테고리만 (recon web smb ad creds cloud pivot wordlist)
# =============================================================================

set -uo pipefail

C_B='\033[1;34m'; C_G='\033[1;32m'; C_R='\033[1;31m'; C_Y='\033[1;33m'; C_0='\033[0m'
LOG(){ printf "\n${C_B}[*] %s${C_0}\n" "$*"; }
OK(){  printf "  ${C_G}[+]${C_0} %s\n" "$*"; }
ERR(){ printf "  ${C_R}[!]${C_0} %s\n" "$*"; }
WARN(){ printf "  ${C_Y}[~]${C_0} %s\n" "$*"; }

OK_LIST=(); FAIL_LIST=()
try(){
  # try <레이블> <명령...>
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then OK "$label"; OK_LIST+=("$label")
  else ERR "실패(계속 진행): $label"; FAIL_LIST+=("$label"); fi
}

need_root(){
  if [ "$(id -u)" -ne 0 ]; then
    ERR "root 권한 필요 — 'sudo $0' 로 실행하세요."; exit 1
  fi
}

# 설치할 카테고리 (인자 없으면 전체)
ALL_CATS=(recon web smb ad creds cloud pivot wordlist)
CATS=("${@:-${ALL_CATS[@]}}")
[ "$#" -eq 0 ] && CATS=("${ALL_CATS[@]}")
want(){ local c; for c in "${CATS[@]}"; do [ "$c" = "$1" ] && return 0; done; return 1; }

need_root

LOG "APT 인덱스 갱신"
try "apt-get update" apt-get update

ensure_pipx(){
  if ! command -v pipx >/dev/null 2>&1; then
    LOG "pipx 설치"
    try "apt pipx" apt-get install -y pipx
    try "pipx ensurepath" pipx ensurepath
  fi
}

apt_pkg(){ try "apt:$1" apt-get install -y "$1"; }
pipx_pkg(){ ensure_pipx; if pipx list 2>/dev/null | grep -q "package $1 "; then
    try "pipx-upgrade:$1" pipx upgrade "$1"; else try "pipx:$1" pipx install "$1"; fi; }
go_pkg(){ if command -v go >/dev/null 2>&1; then try "go:$1" go install "$1";
          else WARN "go 미설치 — '$1' 건너뜀 (apt install -y golang-go 후 재실행)"; fi; }

if want recon; then
  LOG "[recon] 포트/서비스 스캔"
  apt_pkg nmap; apt_pkg masscan; pipx_pkg autorecon
  WARN "rustscan 은 릴리스 바이너리/cargo 로 별도 설치 권장"
fi

if want web; then
  LOG "[web] 웹 열거"
  for p in ffuf gobuster feroxbuster nikto whatweb curl; do apt_pkg "$p"; done
fi

if want smb; then
  LOG "[smb] SMB/RPC 열거"
  apt_pkg smbclient; apt_pkg smbmap; pipx_pkg enum4linux-ng
fi

if want ad; then
  LOG "[ad] Active Directory"
  pipx_pkg netexec           # crackmapexec 후속
  pipx_pkg impacket
  pipx_pkg bloodhound        # bloodhound-python (ingestor)
  pipx_pkg certipy-ad
  apt_pkg bloodhound; apt_pkg neo4j   # BloodHound GUI + DB (Kali)
  apt_pkg evil-winrm; apt_pkg ldap-utils; apt_pkg responder
  go_pkg github.com/ropnop/kerbrute@latest
fi

if want creds; then
  LOG "[creds] 크래킹/브루트"
  apt_pkg hydra; apt_pkg john; apt_pkg hashcat
fi

if want cloud; then
  LOG "[cloud] AWS / S3 열거"
  apt_pkg awscli
  pipx_pkg s3scanner
  pipx_pkg cloud-enum
fi

if want pivot; then
  LOG "[pivot] 셸/터널"
  apt_pkg netcat-traditional; apt_pkg socat
  go_pkg github.com/jpillora/chisel@latest
fi

if want wordlist; then
  LOG "[wordlist] 워드리스트"
  apt_pkg seclists
fi

LOG "요약"
printf "  ${C_G}성공 %d${C_0} / ${C_R}실패 %d${C_0}\n" "${#OK_LIST[@]}" "${#FAIL_LIST[@]}"
if [ "${#FAIL_LIST[@]}" -gt 0 ]; then
  WARN "실패 항목(수동 확인 필요):"
  for f in "${FAIL_LIST[@]}"; do printf "    - %s\n" "$f"; done
fi
echo
echo "설치 확인:  python3 -c 'import sys; sys.path.insert(0,\"src\"); from htb_agent.tools.registry import report; print(report())'"
