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
#   sudo ./install_tools.sh ad cloud   # 지정 카테고리만
#     카테고리: recon web smb ad creds cloud pivot wordlist traffic re pwn forensic llm
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
ALL_CATS=(recon web smb ad creds cloud pivot wordlist traffic re pwn forensic llm)
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

# apt 우선 → 실패 시 pipx(git URL) 폴백. PyPI 에 없거나 이름이 다른 도구용(netexec·enum4linux-ng 등).
apt_or_pipxgit(){   # apt_or_pipxgit <apt-pkg> <pipx-app> <git-url>
  ensure_pipx
  if apt-get install -y "$1" >/dev/null 2>&1; then OK "apt:$1"; OK_LIST+=("apt:$1")
  elif pipx list 2>/dev/null | grep -q "package $2 " \
       || pipx install "git+$3" >/dev/null 2>&1; then OK "pipx-git:$2"; OK_LIST+=("pipx-git:$2")
  else ERR "실패(계속 진행): $1/$2 (apt·git 모두)"; FAIL_LIST+=("$1"); fi; }

# apt 우선 → 실패 시 pipx(PyPI) 폴백. 라이브러리성 도구용(pwntools 등).
apt_or_pipx(){      # apt_or_pipx <apt-pkg> <pipx-name>
  ensure_pipx
  if apt-get install -y "$1" >/dev/null 2>&1; then OK "apt:$1"; OK_LIST+=("apt:$1")
  elif pipx list 2>/dev/null | grep -q "package $2 " \
       || pipx install "$2" >/dev/null 2>&1; then OK "pipx:$2"; OK_LIST+=("pipx:$2")
  else ERR "실패(계속 진행): $1/$2"; FAIL_LIST+=("$1"); fi; }

# PyPI 에 없는 git 전용 도구(cloud_enum 등).
pipx_gitonly(){     # pipx_gitonly <pipx-app> <git-url>
  ensure_pipx
  if pipx list 2>/dev/null | grep -q "package $1 "; then OK "pipx-git:$1 (설치됨)"; OK_LIST+=("$1")
  elif pipx install "git+$2" >/dev/null 2>&1; then OK "pipx-git:$1"; OK_LIST+=("$1")
  else ERR "실패(계속 진행): $1 ($2)"; FAIL_LIST+=("$1"); fi; }

if want recon; then
  LOG "[recon] 포트/서비스 스캔 + DNS/SNMP 열거"
  apt_pkg nmap; apt_pkg masscan; pipx_pkg autorecon
  apt_pkg dnsutils            # dig
  apt_pkg dnsenum
  apt_pkg snmp                # snmpwalk
  apt_pkg onesixtyone
  apt_pkg telnet; apt_pkg ftp; apt_pkg rsync   # 기초 클라이언트(telnet/ftp/rsync 열거)
  WARN "rustscan 은 릴리스 바이너리/cargo 로 별도 설치 권장"
fi

if want web; then
  LOG "[web] 웹 열거"
  for p in ffuf gobuster feroxbuster nikto whatweb curl sqlmap wfuzz wpscan; do apt_pkg "$p"; done
  pipx_pkg git-dumper
  WARN "jwt_tool 은 git clone ticarpi/jwt_tool 로 별도 설치"
fi

if want traffic; then
  LOG "[traffic] 프록시/패킷 (Burp·Wireshark 등)"
  apt_pkg burpsuite
  apt_pkg wireshark; apt_pkg tshark; apt_pkg tcpdump
  apt_pkg zaproxy
  pipx_pkg mitmproxy
fi

if want re; then
  LOG "[re] 리버싱"
  apt_pkg gdb; apt_pkg radare2; apt_pkg ghidra
  WARN "pwndbg/GEF 는 github setup.sh 로 별도 설치 권장"
fi

if want pwn; then
  LOG "[pwn] 포너블"
  apt_pkg checksec
  apt_or_pipx python3-pwntools pwntools   # pwntools 는 라이브러리 — apt 우선
  pipx_pkg ROPgadget
fi

if want forensic; then
  LOG "[forensic] 포렌식/스테가노"
  apt_pkg binwalk; apt_pkg foremost; apt_pkg libimage-exiftool-perl
  apt_pkg steghide; apt_pkg hashid; apt_pkg oathtool   # Debian/Kali 패키지명은 oathtool
  apt_pkg poppler-utils      # pdftotext — NFS/문서에서 PDF 텍스트 추출(온보딩 PDF 자격 수확)
  pipx_pkg volatility3
  WARN "zsteg 는 gem install zsteg 로 설치"
fi

if want smb; then
  LOG "[smb] SMB/RPC 열거"
  apt_pkg smbclient; apt_pkg smbmap
  apt_or_pipxgit enum4linux-ng enum4linux-ng https://github.com/cddmp/enum4linux-ng
  apt_pkg nfs-common         # showmount(NFS export 열거)
  apt_pkg libnfs-utils       # rootless NFS 읽기(nfs-ls/nfs-cp) — sudo·마운트 없이 export 수확
fi

if want ad; then
  LOG "[ad] Active Directory"
  apt_or_pipxgit netexec netexec https://github.com/Pennyw0rth/NetExec   # crackmapexec 후속(실행명 nxc)
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
  apt_pkg sshpass            # 권한상승 규칙(ssh 경유 타겟 명령)에 필요
fi

if want cloud; then
  LOG "[cloud] AWS / S3 열거"
  apt_pkg awscli
  pipx_pkg s3scanner
  pipx_gitonly cloud_enum https://github.com/initstring/cloud_enum   # PyPI 미등록 — git 설치
fi

if want pivot; then
  LOG "[pivot] 셸/터널"
  apt_pkg netcat-traditional; apt_pkg socat
  go_pkg github.com/jpillora/chisel@latest
  WARN "ligolo-ng 은 GitHub 릴리스 바이너리로 별도 설치 (github.com/nicocha30/ligolo-ng/releases)"
fi

if want wordlist; then
  LOG "[wordlist] 워드리스트"
  apt_pkg seclists
fi

if want llm; then
  LOG "[llm] LLM 두뇌 (하이브리드 = Claude + Ollama, 선택)"
  # anthropic 은 Claude 모드에서만 필요한 '선택' 의존성. 최신 Kali 는 PEP 668 로 시스템
  # pip 설치가 막혀 'pip install anthropic' 이 실패한다 → 여러 경로를 순서대로 시도.
  if python3 -c 'import anthropic' >/dev/null 2>&1; then
    OK "anthropic (이미 설치됨)"; OK_LIST+=("anthropic")
  elif pip install -q anthropic >/dev/null 2>&1; then
    OK "pip:anthropic"; OK_LIST+=("anthropic")
  elif pipx list 2>/dev/null | grep -q "package assassin " \
       && pipx inject assassin anthropic >/dev/null 2>&1; then
    OK "pipx-inject:anthropic (assassin)"; OK_LIST+=("anthropic")
  elif pip install -q --break-system-packages anthropic >/dev/null 2>&1; then
    OK "pip(--break-system-packages):anthropic"; OK_LIST+=("anthropic")
  else
    ERR "실패(계속 진행): anthropic"; FAIL_LIST+=("anthropic")
    WARN "  venv 권장:  python3 -m venv .venv && . .venv/bin/activate && pip install -e '.[claude]'"
    WARN "  또는 로컬 LLM(ollama)만 써도 됩니다 — anthropic 불필요"
  fi
  if command -v ollama >/dev/null 2>&1; then
    OK "ollama 설치됨 — 'ollama serve' 후 'ollama pull llama3.1:8b'"
  else
    WARN "ollama 미설치 — 로컬 LLM 쓰려면: curl -fsSL https://ollama.com/install.sh | sh"
    WARN "  설치 후: ollama pull llama3.1:8b  (또는 OLLAMA_MODEL 로 다른 모델 지정)"
  fi
  echo "    연결:  assassin --setup-llm   (키 입력·모델 추천·실제 호출 확인·기본 설정 저장 — sudo 없이 본인 계정으로)"
  echo "    확인:  assassin --llm-test    (LLM 실제 호출 테스트)"
fi

LOG "요약"
printf "  ${C_G}성공 %d${C_0} / ${C_R}실패 %d${C_0}\n" "${#OK_LIST[@]}" "${#FAIL_LIST[@]}"
if [ "${#FAIL_LIST[@]}" -gt 0 ]; then
  WARN "실패 항목(수동 확인 필요):"
  for f in "${FAIL_LIST[@]}"; do printf "    - %s\n" "$f"; done
fi
echo
echo "설치 확인:  python3 -c 'import sys; sys.path.insert(0,\"src\"); from htb_agent.tools.registry import report; print(report())'"
