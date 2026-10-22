# ASSASSIN 빠른 시작 (1쪽)

> 권한이 확인된 대상(HTB·Dreamhack·CTF·인가된 진단)에서만 사용합니다. 자세한 내용은 [USAGE.md](USAGE.md).

## 1. 설치·점검 (처음 한 번)

최신 Kali·Ubuntu 는 PEP 668 로 시스템 `pip install` 이 막히므로 **venv + 심링크**로 설치합니다.

```bash
# 새 PC·VM 스냅샷 — 기본(default) 브랜치(현재: main)로 클론 (clone/pull 이 기본 브랜치 자동 선택)
git clone https://github.com/HyungJinKwon/HTB_AUTO_AGENT.git ~/HTB_AUTO_AGENT
# (이미 받아둔 경우 최신화) git -C ~/HTB_AUTO_AGENT pull --ff-only
cd ~/HTB_AUTO_AGENT/htb-agent
sudo ./scripts/install_tools.sh     # 보안 도구 일괄 설치(Kali/Ubuntu)

python3 -m venv .venv               # 가상환경(PEP 668 우회)
source .venv/bin/activate
pip install -e ".[claude,exploit]"  # 에이전트 + Claude + 익스 실행 의존성(requests)

mkdir -p ~/.local/bin               # 어디서나 쓰도록 심링크(venv activate 불필요)
ln -sf ~/HTB_AUTO_AGENT/htb-agent/.venv/bin/assassin  ~/.local/bin/assassin
ln -sf ~/HTB_AUTO_AGENT/htb-agent/.venv/bin/htb-agent ~/.local/bin/htb-agent
grep -q 'local/bin' ~/.zshrc || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc; hash -r
assassin --version                  # 어디서든 동작하면 성공

assassin --doctor                   # 도구·VPN·LLM 준비 상태 점검 — 빨간 항목만 채우면 됨
assassin --setup-llm                # (선택) Claude·로컬 LLM 연결 마법사 — 질문에 답하면 연결·확인·저장까지
```

> bash 면 `~/.zshrc` → `~/.bashrc`. 규칙 기반·Ollama 만 쓰면 `pip install -e .` 로도 됩니다.
> 새 환경에선 **기본(default) 브랜치**를 그대로 쓰세요 — `claude/*` 작업 브랜치는 체크아웃 불필요.

## 2. 상황별 한 줄

| 하고 싶은 것 | 명령 |
|---|---|
| 처음 써 보기(위험한 것만 물어봄) | `assassin 10.129.1.5` |
| 모든 명령을 보며 배우기 | `assassin 10.129.1.5 --manual` |
| 해커톤: 최대 자율 + 시간 제한 | `assassin 10.129.1.5 --autonomous --time-budget 45 --writeup --html` |
| 🚀 완전 자동 루트 시도(발판·플래그까지) | `assassin 10.129.1.5 --full-auto --llm claude --html --json` |
| LLM 두뇌 붙이기(처음 한 번) | `assassin --setup-llm` → 이후 `assassin 10.129.1.5` 만으로 사용 |
| LLM 연결 다시 확인 | `assassin --llm-test` |
| LLM 직접 지정(비용 상한) | `assassin 10.129.1.5 --llm hybrid --max-cost 2` |
| CTF/Dreamhack 문제 | `assassin chall.host:1337 --platform ctf --category web` |
| 중단한 곳부터 이어서 | 같은 명령 + `--resume` (Ctrl+C 로 멈춰도 저장됨) |
| 자격증명을 넣어 자동으로 채우기 | `--cred 사용자:비밀번호` |
| 터미널 요약 전체 보기 | `-v`/`--verbose` (기본은 핵심만·무거운 섹션은 접힘 · 전체 상세는 `--html`/`--json`) |

> **완전 자동 루트 한 줄의 플래그 뜻** — `--full-auto`(한 플래그 번들: `--autonomous` +
> `--exploit-exec` + `--auto-poc` + `--catch-revshell` + `--fetch-pocs` + `--priv-env`(환경조작), 가능하면 egress
> 샌드박스 자동 선택 → 발판 **실제 실행**·PoC 발사·리버스셸 수신·NFS 수확까지. 기본 OFF, 명시적 옵트인) ·
> `--llm claude`(Claude 두뇌, 먼저 `assassin --setup-llm`) · `--html`/`--json`(결과 저장).
> (개별로 켜려면 `--autonomous --exploit-exec --auto-poc --priv-env` 처럼 풀어 써도 동일.)
> **환경조작(`--priv-env`)** 은 열린 NFS export 를 rootless(`libnfs-utils`)로 읽어 자격·SSH키·플래그를
> 수확(PDF 문서는 `pdftotext` 로 본문 추출)하고 vhost 를 `/etc/hosts` 에 등록합니다 — 기본은 sudo 없이,
> 불가 시에만 `sudo -n` 폴백.
> **권한이 확인된 대상에서만.** 발판이 실제로 성립해야 자격수확·플래그로 이어지고, 성립 안 하면
> 조용히 발판 미확보로 끝납니다(헛발판 안 잡음). 자세히는 [USAGE.md §10.2–10.4](USAGE.md).
>
> **내장 익스 모듈(최신 CVE 자동화)** — 핑거프린트가 수록 CVE(예: FreePBX CVE-2025-57819)와 맞으면
> `--full-auto` 가 **공개 PoC 자동 조달**(레지스트리 출처만)→웹셸 캡처→`--attacker-ip` 로 **nc 리버스셸
> 수신**→user 플래그→privesc 까지 손 안 대고 잇습니다. **다른 CVE/머신**은 `--exploit-modules mods.json`
> 으로 데이터만 추가(코드 수정 없음), exploit-db 등재분은 `--auto-poc` 가 이미 자동. 무기 코드는 레포에
> 없고 공개 PoC 를 런타임 조달합니다(인가 대상 전용). 자세히는 [USAGE.md §10.4](USAGE.md).

## 3. 화면 읽는 법

| 표시 | 뜻 | 할 일 |
|---|---|---|
| `목적` | 이 명령이 무엇을 하려는지 | 읽고 이해 |
| `대안` | 더 안전한 2단계 방법(먼저 확인 → 실행) | 대안대로 해 보기 |
| `▲ 범위 밖` | 바인딩한 타겟 밖 주소 | 내 VPN IP 면 `--attacker-ip`, 아니면 엔터(건너뛰기) |
| `⟳ 앞서 실패한 같은 종류` | 같은 실패 반복 중 | 다른 도구·경로 고려 |
| `[y=실행 / 엔터=건너뛰기]` | 사람 확인 | `y` 실행, 엔터 건너뜀 |
| 맨 끝 `한눈에 보기` | 결과·서비스·찾은 것·실행 현황·**다음에 할 일** | 긴 출력은 건너뛰고 여기부터 보기 |
| `시작할 수 없음 — nmap 이 없습니다` | 첫 단계 도구 없음(대상 문제 아님) | `sudo apt install -y nmap` 후 다시 |
| `→ …` (타겟 거부 아래) | 바로 고칠 수 있는 힌트 | CTF·호스트명이면 `--platform ctf`, HTB 는 Target IP |

> 무엇을 입력할지 모르겠으면 `assassin` 만 입력하세요 — 시작 3단계가 나옵니다. 전체 옵션은 `assassin --help`(그룹별 정리).

## 4. 끝나면 볼 것

- **수동 제안(종류별)**: 자격증명 필요 → `--cred` 로 재실행 / 상한 초과 → `--max-enum` 또는 `--resume` / 실행 위험 → 적힌 대안대로.
- **결과물**: `--writeup`(라이트업) · `--html`(대시보드, 상단 '한눈에 보기') · `--json`.
- **실행 재생**: `assassin --replay state/audit_<타겟>.jsonl` → 단계별로 넘겨 보는 HTML.

## 5. 발표·연습

```bash
./scripts/showcase.sh            # 데모 + 성능 측정 + 재생 HTML + 대시보드를 한 번에(오프라인)
assassin --bench                 # 모의 문제 12개로 성공률 측정(규칙만)
assassin --bench --llm hybrid    # LLM 을 붙였을 때와 비교
```

## 6. 안전 경계 (바뀌지 않음)

모든 명령은 **검증 → 범위 → 승인** 3관문을 통과해야 실행됩니다. 기본은 **생성 전용**(리버스쉘·권한상승·크래킹 등은 준비만) — 실제 익스 실행은 `--full-auto`(옵트인)로만, 권한이 확인된 대상에서. 막히면 [OPERATIONS.md §4 트러블슈팅](OPERATIONS.md).
