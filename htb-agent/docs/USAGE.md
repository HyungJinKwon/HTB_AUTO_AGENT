# ASSASSIN 전체 사용법

> 승인제 자동 풀이 에이전트(HTB · Dreamhack · CTF)의 설치부터 운영·지식 관리·유지보수까지 한 문서로 정리했다.
> 명령은 `assassin`(옛 이름 `htb-agent` 도 같은 별칭). 설치 없이 쓸 때는 `htb-agent/` 에서 `PYTHONPATH=src python3 -m htb_agent ...`.
>
> ⚠️ **권한이 확인된 대상에서만 사용한다**(대회·플랫폼이 명시한 대상, 인가된 진단). 범위 밖 통신은 Scope Guard 가 코드로 막는다.

---

## 목차

1. [한눈에 보기](#1-한눈에-보기)
2. [설치](#2-설치)
3. [첫 실행 3단계](#3-첫-실행-3단계)
4. [실행 흐름과 3관문](#4-실행-흐름과-3관문)
5. [승인 모드 고르기](#5-승인-모드-고르기)
6. [플랫폼별 사용법](#6-플랫폼별-사용법)
7. [자격증명 넣기](#7-자격증명-넣기)
8. [LLM 두뇌 붙이기](#8-llm-두뇌-붙이기)
9. [지식베이스: 시작 지식 · 학습 · 공유 · 자동 반영](#9-지식베이스-시작-지식--학습--공유--자동-반영)
10. [자동 준비 도구(생성 전용)](#10-자동-준비-도구생성-전용)
11. [산출물: 라이트업 · 리포트 · 로그 · 재개](#11-산출물-라이트업--리포트--로그--재개)
12. [설정 파일](#12-설정-파일)
13. [한도와 튜닝](#13-한도와-튜닝)
14. [환경변수](#14-환경변수)
15. [데모](#15-데모)
16. [상황별 레시피](#16-상황별-레시피)
17. [트러블슈팅](#17-트러블슈팅)
18. [유지보수자용](#18-유지보수자용)
19. [파일 위치 지도](#19-파일-위치-지도)

---

## 1. 한눈에 보기

| 항목 | 내용 |
|---|---|
| 무엇 | 타겟 하나를 받아 정찰 → 식별 → 열거 → 침투 → 권한상승 → 리포트까지 단계 순서로 추진하는 보조 에이전트 |
| 대상 | HTB(boot2root) · Dreamhack/CTF(Jeopardy 단일 플래그) |
| 안전 | 모든 명령은 **① 검증 → ② 범위 → ③ 승인** 을 통과해야 실행. 범위 밖·파괴 명령·동적 코드 실행은 자동 실행하지 않음 |
| 지능 | 규칙 기반(기본) + 지식베이스(RAG) + 선택형 LLM(Claude / Ollama / hybrid) |
| 지식 | 59개 주제 번들 시드로 누구나 같은 지식으로 시작 → 학습으로 성장 → 검증 후 모두에게 자동 공유 |
| 산출 | 라이트업(HTB v5 / Tistory 13섹션) · JSON · HTML 대시보드 · 감사 로그 |
| 의존성 | Python 3.10+ 표준 라이브러리만(선택 기능만 추가: LLM=anthropic/Ollama · YAML 설정=pyyaml · PDF 수집=pdftotext 또는 pypdf) |

원칙: 승인제 · 외부 라이트업 미참조(사용자 자료·권위 출처만) · 무한루프 없음(모든 반복에 상한) · 증거 기반 판정(약하면 〔추정〕).

---

## 2. 설치

### 2.1 Kali / Ubuntu (venv + 심링크 — 권장)

최신 Kali·Ubuntu 는 시스템 파이썬이 **PEP 668(externally-managed)** 로 잠겨 있어, 그냥 `pip install -e .` 하면
`error: externally-managed-environment` 로 거부된다. **venv(가상환경)** 에 설치한 뒤 명령을 `~/.local/bin` 에
**심링크**하면, venv 를 매번 activate 하지 않아도 어느 디렉터리에서나 `assassin` 이 바로 동작한다.

```bash
# 새 PC·VM 스냅샷 — 기본(default) 브랜치로 클론 (clone/pull 이 기본 브랜치를 자동 선택)
git clone https://github.com/HyungJinKwon/HTB_AUTO_AGENT.git ~/HTB_AUTO_AGENT
# (이미 받아둔 경우 최신화) git -C ~/HTB_AUTO_AGENT pull --ff-only
cd ~/HTB_AUTO_AGENT/htb-agent
sudo ./scripts/install_tools.sh            # 보안 도구 일괄 설치

python3 -m venv .venv                       # ① 가상환경 생성(PEP 668 우회)
source .venv/bin/activate                   # ② 활성화
pip install -e ".[claude]"                  # ③ 에이전트 + Claude(anthropic) 설치 → 'assassin'·'htb-agent' 생성

mkdir -p ~/.local/bin                        # ④ 어디서나 쓰도록 심링크
ln -sf ~/HTB_AUTO_AGENT/htb-agent/.venv/bin/assassin  ~/.local/bin/assassin
ln -sf ~/HTB_AUTO_AGENT/htb-agent/.venv/bin/htb-agent ~/.local/bin/htb-agent
grep -q 'local/bin' ~/.zshrc || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc   # ⑤ PATH 보장
source ~/.zshrc; hash -r
assassin --version                          # ⑥ 어디서든 동작하면 성공

sudo openvpn your-htb.ovpn                   # (HTB) tun0 → 공격자 IP 자동탐지
```

| 명령 | 바이너리 | 옵션 | 파라미터 |
|---|---|---|---|
| `sudo ./scripts/install_tools.sh recon web` | `install_tools.sh` | (없음) | 설치할 카테고리. 생략 시 전체 |
| `python3 -m venv .venv` | `python3` | `-m venv`: 표준 가상환경 모듈 | `.venv`: 생성할 환경 디렉터리(프로젝트 안) |
| `source .venv/bin/activate` | `source` | (없음) | venv 활성화 스크립트 — 이 셸에서만 적용 |
| `pip install -e ".[claude]"` | `pip` | `-e`: 편집 가능 설치(소스 수정이 바로 반영) | `".[claude]"`: 현재 패키지 + claude extra(anthropic). 따옴표 필수(zsh glob 방지) |
| `ln -sf <venv>/bin/assassin ~/.local/bin/` | `ln` | `-s`: 심볼릭 링크 · `-f`: 기존 링크 덮어쓰기 | venv 의 실행 스크립트(절대 shebang) → PATH 상의 위치 |
| `sudo openvpn your-htb.ovpn` | `openvpn` | (없음) | 플랫폼에서 받은 VPN 설정 파일 |

- **왜 심링크?** venv 의 `bin/assassin` 은 **절대경로 shebang**(`#!…/.venv/bin/python3`)을 가지므로, 링크만
  PATH 에 두면 venv 를 켜지 않아도 올바른 파이썬으로 실행된다. 재설치해도 링크는 그대로다.
- **bash 사용자**는 `~/.zshrc` → `~/.bashrc`(Kali 기본 셸은 zsh). `hash -r` 은 셸의 명령 경로 캐시를 비워
  방금 만든 링크를 즉시 인식시킨다.
- **Claude 를 안 쓰면** `pip install -e .`(extra 생략)로 충분하다. 규칙 기반·로컬 Ollama 는 추가 의존성이 없다.
- venv 를 **삭제**하려면 `rm -rf .venv ~/.local/bin/assassin ~/.local/bin/htb-agent` 면 된다.
- **브랜치**: 새 PC·VM 스냅샷에서는 **기본(default) 브랜치**를 그대로 쓴다 — `git clone`/`git pull` 이 자동
  선택하므로 브랜치명을 지정할 필요가 없다. `claude/*` 작업 브랜치는 CI·리뷰 중 임시로 강제동기될 수 있어
  로컬 실행용으로 체크아웃하지 않는다(최신 릴리스는 항상 기본 브랜치에 병합되어 있다).

설치 카테고리: `recon` `web` `smb` `ad` `creds` `cloud` `pivot` `wordlist` `traffic` `re` `pwn` `forensic` `llm`

### 2.2 설치 없이 실행

```bash
cd htb-agent
PYTHONPATH=src python3 -m htb_agent --help
```

### 2.3 업데이트

```bash
git pull                                  # 코드 + 번들 시드 최신화
```

> 지식(시드)만은 git pull 없이도 실행 시 하루 1회 자동으로 최신화된다(§9.6).

---

## 3. 첫 실행 3단계

```bash
assassin --doctor                         # ① 환경 점검(도구·VPN·LLM) — 스캔 안 함
assassin 10.129.1.5                       # ② HTB 타겟 실행(스마트 승인)
assassin 10.129.1.5 --writeup --html      # ③ 라이트업 + HTML 대시보드까지
```

| 명령 | 바이너리 | 옵션 | 파라미터 |
|---|---|---|---|
| `assassin --doctor` | `assassin` | `--doctor`: 자가진단만 하고 종료 | — |
| `assassin 10.129.1.5` | `assassin` | (기본 = 스마트 승인) | 타겟 IP(HTB 는 VPN 대역만 허용) |
| `assassin 10.129.1.5 --writeup --html` | `assassin` | `--writeup`: 라이트업 MD 생성 · `--html`: 대시보드 생성 | 경로 생략 시 기본 위치(§11) |

`--doctor` 가 빨간 항목을 알려주면 그것만 채우면 된다.

---

## 4. 실행 흐름과 3관문

```
타겟 바인딩 → 정찰(RECON) → 식별(Linux / Windows-AD) → 열거 → 초기 침투(user)
          → 권한 상승(root) → 측면 이동 → 취약점(CVE/CWE) → 리포트 / 라이트업
```

취약점(CVE/CWE)은 마지막 한 번이 아니라 **단계마다 반영**되어 다음 단계·분석가가 바로 쓴다.

**결과 화면 읽는 순서(초보자)**: 목표(Jeopardy=플래그 1개, HTB=user+root)를 달성하면 출력 맨 끝에
**`🏁 다 풀었다(SOLVED)`** 패널이 떠 플래그 **값**(user.txt/root.txt 또는 단일 플래그)을 크게 보여 주고,
**출처**(전부 대상 상호작용 출력에서 나왔으면 `공략 유래(검증)`, 일부라도 사람 관찰이면 `사람 확인 필요`)를
함께 표시한다 — 결과를 복사해 어디에 붙이지 않아도 값이 바로 보인다. 그 바로 위의 **`한눈에 보기`** 박스부터
읽으면 된다 — 결과(플래그), 열린 서비스, 찾은 것(자격증명·수집물·취약점), 실행 현황(실행·도구 없음·미승인·못 돌림),
**다음에 할 일**(최대 3개, 그대로 입력할 명령)이 한곳에 있다. 그 위의 `다음 선택지(NEXT OPTIONS)`·`수동 제안`은
종류별로 묶여 있고, 수동 제안은 묶음마다 앞의 6개만 보여 준다(옵션만 덧붙인 변형은 숨김 — 전체 목록은
`--html`/`--json` 리포트).

**시작 전 막힘 안내**: 인자 없이 `assassin` 을 치면 시작 3단계가, 타겟이 거부되면 바로 고칠 힌트(`→ …`)가,
nmap 이 없으면 정찰을 4번 헛돌리지 않고 설치 명령이 바로 나온다(정찰이 한 번도 실행되지 못하면 '호스트 응답 없음'
대신 '도구/실행 환경 문제'로 표시).
종료코드: 0 완료 · 1 미완(열린 포트 미확보 등) · 2 인자/설정/범위 오류 · 130 Ctrl+C 중단.

모든 명령이 실행 전에 거치는 관문:

| 관문 | 하는 일 | 걸리면 |
|---|---|---|
| ① 검증 | 문법·인코딩·포트·파괴 명령·위험 패턴 검사 | 자동 거부 |
| ② 범위 | 명령 안의 모든 호스트/IP 가 바인딩된 타겟·공격자 IP 인지 확인(비정규 숫자 표기·IPv6 포함) | 확인 필요(자동 실행 안 함) |
| ③ 승인 | 승인 모드에 따라 자동/사람 확인 | 모드별 처리(§5) |

- 범위 안이라도 **동적·원격 코드 실행**(파이프→셸, `eval`, `IEX`, 명령 치환 등)은 사람 검토로 넘어간다. 프롬프트에 `▲ … 포함 — 위 '대안'을 먼저 보고 결정하세요. 실행?` 과 함께 더 안전한 대안이 표시된다.
- 단계·라운드·명령 수·스윕 횟수에 모두 상한이 있어 무한루프가 없다(§13).
- 목표를 달성하면(Jeopardy=플래그 1개, HTB=user+root) 남은 단계를 돌리지 않는다. 대상과 상호작용한
  명령의 출력에서 나온 플래그만 인정한다. 도구가 설치되지 않아 건너뛴 명령은 명령 수 상한에 포함되지 않는다.
- 같은 목적의 명령을 도구별 안전한 옵션 조합으로 몇 가지 더 시도한다(`--variants`, 기본 2).

---

## 5. 승인 모드 고르기

| 모드 | 명령 | 범위 안 + 검증 통과 | 범위 밖 | 동적 코드 실행 | 언제 |
|---|---|---|---|---|---|
| 스마트(기본) | `assassin <t>` | 자동 실행 | 사람 확인 | 사람 확인 | 평소 |
| 완전 자동 | `--auto` | 자동 실행 | 조용히 건너뜀 | 수동 제안으로 강등 | 무인 실행·배치 |
| 완전 수동 | `--manual` | 사람 확인 | 사람 확인 | 사람 확인 | 수업·검토·민감 환경 |
| 능동적 완전자동 | `--autonomous`(=`--hackathon`) | 자동 실행 + 깊은 스윕·병렬 열거·변형 학습·자동 학습 | 실행 안 함 | 수동 제안으로 강등 | 해커톤·시간 제한 대회 |

- `--manual` 은 `--autonomous` 보다 우선한다.
- 사람 확인 프롬프트는 `실행할까요? [y=실행 / 엔터=건너뛰기]` — 엔터만 치면 **실행 안 함**.

**확인이 필요할 때 화면**: 명령마다 `목적`(무엇을 하려는지 한 줄)과 3분할 해설이 나오고, 동적·원격 코드 실행처럼
검토가 필요한 명령에는 `대안`(먼저 내려받아 확인 → 그 다음 실행)이, 범위 밖 주소에는 할 일(내 VPN IP 라면
`--attacker-ip`)이 함께 표시됩니다. `y` 는 실행, 엔터는 건너뛰기(수동 제안으로 보관)입니다.

**사람 관찰 입력(`--observe`)**: 대화형 실행에서 건너뛴(미승인) 명령 대신, 브라우저 등으로 직접 확인한 내용을
적으면 기록에 반영됩니다. 이 내용은 `사람 관찰`로 표시돼 에이전트가 검증한 결과와 섞이지 않습니다
(거기서 읽은 플래그는 '대상 상호작용 유래'가 아니므로 목표 달성 판정에는 쓰이지 않습니다). GUI 문제처럼
에이전트가 직접 다루기 어려운 부분을 학습자가 메워 넣는 용도입니다.

**실행이 끝난 뒤**: 수동 제안은 종류별로 묶여 바로 하는 법이 붙습니다 — 자격증명이 필요한 명령은
`--cred 사용자:비밀번호` 를 붙여 다시 실행하면 자동으로 채워 실행하고, 상한 초과분은 `--max-enum`/`--resume`,
실행 위험분은 함께 적힌 대안대로 확인 후 직접 실행합니다.

---

## 6. 플랫폼별 사용법

### 6.1 HTB(기본)

```bash
assassin 10.129.1.5
assassin 10.129.1.5 --attacker-ip 10.10.14.5      # tun0 자동탐지가 안 될 때
assassin 10.129.1.5 --range 10.129.0.0/16         # 허용 대역 직접 지정
```

- VPN 대역을 강제한다. 플래그: `user.txt` / `root.txt`(32-hex, `HTB{}`).

### 6.2 Dreamhack

```bash
assassin web-chall.dreamhack.games:8080 --platform dreamhack
assassin chall.dreamhack.io:8080 --platform dreamhack --category pwn --llm hybrid
```

### 6.3 CTF

```bash
assassin http://ctf.example.com/chall --platform ctf --flag-prefix myctf
```

| 옵션 | 설명 |
|---|---|
| `--platform {htb,dreamhack,ctf}` | dreamhack/ctf 는 단일 타겟(host:port/URL) 바인딩 + 단일 플래그 모드 |
| `--category {web,pwn,rev,crypto,forensic,misc}` | LLM 제안을 카테고리에 맞게 유도 |
| `--flag-prefix TAG` | 우선 인식할 플래그 접두(반복 가능). `DH{}` `flag{}` `CTF{}` 등 `TAG{}` 는 기본 자동 인식 |

---

## 7. 자격증명 넣기

`--cred` 를 주면 `{user}` `{pass}` `{domain}` `{hash}` 가 들어간 제안이 실행 후보로 승격된다(반복 가능).

| 형식 | 예 |
|---|---|
| `user:pass` | `--cred admin:Passw0rd` |
| `user:pass:domain` | `--cred svc:Summer2024:corp.htb` |
| `user:pass:domain:nthash` | `--cred svc:x:corp.htb:<32hex>` |
| Pass-the-Hash | `--cred administrator:<32hex>` 또는 `--cred administrator::corp.htb:<NT 또는 LM:NT>` |

```bash
assassin 10.129.1.5 --auto --cred administrator:Passw0rd --writeup
```

---

## 8. LLM 두뇌 붙이기

LLM 없이도(`--llm none`, 기본) 규칙 기반으로 완전 동작한다. 붙이면 열거·분석 제안이 풍부해진다.

**가장 쉬운 방법 — 연결 마법사(처음 한 번)**

```bash
assassin --setup-llm      # 질문에 답하며 Claude·로컬 LLM 연결 → 실제 1회 호출로 확인 → 기본 설정 저장
assassin --llm-test       # 나중에 다시 확인(환경 진단 + 짧은 실제 호출)
assassin 10.129.1.5       # 이후엔 --llm 없이도 마법사에서 고른 백엔드로 실행
```

| 마법사 단계 | 하는 일 |
|---|---|
| ① 선택 | `[1] 하이브리드(권장)` · `[2] Claude 만` · `[3] 로컬만` · `[q] 취소` |
| ② Claude | `anthropic` 패키지 확인(없으면 설치할지 물음) → API 키 붙여넣기(화면에 안 보임) → 실제 호출 → 성공하면 키 저장 |
| ③ 로컬 | Ollama 설치·서버 확인 → 받아 둔 모델 목록 → **PC 메모리에 맞는 추천 모델**(8GB→`qwen2.5:7b`, 16GB→`qwen2.5:14b` 등) → 받을지 물음 → 실제 호출 |
| ④ 저장 | `~/.config/assassin/config.json`(백엔드·로컬 모델·비용 상한 기본 $2) — `--config` 없이 자동으로 읽음 |

- **키 보관**: `~/.config/assassin/credentials`(폴더 700·파일 600, 본인만 읽기). 화면엔 `sk-ant-…abcd` 처럼 가린 값만 보이고,
  상태 파일·감사 로그·리포트·라이트업에는 남지 않는다. `ANTHROPIC_API_KEY` 환경변수가 있으면 그쪽이 우선.
- **동의 원칙**: 패키지 설치·모델 다운로드는 항상 먼저 묻는다(엔터=아니오). Ollama 설치 스크립트(`curl … | sh`)는
  자동 실행하지 않고 명령만 보여 준다(내용 확인 후 직접 실행).
- **틀린 키**: 실제 호출이 실패하면 저장하지 않고 이유를 알려 준다(예: `API 키가 올바르지 않습니다`, `연결 실패 — 'ollama serve' 확인`).
- **설정 우선순위**: CLI(`--llm` 등) > 환경변수(`OLLAMA_HOST`·`OLLAMA_MODEL`) > 기본 설정 파일 > 내장 기본값. 한 번만 끄려면 `--llm none`.
- 설정 위치를 바꾸려면 `ASSASSIN_CONFIG_DIR=/경로` (또는 `XDG_CONFIG_HOME`).

**직접 연결(수동)**

| 백엔드 | 명령 | 준비 |
|---|---|---|
| Claude | `--llm claude` | `pip install anthropic` + `export ANTHROPIC_API_KEY=...` |
| Ollama(로컬) | `--llm ollama` | `ollama serve` + `ollama pull qwen2.5:7b` |
| hybrid | `--llm hybrid` | 위 둘 중 하나 이상. 단계 난이도로 라우팅하고 실패 시 폴백 |

- 비용/성능: `--llm-tier {cheap,standard,strong}`(기본 standard). 어려운 단계에서 자동 승격된다.
- 일괄 준비: `sudo ./scripts/install_tools.sh llm`
- LLM 출력도 3관문을 그대로 통과해야 실행된다.

**hybrid 동작 방식**

| 상황 | 동작 |
|---|---|
| 열거·일반 단계(cheap/standard) | 로컬(Ollama) 우선 → 빈 응답·오류·거절이면 Claude 로 폴백 |
| 권한상승·분석(strong) | Claude 우선 → 실패 시 로컬로 폴백 |
| 한 백엔드가 연속 2회 오류(타임아웃 등) | 그 세션 동안 건너뜀(서킷 브레이커) — 매 호출 180초 대기 방지 |
| 설정된 Ollama 모델(예: strong=`llama3.3:70b`)이 미설치 | 설치된 다른 모델로 대체하고 시작 시 `로컬 모델 대체: strong→qwen2.5:7b` 로 표시 |
| 모델이 응답을 거절(refusal) | 빈 응답과 구분해 집계하고 다른 백엔드로 폴백 |

**LLM 이 생각하는 방식(다관점 · 병렬 가설)**

LLM 이 붙으면 단계마다 먼저 **분석가**가 상황을 판단하고, 그 판단으로 명령을 고른다.

- 레드팀(악용 가능성)·개발자(입력 처리·인증·로직 결함)·인프라 운영자(기본값·잘못된 구성)·
  방어(흔적·막힐 지점) 관점에서 같은 관측을 본다.
- 한 해석에 고정하지 않고 가설 2~4개(`H1 [우선:상] …`)를 세워 **병렬로** 비교하고, 가설마다
  가장 싼 확인 방법과 기각 시 대안을 정한 뒤 `계획:` 으로 검증 순서를 낸다.
- 어떤 명령이 어떤 가설을 검증했는지는 결과의 비고(`가설 H1 · 근거: …`)에 남는다.
- `확신도: 하` 면 처음부터 강력 모델로 올려 다시 판단한다. 모든 명령은 여전히 3관문을 통과해야 실행된다.

**방향을 잡고 진행하기(가설 기록)**

LLM 이 매번 처음부터 다시 생각하지 않도록, 분석가가 세운 가설을 **가설 기록**으로 들고 간다.

| 단계 | 누가 | 하는 일 |
|---|---|---|
| 계획 | 분석가(hybrid 면 Claude 우선) | 가설 H1~H4 를 세우고, 이후엔 기록을 **갱신**(같은 ID 유지 · 상태만 변경 · 필요할 때만 추가) |
| 실행 | 명령 생성(hybrid 면 로컬 우선) | 분석 전문 대신 **지금 할 일 1개**만 받음 — 가설 · 확인 방법 · 기대 신호 · 이미 해 본 명령 |
| 대조 | 규칙(LLM 없음) | 결과를 기대 신호와 비교 → 일치면 `확인〔추정〕`, 대상 거부·불일치면 연속 불일치 +1 |
| 재계획 | 분석가 | 같은 가설이 **2회 연속** 어긋나면 `막힘` → 분석가가 확인 방법을 바꾸거나 기각하고 대안으로 |

- 분석가는 **의미 있는 변화**가 있을 때만 다시 부른다: 새 크리덴셜·서비스·수집물·취약점·권한·플래그, 가설
  확인·기각·막힘. 명령이 하나 더 실행된 것만으로는 다시 부르지 않는다(비용 절감 · 방향 유지).
- 화면에는 `🎯 지금 집중: H2 …`, `H1 기대 신호 2회 연속 불일치 — 분석가에게 재계획 요청` 이 뜨고, 결과 요약·HTML·
  라이트업에 **가설 보드**(`✔ H2 [상] 확인 — … (시도 1 · 일치 1)`)가 나온다. 실행 재생에도 계획 갱신·막힘이 보인다.
- `--resume` 하면 가설 기록과 분석이 복원되어 재개 후 첫 분석도 '갱신'이 된다.
- 분석가가 가설을 주지 못하면(형식 불일치 등) 예전처럼 분석 전문을 명령 생성에 넘기고 결과가 늘 때마다 다시 판단한다.
- 가설 상태는 **방향 잡기용〔추정〕**이다. 플래그 출처·목표 달성은 지금처럼 실행 결과로만 판정한다.

실행 끝의 비용 요약에 `라우팅: 로컬 N · 강력 N · 폴백 N · 거절 N · 빈응답 N · 오류 N · 미응답 N` 이 붙어,
실제로 어느 백엔드가 일했는지 확인할 수 있다. `차단: local(...)` 이 보이면 Ollama 서버 상태를 점검한다.

---

## 9. 지식베이스: 시작 지식 · 학습 · 공유 · 자동 반영

### 9.1 구조

```
knowledge/
├── rules/*.json            서비스·OS별 점검 규칙(제안 명령)
├── vulns/*.json            배너/버전 기반 CVE 지식
├── notes/                  자유 노트(RAG 로 풀이 중 참조)
│   ├── learned/seed-*.md   ★ 번들 시드(저장소에 포함, 모두 동일한 시작 지식)
│   ├── learned/learned-*.md  내가 학습한 노트(로컬, git 추적 안 함)
│   └── ingested/           내가 넣은 자료(로컬)
├── shared_seeds/           공유 저장소 최신 시드 캐시(로컬, 자동 동기화)
└── cve_cache/              CVE 수집 캐시(로컬)
```

### 9.2 지식이 자라는 전체 흐름

```
① 번들 시드(카탈로그 59개 주제 + 보조 3개 = 62개)  ── 누구나 clone 즉시 같은 지식으로 시작(오프라인 포함)
        │
② 각자 학습  ── --learn / --learn-gaps / --web-learn / --ingest  → 내 로컬에만 쌓임
        │
③ 승격(공유)  ── 매주 자동: 학습 → 품질 관문 → 전체 테스트 → PR → 자동 병합
        │
④ 로컬 반영  ── 에이전트 실행 시 하루 1회 자동 동기화(검증 통과분만)
        ▼
  모두의 시작 지식이 함께 커짐
```

### 9.3 학습하기(내 로컬)

| 명령 | 하는 일 |
|---|---|
| `assassin --learn list` | 학습 가능한 주제 목록 |
| `assassin --learn kerberoasting` | 한 주제를 권위 출처(MITRE ATT&CK·OWASP·PortSwigger·RFC 등)에서 학습 |
| `assassin --learn all` | 59개 주제 전체를 한 번에 학습(주제당 최대 2개 권위 출처). 수집에 실패한 출처(끊긴 링크 등)는 경고로 표시 — 주간 워크플로에서는 Actions 경고로 남음 |
| `assassin --ingest ./my-writeups/` | 내 자료(.md/.txt/.pdf)를 노트로 학습. 본인 자료는 풀이 중 참조 허용 |
| `assassin <t> --learn-gaps` | 풀이 중 모르는 기술을 만나면 권위 출처에서 자동 학습(autonomous 기본) |
| `assassin <t> --web-learn` | 카탈로그 밖 공백을 인터넷 검색으로 학습(`--learn-gaps` 를 함께 켬). HTB 라이트업은 출처 불문 차단, 교차검증 통과분만(autonomous 기본) |

- 학습 내용은 노트로만 저장된다(실행·명령화하지 않음).
- 오프라인이면 출처 포인터만 남고, 시작 지식은 번들 시드가 보장한다.

### 9.4 승격(공유) — 보통은 자동, 손으로도 가능

품질 관문(하나라도 걸리면 승격 안 함):

| 관문 | 기준 |
|---|---|
| 출처 | 허용(권위) 도메인 + 해당 주제의 현재 카탈로그에 있는 출처 |
| 요약 | 120자 이상(승격 시 500자로 정리) |
| 잡음 | 쿠키·JavaScript 안내·사이트 공지 등 웹페이지 군더더기 없음 |
| 라이트업 | HTB 라이트업 신호 없음 |
| 형식 | 제어문자 없음 |

규칙: 사람이 다듬은 시드 본문은 그대로 두고 `## 최신 보강(승격)` 섹션에만 쓴다. 같은 출처는 교체되고 주제당 3건까지만 둔다. 카탈로그에서 빠진 출처의 승격분은 정리하며, 내용이 같으면 처음 승격일을 유지한다.

손으로 할 때(유지보수자·기여자):

```bash
assassin --learn all
assassin --promote all                       # 또는 --promote sqli
git diff knowledge/notes/learned/seed-*.md   # 검토
# → 커밋 → PR → CI 통과 → 병합
```

### 9.5 공유 저장소 자동 반영(주간)

GitHub Actions **`KB 자동 승격`** (`.github/workflows/kb-auto-promote.yml`)

| 항목 | 내용 |
|---|---|
| 일정 | 매주 월요일 03:17(KST). Actions 탭에서 **Run workflow** 로 수동 실행 가능 |
| 순서 | `--learn all` → `--promote all` → 시드 변경 확인 → 전체 테스트 + 컴파일 → PR `kb/auto-promote` 생성 → 자동 병합 |
| 변경 없음 | 테스트·PR 단계 건너뜀(정상) |
| 실패 | Actions 탭에 빨간 표시. 기존 시드는 그대로 |

필요한 저장소 설정(1회): Settings → Actions → General → Workflow permissions → **Read and write permissions** + **Allow GitHub Actions to create and approve pull requests**.

### 9.6 로컬 자동 반영(하루 1회)

타겟을 실행하면 공유 저장소의 시드 목록을 조회해 **로컬과 다른 것만** 받고, 아래 검증을 모두 통과한 것만 `knowledge/shared_seeds/` 캐시에 적용한다. 지식베이스는 캐시본을 우선 사용한다.

| 검증 | 내용 |
|---|---|
| 형식 | 시드 파일명 · UTF-8 · 제어문자 없음 · 650B 이상 6000자 이하 |
| 내용 | 필수 5개 섹션(개요·핵심 기법·표준 도구·블루팀 탐지·완화) · 권위 출처 URL |
| 승격분 | 승격 관문 통과 · 주제당 3건 이하 |
| 무결성 | 내용 해시 = 목록 해시 · 다운로드 주소 = 이 저장소 raw 주소 |

안전 장치:
- 데이터(노트)만 받고 코드·규칙은 받지 않는다.
- git 추적 파일을 건드리지 않으므로 git pull 충돌이 없다.
- 내가 편집 중인(미커밋) 시드는 덮어쓰지 않는다.
- git pull 로 시드가 바뀌면 해당 캐시본은 자동으로 무시한다.
- 오프라인이면 조용히 건너뛰고, 하루 1회만 재시도한다.

| 명령 | 동작 |
|---|---|
| `assassin --kb-sync` | 지금 바로 동기화하고 결과 출력(`--offline` 과 함께 쓰면 접속하지 않고 오류) |
| `assassin <t> --no-kb-sync` | 이번 실행만 끄기 |
| `export ASSASSIN_NO_KB_SYNC=1` | 항상 끄기 |
| `assassin <t> --offline` | 네트워크 수집 전부 끄기(동기화 포함) |

---

## 10. 자동 준비 도구(생성 전용)

풀이 중 조건이 갖춰지면 자동으로 생성되어 리포트·라이트업·JSON/HTML 에 포함된다. 단독 실행도 가능하다. **실행은 하지 않는다** — 권한 확인 대상에서 사용자가 직접 판단해 쓴다.

| 도구 | 단독 실행 | 자동 생성 조건 | 생성물 |
|---|---|---|---|
| 리버스쉘 | `assassin --revshell 10.10.14.5:4444` | 공격자 IP 확보(리스너 포트 `--lport`, 기본 4444) | bash/nc/python3/php/powershell/socat 페이로드 + 리스너·안정화 힌트 |
| AWS/S3 | `assassin --cloud acme.htb` | 호스트명/도메인 확보 | 버킷명 후보 + 비인증 점검 명령 |
| 권한상승 | `assassin --privesc linux` | OS 식별 | sudo·SUID·capabilities·cron·커널·토큰·서비스 점검 + LPE 후보 |
| 해시 크래킹 | `assassin --crack '$krb5tgs$23$...'` | 출력·자격증명에서 해시 발견 | 해시 종류 식별 + john/hashcat 명령(모드·포맷·워드리스트) |

### 10.1 패킷 분석 · 웹 프록시 도구(Wireshark · Burp 등)

| 하고 싶은 것 | 자율 실행(헤드리스) | 수동(사용자 Kali) |
|---|---|---|
| 패킷 캡처 분석 | **`tshark`**(Wireshark CLI, 샌드박스 내장) · `tcpdump` — pcap 에서 HTTP/자격/스트림 추출 | Wireshark GUI 로 열람 |
| 웹 요청 가로채기·변조 | **`mitmproxy`/`mitmdump`** · **OWASP ZAP**(`-daemon` API) — 데몬/CLI 라 자동화 가능 | **Burp Suite**(GUI — 프록시·Repeater·Intruder); 브라우저 프록시 `127.0.0.1:8080` |
| 파라미터 퍼징·주입 | `ffuf`·`sqlmap`·`wfuzz`(자율) | Burp Intruder |

> Wireshark·Burp Suite 는 **GUI 라 자율(헤드리스) 실행 대상이 아닙니다** — 자율 파이프라인에선 동등한 CLI/데몬 도구(`tshark`·`tcpdump`·`mitmproxy`·`zaproxy`)를 쓰고, GUI 는 사용자 Kali 에서 직접 사용합니다. 모든 도구는 `assassin --doctor` 로 설치 상태를 확인하고 `--install-missing` 또는 `install_tools.sh` 로 설치합니다(레지스트리 등록 완료).

### 10.2 발판 자동 실행(`--exploit-exec`) — 생성 전용의 유일한 예외(옵트인)

§10 의 도구들이 **생성만** 하는 것과 달리, `--exploit-exec`(기본 OFF)는 **확보한 평문 자격으로 실제 발판을
잡아** 플래그 읽기·권한상승 열거를 **실행**한다. 단, 새로 늘어나는 권한은 없다 — 모든 명령은 그대로 ① 검증 →
② 범위 → ③ 승인 3관문을 통과하고, 범위 밖·파괴 명령은 여전히 막힌다. "자격만 있으면 플래그까지 자동"이
목적이며(자격이 이미 있는 Easy 머신), **침입(익스플로잇) 자체는 아직 자동화하지 않는다.**

| 항목 | 내용 |
|---|---|
| 켜는 법 | `assassin <t> --cred user:pass --exploit-exec` (자격은 열거로 확보돼도 됨) |
| 하는 일 | 평문 자격으로 SSH 접속 → `user.txt`/`root.txt` 자동 읽기 → 권한상승 **열거**(`id`·`whoami`·`sudo -l`·SUID·capabilities — 파괴 없음) |
| 쓰는 자격 | **평문만**(`user:pass`). 해시(`<…>`)·빈 값은 건너뜀. 앞의 3개 자격까지 시도 |
| 건너뛰는 경우 | 자격 없음 · 22번 포트 닫힘 · `sshpass` 미설치 → 조용히 스킵(감사 로그에 사유 기록) |
| 승인 | `--autonomous` 와 함께면 무프롬프트, 없으면 각 명령 y/n |
| 결과 | 플래그 확보 시 **`🏁 다 풀었다(SOLVED)`** 패널에 값·출처 표시(§4). 출처는 `공략 유래(검증)` |
| OFF 일 때 | 동작은 지금과 100% 동일(아무 변화 없음) |

```bash
# 자격을 확보한 Easy 머신 → 접속·플래그 읽기·권한상승 열거까지 한 번에, SOLVED 화면에 값 출력
assassin 10.129.1.5 --cred svc:Summer2024 --exploit-exec --autonomous
```

### 10.3 PoC 자동 선택·발사(`--auto-poc`) — 발판까지 한 흐름(옵트인)

`--exploit-exec` 와 **함께** 켜는 상위 옵션. 자격을 미리 주지 않아도, 핑거프린트된 웹앱 **버전에 맞는
공개 PoC(⭐ 1순위)를 자동 선택**해 실행 큐에 올린다(①~③단계). 생성 전용 경계는 유지되며, 실제
네트워크 발사는 전부 3관문을 거친다.

> ⚠️ **현재 구현 범위(정직한 상태)** — ⭐ PoC 자동 선택·발사 → 자격이 나오면 SSH 발판에 더해, 그 다음
> 단계인 **웹 RCE 발판 세션 → 설정/DB 자격 수확 → 플래그 읽기**(`_foothold_stage`)와 **측면 이동 후보
> 생성**(`lateral_candidates`)도 **옵트인(`--exploit-exec`) 뒤 실행 루프에 배선**돼 호출된다
> (orchestrator `run()` 의 PHASE 3.9 직전). 다만 발판 채널의 실제 네트워크 구동부(소켓/HTTP)는
> **RCE 실행 표면**이라, `requests` 같은 실행 의존이 없으면 **명령·후보 생성까지만 하고 조용히 안전하게
> degrade** 한다(섣부른 발사 없음). 측면 이동은 끝까지 **생성 전용**(명령 문자열만, 발사 없음)이다.

| 항목 | 내용 |
|---|---|
| 켜는 법 | `assassin <t> --exploit-exec --auto-poc` (보통 `--autonomous --llm claude` 와 함께) |
| 지금 도는 것 | ⭐ 버전매칭 PoC 자동 선택·발사 → (PoC 가 자격을 뱉으면) SSH 발판 → 플래그 읽기 |
| 측면 이동(lateral) | 수확한 크리덴셜/NT 해시를 **열린 다른 서비스**(SSH/SMB/WinRM/RDP/MSSQL/FTP/MySQL/PostgreSQL)에 재사용·PtH 하는 후보를 자동 생성(`_prepare_lateral`). **생성 전용** — 명령 문자열만, 발사 없음(사용자가 권한 확인 자산에서 실행) |
| 발판 성립 검증 | 발판에서 `id`/`uname` 신호가 나와야 **진짜 셸**로 인정. 로그인 페이지 HTML·빈 응답 등 **헛발판은 버림** → 성립 안 하면 조용히 발판 미확보(섣부른 단정 없음) |
| 채널 | `_acquire_session` 이 (1) 웹 RCE(`cmd=` 엔드포인트) → 실패 시 (2) **리버스셸 수신**(`--catch-revshell`, 준비된 payload 콜백을 소켓 리스너로 수신) 순으로 발판을 시도. 모두 같은 `ShellSession` 인터페이스. 리버스셸 수신은 opt-in 이라 꺼두면 소켓 블로킹 없음 |
| 승인 | `--autonomous` 와 함께면 무프롬프트, 없으면 각 명령 y/n. 권한 확인 대상 전용 |
| 비고 | 발판 채널의 실제 네트워크 실행부(소켓/HTTP)는 **RCE 실행 표면**이라 운영 리포에서 연결한다(`shell_transport`/`_acquire_session`, 그리고 `_foothold_stage` 호출 배선). 미연결이면 발판 미확보로 안전하게 끝남 |

```bash
# 🚀 완전 자동 루트 시도(초보자용 한 줄): 정찰→버전→⭐PoC 자동선택→발판→플래그 + 결과물 저장
assassin 10.129.1.5 --autonomous --llm claude --exploit-exec --auto-poc --html --json
```
플래그 뜻 — `--autonomous`(무프롬프트 완전자동) · `--llm claude`(Claude 두뇌) · `--exploit-exec`(발판
실제 실행 켜기) · `--auto-poc`(⭐ PoC 자동 선택·발사) · `--html`/`--json`(대시보드·기계판독 결과 저장).

> ⚠️ 권한이 확인된 대상(HTB·인가된 진단)에서만. 자격·대상 모두 범위 가드의 통제를 받는다.

---

## 11. 산출물: 라이트업 · 리포트 · 로그 · 재개

| 산출물 | 옵션 | 기본 위치 |
|---|---|---|
| 라이트업(HTB v5) | `--writeup [경로]` | `writeup_<타겟>.md` |
| 라이트업(Tistory 13섹션) | `--writeup --writeup-format tistory` | 위와 같음 |
| JSON 리포트 | `--json [경로]` | `<state-dir>/report_<타겟>.json` |
| HTML 대시보드 | `--html [경로]` | `<state-dir>/report_<타겟>.html` |
| 감사 로그(JSONL) | `--log-file 경로` / 끄기 `--no-audit` | `<state-dir>/audit_<타겟>.jsonl` |
| 세션 상태 | `--state-dir 경로` / 끄기 `--no-save` | `./state` |

- 라이트업에는 CVE 레퍼런스(NVD·CVSS·PoC)와 블루팀 탐지 지표(SIEM·Snort·Wireshark)가 자동으로 들어간다.
- HTML 상단 "한눈에 보기"에는 3관문 지표·플래그 출처·지식 기반(시작 지식 커버·승격 발췌·공유 동기화·이번 세션 자율 학습과 공백)·안전 경계·단계 진행이 요약된다(발표·심사용).
- 중단 후 재개: `assassin <t> --resume` — 저장된 RECON 결과를 재사용해 재스캔을 생략하고,
  이미 실행한 명령은 다시 돌리지 않는다(결과·플래그는 복원). 지난번에 도구가 없거나 거부돼
  못 한 명령은 이번에 다시 판단한다. 실행 중 **Ctrl+C** 로 멈춰도 그때까지의 결과가 저장되며
  (`status=interrupted`, 종료코드 130) 같은 명령에 `--resume` 을 붙여 이어 간다.

---

## 12. 설정 파일

우선순위: **CLI > 설정 파일 > 기본값** — `--learn`·`--promote`·`--kb-sync`·`--ingest` 같은 단독 명령도 설정의 `knowledge_dir` 를 따른다.

```bash
assassin 10.129.1.5 --config config/config.example.json
```

```json
{
  "platform": "htb",
  "allowed_ranges": ["10.129.0.0/16"],
  "attacker_ips": [],
  "llm": {"backend": "none", "tier": "standard"},
  "max_attempts": 4,
  "max_enum": 6,
  "max_llm": 5,
  "max_rounds": 2,
  "max_sweeps": 2,
  "max_parallel": 1,
  "max_variants": 2,
  "knowledge_dir": "knowledge",
  "state_dir": "state",

  "sandbox": "vm",
  "vm_ssh": "kali@192.168.56.10",
  "vm_ssh_key": "~/.ssh/id_ed25519",
  "vm_ssh_port": 22,
  "vm_sudo": true,
  "vm_confine": true
}
```

- **기본 실행 환경을 VM 으로**: `sandbox`·`vm_ssh`(+ 선택 `vm_ssh_key`/`vm_ssh_port`/`vm_sudo`/`vm_confine`)를
  설정 파일에 적어 두면 매번 `--sandbox vm --vm-ssh …` 를 붙이지 않아도 그 VM 을 기본으로 쓴다. `sandbox` 값은
  `none`(기본)·`shell`·`docker`·`vm` 중 하나다. CLI 플래그를 주면 설정값보다 우선한다.
- YAML(`config/config.example.yaml`)도 지원한다(`pip install pyyaml` 필요).
- 알 수 없는 키는 경고와 함께 무시된다.
- 개인 설정은 `config/config.yaml` 에 두면 git 에 올라가지 않는다.

---

## 13. 한도와 튜닝

| 옵션 | 기본 | autonomous 기본 | 의미 |
|---|---|---|---|
| `--max-attempts` | 4 | 4 | 포트스캔 폴백 최대 시도 |
| `--max-enum` | 6 | 24 | 열거 자동 실행 최대 개수(자율 모드는 실제 머신에서 리드를 충분히 파도록 상향 — 반복 억제·중복제거·정체 조기종료로 상한 안전) |
| `--max-rounds` | 2 | 3 | 열거/LLM 반복 라운드 |
| `--max-sweeps` | 2 | 3 | 새 관측·자격증명으로 이전 단계 재진입하는 횟수(정체 시 조기 종료) |
| `--max-parallel` | 1 | 4 | 열거 명령 동시 실행 수(I/O 만 병렬, 관문·결과 처리는 순차) |
| `--variants` | 2 | 3 | 명령당 옵션 조합 변형 수(1 = 변형 끔) |
| `--time-budget 분` | 무제한 | 무제한 | 해커톤 시간 예산 — 마감 시 남은 단계 생략·상태 저장(§16.1) |
| `--max-cost USD` | 무제한 | 무제한 | LLM 누적 추정 비용 상한 — 넘으면 LLM 호출 멈추고 규칙 기반으로 계속 |
| `--no-enrich` | — | — | CVE/CWE 자동 수집(NVD·GitHub) 끄기 |
| `--enrich-cache 경로` | `<knowledge>/cve_cache` | — | CVE 캐시 위치 |
| `--knowledge 경로` | `./knowledge` | — | 지식베이스 위치 |

---

## 14. 환경변수

| 변수 | 용도 |
|---|---|
| `ANTHROPIC_API_KEY` | Claude 백엔드 API 키 |
| `OLLAMA_HOST` | Ollama 서버 주소(기본 `http://localhost:11434`) |
| `OLLAMA_MODEL` | 모든 tier 에 쓸 Ollama 모델 이름(미설정 시 설정 파일 `llm.ollama_model` → cheap/standard `qwen2.5:7b`, strong `llama3.3:70b`) |
| `ASSASSIN_CONFIG_DIR` | 마법사의 키·기본 설정 위치(기본 `~/.config/assassin`, `XDG_CONFIG_HOME` 존중) |
| `ASSASSIN_NO_KB_SYNC` | `1` 이면 실행 시 공유 시드 자동 동기화 끄기 |
| `ASSASSIN_KB_SYNC_REPO` | 동기화할 공유 저장소(`owner/repo`, 기본 `HyungJinKwon/HTB_AUTO_AGENT`) — 포크 운영 시 |
| `ASSASSIN_KB_SYNC_REF` | 동기화할 브랜치/태그(생략 시 저장소 기본 브랜치) |
| `NO_COLOR` / `FORCE_COLOR` | 터미널 색 끄기 / 강제 켜기(비-TTY·파이프에서는 자동으로 꺼짐) |

---

## 14.5 성능 측정(--bench)과 실행 재생(--replay)

**로컬 모의 문제로 성공률 측정** — 실제 네트워크·도구 없이 가짜 응답만 쓰는 연습 문제(`bench/challenges/*.json`)로
풀이 성공률·명령 수·시간·비용을 잰다. 개선 효과를 숫자로 보여줄 때(해커톤 발표) 쓴다.

```bash
assassin --bench                      # 번들 문제 세트(오프라인)
assassin --bench --attempts 5         # 문제당 5회 → pass@5
assassin --bench --llm hybrid         # LLM 유무 비교
```

- 결과는 표로 출력하고 `state/bench/<시각>/results.json` 에 저장한다(난이도별 성공, pass@N, **검증된 풀이율**(대상과 실제 상호작용한 출력에서 나온 플래그만 인정), 승인 부담, 평균 명령 수, 플래그까지 단계, 시간, 비용, **LLM 호출 수**(총·풀이 1건당 — 방향을 잡고 진행할수록 작아짐)).
- 시도마다 감사 로그를 남겨 아래 `--replay` 로 그대로 재생할 수 있다.
- 쉬운 문제는 규칙만으로 풀리고, 단서를 이어가야 하는 중간 문제는 LLM 을 붙여야 풀린다 — 효과를 바로 대비해 볼 수 있다.

**실행을 단계별로 재생** — 감사 로그(JSONL)를 '명령 제안 → 관문 → 실행 결과' 타임라인 HTML 로 바꾼다.
브라우저에서 ←/→/스페이스로 넘겨 본다. 교육·심사 발표에 쓴다.

```bash
assassin --replay state/audit_10.129.1.5.jsonl    # → 같은 이름의 .html
```

로그 내용은 신뢰하지 않는 데이터로 다뤄 화면에 안전하게(스크립트 주입 불가) 표시한다.

---

## 15. 데모

네트워크·실제 도구 없이 전체 흐름을 볼 수 있다.

```bash
cd htb-agent
python3 scripts/demo.py                    # 전체 흐름 요약
python3 scripts/demo.py --live             # 발표용 6단계 시연(범위 밖 거부 → 정찰·식별 → 열거 → 3관문 → 지식 → 산출)
python3 scripts/demo.py --live --pace 2    # 단계 사이 2초 멈춤
python3 scripts/demo.py --write out/       # 라이트업·JSON·HTML 파일 저장
```

---

## 16. 상황별 레시피

### 16.1 해커톤 대회(시간 제한, 최대 자율)

```bash
assassin --doctor
assassin 10.129.1.5 --autonomous --llm hybrid --time-budget 45 --writeup --html
assassin 10.129.1.5 --autonomous --llm hybrid --time-budget 30 --resume   # 남은 시간으로 이어서

# 자격을 확보(또는 --cred 로 직접 제공)한 Easy 머신이면 → 발판·플래그 읽기까지 한 번에
assassin 10.129.1.5 --autonomous --llm hybrid --cred svc:Summer2024 --exploit-exec --writeup --html
```

`--time-budget <분>` 이 지나면 진행 중이던 단계를 마치고 남은 단계를 `생략(시간 예산 소진)` 으로
표시한 뒤 상태를 저장합니다(`status=interrupted`, 종료코드 130). 대회 시간 안에 결과물(라이트업·HTML)이
반드시 남도록 하는 장치입니다. 경과 시간은 정찰부터 셉니다.

- **`--exploit-exec`**(옵트인): 평문 자격이 있으면 SSH 발판을 잡아 플래그 읽기·권한상승 열거까지 자동
  실행하고, 끝에 **`🏁 SOLVED`** 패널로 user.txt/root.txt 값을 보여 줍니다(§10.2). 사람은 각 명령에 `y/n`
  (또는 `--autonomous` 면 무프롬프트)만 하면 됩니다.
- **전용 풀이 VM 에서 완전 자율**: `--sandbox vm --vm-ssh kali@<VM> --vm-confine` 으로 접속한 VM 안에서
  egress 를 타겟 대역으로 묶어 docker 처럼 동적 실행을 자동 허용합니다(`--vm-ssh-key`/`--vm-ssh-port`/`--vm-sudo`).
  설정 파일(§12)에 `sandbox`·`vm_ssh` 를 적어 두면 매번 플래그를 붙이지 않아도 기본으로 그 VM 을 씁니다.

### 16.2 교육·수업(모든 명령을 보며 설명)

```bash
assassin 10.129.1.5 --manual --writeup --writeup-format tistory
python3 scripts/demo.py --live --pace 3      # 강의 도입부 시연
```

### 16.3 Dreamhack 웹 문제

```bash
assassin chall.dreamhack.io:8080 --platform dreamhack --category web --llm hybrid --html
```

### 16.4 인터넷이 막힌 환경

```bash
assassin 10.129.1.5 --offline                # CVE 수집·학습·동기화 모두 끔(번들 시드로 동작)
```

### 16.5 시작 전에 지식 최신화

```bash
assassin --kb-sync                           # 공유 저장소 최신 시드 받기
assassin --ingest ./my-notes/                # 내 자료 추가
```

### 16.6 결과를 다른 도구로 넘기기

```bash
assassin 10.129.1.5 --auto --json out/result.json
```

---

## 17. 트러블슈팅

| 증상 | 원인 | 조치 |
|---|---|---|
| `VPN IP 미탐지` · 공격자IP `(없음)` | VPN 미연결 | `ip a` 확인 후 `--attacker-ip <VPN IP>`(리버스쉘 자동 준비 생략) |
| ScopeViolation(범위 위반) | 타겟/대역 밖 주소 포함(설계상 차단) | HTB 는 `--range` 확인, CTF/Dreamhack 은 `--platform` 지정 |
| `error: externally-managed-environment` | 최신 Kali·Ubuntu 의 PEP 668 잠금(시스템 pip 거부) | venv 로 설치(§2.1). `--break-system-packages` 로 전역 설치하지 말 것 |
| `assassin: command not found`(설치했는데) | venv 의 bin 이 PATH 에 없음 | `~/.local/bin` 심링크 + PATH 설정(§2.1), `hash -r` 로 캐시 비우기. 또는 `source .venv/bin/activate` |
| `'<도구>' 미설치` | 도구 없음 | `sudo ./scripts/install_tools.sh <카테고리>` |
| `hybrid 사용 불가` | LLM 백엔드 미준비 | `assassin --setup-llm` 으로 한 번에 연결(§8). LLM 없이도 동작 |
| `API 키가 올바르지 않습니다` | 키 복사 누락·만료 | 콘솔에서 키 재발급 후 `assassin --setup-llm` → "다른 키로 바꿀까요? y" |
| `연결 실패 — 'ollama serve' …` | Ollama 서버 꺼짐·주소 다름 | 다른 터미널에서 `ollama serve`, 원격이면 `OLLAMA_HOST=http://<IP>:11434` |
| 라우팅에 `차단: strong(...)` / `최근오류: ...` | LLM 백엔드가 반복 오류로 차단됨(간헐 400 등) | 괄호 안 메시지가 원인(모델·파라미터·빈 content 등). 전체 메시지를 확인해 대응. Ollama 를 함께 띄우면 폴백으로 세션은 계속 진행 |
| `키 파일 권한이 넓습니다` | credentials 파일을 다른 사용자가 읽을 수 있음 | `chmod 600 ~/.config/assassin/credentials` |
| 매번 원치 않는 LLM 이 붙음 | 마법사가 저장한 기본 설정 | 한 번만 끄기 `--llm none`, 영구는 `~/.config/assassin/config.json` 의 `llm.backend` 를 `none` 으로 |
| CVE 정보가 비어 있음 | 오프라인·`--no-enrich`·캐시 없음 | 온라인에서 1회 실행해 캐시 생성 |
| `공유 시드 동기화 실패` | 오프라인·차단·저장소 비공개 | 무시해도 됨(기존 시드로 동작). 즉시 재시도는 `assassin --kb-sync` |
| `✗ seed-x.md — 로컬 수정본(미커밋) 보존` | 내가 편집 중인 시드 | 의도된 동작. 커밋하거나 되돌리면 다음 동기화부터 반영 |
| 주간 워크플로가 PR 단계에서 실패 | Actions 권한 미설정 | §9.5 저장소 설정 확인 |
| `함께 쓸 수 없는 단독 명령` / `타겟 없이 단독으로 실행` | `--learn`·`--promote`·`--doctor` 등 단독 명령을 둘 이상 또는 타겟과 같이 지정 | 하나씩, 타겟 없이 실행 |
| `'…' 가 출력 경로로 읽혔습니다` | `--html 10.129.1.5` 처럼 타겟이 출력 옵션 뒤에 옴 | 타겟을 맨 앞에: `assassin 10.129.1.5 --html` |
| 프롬프트에서 멈춘 것 같음 | 사람 확인 대기(`[y=실행 / 엔터=건너뛰기]`) | `y` 실행 / 엔터 건너뜀. 무인 실행은 `--auto` |

더 자세한 운영 가이드: [OPERATIONS.md](OPERATIONS.md)

---

## 18. 유지보수자용

### 18.1 테스트

```bash
cd htb-agent
python3 tests/run_all.py                          # 전체 스위트(네트워크·도구 없이)
python3 tests/test_kb_sync.py                     # 개별 스위트
python3 -m py_compile src/htb_agent/*.py src/htb_agent/*/*.py
python3 scripts/gen_cli_docs.py --check           # README CLI 표가 최신인지
```

### 18.2 CI

| 워크플로 | 트리거 | 내용 |
|---|---|---|
| `htb-agent CI` | `htb-agent/**` push/PR | Python 3.10~3.13 테스트 + 컴파일 + README CLI 표 최신 여부 + ruff·mypy(모두 게이트, 버전 고정) |
| `KB 자동 승격` | 매주 월 03:17 KST · 수동 | §9.5 |

CI 가 강제하는 지식 불변식:
- 모든 주제에 시드가 있고 필수 섹션·권위 출처를 갖춘다.
- 커밋된 승격분은 관문을 통과하고, 출처가 카탈로그에 있으며, 주제당 3건 이하다.
- 커밋된 시드는 모두 로컬 동기화 검증을 통과한다.

### 18.3 학습 출처(카탈로그) 바꾸기

1. `src/htb_agent/learn.py` 의 `SOURCES` 에서 주제의 `(제목, URL)` 을 수정한다. 허용 도메인은 `ALLOWED_DOMAINS`.
2. `assassin --learn <주제>` → `assassin --promote <주제>` → `git diff` 로 확인한다.
3. 커밋 → PR. 빠진 출처의 옛 승격분은 promote 가 정리한다.

### 18.4 CLI 옵션을 추가했다면

```bash
python3 scripts/gen_cli_docs.py                   # README 의 전체 CLI 옵션 표 재생성
```

---

## 19. 파일 위치 지도

| 경로 | 내용 |
|---|---|
| `htb-agent/src/htb_agent/main.py` | CLI 진입점 |
| `.../scope_guard.py` · `command_validator.py` · `approval.py` | 3관문(범위·검증·승인) |
| `.../orchestrator.py` | 단계 순서 실행·스윕·병렬 열거 |
| `.../knowledge.py` | 지식베이스 로드·RAG |
| `.../learn.py` · `promote.py` · `kb_sync.py` | 학습 · 승격 · 로컬 자동 동기화 |
| `htb-agent/knowledge/` | 규칙·취약점·노트·시드 |
| `htb-agent/config/` | 설정 예시 |
| `htb-agent/scripts/` | 도구 설치 · 데모 · CLI 문서 생성 |
| `htb-agent/docs/` | 이 문서 · [ARCHITECTURE.md](ARCHITECTURE.md) · [OPERATIONS.md](OPERATIONS.md) |
| `.github/workflows/` | CI · 주간 자동 승격 |

전체 CLI 옵션 표(자동 생성): [README.md#전체-cli-옵션](../README.md#전체-cli-옵션)
