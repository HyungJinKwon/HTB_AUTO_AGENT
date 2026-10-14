# ASSASSIN — 승인제 자동 풀이 에이전트 (HTB · Dreamhack · CTF)

```
▄▀█ █▀ █▀ ▄▀█ █▀ █▀ █ █▄░█
█▀█ ▄█ ▄█ █▀█ ▄█ ▄█ █ █░▀█
```

레드팀 학습·모의해킹·CTF 연습용. **권한이 확인된 대상에 한정**해 동작하는 승인제
(Human-in-the-loop) 자동 풀이 보조 에이전트. **명령은 `assassin`**(`htb-agent` 는 하위호환 별칭).

> ⚠️ **대상 범위**: 대회/플랫폼이 명시한 권한 확인 대상만. 그 외 자산 사용 금지(Scope Guard 가
> 코드로 강제). 실제 공격 실행은 사용자 Kali 환경에서. 터미널 UI 는 블루/네이비 팔레트
> (비-TTY·파이프·`NO_COLOR` 에서는 색 자동 비활성 → 로그/CI 안전).

### ⚡ 모드 한눈에 (자주 쓰는 명령)

| 상황 | 명령 |
|---|---|
| 처음 써 보기(위험한 것만 확인) | `assassin 10.129.1.5` |
| 모든 명령 보며 배우기 | `assassin 10.129.1.5 --manual` |
| 해커톤(최대 자율+시간제한) | `assassin 10.129.1.5 --autonomous --time-budget 45 --writeup --html` |
| 샌드박스에서 실제 익스까지 | `assassin 10.129.1.5 --autonomous --sandbox docker --llm hybrid` |
| 🚀 완전 자동 루트 시도(발판·플래그까지) | `assassin 10.129.1.5 --full-auto --llm claude --html --json` |
| CTF/Dreamhack 문제 | `assassin chall.host:1337 --platform ctf --category web` |

> `--full-auto` = `--autonomous + --exploit-exec + --auto-poc + --catch-revshell`(가능하면 egress
> 샌드박스 자동 선택). **실제 익스플로잇·PoC 발사·리버스셸 수신**을 수행하는 **명시적 옵트인**
> 이다(기본은 생성 전용). 권한이 확인된 대상 전용. 자세히는 [docs/USAGE.md §10](docs/USAGE.md).

### 📚 문서 안내 (역할 분담 — 중복 없이 링크)

| 문서 | 역할 |
|---|---|
| **[docs/QUICKSTART.md](docs/QUICKSTART.md)** | 1쪽 빠른 시작(설치·상황별 한 줄·화면 읽는 법) — **처음이라면 여기부터** |
| **[docs/USAGE.md](docs/USAGE.md)** | 유일 종합 매뉴얼(설치·모드·플랫폼·지식·발판 실행·산출물·설정·전체 옵션) |
| **[docs/OPERATIONS.md](docs/OPERATIONS.md)** | Kali 실전 운영 + **트러블슈팅**(막혔을 때 여기) |
| **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** | 구조·파이프라인·모듈 지도·설계 결정(ADR) |
| **[docs/VALIDATION.md](docs/VALIDATION.md)** | 실제 Kali 수용 테스트 런북(단계별 기대 결과·체크리스트) |
| [docs/RESEARCH.md](docs/RESEARCH.md) · [CHANGELOG.md](CHANGELOG.md) | 연구 근거 대응표 · 변경 이력 |

**플랫폼 프로파일** `--platform {htb,dreamhack,ctf}`:
- `htb`(기본): HTB VPN 대역 강제 · boot2root(user.txt/root.txt, 32-hex/HTB{})
- `dreamhack` / `ctf`: 챌린지 단일 타겟(host:port/URL) 바인딩 · Jeopardy 단일 플래그
  (DH{}/flag{}/CTF{} 등 `TAG{}` 자동 인식, `--flag-prefix` 로 추가)

---

## 진행 흐름 (모의해킹 단계 순서)

```
타겟 바인딩 → 정찰(RECON) → 식별(Linux/Win-AD) → 열거 → 초기 침투(user.txt)
          → 권한 상승(root.txt) → 측면 이동 → 취약점(CVE/CWE) → 리포트/라이트업
```

모든 실행 명령은 **① 검증 → ② 범위 → ③ 승인** 3관문을 통과해야 실행된다. 범위 안이라도
**동적·원격 코드 실행**(파이프→셸, `eval`, `IEX` 등)은 자동실행하지 않고 사람 검토로 넘긴다
(`--auto`/`--autonomous` 에선 수동 제안으로 강등). 취약점(CVE/CWE)은 단계마다 반영되어 다음
단계 판단에 바로 쓰이고, 목표(Jeopardy=플래그 1개, HTB=user+root)를 대상 상호작용 출력에서
확보하면 남은 단계는 `생략(목표 달성)` 으로 조기 종료한다. 단계·라운드·명령 수에 상한이 있어
무한루프가 없다. 구조·다이어그램·모듈 지도는 **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

---

## 설치 (요약)

최신 Kali·Ubuntu 는 **PEP 668** 로 시스템 `pip install` 이 막히므로 **venv + 심링크**로 설치한다.

```bash
# git clone 은 '기본(default) 브랜치'(현재: main)를 자동 체크아웃한다 — 완성본이 여기 병합된다.
# 브랜치명을 손으로 지정하지 말 것(특히 claude/* 작업 브랜치는 체크아웃 금지).
git clone https://github.com/HyungJinKwon/HTB_AUTO_AGENT.git ~/HTB_AUTO_AGENT
cd ~/HTB_AUTO_AGENT/htb-agent
sudo ./scripts/install_tools.sh            # 보안 도구 일괄 설치
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[claude,exploit]"        # 에이전트 + Claude + 익스 실행 의존성(requests)
assassin --doctor                          # 환경 점검(도구·VPN·LLM)
```

> **전체 설치 절차**(심링크로 어디서나 실행·bash/zsh·LLM 연결 마법사)는
> **[docs/QUICKSTART.md §1](docs/QUICKSTART.md)** 또는 **[docs/USAGE.md §2](docs/USAGE.md)**.
> Python 3.10+ (코어는 표준 라이브러리만). 규칙 기반·로컬 Ollama 만 쓰면 `pip install -e .` 로 충분.
> 최신화는 `git pull --ff-only`(기본 브랜치 그대로). `claude/*` 작업 브랜치는 CI·리뷰 중 강제동기될
> 수 있으니 로컬 실행용으로 체크아웃하지 말 것 — 최신 릴리스는 항상 기본 브랜치에 병합된다.

---

## 핵심 특징

| 분류 | 내용 |
|---|---|
| 안전 | Target-Binding 범위강제 · 명령 검증(문법·base64·해시·포트·파괴명령) · 승인 게이트(스마트/auto/manual) · **능동적 완전자동(`--autonomous`)** · 신뢰불가 출처 인젝션 차단 |
| 관측 | nmap·HTTP(쿠키·보안헤더·로그인폼·CMS)·gobuster/ffuf/feroxbuster/nikto/whatweb·smb·ldap·dns/snmp 파싱 · **vhost/도메인 자동 이름해석**(범위 자동 등록 + 권한 있으면 `/etc/hosts` 자동 기입) |
| 식별 | Linux vs Windows-AD 증거기반 판정(확신도) · 플랫폼 프로파일(HTB/Dreamhack/CTF) |
| 지능 | 지식베이스(사용자 학습·자가학습으로 성장, 경량 RAG) · 단계 순서 오케스트레이터 · **월드 모델(구조화 상태 단일 상태원)** · **웹앱 핑거프린트(제품/버전 식별→`searchsploit` 자동 치환)** · 반복·재진입 스윕 · 옵션 조합 변형 + 변형 학습 · 병렬 열거 · LLM(Claude/Ollama/**하이브리드**·다관점 분석가·JSON 출력 계약·적응형 tier) · 목표 달성 조기 종료 · 권위출처 자가학습(`--learn`) |
| 목표 | CVE/CWE 탐지·매핑 + **자동 수집(NVD)** · user.txt/root.txt·CTF 단일 플래그 · **🏁 SOLVED 결과 패널(플래그 값·출처 표시)** |
| 공격(기본 생성 전용) | **리버스쉘·AWS/S3·권한상승·해시크래킹 자동 준비**(`--revshell`/`--cloud`/`--privesc`/`--crack`) — 공격자 IP/호스트명/OS/해시 확보 시 자동 생성 · **옵트인 실행**: **발판 자동 실행(`--exploit-exec`)**·**PoC 자동 선택(`--auto-poc`)**·**내장 익스 모듈**(`--exploit-modules`, 수록 `CVE-2025-57819` FreePBX)로 공개 PoC 조달→웹셸→nc 리버스셸→user→privesc→root 자동(`--full-auto`) |
| 운영 | 중단/재개(Ctrl+C 저장) · **시간 예산(`--time-budget`)·비용 상한(`--max-cost`)** · 크리덴셜 볼트(해시 PtH) · 감사 로그 · 설정 파일 · **환경 자가진단(`--doctor`)** |
| 산출 | 라이트업 자동 생성(htb-ctf-writeup-v5 / Tistory 13섹션) · **결과 내보내기(JSON·HTML 대시보드)** · **실행 재생 뷰어(`--replay`)** |
| 평가 | **성능 측정(`--bench`/`--live-bench`)** — 성공률·pass@N·검증된 풀이율·시간·비용 |

원칙: 승인제 · **외부 라이트업 미참조(사용자 자료·권위 출처만)** · 무한루프 금지 ·
증거기반(〔확인〕/〔추정〕). 기능별 상세·예시·지식 성장 파이프라인은 **[docs/USAGE.md](docs/USAGE.md)**.

---

## 테스트

```bash
cd htb-agent && python3 tests/run_all.py     # 전체 스위트(끝에 '총 N 스위트 | N passed' 요약)
```

네트워크·도구 없이도 러너 주입으로 전 로직 검증. CI(GitHub Actions)가 push/PR 마다 파이썬
3.10~3.13 매트릭스로 테스트+컴파일+README CLI 옵션 표 최신 여부(게이트) + ruff/mypy(비차단) 수행.
버전 확인: `assassin --version`. 변경 이력: [CHANGELOG.md](CHANGELOG.md).

## 라이선스

[MIT](LICENSE) — 권한이 확인된 대상(HTB·CTF·인가된 진단)·교육·연구 목적에 한해 사용하세요.

## 한계 (과장 금지)

- 명령 검증은 "형식적 무오류 + 실행 가능 형태"까지 보장(도구별 옵션 의미·해시 정답은 미보장).
- OS/취약점 판정은 증거기반 확신도 — 약하면 `〔추정〕` 표기.
- 기본은 생성 전용. 실제 익스 실행은 옵트인(`--full-auto` 등)이며 **표준 상승 경로**가 있을 때만
  root 가 자동 성립한다(비표준 체인은 열거·제안으로 남김). LLM 비용은 추정치. 실제 공격·VPN 은 Kali 전용.

## 전체 CLI 옵션

<!-- CLI-OPTIONS:START (scripts/gen_cli_docs.py 가 자동 생성 — 직접 수정 금지) -->
| 옵션 | 설명 |
|---|---|
| `--help-all` | 고급·전문 포함 '모든' 옵션 보기 |
| `--version` | 버전 표시 |
| `--doctor` | 환경 자가진단(도구·LLM·VPN 점검, 스캔 안 함). 완전 초보자 권장 첫 실행 |
| `--install-missing` `CATS` | 빠진 보안 도구를 install_tools.sh 로 자동 설치(카테고리 지정 가능: 'recon web smb …'). 저장소의 공식 스크립트만 실행, 루트 필요 |
| `--setup-llm` | LLM 연결 마법사: Claude(API 키)·로컬 LLM(Ollama 모델)을 질문에 답하며 연결하고 실제 1회 호출로 확인 → 기본 설정 저장(이후 --llm 생략 가능). 키는 ~/.config/assassin 에 600 권한 |
| `--llm-test` | 환경 자가진단 + LLM 실제 호출 테스트(짧은 요청 1회 — 틀린 키·없는 모델·막힌 네트워크 확인) |
| `--revshell` `LHOST:LPORT` | 리버스쉘 페이로드 생성(실행 안 함). 'IP:PORT' 또는 'PORT'(공격자 IP 자동/--attacker-ip). 권한 확인 대상 전용 |
| `--learn` `TOPIC` | 권위 출처 자가학습(도구·공격기법·개념·프로토콜)을 지식베이스에 저장. 예: --learn kerberoasting / burp / http. 전체 일괄: --learn all. 목록: --learn list |
| `--promote` `TOPIC` | 로컬 학습 노트(learned-&lt;주제&gt;.md) 중 품질 관문을 통과한 항목을 번들 시드의 '최신 보강(승격)' 섹션으로 승격. 결과를 커밋·PR 하면 모든 사용자에게 공유. 예: --promote sqli / 전체: --promote all |
| `--list-sessions` | 저장된 세션(타겟) 목록 출력 — --resume 대상 확인용(타겟 없이 단독 실행) |
| `--kb-sync` | 공유 저장소의 최신 번들 시드를 지금 동기화(검증 통과분만 로컬 캐시에 적용). 타겟 실행 시에는 하루 1회 자동 |
| `--update` | 최신화 원클릭: 공유 시드 동기화 + 권위출처 재학습·승격(--offline 이면 네트워크 생략) |
| `--export-stats` `파일` | 실행 학습 통계(변형 성공률) 내보내기 — 성장 공유용(명령 전체·타겟·출력 미포함) |
| `--import-stats` `파일` | 공유된 실행 학습 통계를 로컬에 병합(성장 공유 — succ/att 합산) |
| `--no-kb-sync` | 실행 시 공유 시드 자동 동기화 끄기(환경변수 ASSASSIN_NO_KB_SYNC=1 도 동일) |
| `--ingest` `PATH` | 사용자 제공 자료(.md/.txt/.pdf 파일 또는 디렉터리)를 지식베이스 노트로 미리 학습. 예: --ingest ./my-writeups/ |
| `--cloud` `NAME` | AWS/S3 열거 자동 준비(생성 안 실행). 호스트명/도메인에서 버킷명 후보+비인증 점검 생성. 예: --cloud acme.htb. 권한 확인 자산 전용 |
| `--privesc` `OS` | 권한상승 플레이북 자동 준비(생성 안 실행). OS 별 열거·점검·LPE 체크리스트 생성. 예: --privesc linux. 획득한 대상 셸에서 직접 실행 |
| `--crack` `HASH` | 해시 크래킹 자동 준비(생성 안 실행). 해시 종류 식별 + john/hashcat 명령 생성. 예: --crack '$krb5tgs$23$...'. 권한 확인 자산 해시 전용 |
| `--list-exploits` | 내장 익스 모듈(공개 PoC 오케스트레이션) 목록 표시 — 자동 발사 대상 CVE·제품·취약버전·PoC 출처. --exploit-modules 로 로드한 사용자 모듈도 함께 표시 |
| `--bench` `SUITE` | 로컬 모의 문제로 풀이 성공률·명령 수·시간·비용 측정(오프라인, 실제 통신 없음). SUITE 생략 시 번들 문제 세트. --attempts N 으로 반복(pass@N), --llm 으로 LLM 비교 |
| `--attempts` `N` | --bench/--live-bench 에서 문제당 시도 횟수(기본 1) |
| `--live-bench` `DIR` | 실제 서비스(loopback 파이썬 / docker 컨테이너 / vm 외부·가상머신)를 띄우거나 붙어 진짜 도구로 풀이 — 성공률·검증된 풀이율·시간 측정. DIR 생략 시 bench/live. docker 타겟은 데몬 필요. --attempts·--llm 적용 |
| `--replay` `JSONL` | 감사 로그(JSONL)를 단계별 재생 HTML 로 변환(이전/다음/자동 재생). 예: --replay state/audit_10.129.1.5.jsonl → 같은 이름의 .html |
| `--platform` | 플랫폼 프로파일 (기본 htb). dreamhack/ctf=단일 타겟+flag{} 모드 |
| `--category` | Jeopardy 카테고리 힌트(web/pwn/rev/crypto/forensic/misc). CTF/Dreamhack 에서 LLM 제안을 카테고리에 맞게 유도 |
| `--flag-prefix` `PREFIX` | 우선 인식할 플래그 접두 (반복 가능, 예: --flag-prefix DH). 플랫폼 기본값에 추가 |
| `--range` `CIDR` | 허용 타겟 CIDR (반복 가능). 생략 시 플랫폼 기본(HTB만 대역 강제) |
| `--attacker-ip` `IP` | 공격자 VPN IP (반복 가능). 생략 시 tun0 자동탐지 |
| `--files` `PATH` | 챌린지 첨부파일/디렉터리(반복 가능, zip·tar 는 안전하게 풀어 둠). 작업공간 files/ 에 복사되어 LLM 이 소스를 읽고 분석. 포트가 없어도 파일 분석으로 진행 |
| `--lport` `PORT` | 리버스쉘 리스너 포트(자동 준비 페이로드용, 기본 4444) |
| `--cred` `USER:PASS` | 자격증명 'user:pass' / 'user:pass:domain' / 'user:pass:domain:nthash' (반복 가능). Pass-the-Hash 는 'user:&lt;32hex&gt;' 또는 'user::domain:&lt;NT\|LM:NT&gt;'. {user}/{pass}/{domain}/{hash} 제안을 실행 후보로 승격 |
| `--cred-file` `경로` | 자격증명 JSON 파일에서 일괄 로드(인라인 --cred 와 함께 사용 가능). 형식: {"username":..,"password":..,"domain":..,"nt_hash":..} 또는 그 목록 |
| `--config` | 설정 파일(.json/.yaml). 우선순위: CLI &gt; 설정파일 &gt; 기본값 |
| `--autonomous`, `--hackathon` | 능동적 완전자동 모드: 범위내 자동승인 + 깊은 재진입 스윕 + 병렬 열거 + 변형학습 + 전 자동준비. 목표(flag/root)까지 스스로 추진(안전 게이트 유지) |
| `--poc` `CMD` | 옵트인: searchsploit 결과에서 고른 '공개 PoC 한 줄'을 게이트로 실행(반복 가능). 권한 확인 대상 전용. 버전 대조 후 사용 |
| `--auto-poc` | ⭐ 버전매칭 1순위 PoC 실행계획을 자동으로 --poc 큐에 투입(권한 확인 대상 전용) |
| `--poc-dir` `DIR` | 내장 익스 모듈용 공개 PoC 디렉터리(선택, 기본 ~/.assassin/pocs). 받은 PoC 를 여기서 찾고, --fetch-pocs 로 자동 조달 시 여기로 받는다 |
| `--fetch-pocs` | 옵트인(--full-auto 가 자동 켬): 내장 익스 모듈이 매칭되고 로컬에 PoC 가 없으면 '레지스트리가 선언한 공개 출처'에서 자동 조달(git/searchsploit). 임의 URL 아님(주입 방지)·받기만 함(실행은 3관문). 인가 대상 전용 |
| `--exploit-modules` `FILE` | 사용자 익스 모듈 매니페스트(JSON). 코드 수정 없이 CVE 모듈(핑거프린트·취약버전·PoC 출처·실행템플릿·웹셸 파서)을 추가해 다른 CVE/머신에 적용 |
| `--sandbox` | 명령을 '어디서' 실행할지: none=로컬 셸 비경유(기본, 파이프 불가) · shell=로컬 bash(파이프 O, 네트워크 강제 X) · docker=Kali 컨테이너+egress 방화벽 · vm=SSH 로 접속한 가상머신/공격호스트. 스크립트 작성·동적 실행 자동은 egress 강제된 docker 또는 'vm --vm-confine' 에서만 |
| `--sandbox-image` `IMAGE` | docker 샌드박스 이미지(기본 assassin-sandbox:latest — scripts/build_sandbox.sh) |
| `--vm-ssh` `USER@HOST` | --sandbox vm: 명령을 실행할 VM 의 SSH 접속 대상(예: kali@192.168.56.10) |
| `--vm-ssh-key` `KEYFILE` | --sandbox vm: SSH 개인키 파일(미지정 시 ssh 기본·에이전트 사용) |
| `--vm-ssh-port` `PORT` | --sandbox vm: SSH 포트(기본 22) |
| `--vm-sudo` | --sandbox vm: VM 에서 egress 정책 적용 등에 sudo 사용(--vm-confine 과 함께) |
| `--vm-confine` | --sandbox vm: 접속한 VM 에 egress 방화벽(타겟 대역만)을 적용해 docker 처럼 완전자율 동적 실행을 자동 허용. 그 VM 네트워크를 타겟으로 제한하므로 전용 풀이 VM 에서만 |
| `--auto` | 완전 자동: 범위내+검증통과만 실행, 범위 밖은 조용히 건너뜀(무프롬프트) |
| `--manual` | 완전 수동: 모든 명령을 실행 전 확인(승인제 최대) |
| `--full-auto` | 🚀 한 플래그 완전 발사: --autonomous + --exploit-exec + --auto-poc + --catch-revshell 을 모두 켜고, 가능하면 egress 샌드박스를 자동 선택한다. ⚠️ 실제 익스플로잇·PoC 발사·리버스셸 수신을 수행 — 권한이 확인된 대상 전용. 범위 밖·파괴명령 게이트는 그대로 유지된다 |
| `--dry-run` | 계획 미리보기: 정찰·분석은 하되 제안된 명령은 '실행하지 않고' 보여만 준다(무해 점검) |
| `--exploit-exec` | 옵트인(기본 OFF): 확보한 평문 자격으로 SSH 접속해 플래그 읽기·권한상승 열거를 게이트를 거쳐 자동 실행(권한 확인 대상 전용) |
| `--catch-revshell` | 옵트인(기본 OFF): 웹 RCE 로 발판이 안 잡힐 때 리버스셸로 발판 잡기 — --exploit-exec 발판 단계에서 준비된 리버스셸 payload 의 콜백을 소켓 리스너로 수신해 발판 세션화(공격자 IP/포트 확보 시). 성립 검증 통과분만 인정. 소켓 수신은 RCE 실행 표면 — 권한 확인 대상 전용 |
| `--judge` | 옵트인(기본 OFF): 종료 시 LLM-심판이 '공략 달성' 주장이 증거로 뒷받침되는지 별도 채점(조언만 — 규칙 판정·목표 달성을 덮지 않음). LLM 필요 |
| `--gate-judge` | 옵트인(기본 OFF): 자동 모드에서 더 신중하게 — 자동승인될 명령을 LLM 심판이 ALLOW/ASK/DENY 로 재검토해 더 엄격하게만 조정(완화 불가·오류 시 기존 동작). LLM 필요 |
| `--max-restarts` `N` | 옵트인(기본 0=끔): 미처리 예외로 죽으면 저장 지점부터 --resume 로 최대 N회 자동 재시작(무인 완주 보조). 사용자 중단은 제외 |
| `--htb-machine-id` `ID` | HTB 머신 ID(--htb-spawn/--submit-flags 에 필요) — 머신 페이지 URL 끝 숫자 |
| `--htb-spawn` | 옵트인: 실행 전 HTB 머신 스폰(vm/spawn). HTB_TOKEN env + --htb-machine-id 필요 |
| `--submit-flags` | 옵트인: 공략으로 획득한 플래그를 HTB 에 자동 제출(machine/own). HTB_TOKEN env + --htb-machine-id 필요(권한 확인 자산 한정 §4) |
| `--htb-difficulty` `N` | 플래그 제출 시 난이도 투표(10~100, 기본 30) |
| `--no-enrich` | CVE/CWE 자동 수집(NVD/GitHub) 비활성 |
| `--learn-gaps` | 자율 지식 획득: 풀이 중 모르는 기술을 권위 출처에서 자동 학습해 KB 에 즉시 반영(allowlist·P1 유지). autonomous 모드에선 기본 활성 |
| `--no-learn-gaps` | 자율 지식 획득 비활성(autonomous 모드에서도 끔) |
| `--web-learn` | 인터넷 검색 학습: 카탈로그 밖 '미해석 공백'을 웹 검색으로 학습해 KB 반영(--learn-gaps 를 함께 켬). HTB 라이트업(공식·제3자)은 가드로 차단. autonomous 기본 활성 |
| `--no-web-learn` | 인터넷 검색 학습 비활성(autonomous 모드에서도 끔) |
| `--offline` | 오프라인: 네트워크 수집 금지(캐시만 사용) |
| `--enrich-cache` | CVE 캐시 디렉토리 (기본 &lt;knowledge&gt;/cve_cache) |
| `--max-attempts` | 포트스캔 폴백 최대 시도 (기본 4, 무한루프 방지) |
| `--max-enum` | enum 자동실행 최대 개수 (기본 6, 무한확장 방지) |
| `--max-llm` | LLM 제안 명령 최대 개수 (기본 5, 자율모드 8) |
| `--max-rounds` | ENUM/LLM 반복 라운드 수 (기본 2, 무한루프 방지) |
| `--max-sweeps` | 단계 재진입 스윕 수 (기본 2). 새 관측·크리덴셜로 이전 단계 재시도. 상태 정체 시 조기종료(유한) |
| `--max-parallel` | 열거 명령 동시 실행 수 (기본 1=순차). 독립 명령의 I/O 만 병렬 — 게이트·결과처리는 순차로 안전 |
| `--variants` | 명령당 옵션 조합 변형 수 (기본 2, 1=변형끔). 경우의 수 시도 |
| `--time-budget` `분` | 해커톤 시간 예산(분). 마감이 되면 진행 중 단계를 마치고 남은 단계를 생략한 뒤 상태를 저장한다(--resume 으로 이어감). 기본: 무제한 |
| `--max-cost` `USD` | LLM 누적 추정 비용 상한(달러). 넘으면 LLM 호출을 멈추고 규칙 기반으로 계속 진행한다. 기본: 무제한 |
| `--observe` | 사람 관찰 입력: 건너뛴(미승인) 명령 대신 브라우저 등으로 직접 확인한 내용을 적어 기록에 반영한다('사람 관찰'로 표시, 에이전트 검증 결과와 구분). 대화형 실행용 |
| `--knowledge` | 지식베이스 디렉토리 (기본 ./knowledge). 사용자 규칙/노트로 성장 |
| `--llm` | LLM 두뇌 백엔드 (기본 none=규칙기반). claude=API, ollama=로컬, hybrid=둘을 단계 난이도로 라우팅+폴백·연속 오류 백엔드 차단·라우팅 집계 |
| `--llm-tier` | LLM 기본 티어(기본 standard). 명령 생성은 단계별 티어 우선(열거=cheap·침투=standard·권한상승/측면=strong), 저확신 시 자동 승격 |
| `--state-dir` | 세션 상태 저장 디렉토리 (기본 ./state) |
| `--resume` | 저장된 상태에서 재개 (RECON 재사용 · 실행된 명령·결과·플래그 복원, 다시 실행 안 함). Ctrl+C 로 중단한 세션도 이어감 |
| `--no-save` | 상태 저장 안 함 |
| `--log-file` | 감사 로그(JSONL) 경로. 생략 시 &lt;state-dir&gt;/audit_&lt;타겟&gt;.jsonl |
| `--no-audit` | 감사 로그 비활성 |
| `--writeup` | 풀이 라이트업 Markdown 생성(경로 생략 시 writeup_&lt;타겟&gt;.md) |
| `--writeup-format` | 라이트업 형식: htb(기본, htb-ctf-writeup-v5) / tistory(13섹션) |
| `--json` | 결과를 기계판독 JSON 으로 내보내기(경로 생략 시 &lt;state-dir&gt;/report_&lt;타겟&gt;.json) |
| `--html` | 결과를 HTML 대시보드로 내보내기(블루/네이비, 경로 생략 시 &lt;state-dir&gt;/report_&lt;타겟&gt;.html) |
<!-- CLI-OPTIONS:END -->
