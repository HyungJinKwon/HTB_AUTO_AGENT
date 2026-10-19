# 격차 분석 — 참고 구현 → 무개입 자동화

기준일 2026-10-03. 대회 종료 2026-10-23 21:00 (**20일**), 히든문제 공개 10-21.
인원 2명. 설계 목표 난이도는 **Hard 가정**(Active Machine 은 난이도 혼재이나,
Hard 를 기준으로 잡아 손해 볼 것이 없다).

출처 구분: 〔확인〕 = 이 저장소에서 실행·측정함 / 〔추정〕 = 코드 근거 기반 판단.

---

## 0. 에이전트 룰셋 [2-1]~[2-5] 대응

| 룰 | 상태 | 근거(코드) |
|---|---|---|
| **2-1** 외부 라이트업 참고 금지 | 구조적 충족 | 웹/검색 도구가 **아예 없다**(가져올 수단 부재). LLM 시스템 프롬프트가 라이트업 인용 금지. 지식베이스는 로컬 `knowledge/` 뿐. 남은 것은 발표용 *증빙*(G6) |
| **2-2** 무한 루프 제한 | 충족 | phase 유한 진행 + `max_rounds`·`max_enum`·`max_llm`, 루프의 `total_timebox`·`refute_cap`·`max_retries` |
| **2-3** 명령어 사전 검증 | 충족 | `command_validator.validate` + `Gate`(검증→범위→승인 3관문). 우회 경로 없음 |
| **2-4** 출력 파싱·교차검증 | 충족 | `observation/parsers` + `verify.py`(증거 기반 판정, 도구의 success 출력 불신) |
| **2-5** 난이도별 모델 차등 | 충족(이번 커밋) | `tiering.py` — `tier_for`(단계·막힌정도 → 티어) + `HybridProvider`(로컬 기본, 어려운 호출만 외부 API). `--llm hybrid` |

〔확인〕 2-2·2-3·2-4 는 **이미 구현돼 있었다**(참고 구현에서 계승). 2-5 만
이번에 실제 라우팅을 채웠다 — 이전엔 티어 인프라만 있고 호출은 고정 티어였다.

---

## 1. 출발점 (`HyungJinKwon/Blog_Custom_Skin` @ `claude/zen-goldberg-yma7t2`)

〔확인〕 Kali(WSL, Python 3.13.12)에서 `python3 tests/run_all.py` → **22 스위트
359 passed, 0 failed**. src 4,439줄 / tests 1,614줄. CI 워크플로 존재.

재사용 가치가 높아 **이 저장소의 출발점으로 그대로 가져왔다**(재작성 아님):

| 계층 | 모듈 | 상태 |
|---|---|---|
| 안전 | `scope_guard` · `command_validator` · `approval` | 유지 — 대상 범위 강제는 그대로 필요 |
| 관측 | `observation/{parsers,web,smb,ad,net,summarize,compressor}` | 유지 — 파서 품질 양호 |
| 운영 | `state`(중단/재개) · `audit`(JSONL) · `creds` · `config` | 유지 — 재분석 루프의 기반 |
| 산출 | `writeup` (htb / tistory 13섹션) | 유지 — 대회 제출물 |
| 도구 | `tools/registry` + `scripts/install_tools.sh` | 유지 — 59개 도구 등록 |

---

## 2. 구멍 (대회 요구 = VPN·IP 만 주면 플래그까지)

### G1. 익스플로잇 실행이 설계상 제외 — **해결 (orchestrator 배선 완료)**

〔이력〕 원래 `vuln.py` 는 *"탐지 + 수동 제안으로만 제시, 자동 실행하지 않는다"*
였다 — CVE 를 찾아도 `searchsploit ...` 문자열을 출력하고 끝났고, `user.txt` 는
사람이 `--cred` 로 자격증명을 넣어줘야 도달했다. 이 수비적 자기제한을 제거했다
(HTB 는 승인된 CTF 이고 scope_guard 가 단일 타깃에 바인딩돼 있다). **범위 밖
타격과 파괴 명령 차단(scope_guard·command_validator)은 유지** — 이건 자기제한이
아니라 인가 경계이고, HTB 머신을 브릭하면 리셋 대기로 오히려 손해다.

〔확인〕 하드코딩 CVE 는 7건 — vsftpd 2.3.4 / Apache 2.4.49 / Samba
is_known_pipename / Heartbleed / EternalBlue / OpenSSH 유저열거. 전형적인 Easy
레퍼토리이며 Hard 에는 거의 쓰이지 않는다.

→ 탐지와 실행 사이의 단계(선택 → 준비 → 실행 → 검증 → 가설 전환)가 통째로
없었다. `verify.py` + `exploit_loop.py` 로 그 단계를 채웠다.

〔확인〕 `tests/test_verify.py` 22 + `tests/test_exploit_loop.py` 41 passed.
전체 **26 스위트 458 passed, 0 failed**.

- `verify.py` — 증거 기반 판정. **익스플로잇 자신의 출력으로 `confirmed` 를
  낼 수 있는 경로는 플래그 하나뿐**이고, 나머지는 전부 독립 probe 를 거친다.
  셸은 난수 토큰 왕복으로만 인정한다(프롬프트 모양 금지).
- `exploit_loop.py` — ①~⑥. `expected` 를 기계가 읽는 규약
  (`shell:` / `probe:…::…` / `flag:`)으로 고정해, **검증 불가능한 후보는
  실행 전에 탈락**시킨다. 전제조건 미충족은 원장에 남기지 않고 보류 과제로
  돌린다(반증 아님). 후보 생성원은 주입식이라 KB/CVE/LLM 기여를 따로 잴 수 있다.

구현 중 실제로 잡은 결함 2건 — 기록해 둔다:
- **범위 봉쇄를 승인자가 뒤집을 수 있었다.** `inspect_command` 는 범위 밖을
  `needs_confirmation` 으로 돌려줄 뿐 예외를 던지지 않는다. 승인자가 주입식인
  무개입 루프에서는 느슨한 승인자 하나로 봉쇄가 뚫린다. → `Gate` 가 범위를
  **승인자보다 먼저** 막는다. 승인자는 더 조이는 것만 가능하다.
- **같은 후보가 한 라운드에 두 번 실행됐다.** 생성원과 재시도 큐에서 동시에
  올라와 `inconclusive` 재시도 상한이 절반 속도로 타버렸다. → 라운드 내 hid 중복 제거.

〔확인〕 **orchestrator 배선 완료** (`tests/test_exploit_wiring.py` 23 passed,
전체 28 스위트 509 passed). `access`·`privesc`·`lateral` phase 가 열거로 관측을
쌓은 뒤, 그 위에서 `ExploitLoop` 를 돌린다(공유 `Ledger` 로 Foothold 가 단계
간 이어진다). root 플래그 확보 시 조기 종료.

후보 생성원은 **기존 도구를 고르는** 방식이다(새 익스플로잇을 짜지 않음):
- `generators.make_llm_generator` — LLM 이 관측·CVE·죽은 가설을 보고 searchsploit·
  msfconsole·nuclei·hydra·netexec·impacket·evil-winrm 등 **이미 설치된 도구**를
  `expected` 와 함께 제안. `LLMRouter.suggest_candidates` 가 `CMD … ||| expected`
  를 파싱, 규약 밖은 버린다. 막힐수록(라운드↑) 티어 상승(G2-5 연계).
- `generators.make_flag_generator` — 셸 Foothold 나 자격증명이 생기면 기존 도구로
  user.txt/root.txt 를 읽는 결정적 후보. LLM 없이도 동작.
- `vuln.py` 매칭은 종착점에서 **LLM 컨텍스트**로 격하 — "서비스→CVE→기존도구".

→ 남은 것: 실제 HTB 머신 실행(아직 0회), 셸 획득 후 중첩 세션 검증, privesc 열거
도구(linpeas 등 G4). 자동승인은 `--auto`(scope 기반), 기본은 대화형 승인.

### G2. 지속 셸·세션 부재 — **해결됨 (이번 커밋)**

〔확인〕 `tools/runner.py` 의 `SubprocessRunner` 는 one-shot
`subprocess.run(shell=False, timeout=120)`. 결과: `cd`·환경변수 소실, 파이프·
리다이렉트·`&&`·`$()` 전부 불가, pty 없어 `nc`·`ssh`·`evil-winrm`·`gdb` 상호작용
불가, 120초 넘는 `nmap -p-`·크래킹·퍼징 전부 중단.

→ `tools/session.py` `ShellSession` 추가. `Runner` 프로토콜을 만족해
**orchestrator 무수정 교체**. `--runner session` 이 기본값이고, pexpect/pty 가
없으면 oneshot 으로 자동 강하.

〔확인〕 `tests/test_session.py` **28 passed**. 전체 **23 스위트 387 passed, 0 failed**.
측정으로 확인한 동작: `cd`/env 유지, 파이프·리다이렉트·`&&`·명령치환, 종료코드
회수, 타임아웃→Ctrl-C→재동기화 후 세션 재사용, 백그라운드 작업(긴 스캔 중 다른
명령 동시 진행), 대화형 stdin 전달, 셸 사망 시 자동 교체.

구현 중 실제로 잡은 결함 2건 — 기록해 둔다:
- **Ctrl-C 가 터미널 입력 큐를 함께 비운다.** 미리 큐에 넣어둔 종료 마커가
  유실돼 타임아웃 복구가 영구 실패했다. → 복구 시 **새 마커로** 재동기화.
- **`exit` 한 줄로 지속 셸이 죽는다.** 무개입 운용에서는 런 전체 손실.
  → EOF 시 셸 자동 교체(`respawns` 카운트), 단 작업디렉토리·환경변수가
  초기화된 사실을 호출측에 **숨기지 않고 보고**.

### G3. 지식베이스가 사실상 빈 상태 — **해결 (KB 채움)**

〔이력〕 원래 `knowledge/rules/` 1개(9줄)뿐, KB 기여가 0 → 사실상 LLM 단독이었다.

〔확인〕 `knowledge/rules/*.json` 6개 파일로 확장 — 전체 룰 **16→58건**. 표준
방법론(라이트업 아님, SEED_RULES 와 동일 성격): 서비스 열거(MSSQL·MySQL·SNMP·
NFS·RPC·DNS·SMTP·Redis·RDP), 웹(ffuf·nikto·wpscan·sqlmap·LFI), AD(RID브루트·
AS-REP·Kerberoast·LDAP덤프·certipy), privesc, lateral. `notes/methodology.md`
추가. 룰은 enum 라운드 자동실행 + 익스플로잇 루프 LLM 컨텍스트 양쪽에 쓰인다.
`tests/test_knowledge_content.py` 17 passed 로 콘텐츠 회귀 보호.

단계별 커버리지(시드+사용자): enum linux 13 / win_ad 16, access 4 / 9,
privesc 8 / 9, lateral 2 / 5. 〔추정〕 품질은 실제 머신 측정 전까지 미검증.

### G4. 권한상승 열거 수단 없음 — **부분 해결 (KB 경유)**

〔이력〕 원래 src 전체에 `linpeas`/`winpeas`/`pspy` 참조 0건이었다.

〔확인〕 `privesc-linux.json`·`privesc-windows.json` 에 linpeas/winPEAS/pspy/
PowerUp/accesschk + 설정오류 점검(sudo·SUID·capabilities·cron·토큰권한·서비스·
AlwaysInstallElevated·저장자격증명)을 KB 규칙으로 등록. privesc phase 에서
LLM 후보 생성 컨텍스트로 투입된다. 남은 것: 도구 전송·실행의 **중첩 세션**
검증(셸 획득 후 그 컨텍스트에서 돌리기) — 로컬 셸만 검증됨(G2 미검증 항목).

### G5. 승인 게이트가 기본 전제 — 부분 해결

〔확인〕 `--auto` 는 scope 기반 자동승인이라 범위 내에서는 사람 없이 돈다.
남은 문제는 승인이 아니라 **판단 루프**: 실패했을 때 가설을 바꾸고 다음 수를
고르는 주체가 없다. G1 과 같은 작업.

### G6. Writeup 미참조가 "원칙" 문장뿐 — 미해결, 대회 필수

〔확인〕 `docs/ARCHITECTURE.md` 5절 "외부 검색 없음"이 전부. 대회 규칙은 1등이
**어떤 조치를 취했는지 발표에서 설명**할 것을 요구한다. 증빙 가능한 메커니즘이
필요하다. → `docs/NO-WRITEUP-POLICY.md` 에 설계만 작성, 구현 미완.

---

## 3. 우선순위 (2명 20일)

| 순위 | 항목 | 근거 |
|---|---|---|
| 1 | **G1** 익스플로잇 실행 루프 | 이게 없으면 Hard 는 0문제. 작업량 최대 |
| 2 | **G4** privesc 열거 + G3 KB 채우기 | Hard 의 실제 병목. 둘이 같은 작업 |
| 3 | **G6** 미참조 증빙 | 대회 필수 제출물. 작업량 작음 → 빨리 끝내 둘 것 |
| 4 | 평가 하네스 | 아래 참조 |

### 평가 하네스를 먼저 만들 것

속도가 평가 기준인데 **측정 수단이 없다**. 같은 모델·같은 시간 예산에서
기준선(`--runner oneshot` + LLM 단독)을 먼저 재고, 거기에 지식 계층 → 세션 →
익스플로잇 루프를 하나씩 얹어 각 단계의 기여를 분리 측정해야 한다. 그러지 않으면
무엇이 도움이 됐는지 알 수 없고, 발표에서 설명할 근거도 없다.

측정 항목: 플래그 도달률 · user.txt/root.txt 까지 경과시간 · 토큰·비용 ·
사람 개입 횟수(목표 0) · 막힌 지점 분류.

### 미검증으로 남은 것 — 과장하지 않기 위해 명시

- 실제 HTB 머신 대상 실행을 **한 번도 하지 않았다**. VPN 미연결(`tun0` 없음).
- `ShellSession` 은 로컬 Kali 셸에서만 검증했다. 리버스 셸·`evil-winrm` 경유
  중첩 세션은 미검증.
- 백그라운드 `bg_kill` 은 자식 프로세스까지 확실히 정리하지 않는다
  (`session.py` 의 `ponytail:` 주석 참조).
- 히든문제(10-21)가 어떤 성격인지 모른다. 그 전까지의 측정은 전부 대리지표다.
