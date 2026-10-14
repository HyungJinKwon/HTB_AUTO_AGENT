# 변경 이력

형식: 추가(Added) · 변경(Changed) · 수정(Fixed) · 안전(Safety). 버전은 [SemVer](https://semver.org/lang/ko/)를 따릅니다.

## [2.39.11] — 2026-10-14

발판 캡처 실패의 '진짜' 원인 수정 — 요약기가 PoC 성공 URL 줄을 삭제하고 있었다(실측 기반).

### 수정(Fixed)
- **요약기 200자 트렁케이트가 PoC 웹셸 URL 줄을 삭제 → 발판 미성립(실 머신 재현)**: 실 머신
  실행에서 watchTowr PoC 가 `-u`·urllib3 자가치유로 정상 실행되고 HTTPS 요청(verify=False)까지
  진행했으나, 발판이 또 안 섰다. 원인은 PoC 가 아니라 **우리 출력 요약기**였다.
  `summarize_tool_output` 은 매칭 파서가 없는 출력(= PoC 처럼 `python3` 로 돈 스크립트)에
  200자 트렁케이트 폴백을 걸었고, PoC 의 **긴 ASCII 배너(>200자) 뒤에 늦게 출력되는**
  `[+] VULNERABLE - webshell found: <url>` 줄이 통째로 잘려 나갔다. 그런데 발판 URL 캡처
  (`_run_one_poc`)는 그 '요약본(`f.output`)'에서 URL 을 찾고 있어, URL 은 분명히 출력됐는데도
  (요약 전에) 사라져 캡처 실패 → `rce_url` 미설정 → 발판 미성립 → user 플래그 미수집.
  - **발판 캡처·자격수확·의존성 파싱을 원본(`raw_output`, 20000자)에서 수행**: 요약본이 아니라
    원본에서 뽑도록 `_run_one_poc` 를 수정(핑거프린트·searchsploit 가 이미 쓰던 `raw_output`
    우선 원칙과 동일). 긴 배너 뒤 늦은 URL 도 놓치지 않는다.
  - **스크립트/PoC 출력 표시 요약 개선**: 인터프리터(python/ruby/php/perl/sh/bash)로 돈 출력은
    200자 트렁케이트 대신 '신호 줄'(웹셸 URL·성립/실패 판정·예외)을 보존하도록 `_summarize_script`
    추가 — 사람이 리포트에서 '배너만' 보고 결과를 놓치지 않게 한다(캡처 경로와 독립한 표시용).

### 추가(Added)
- **`test_e2e_slow_poc_capture` 보강**: 배너를 일부러 **200자 초과**로 만들어 요약 트렁케이트를
  '진짜로' 재현하고, ① 캡처가 요약이 아닌 `raw_output` 에서 이뤄지는지 ② 표시 요약도 결과
  줄(URL)을 보존하는지 회귀 가드를 추가(실 ShellRunner + 기록 러너 양쪽).

### 배경
- 직전(2.39.10)의 `-u`·`run_timeout` 수정은 '늦게 나오는 출력의 버퍼·타임아웃 유실'을 막았지만,
  실 머신 로그를 받아 보니 '요약기가 결과 줄을 삭제'하는 별개의 손실 지점이 하나 더 있었다. 이
  릴리스로 캡처 경로가 요약 손실과 완전히 분리된다("배너만 보고 끊김"의 마지막 기계적 원인 제거).

## [2.39.10] — 2026-10-14

폴링형 PoC '배너만 보고 끊김' 수정 — 실 머신에서 user 플래그를 못 찾던 실패의 기계적 원인 제거.

### 수정(Fixed)
- **폴링형 PoC 의 '늦은' 웹셸 URL 유실 → 발판 미성립**: watchTowr FreePBX CVE-2025-57819 PoC 는
  배너를 먼저 찍고, SQLi 로 cron 을 주입한 뒤 **웹셸이 떨어질 때까지 최대 120s 폴링**하다가 성공 시
  드롭된 웹셸 URL(랜덤 접미사라 추측 불가)을 **늦게** 출력한다. 이를 두 원인으로 놓쳐 '배너만' 보고
  발판이 안 섰다 — ① 러너 기본 실행 상한(180s)이 폴링+주입+폴백+정리를 못 버팀 ② `python3` 를
  `-u` 없이 띄워 파이프 연결 시 stdout 이 **블록버퍼링**되어 늦은 성공 URL 줄이 (중단·버퍼에) 유실.
  - **`-u`(unbuffered) 강제**: 내장/자동 모듈의 python 호출을 `python3 -u {poc} …` 로 띄워 늦은
    출력 줄도 안전히 캡처. (실 watchTowr CLI `-H <base-url>` 는 공개 소스 argparse 로 검증 반영.)
  - **모듈별 `run_timeout`**: `ExploitModule.run_timeout`(초, 0=기본 180s)을 추가하고 PoC 실행에
    플럼(`_run_one_poc`→`_attempt(timeout=)`→`_safe_run`→러너). CVE-2025-57819 은 `run_timeout=300`.

### 추가(Added)
- **`test_e2e_slow_poc_capture`(신규)**: 가짜 주입이 아닌 '실 서브프로세스' 검증 — ① 모듈 `run_timeout`
  (300)이 러너 실행 상한까지 실제로 플럼되는지 ② '배너 → 지연 → 늦은 웹셸 URL' 을 내는 **진짜 PoC
  를 진짜 ShellRunner 로** 돌려 늦은 URL 이 버퍼 유실 없이 캡처돼 `rce_url`(발판)이 서는지 검증.
  표준 라이브러리만 사용 → 기본 test CI 매트릭스에서 함께 돈다(실 머신 실패 경로 재발 방지).

### 배경
- 직전(2.39.8/2.39.9)은 PoC 의존성 자가치유와 '실 HTTP 발판 e2e' 를 고정했으나, PoC '실행 캡처'
  자체(늦게 나오는 성공 URL)를 실 프로세스로 검증하진 않았다. 이 릴리스는 그 마지막 실 경로를 닫아
  "PoC 가 돌긴 하는데 배너만 보고 발판이 안 서는" 실 머신 실패를 기계적으로 제거하고 CI 로 고정한다.

## [2.39.9] — 2026-10-14

실 end-to-end 검증 상설화 — '가짜 주입 단위 테스트'가 놓친 실 경로를 CI 로 고정(재발 방지).

### 추가(Added)
- **`test_e2e_real_foothold`(신규)**: fake 주입이 아닌 '진짜' end-to-end — 실 HTTP 웹셸을
  loopback 에 띄우고, **실 `requests`(web_http_fn) → WebRceSession → 발판 성립 검증(실 id/uname)
  → flag_read.read_flags 로 user 플래그 실 읽기**까지 돌린다. 실 pip 경로(`_pip_install`/
  `ensure_module`/`missing_module`)도 주입 없이 검증. requests 미설치(코어 전용)면 그 블록만 skip.
- **CI 잡 `foothold-e2e`**: `pip install -e ".[exploit]"` 로 requests 를 깔고 위 실 발판 e2e 를
  매 push/PR 에 실행한다. urllib3/requests 미설치로 발판이 조용히 degrade 되던 사고를 '단위
  테스트는 통과하는데 실제론 실패'로 다시 못 빠지게 CI 가 실 경로를 강제한다.

### 배경
- 직전(2.39.8) 자가치유는 단위 테스트(주입)만으로 검증됐고, '실 requests HTTP 왕복'은 한 번도
  실행되지 않았다. 이 릴리스는 그 실 경로를 상설 테스트+CI 로 고정해 "만들고 병합 후 실제론 미작동"
  의 반복을 구조적으로 차단한다.

## [2.39.8] — 2026-10-14

완전 자동 보강 — PoC 런타임 의존성을 에이전트가 스스로 갖춘다(수동 pip 제거).

### 추가(Added)
- **PoC 의존성 자가치유(`poc_fetch.ensure_module`/`ensure_common_deps`)**: 실제 머신 풀이에서
  조달한 공개 PoC(예: watchTowr FreePBX CVE-2025-57819)가 `urllib3`/`requests` 미설치로
  `ModuleNotFoundError` 를 내며 죽어 발판이 안 서던 문제를 자동화로 해소. 옵트인(`--full-auto`/
  `--fetch-pocs`) + 네트워크 허용 시: (1) 익스 실행 단계 진입에 공용 의존성(requests·urllib3)을
  현재 venv 에 선제 설치, (2) PoC 가 `No module named X` 로 실패하면 **그 모듈을 자동 설치하고
  PoC 를 1회 재실행**(`_run_one_poc`). 설치는 `sys.executable`(현 venv) 한정·전역 비간섭, 모듈명
  엄격 검증(인자 주입 차단)·표준 라이브러리 제외, `ASSASSIN_NO_NET=1` 이면 생략. 사용자가 수동
  `pip install` 을 하지 않아도 완전 자동 익스 체인이 성립한다.

### 변경(Changed)
- 설치 문서(README·QUICKSTART·USAGE)의 권장 설치를 `pip install -e ".[claude,exploit]"` 로
  통일(익스 실행 의존성 requests 포함) — 완전 자동 사용 시 1줄로 끝나게.

### 테스트(Tests)
- `test_poc_fetch`(+12): 빠진 모듈명 파싱·stdlib 제외·점분리 축약·ensure_module 게이팅(기존/주입/
  인자주입차단/NO_NET)·`_run_one_poc` 의존성 부족→자동설치→재실행→웹셸 URL 캡처.

## [2.39.7] — 2026-10-14

라이브 벤치 결정성 완결 — 실 curl loopback 체크의 잔여 플래키 제거.

### 수정(Fixed)
- **`test_livebench` 실 curl 체크(web-source-comment·web-header-leak) 플래키 제거**: 공유 컨테이너
  부하에서 loopback 서비스 기동/응답 타이밍 변동으로 간헐 실패하던 두 체크를, net-banner(nc)와
  동일하게 **1회 재시도 후에도 미성립이면 skip**(환경 변동 명시)으로 처리. v2.39.3 에서 nc 만
  안정화하고 curl 두 건을 단일 시도로 남겨둔 누락을 메움. 규칙 기반 풀이 로직은 다른 결정적
  테스트가 커버하며, 여기선 실 curl 왕복 가능 여부만 확인한다. 전체 스위트가 환경에 무관하게
  `0 failed`(pass-or-skip)로 수렴.

## [2.39.6] — 2026-10-14

CI `lint` 게이트(mypy) 적색 해소 — 타입 애노테이션만, 런타임 무변경.

### 수정(Fixed)
- **mypy 게이트 통과(0건)**: CI 의 `mypy src/ --ignore-missing-imports`(차단 게이트)가 7건으로
  실패하던 것을 교정. (1) `foothold.py` FootholdMixin 의 TYPE_CHECKING 스텁에 `_goal_reached`·
  `_time_up`(합성 대상 Orchestrator 제공 메서드)을 선언해 `_privesc_loop` 등 애노테이트 본문의
  `attr-defined` 제거. (2) `orchestrator.py` `_active_exploit_module` 를 `"ExploitModule | None"`
  로 명시(초기 `None` 추론이 모듈 대입과 충돌하던 `assignment` 오류 제거). 테스트·실행 경로 불변.
- (품질) 로컬 최종 점검에 `mypy src/` 를 ruff 와 함께 상시 포함하도록 운영 체크리스트 보강
  (이번 적색의 근인 = 로컬에서 mypy 미실행).

## [2.39.5] — 2026-10-14

문서 전면 정리 — 연속 수정으로 흩어진 마크다운을 "한 주제=한 문서(SSOT)" 구조로 재배치.

### 변경(Changed)
- **문서 역할 분리(중복 제거→링크)**: README=현관(소개·모드표·문서지도·요약 설치·핵심특징·한계,
  469→217행), QUICKSTART=1쪽 빠른 시작, USAGE=유일 종합 매뉴얼, OPERATIONS=실전 운영+트러블슈팅,
  ARCHITECTURE=구조·모듈 지도. 설치·실행·모드·산출물 중복 설명을 걷어내고 SSOT 로 링크.
- **CLI 옵션 표 생성기**: `scripts/gen_cli_docs.py` 가 `build_parser(full=True)` 로 전체 옵션을
  렌더(고급 옵션 help 가 비full 에서 SUPPRESS 되던 문제 제거).

### 수정(Fixed)
- **README CLI 옵션 표 stale(CI 게이트 RED) 교정**: 누락돼 있던 `--list-exploits`·`--poc-dir`·
  `--fetch-pocs`·`--exploit-modules`·`--help-all` 포함해 재생성(89행, `--check` 통과).
- **ARCHITECTURE 모듈 지도 누락 보강**: `exploit_modules.py`·`poc_fetch.py`·`foothold.py` 3개
  모듈과 내장 익스 모듈(CVE-2025-57819)·PoC 런타임 조달·revshell listener-first 를 반영.
- **`--list-exploits` 문서화**(USAGE §10.4): 출시됐으나 전 문서에 없던 단독 도구를 기재.
- **매뉴얼 누락 보강(USAGE)**: README 트림으로 prose 가 사라졌던 `--files`(챌린지 첨부, §6.3)·
  `--live-bench`(실서비스 라이브 측정, §14.5)와, 그간 CLI 표에만 있던 옵트인 플래그
  (`--judge`·`--gate-judge`·`--max-restarts`·`--htb-spawn`·`--submit-flags`, 신설 §10.5)를 종합
  매뉴얼에 기재 — 모든 핵심/옵트인 플래그가 표뿐 아니라 설명을 갖도록.
- **문서 정직성**: OPERATIONS 안전 요약이 "탐지+수동 제안까지만"으로 `--full-auto`(옵트인 실제
  실행)와 모순되던 것, QUICKSTART 안전 경계 서술을 "기본 생성 전용 + 옵트인 실행"으로 정정.
- 깨진/부정확 교차링크 정리(QUICKSTART 트러블슈팅·full-auto 섹션 참조).

### 제거(Removed)
- **`RELEASE-v2.5.1.md` 삭제**: 현재(2.39.x)보다 34 마이너 뒤처진 고아 릴리스 노트. 릴리스 기록은
  `CHANGELOG.md` 로 일원화.

## [2.39.4] — 2026-10-14

최종 마감 적대적 검토(full-auto 체인 end-to-end 추적)에서 찾은 실 결함 2건 교정 + 문서 정합.

### 수정(Fixed)
- **리버스셸 채널 모듈의 콜백 유실(경쟁) 제거 [MED]**: `channel="revshell"` 내장/매니페스트 모듈은
  PoC 자체가 리버스셸을 트리거한다. 기존 흐름은 `_exploit_run_stage` 에서 트리거를 먼저 쏘고
  리스너는 `_acquire_session`(발판 단계)에서야 떠, 콜백이 '아직 열리지 않은/이미 닫힌' 포트로 가
  유실되고 리스너는 오지 않을 콜백을 최대 120s 대기했다. 이제 트리거 발사 '전에' 리스너를
  백그라운드로 **선기동(listener-first)** 하고(`_start_revshell_prelisten`), 수신분을 보관했다가
  `_acquire_session` 이 성립검증 후 소비한다(`_consume_prelistened_revshell`). 웹→리버스셸 업그레이드
  경로와 동일한 패턴. `channel="web"`(내장 FreePBX 등)·`catch_revshell` OFF 엔 무영향.
- **캡처된 웹셸 URL 이 핑거프린트 없을 때 유실되던 문제 [LOW]**: `_acquire_session` 이 웹 RCE 분기를
  `web_product` 가 있을 때만 탔다. 수동 `--poc` 로 핑거프린트 없이 웹셸만 드롭된 경우 캡처한
  `rce_url` 이 쓰이지 못하고 리버스셸 분기로 건너뛰었다. 이제 `rce_url` 이 잡혔으면 `web_product`
  없이도 웹 RCE 분기로 진입한다.

### 문서(Docs)
- `--live` 데모 단계 수 6→7(성능 측정 누락분, VALIDATION.md 와 정합). USAGE §10.4 에 revshell 채널
  모듈의 listener-first 보장 명시.

### 테스트(Tests)
- `test_foothold_prelisten`(신규 11): 선기동 listener-first·콜백 보관·성립검증 소비·헛발판 폐기·
  web 채널/OFF 무영향·rce_url 분기. 전체 144 스위트 무회귀.

## [2.39.3] — 2026-10-14

라이브 벤치 플래키 안정화 — 전체 스위트 결정성 확보.

### 수정(Fixed)
- **`test_livebench` net-banner(실 nc TCP 상호작용) 플래키 제거**: 공유 컨테이너 부하에서
  실제 nc TCP 왕복의 타이밍 변동이 커 간헐 실패하던 `net-banner-flag` 체크를, 1회 재시도 후에도
  미성립이면 '허위 통과' 대신 `skip`(환경 변동 명시)으로 처리. 규칙 기반 nc 풀이 로직 자체는 다른
  결정적 테스트가 커버하며, 여기서는 실 nc 왕복 가능 여부만 확인한다. 전체 스위트가 환경에
  무관하게 `0 failed` 로 수렴.

## [2.39.2] — 2026-10-14

최종 마감 — 전수 검증(전체 ruff·버전 정합·전체 스위트)에서 발견한 누락 1건 교정.

### 추가(Added)
- **`--list-exploits` 단독 도구**: 내장/사용자(`--exploit-modules`) 익스 모듈 목록(자동 발사 대상
  CVE·제품·취약버전·PoC 출처)을 타겟 없이 표시. 지금까지 코드 주석/docstring 에서만 참조되고 CLI
  에 없던 'dangling reference' 를 실제 명령으로 구현해 닫음.

### 테스트(Tests)
- `test_cli_consistency`(+3: --list-exploits rc 0·CVE 표시·안내). 전체 143 스위트 무회귀.

## [2.39.1] — 2026-10-14

자동화·논리 흐름 적대적 검토(2 리뷰 에이전트)에서 찾은 실제 결함 수정.

### 수정(Fixed)
- **[HIGH] SSH 발판 GTFOBins 상승이 대화형 `.plan` 을 발사해 상승을 확인 못 하던 死경로 교정**:
  `_exploit_exec_stage` 가 비대화형 `v.oneshot()` 으로 실행하도록 변경(`_privesc_loop` 과 동일 규칙).
  SSH 채널(`sshpass ssh "<cmd>"`)에서 `sudo -i`·`find -exec /bin/sh \;` 같은 대화형 escape 는
  EOF 로 죽어 뒤의 `id` 가 원 유저로 돌던 문제.
- **[HIGH] 자동 CVE 모듈의 전역 레지스트리 누수 제거**: `_auto_module_from_cve` 가 전역 `_RUNTIME`
  에 등록하지 않고 세션 로컬(`_active_exploit_module`)로만 쓴다 — 단일 프로세스 다중 타겟(livebench
  배치)에서 A 의 PoC 가 B 로 누수·오염되던 문제 차단. 사용자 매니페스트 모듈만 전역 영속.
- **[MED] 자동 발사 루프가 one-shot 없는 대화형 전용 고신뢰 벡터(less·nano·vi 등)를 제외**:
  두 루프 모두 `confidence=="high" and v.oneshot("id")` 로 필터 → 프레이밍 채널에서 상승 불가·tty
  블록·top-3 슬롯 낭비 방지(해당 벡터는 제안에는 그대로 유지).
- **[MED] 발판 세션 degrade 가 `RuntimeError`(닫힌 세션)도 흡수**: `_foothold_stage`·`_privesc_loop`
  의 예외를 `(OSError, RuntimeError)` 로 넓혀 이후 생성/준비 스테이지가 계속 돌게 보장.
- **[MED] 비기본 러너에서 `searchsploit -m` 조달물 미탐지 교정**: `find_local_poc` 탐색에 러너
  작업디렉터리(`workspace.root`)를 추가.
- **[LOW] `module_for_cve` 미지 언어 interp/호출 일치**(`sh {poc}`) · **`parse_foothold_url` 꼬리
  문장부호·다중 URL 과포획 제거** · **탐지-CVE 필터 `re.fullmatch`**.

### 테스트(Tests)
- `test_exploit_modules`(+2 URL 트림) · `test_privesc_analyze`(+2 one-shot 필터 정합). 기존 스위트 무회귀.

## [2.39.0] — 2026-10-14

**탐지 → 자동 모듈 등록 → 익스** 루프를 닫았다. 매니페스트를 손으로 편집하지 않아도, 탐지된 CVE 를
로컬 exploit-db 로 해석해 런타임 익스 모듈을 자동 등록하고 기존 조달·발사·캡처 체인에 태운다.

### 추가(Added)
- **탐지 CVE → 런타임 모듈 자동 등록(`_auto_module_from_cve` + `exploit_modules.module_for_cve`)**:
  내장/매니페스트에 매칭이 없을 때, `report.detected_cve`/`discovered_cve`/`vuln_matches` 의 CVE 를
  `searchsploit --cve <id>` 로 해석해 exploit-db PoC(EDB-ID)가 있으면 **런타임 ExploitModule 을
  자동 등록**하고 `_consider_builtin_exploit` 의 조달(`searchsploit -m`)·발사·웹셸 캡처 체인을 그대로
  탄다. 사람이 `--exploit-modules` 를 편집할 필요 없이 '탐지 결과 기반 자동 추가'.

### 안전(Safety)
- 자동 등록 모듈의 PoC 출처는 **로컬 exploit-db 뿐**이다 — 임의/LLM/타겟 URL 을 쓰지 않는다(공급망
  안전, 출처 비창작). 실행은 기존 3관문·`--exploit-exec`/`--auto-poc` 옵트인·스코프 게이트 하.
  exploit-db 에 없는 CVE 는 자동 등록되지 않는다(매니페스트/내장 모듈로 보강).

### 테스트(Tests)
- `test_builtin_exploit_wiring`(+2: 탐지 CVE→EDB 자동 모듈 / 미해석 시 무등록). 주입형 lookup(실행 없음).

## [2.38.0] — 2026-10-14

자동 커버리지를 '발판 캡처 범위'와 '표준 권한상승 벡터' 양쪽으로 넓혔다(신종 익스 창작·임의 PoC
자동실행·커널 자동발사는 안전·정직성상 자동화하지 않고 제안 품질로 보강).

### 추가(Added)
- **발판 캡처 범위 확장(`parse_foothold_url`)**: `.php` 외 `.jsp/.jspx/.asp/.aspx/.cfm/.cgi/.pl`
  웹셸과, 확장자 없이 'Webshell:/shell at/RCE at/uploaded to/endpoint <url>' 식으로 지목하는
  PoC 출력까지 캡처 → 더 많은 공개 PoC 에서 웹 RCE 발판 자동 포착.
- **비-GTFOBins 표준 privesc 벡터(`analyze_extra`)**: docker/lxd 그룹·NFS no_root_squash·
  sudo env_keep LD_PRELOAD·writable /etc/passwd 탐지. **docker 그룹**은 조건 충족 시 `_privesc_loop`
  에서 **자동 발사**(호스트 / 마운트 chroot → root.txt), 나머지는 **정확한 실행 단계를 고신뢰
  제안**(자동 발사 안 함)으로 surface. PRIVESC_ENUM 에 NFS/writable-passwd 신호 수집 추가.
- **벡터 권한 직독**: 상승 벡터 성공 시 그 벡터의 root 권한 one-shot 으로도 root.txt 를 직독(해당
  벡터로만 읽히는 경우 — docker chroot 등) 캡처.

### 안전(Safety)
- 넓힌 것은 **"공개 PoC 로 서는 발판"과 "표준·스크립트형 권한상승"**뿐이다. 자동 발사는 신뢰도
  높은 벡터(GTFOBins·자격재사용·docker)에 한하고, 파괴적/환경의존 벡터(writable passwd·LD_PRELOAD·
  NFS·lxd)·커널 LPE·DB UDF 는 **자동 발사하지 않고 제안**으로 남긴다. 임의 인터넷 PoC 자동실행·
  신종 익스 창작은 하지 않는다(공급망·정직성). 전부 옵트인·스코프 게이트·인가 대상 전용.

### 테스트(Tests)
- `test_exploit_modules`(+5 캡처) · `test_privesc_analyze`(+8 analyze_extra) · `test_privesc_loop`(+3 docker).

## [2.37.1] — 2026-10-14

세밀 검토 후속 — 비차단 관찰 2건을 반영.

### 추가(Added)
- **SSH 발판에도 `sudo -S` 자격 재사용(`_exploit_exec_stage`)**: 웹/리버스셸 발판(`_privesc_loop`)에만
  있던 자격 재사용 root 경로를 SSH 발판에도 GTFOBins 벡터 루프 '앞'에 추가(대칭). 평문 비번을
  `sudo -S` 로 넣어 전체권한 sudo → `uid=0` → `/root/root.txt`(기존 root.txt 읽기와 동일하게
  `_attempt` 게이트 경유). `--full-auto`(auto_poc) 하에서 자동.

### 변경(Changed)
- **리버스셸 업그레이드 전용 짧은 수신 타임아웃**: 웹 발판 성공 후 `--catch-revshell` 업그레이드
  콜백 대기를 기본 120s 대신 ~25s(`_revshell_upgrade_timeout`)로 단축 — user 플래그는 이미
  확보돼 있으므로 콜백이 없으면 빠르게 웹 세션으로 복귀(기본 리버스셸 발판의 120s 와 구분).
  실제 catcher 에만 timeout 을 전달하고, 주입형 2-인자 catcher 는 TypeError 폴백으로 호환.

### 테스트(Tests)
- `test_exploit_exec_stage`(+3: SSH sudo -S 자격재사용 → root). `test_revshell_upgrade` 무회귀.

## [2.37.0] — 2026-10-13

루트 플래그 자동화의 '표준 경로' 커버리지를 넓히고, 옵션이 많아 헷갈리던 CLI 도움말을 2단으로 정리했다.

### 추가(Added)
- **자격 재사용 자동 root(`_privesc_loop`)**: 수확한 평문 비번을 `sudo -S`(stdin 비번)로 넣어
  전체권한 sudo 를 자동 시도 → `uid=0` 확인 시 `/root/root.txt` 직독. `su` 와 달리 TTY 없이
  파이프 비번이 동작해 비대화형 발판 세션에서 신뢰도가 높다(매우 흔한 HTB 경로). NT 해시는 제외.
- **GTFOBins 벡터 대폭 확장(`privesc_analyze`)**: php·node·lua·gdb·make·taskset·nice·stdbuf·
  timeout·flock·setarch·xargs·busybox·dash·ash·zsh·ksh·cpulimit·ed·rvim·crontab·ssh 등 sudo/SUID
  상승 벡터와 비대화형 one-shot 추가 → 표준 privesc 자동 커버리지 확대.
- **CLI 도움말 2단 구성**: 기본 `assassin -h` 는 자주 쓰는 ~20개만, 고급·전문 전체는 `--help-all`.
  옵션 자체·파싱·동작은 전부 그대로(표시만 정리). epilog 를 '이 5개면 거의 다 됩니다'로 갱신.

### 안전(Safety)
- 자동 root 확대는 **표준 상승 경로(sudo/SUID/capability·자격 재사용)**에 한한다. 비표준 체인
  (DB UDF·커널 LPE 등)은 여전히 자동 발사하지 않고 열거·제안으로 남긴다(정직성 §3). 모든 상승은
  **이미 획득한 셸** 위에서, 옵트인·스코프 게이트 하에서만. sudo -S 시도는 비번당 1회·최대 5개로 제한.

### 테스트(Tests)
- `test_privesc_loop`(+4: sudo -S 자격재사용·NT 해시 제외) · `test_beginner_ux`(2단 도움말) 갱신.

## [2.36.0] — 2026-10-13

내장 익스 체인의 **마지막 수동 단계(공개 PoC git clone)를 제거**하고, CVE 모듈을 **데이터로
확장**할 수 있게 해 다른 CVE/머신에도 적용되게 했다. 플래그 자동 탐색도 비표준 위치까지 넓혔다.

### 추가(Added)
- **공개 PoC 자동 조달(`poc_fetch.py`, 옵트인 `--fetch-pocs` — `--full-auto` 가 자동 켬)**:
  내장 모듈이 매칭되고 로컬에 PoC 가 없으면 **레지스트리가 선언한 공개 출처에서만** 자동 조달한다
  (`git clone --depth 1` / `searchsploit -m`). 수동 git clone 단계가 사라졌다.
- **사용자 확장 레지스트리(`exploit_modules.load_manifest`, `--exploit-modules FILE`)**: JSON
  매니페스트로 **코드 수정 없이** 다른 CVE/머신용 모듈(핑거프린트·취약버전·PoC 출처·실행
  템플릿·웹셸 파서)을 추가한다. `match`/`known` 이 내장+사용자 모듈을 함께 조회.
- **플래그 자동 탐색 강화(`flag_read`)**: user/root 직접 경로에서 못 찾으면 깊이 제한(`-maxdepth`)
  바운디드 `find` 폴백으로 비표준 위치(`/var/www`·`/srv`·커스텀 홈 등)까지 커버. CTF single 도 동일.

### 안전(Safety)
- 조달 출처는 **레지스트리/매니페스트가 선언한 값만** 쓴다 — LLM·타겟 응답·자유입력 URL 을
  clone 하지 않는다(주입 표면 없음). 받기만 하고 **실행은 기존 3관문**. `ASSASSIN_NO_NET=1` 이면
  실 네트워크 조달 차단. 받은 공개 제3자 코드의 신뢰 가정은 운영자 책임(문서화). 전부 옵트인·
  스코프 게이트·인가 대상 전용. 플래그 find 폴백은 깊이 제한으로 전체 디스크 스캔을 피한다.

### 테스트(Tests)
- `test_poc_fetch`(8) · `test_exploit_manifest`(9) 추가 · `test_flag_read`(+3). 전부 실 네트워크 없이 검증.

## [2.35.0] — 2026-10-13

`--full-auto` 가 **핑거프린트 → 공개 익스 실행 → 웹셸 캡처 → nc 리버스셸 수신 → user 플래그 → privesc** 까지 손 안 대고 잇도록 발판 체인을 완성했다. exploit-db 에 없는 최신 CVE(예: 2025)도 내장 모듈로 자동화하되, 무기화 코드는 레포에 심지 않고 공개 PoC 를 런타임에 조달·오케스트레이션한다.

### 추가(Added)
- **내장 익스 모듈 레지스트리(`exploit_modules.py`)**: CVE별 (핑거프린트 매칭·취약버전
  범위·공개 PoC 조달 방법·실행 인자 템플릿·출력→웹셸 URL 파서) 메타데이터. 시드로
  **CVE-2025-57819**(FreePBX < 16.0.89 pre-auth RCE) 등록. searchsploit 가 못 찾는 신규
  CVE 의 자동화 공백을 메운다. `--poc-dir` 로 선조달 PoC 디렉터리 지정.
- **PoC 출력→웹셸 URL 캡처(`exploit_run.harvest_foothold`)**: PoC 가 드롭한 웹셸 URL 을
  파싱해 `rce_url`+cmd 스펙(param/method/inject)으로 세팅 → `_acquire_web_rce` 가 그 채널로
  발판을 세운다. 발판이 서면 user 플래그 읽기가 자동으로 따라온다.
- **내장 모듈 자동 조달·큐잉(`_consider_builtin_exploit`)**: 매칭 시 게이트-세이프하게 PoC 를
  조달(로컬/`searchsploit -m`)해 실행 큐에 투입. 외부 git 는 자동 clone 하지 않고 1회 수동
  조달 안내만(스코프 게이트 보존).
- **웹 RCE → 리버스셸 자동 업그레이드(`_maybe_upgrade_revshell`)**: nc 리스너를 백그라운드로
  띄우고 웹셸로 리버스셸 payload 를 쏴 콜백을 수신(오늘의 `nc -lvnp 4444` 수동 과정 자동화).
  성립 시 더 안정적인 리버스셸로 승격, 실패 시 웹 세션 유지(무손실).
- **privesc 폐루프 일반화(`_privesc_loop`)**: SSH 전용이던 열거→HIGH 벡터 랭킹→one-shot
  상승→uid=0→root.txt 폐루프를 웹셸/리버스셸 발판 세션에도 적용.

### 안전(Safety)
- 전부 **기본 OFF·명시적 옵트인**(`--full-auto`, 개별 `--exploit-exec`/`--auto-poc`/
  `--catch-revshell`). 스코프 게이트(인가 대상 전용)·3관문·감사로그는 모든 경로에서 그대로.
  내장 모듈은 **무기화된 익스 코드를 레포에 벤더링하지 않고** 공개 PoC 를 런타임 조달한다
  (대량 악용 표면 비생성). 실행은 '이미 획득한 셸' 또는 게이트를 거친 PoC 호출로만.
- 생성 전용 기본값은 유지하되, 옵트인 시 실제 익스 체인을 자동 실행한다(인가/CTF 대상 §4).

### 테스트(Tests)
- `test_exploit_modules`(21) · `test_foothold_capture`(9) · `test_builtin_exploit_wiring`(11) ·
  `test_revshell_upgrade`(14) · `test_privesc_loop`(9) 추가. 전부 실 네트워크/소켓 없이 주입으로 검증.

## [2.34.1] — 2026-10-13

### 문서(Docs) — `--full-auto` 문서 동기화
2.33 에서 추가한 `--full-auto` 번들이 README 에만 반영되고 QUICKSTART·USAGE 의
'완전 자동 루트 한 줄' 예시는 구형 4-플래그 콤보로 남아 있던 불일치를 교정.
세 문서 모두 `--full-auto`(= `--autonomous`+`--exploit-exec`+`--auto-poc`+`--catch-revshell`,
샌드박스 자동선택) 한 줄로 통일하고, "`--autonomous` 단독은 실제 발사 안 함(인지된 옵트인)"
설명을 함께 명시. 코드 변경 없음(문서 전용).

## [2.34.0] — 2026-10-13

### 수정(Fixed) — 논리적 흐름 최종 점검: 리버스셸 발판 순서 버그
전체 파이프라인 흐름·누락 정밀 검토에서 확인된 **순서(ordering) 버그** 교정.
- **리버스셸 수신 발판이 구조적으로 무력화되던 문제(MED)**: `run()` 에서 발판 단계
  (`_foothold_stage`, PHASE 3.9 직전)가 `report.revshell_lhost` 를 읽는데, 그 값의
  **유일한 writer** 인 `_prepare_revshells`(PHASE 3.9)가 발판 **뒤에** 실행됐다. 그래서
  발판 시점엔 lhost 가 항상 "" → `_acquire_reverse_shell` 의 가드가 매번 발동해
  `--catch-revshell` 리스너가 **한 번도 뜨지 못했다**(웹 RCE 가 아닌 리버스셸 콜백이
  발판 벡터인 전형적 경로가 막힘). `_prepare_revshells` 를 발판 **이전**으로 이동해 교정
  (생성 전용이라 먼저 돌아도 부작용 없음). 회귀 테스트로 run() 순서 불변식 고정
  (기존 테스트는 report 를 미리 채워 호출해 이 순서를 못 잡았음).

### 참고(Known limitations) — 정직성(§3), 이번 릴리스에서 변경 없음
- 웹 RCE 발판 엔드포인트(`foothold._acquire_web_rce`)는 현재 FreePBX 참조머신 기준
  (`/admin/config.php`)이며 PoC 가 RCE 를 얻은 실제 엔드포인트로 자동 배선되지는 않는다
  (`rce_url` 은 테스트에서만 설정). 일반 머신의 웹 RCE 발판은 PoC 출력·SSH 경로가 보완.
- 소비 스테이지 멱등 가드(`_version_probed` 등)는 영속되지 않아 `--resume` 시 읽기 전용
  프로브가 1회 재발행된다(무해·생성 전용, 재공격 아님).

## [2.33.0] — 2026-10-13

### 추가(Added) — 게이트 유지하 최대 자동화
승인 모델(범위 밖·파괴명령·생성 전용 경계)은 그대로 두고, "안전한데 불필요하게 사람을
멈춰 세우던/수동이던" 지점을 자동화.
- **`--full-auto`(신규)**: `--autonomous + --exploit-exec + --auto-poc + --catch-revshell` 을
  한 플래그로 켜고 가능하면 샌드박스를 자동 선택하는 '완전 발사' 번들. ⚠️ 실제 익스·PoC 발사·
  리버스셸 수신(권한 확인 대상 전용). **일반 `--autonomous` 에는 발사를 묻지 않는다** — 익스
  발사 옵트인은 이 명시적 플래그로만 켜 '인지된 옵트인'(생성 전용 경계)을 보존.
- **자율 샌드박스 자동선택**: `--autonomous` 에서 사용자가 샌드박스를 명시하지 않았고 docker
  데몬이 떠 있으며 이미지가 **이미 빌드돼** 있으면 egress 강제 docker 샌드박스를 자동 선택
  (동적·스크립트 실행이 무중단 자동화). 컨테이너 방화벽이 egress 를 타겟 대역으로 강제하므로
  '더 격리'되는 방향 — 안전 완화 아님. 이미지가 없으면 빌드하지 않고 기존 경고만.
  신규 헬퍼 `sandbox.image_available`(이미지 존재 확인, 빌드 부작용 없음).
- **자율 도구 자동설치**: `--autonomous` 에서 빠진 보안 도구를 저장소 공식 스크립트로 자동 설치
  (전부 있으면 no-op, 스크립트 미발견·실패 시 비치명적 안내 후 진행) — '도구 미설치로 조용한
  건너뛰기'를 줄임.

### 추가(Added) — 회귀 테스트
`_expand_full_auto` 전개·경계 보존(autonomous 단독은 발사 OFF), `sandbox.image_available`
(rc0 True / rc1·예외 False) 고정.

## [2.32.0] — 2026-10-13

### 안전(Safety) — 4-에이전트 교차감사: 스코프 egress 경계 강화
독립 4-에이전트(정확성·안전경계·테스트문서·가독성) 재감사에서 **두 에이전트가 교차 확인**한
최상위 이슈 교정. 생성 전용 RCE·HTB_TOKEN 비로깅·3관문은 재검증 결과 무결.
- **vhost 자동등록 신뢰 경계(MED)**: 대상이 통제하는 리다이렉트 Location 의 **임의 외부
  도메인**을 `hosts_map` 에 타겟 IP 로 자동 등록하면 scope_guard 가 그 호스트를 TARGET 으로
  오분류해 **비스코프 egress 를 auto-allow** 하던 우회를 차단. HTB 랩 관례(`.htb`/`.local`)로만
  자동 등록하고 외부 도메인은 등록 거부 + 1회 수동 안내(`_maybe_register_vhost`).
- **curl `-L` 리다이렉트 egress 상한(MED)**: scope_guard 는 정적 명령 문자열만 보므로 런타임
  리다이렉트 호스트를 못 본다. 생성·교정 양쪽에서 `-L` 에 `--max-redirs 2` 를 동반해 악성
  리다이렉트 '체인'이 에이전트를 비스코프 호스트로 끌고 가지 못하게 상한(`orchestrator`·
  `results_verify`). 완전 격리는 여전히 egress-contained 샌드박스에서 보장.
- **라이브 lateral 빌더 인자 인젝션 방어(LOW-MED)**: 실제 파이프라인이 쓰는 `lateral.generate`
  의 네이티브 클라이언트(mysql/psql) 경로가 선행 `-` 수확값을 옵션으로 오인하던 것을 `_arg_safe`
  가드로 차단(2.31 에서 `cred_sources` 에만 있던 가드를 라이브 경로로 이식).

### 수정(Fixed)
- **NT 해시를 SSH 평문 비번으로 분사(LOW)**: `_exploit_exec_stage` 가 각괄호 없는 32-hex
  NT 해시를 SSH password 로 분사하던 것을 PtH 전용으로 건너뛰도록 교정(`foothold.py`,
  `_prepare_lateral` 과 동일 구분).
- **write-only 死상태 제거(LOW)**: `SessionState.detected_cve/detected_cwe` 는 `_persist` 가
  쓰기만 하고 `_restore` 가 읽지 않는(재개 시 재도출) 상태라 SSOT 오해를 유발 → 필드·쓰기 제거
  (`state.py`·`orchestrator.py`). 구버전 상태 JSON 과 호환(from_dict 가 미지 필드 무시).
- **문서 정직성**: `requirements.txt` 의 `ollama>=0.3` 주석이 pip 패키지 설치로 로컬 LLM 이
  켜진다는 오해를 주던 것을 정정 — 코드는 stdlib urllib 로 Ollama **서버** HTTP API 를 호출하며
  pip 패키지는 쓰지 않음(§3).

### 추가(Added) — 회귀 테스트
- 외부 도메인 리다이렉트 **미등록·미승인**(vhost 신뢰 경계), `-L` **--max-redirs 상한** 동반,
  비정수 `portid` **fail-closed skip**, lateral 선행 `-` 인자 인젝션 방어, NT 해시 SSH 분사 제외,
  F3 **persist-always**(`_run_vuln` 예외에도 상태 저장), `submittable_flags` 제출 루프 배선.

## [2.31.0] — 2026-10-12

### 수정(Fixed) — 최종본 전수 감사(5-에이전트) 교정 배치
전 코드·파일·문서 정밀 감사에서 확인된 결손·오류를 교정. 안전 경계(생성 전용 RCE·HTB_TOKEN
비로깅·3관문)는 감사 결과 **무결(intact)** 확인됨.
- **재개(resume) 상태원 결손**: `_maybe_register_vhost` 가 채우는 `hosts_map`/`_vhost_seen`,
  `world.learned`(학습 토픽), `world.access_level`(직접 상승분)이 영속되지 않아 `--resume` 후
  vhost-only 웹앱이 스코프 밖으로 퇴행하거나 권한레벨·학습이 초기화되던 문제 교정
  (`state.py` 3필드 추가 + `_persist`/`_restore` 왕복 배선). 회귀 테스트 추가.
- **플래그 과매칭(정직성)**: CSS/코드 `word{...}`(예: `header{display:none}`)가 익스 유래
  플래그로 기록되던 오탐을, 알려진 플래그 TAG·지정 접두·플래그 파일 맥락으로 한정해 차단
  (`flag.py`). 6개 검증 추가.
- **파서 내구성**: 변형된 nmap XML 의 `portid` 비정수 값에서 `int()` 미처리 예외로 전체
  파싱이 크래시하던 것을, 해당 포트만 건너뛰도록 fail-closed 가드 추가(`observation/parsers.py`).
- **지속 불변식(persist-always)**: 스윕 루프·최종 취약점 단계의 미처리 예외가 진행분 저장을
  건너뛸 수 있던 경로에 가드 추가(`orchestrator.py`).
- **인자 인젝션 심층 방어**: `lateral_candidates` 가 선행 `-` 자격값을 ssh 옵션으로 오인당하지
  않도록 제외 + `shlex.quote` 로 감쌈(`lateral.py` 와 일관, `cred_sources.py`). 회귀 추가.
- **발판 벡터 선택 오류**: `_exploit_exec_stage` 가 교정 재시도로 밀려난 `enum_findings[-1]`
  대신 해당 벡터의 결과를 정확히 참조하도록 수정(`foothold.py`).

### 수정(Fixed) — 문서·패키징 정직성/정확성
- README/USAGE 의 "웹 RCE 발판·측면이동 미배선" 서술이 실제 배선 상태(`--exploit-exec` 옵트인
  뒤 `run()` 에 배선·호출, 실행 의존 없으면 생성까지만 안전 degrade)와 어긋나던 것을 정정.
- `MANIFEST.in` 의 깨진 `include USAGE.md`(파일은 `docs/USAGE.md`) → 정정(sdist 누락 방지).
- `requirements.txt` 의 "사용 예정" 표현을 실제(선택적 기능 의존·미설치 시 안전 비활성)로 갱신.

### 수정(Fixed) — NIT
- `doctor.py`: Ollama 로드 실패 메시지도 `llm_setup.scrub` 적용(Claude 분기와 대칭).
- `report_export.py`: 지역변수 `html` 이 모듈 `import html` 를 가리던 섀도잉 제거.
- `main.py`: `--llm-test` 단독 충돌 오류가 `--doctor` 로 오귀속되던 라벨 정정.

## [2.30.0] — 2026-10-12

### 변경(Changed) — 가독성: `render_summary` 섹션 분해(동작 불변)
가독성 리뷰 권고(R1) 반영. 244줄 단일 함수 `report_view.render_summary` 를 형제 `report_export.
to_html`(섹션별 `_html_*` 위임)과 같은 구조로 분해 — 섹션별 `_view_*(report, ui) -> list[str]`
렌더러 20개로 나누고, `render_summary` 는 선언 순서대로 이어 붙이는 얇은 스파인으로 축소.
- REPETITION 분석(`_rr`)은 스파인에서 1회 계산해 REPETITION·NEXT OPTIONS 두 섹션이 공유(기존
  "반복 분석 1회만" 동작 보존).
- **동작 불변 보증**: 분해 전후 `render_summary` 출력이 **바이트 동일**함을 풍부한 리포트(모든 섹션
  채움) 골든 diff 로 검증. 섹션 로직이 독립 함수가 되어 개별 테스트·수정 가능(HTML 형제와 대칭).
- 신규 `test_report_view_sections.py`(20): 섹션 존재·순서·빈 리포트·`_view_*` 빈 목록 반환.
  전체 **134 스위트 | 2977 passed, 0 failed**.

## [2.29.0] — 2026-10-12

### 변경(Changed) — 최적화·안정화·가독성·초보자 친화 재검토(3-에이전트) 후속
3개 독립 리뷰 에이전트(최적화·안정화 / 가독성·구조 / 초보자 UX)가 전체를 교차검토. 대부분
이미 양호(핫패스 캐시·방어 가드·결정성·믹스인 분해·시작 가이드)로 확인됐고, 확정 개선만 반영.

#### 최적화(Perf)
- **`_run_vuln` 반복 전체 코퍼스 재스캔 제거**: 스윕당 6~10회+ 호출되며 매번 배너·스크립트·전
  finding 출력을 join + 정규식 스캔(CVE/CWE 추출·웹앱 핑거프린트)했다. 결과가 멱등이므로 입력
  코퍼스 크기(`len(enum), len(llm), len(host.ports)`)가 지난 호출과 같으면 조기 반환. finding
  출력은 생성 시점에 채워져 개수 키가 변이를 놓치지 않는다.
- **`repetition.signature` 캐시**: 게이트마다 후보·과거 명령 서명을 재계산(shlex.split+정규식)하던
  것에 `functools.lru_cache(4096)` — 순수 함수라 안전.

#### 가독성(Readability)
- **死코드 제거**: 호출부 0인 `orchestrator._flag_in_external_notes`(flag_assess 모듈 함수를
  `classify_flag` 가 직접 호출) 삭제 + `flag_assess.py` 헤더의 stale 주석 정정.

#### 초보자 친화(UX)
- **HTB 연동 막다른 길 복구 안내**: `--htb-spawn`/`--submit-flags` 의 "HTB_TOKEN 미설정 — 생략"
  메시지에 토큰 발급처(HTB 프로필 → App Tokens)·`export HTB_TOKEN=<토큰>`·머신 ID 위치(머신
  페이지 URL 끝 숫자) 안내 추가. `--htb-machine-id` 도움말에도 위치 명시.
- **신규 플래그 도움말에 '언제 쓰나'**: `--catch-revshell`("웹 RCE 로 발판이 안 잡힐 때")·
  `--gate-judge`("자동 모드에서 더 신중하게") 앞머리 추가.
- **시작 화면 안심 문구**: 인자 없이 실행 시 `_start_guide` 끝에 "권한이 확인된 대상에서만 ·
  위험한 건 '생성'만 하고 실행은 사람이 결정" 한 줄 추가.
- VPN 미탐지 경고에 `sudo openvpn <파일>.ovpn` 즉시 복구 명령, 리포트의 PtH 에 "(Pass-the-Hash,
  해시 그대로 재사용)" 해설.

### 테스트(Tests)
- `test_knowledge.py` TF-IDF 캐시(2.28.0)·`test_beginner.py` 시작 안내/플래그 WHEN 보강.
  전체 **133 스위트 | 2957 passed, 0 failed**.

### 검토 — 정상 확인 / 보류
- 안정화: broad except 는 전부 best-effort/서킷브레이커 경계(audit 로깅)·리소스 누수/무한 성장
  없음·결정성 유지 — 변경 불필요(에이전트 교차확인).
- 보류(범위 큰 순수 리팩터, 별도 제안): `report_view.render_summary`(244줄)를 `_html_*` 처럼
  섹션 헬퍼로 분해, `main._run_target` 출력 꼬리 `_emit_outputs` 추출 — 동작 불변·테스트 커버리지
  부분적이라 골든-출력 가드와 함께 독립 PR 로 진행 권장.

## [2.28.0] — 2026-10-12

### 변경(Changed) — 최적화·안정화·가독성 검토 후속
전체 코드베이스를 최적화·안정화·가독성·초보자 친화 관점으로 검토. 대부분 이미 양호(핫패스·
방어 가드·초보자 가이드 `_start_guide`/`_scope_hint`·렌더링 구조). 측정 가능한 실질 개선만 반영
(anti-gold-plating — 무의미한 churn 배제).

- **[최적화] TF-IDF 색인 호출마다 재구성 제거**: `knowledge.relevant_notes` 의 경량 RAG 가 매
  호출 `TfidfIndex(...)` 를 새로 만들어 전 노트 코퍼스를 토크나이즈·df/idf/norm 재계산했다.
  RAG 는 **단계×라운드×스윕마다** 호출되므로 같은 노트 집합에 대한 반복 재구성이 누적됐다.
  `_tfidf_index()` 캐시 추가 — `_lowered_notes` 와 동일한 '노트 id 튜플' 시그니처로 키잉해
  노트 추가·교체 시 자동 무효화(항상 최신·결정적), 그 외엔 색인 재사용.
- `test_knowledge.py` 에 색인 캐시 재사용·무효화 회귀 3건 추가. 전체 **133 스위트 | 2953 passed, 0 failed**.

### 검토 — 정상 확인(변경 불필요)
- 초보자 친화: `_start_guide`(번호 첫 실행 안내·autonomous/manual/sandbox/CTF/resume)·`_scope_hint`
  (바인딩 실패 시 바로 고칠 명령)·`test_beginner.py` 가 이미 충실.
- 안정화: 후처리 F3 가드·세션 I/O OSError 흡수·라우터 fail-safe·예산/시간 상한 등 방어 가드 양호.
- 가독성: god-object 는 믹스인(foothold/preparations/flag_assess)로 분해됨. report_export/view/
  writeup 의 준비-필드 렌더링은 출력 매체가 달라(JSON·터미널·Markdown) 통합 이득 대비 churn 이
  커 보류. run() 분해도 동일 — 현 구조가 단계 주석으로 가독 가능해 강제 분할 안 함.

## [2.27.0] — 2026-10-12

### 수정(Fixed) — 병합본 전체 적대적 재검토 후속(2.23~2.26 변경 교차검증)
2개 독립 리뷰 에이전트가 이번 세션 병합분(2.23.0~2.26.0) 전체를 READ-ONLY 재검토. 안전 경계·
핵심 로직은 모두 정상 확인, 아래 확정 결함만 테스트 선작성으로 수정(HIGH 0 · MED 4 · LOW 2).

- **[MED] 발판 웹 probe 런타임 예외 미흡수**: `_acquire_web_rce` 가 `ws.run()`(HTTP 요청) 의
  런타임 실패(연결거부·타임아웃·TLS)를 감싸지 않아, 예외가 `_foothold_stage` 밖으로 새면 **리버스셸
  폴백과 이후 생성 전용 준비 스테이지(revshell/lateral/crack/privesc·평가·심판)가 통째로 생략**됐다
  (오케스트레이터 F3 가 흡수하나 산출물 손실). 요청 실패를 '발판 미확보'로 degrade → None 반환해
  폴백·준비 스테이지로 진행.
- **[MED] 측면 이동 NT 해시 오분류**: `_prepare_lateral` 이 `user:HASH`(꺾쇠 없는 실제 저장 형식)를
  `parse_cred` 로 평문 취급해 **NT 해시를 `-p`(평문 비밀번호)로 스프레이하는 가짜 후보**를 만들었다.
  해시 모양(정확히 32 hex)이면 PtH(`-H`)로만 라우팅하도록 수정(평문/해시 분리).
- **[MED] 래퍼 값-옵션 바이너리 오인**: `binary_of(skip_wrappers=True)` 가 값 받는 래퍼 옵션의 값을
  바이너리로 오인(`sudo -u www-data cat` → `www-data`, `nice -n 10 nmap` → `10`). 결과로 provenance 가
  `sudo -u user cat flag`(로컬 읽기)를 exploit-derived 로 **과장**(정직성 신호 훼손). 래퍼별 값-옵션
  표(`_WRAPPER_VALUE_OPTS`)로 값 토큰까지 정확히 건너뛰도록 수정(sudo `-n` boolean vs nice `-n` 값 구분).
- **[MED] 발판 세션 I/O 예외 미흡수**: `_foothold_stage` 자격수확/플래그읽기 루프와 리버스셸 성립
  검증 `session.run()` 이 OSError 가드 밖이라, 세션이 중간에 끊기면 준비 스테이지가 생략되고(리버스셸)
  세션이 누수됐다. 세션 I/O 를 OSError 로 흡수(발판 중단·세션 close)하고 이후 스테이지는 계속.
- **[LOW] `_has_token` 대소문자 충돌**: curl `-K`(설정파일)가 `-k`(--insecure)로 오인돼 자가서명 TLS
  교정을 삼키던 것 → 단축 플래그 **대소문자 구분**(nmap `-Pn`/`-pn` 은 호출부가 두 형태 모두 전달).
- **[LOW] 후처리 예외 후 'done' 과장**: F3 블록이 후처리 예외를 흡수한 뒤 상태를 'done' 으로 표기하던
  것 → 리포트 메시지에 ⚠ 후처리 일부 오류 명시(정직성 §3, 코어·저장은 정상).

### 테스트(Tests)
- 신규 `test_wrapper_binary.py`(14, 래퍼 값-옵션). 보강: provenance(sudo -u 로컬 분류)·results_verify
  (-K/-k)·lateral(NT 해시 PtH 전용 라우팅·평문만 재사용)·foothold_revshell(웹 probe 예외→폴백·검증
  OSError→close). 전체 **133 스위트 | 2950 passed, 0 failed**.

### 검토 — 정상 확인(수정 불필요)
- 안전 경계(생성 전용·3관문·토큰 비노출·opt-in 게이트)·`select_approver` 우선순위·gate_judge fail-safe·
  detections 이스케이프·F3 try 구조·F4/F5·`_record_signal` budget·오프라인 재개 dedup·lateral 영속
  일관성 — 전부 정상(두 리뷰어 교차확인).

## [2.26.0] — 2026-10-12

### 추가(Added) — 측면 이동(lateral) 후보 자동 준비 (생성 전용)
마지막 미배선 축이던 '측면 이동 후보 추적'을 배선한다. 수확한 **크리덴셜(user:pass)·NT 해시**를
대상의 **열린 다른 서비스**에 재사용·해시전달(PtH)하는 후보를 자동 생성한다(다른 `_prepare_*`
스테이지와 동일하게 **생성 전용** — 명령 문자열만, 에이전트 발사 없음).
- **`lateral.py` 신설**: `generate(target, creds, nt_hashes, open_ports)` — 열린 포트를 서비스로
  매핑(SSH/SMB/WinRM/RDP/MSSQL/FTP/MySQL/PostgreSQL)하고, 크리덴셜 재사용은 `nxc <proto>` 또는
  네이티브 클라이언트(mysql/psql), NT 해시는 SMB/WinRM/MSSQL/RDP 에 PtH(`nxc -H`) 후보로 만든다.
  user/pass/해시는 `shlex` 인용(주입 차단), 크리덴셜·후보 수 상한(스프레이 남발 방지).
- **`preparations.prepare_lateral`**: 열린 서비스 + 수확 크리덴셜/해시로 후보를 만들어
  `report.lateral_candidates` 에 담고 수동 제안으로 surface. 근거 없으면 조용히 생략(지어내지 않음).
- **오케스트레이터 `_prepare_lateral`**: world.creds(평문 → 재사용, `user:<NT>` → PtH)·볼트 NT 해시를
  모아 PHASE 3.965(privesc 준비 뒤)에서 준비. F3 저장-보장 블록 안이라 예외도 안전.
- **표면화**: 터미널 리포트·JSON 내보내기(`lateral`)에 후보 노출(다른 준비 산출물과 동일 취급).

### 안전(Safety)
- 전부 **생성 전용**: 측면 이동은 노이즈·영향이 큰 스프레이라 에이전트가 자동 발사하지 않는다.
  근거(수확 크리덴셜/해시 + 관측된 열린 서비스)가 있을 때만 후보를 만들고, 실행은 사용자 몫
  (권한 확인 자산 전용 §4). 자격·해시는 shlex 인용으로 주입 차단.

### 테스트(Tests)
- 신규 `test_lateral.py`(24): 서비스 매핑·재사용·PtH·네이티브 클라이언트·shlex 인용·상한·근거없음
  생략·prepare 반영·오케스트레이터 크리덴셜/해시 수집 배선. 전체 **132 스위트 | 2928 passed, 0 failed**.

### 비고
- 이로써 정찰→열거→발판(웹RCE·역쉘)→자격수확→플래그→권한상승→**측면 이동**까지 전 축이 배선됐다
  (네트워크 실행부·스프레이는 설계상 opt-in / 생성 전용 RCE 표면으로 유지). 실 HTB 엔드투엔드
  라이브 검증은 권한 확인 환경에서 사용자 확인 몫(§3 — 샌드박스 검증 불가).

## [2.25.0] — 2026-10-12

### 추가(Added) — 리버스셸 수신 발판 배선(`_acquire_session`) (opt-in)
남은 설계 간극이던 '역쉘 수신 경로'를 발판 획득에 실제로 배선한다. 기존엔 `_acquire_session` 이
웹 RCE 분기만 활성이었다(역쉘은 인터페이스·transport 만 존재, 미배선).
- **`foothold.py`**: `_acquire_session` 을 (1) 웹 RCE 분기 → 실패 시 (2) **리버스셸 수신 분기**
  순으로 재구성. `_acquire_web_rce`/`_acquire_reverse_shell` 로 분리.
  - 리버스셸 분기는 준비된 payload 컨텍스트(`revshell_lhost`/`lport`)가 있을 때 소켓 리스너로
    콜백을 수신하고, **성립 검증(`looks_like_shell`)을 통과한 세션만** 인정(거짓 발판 폐기).
  - 실제 소켓 accept/recv 는 주입 가능한 catcher(기본 `shell_transport.catch_reverse_shell` —
    RCE 실행 표면). 테스트는 catcher 를 주입해 **네트워크 없이** 전 경로를 검증.
- **CLI `--catch-revshell`**(기본 OFF): 켜야 리스너 수신을 시도한다. 기본 흐름엔 소켓 블로킹 없음.
  `Orchestrator(catch_revshell=...)` 로 전달.
- **`shell_transport.py`**: `import requests` 를 `web_http_fn` 안으로 지연 임포트 — 리버스셸 수신
  (표준 socket)은 requests 미설치 환경에서도 동작하도록 선택 의존 분리.

### 안전(Safety)
- 역쉘 수신은 **opt-in + `--exploit-exec` 전용 + 성립 검증 통과분만** 인정. payload 발사·소켓
  수신은 RCE 실행 표면이라 명시 플래그 없이는 동작하지 않는다(권한 확인 대상 전용). 콜백 없음·
  bind 실패·타임아웃은 `OSError` 로 흡수해 '발판 미확보'로 안전 degrade(run 크래시 없음).

### 테스트(Tests)
- 신규 `test_foothold_revshell.py`(9): catch off→미접촉 · 컨텍스트 없음→안내 · 콜백+검증통과→세션 ·
  헛발판→폐기 · 타임아웃(OSError)→안전 degrade · 웹 분기 우선. 실 소켓 없이 catcher 주입.
- 전체 **131 스위트 | 2904 passed, 0 failed**.

### 비고 — 라이브 검증
- 실 HTB 타겟에 대한 **엔드투엔드 라이브 실행**(VPN·실제 콜백 수신)은 이 샌드박스에서 검증 불가하다
  (§3 — 검증 못 한 것은 '됐다'고 하지 않음). 본 변경은 수신 경로의 **코드 배선 + 오프라인(주입)
  검증**까지이며, 실 타겟 콜백 수신은 권한 확인된 환경에서 사용자가 확인할 몫이다.

## [2.24.0] — 2026-10-12

### 수정(Fixed) — 감사 잔여 LOW 항목·방어적 하드닝 일괄 반영
2.23.0 에서 확정 HIGH/MED 를 처리한 뒤 남겨둔 LOW·방어 항목을 '가능한 전부' 반영(테스트 선작성).

- **[A-LOW7] HTB 머신 ID 비정수 크래시**: `submit_flag`/`spawn_machine` 의 `int(machine_id)` 가
  비정수 입력에서 `ValueError` 로 터지던 것 → `_as_machine_id` 로 `HtbError` 승격(호출부 흡수).
- **[A-LOW8] RAG 노트 캐시 stale**: `_lowered_notes` 시그니처가 `(len, id(마지막))` 이라 중간
  원소 in-place 교체 시 소문자 캐시가 갱신 안 됨 → '모든 노트 id 튜플'로 교체(모든 치환 감지).
- **[A-LOW9] 리다이렉트 교정 누락**: Results Verifier 의 `-L` 규칙 정규식 `30[1278]` → `30[12378]`
  (303 See Other·307·308 포함).
- **[A-LOW10] VPN 대역 데드 엔트리**: `_HTB_RANGES` 의 `"10.10.1"`(이미 `"10.10."` 부분집합) 제거.
- **[B-F5] 변형학습 통계 오염**: `_enum_round` 가 `enum_findings[-1]` 로 기록해 출력구동 교정
  발화 시 교정본을 변형결과로 오기록하던 것 → `enum_findings[before]`(원본 변형)으로.
- **[B-F4] 마감 무한 연장 방지**: `_time_up` 의 slept(백오프 대기) 제외에 상한 추가 — 지속적
  네트워크 장애에도 마감 연장은 '예산 1회분'(time_budget 분)까지만(총 실행 ≤ 2×예산).
- **[B-F3] 루프-후 스테이지 예외 → 상태 유실 방지**: 준비·평가·심판 스테이지(_prepare_*·
  _assess_flags·_run_judge 등)에서 예기치 못한 예외가 `_persist` 를 건너뛰어 재개 상태를 통째로
  잃던 것 → 예외를 감사 로그에 남기고(침묵 금지) PHASE 4(저장)로 진행.
- **[D-#7] 무인 자율에서 gate-judge ASK 가 멈추던 것**: `--auto`/`--autonomous` + `--gate-judge`
  에서 ASK 판정이 입력 프롬프트로 정지하던 것 → `judging_approver(interactive=False)` 로 ASK→스킵
  (보수적 거부). '최소 y/n' 자율성 유지. 사람 있는 수동/스마트 모드는 기존대로 대화형 확인.
- **[D-#6] provenance 래퍼 인식**: `classify` 가 `binary_of(skip_wrappers=True)` 로 `sudo nmap`·
  `proxychains curl` 의 실제 도구를 인식(이전엔 래퍼를 바이너리로 오인). **미지 도구 → exploit-derived
  는 검토 후 의도대로 유지**(커스텀 익스·sshpass 래핑·발판 셸 직독이 흔하며 실제 공략 유래 —
  로컬 조회/입력값/외부자료만 신뢰 제외, HTB 는 정답만 수락해 조작 제출 위험 없음). 근거 주석 명문화.
- **[C-minor] 일관성**: `ClaudeProvider.slept_sec = 0.0` 명시(라우터 Deadline pause getattr 일관).

### 테스트(Tests)
- 강화: provenance(래퍼·의도 유지)·gate_judge(무인 ASK→스킵)·results_verify(303/308)·
  htb_platform(비정수 ID)·knowledge(중간 원소 교체 캐시)·hypothesis_ev(정확값·감쇠 방향)·
  detections(triage 실제 라인). 전체 **130 스위트 | 2895 passed, 0 failed**.

### 비고 — 반영하지 않은 항목(정직성 §3)
- **[B-F6]** 출력구동 교정본이 원본이 LLM finding 이어도 `enum_findings` 에 기록되는 점: 집계가
  약간 오도되나 예산·정렬·상태에 영향 없음(정보 수준). 라우팅 변경은 `llm_findings` zip 정합을
  건드려 위험 대비 이득이 낮아 **의도적으로 보류**.

## [2.23.0] — 2026-10-12

### 수정(Fixed) — 4-에이전트 적대적 감사 후속(누락·오류·개선 일괄 반영)
직전까지 만든 전 산출물(가설 EV·Results Verifier·배포형 탐지·TF-IDF·gate-judge·auto-relaunch·
리버싱·HTB 통합)을 4개 독립 리뷰 에이전트가 READ-ONLY 교차검증. 확정 결함만 테스트 선작성으로 수정.

- **[H1·安] gate-judge 가 자율+샌드박스에서 무력화되던 버그**: `--gate-judge` 래핑 뒤에 contained
  자동승인(`auto_approve_contained`)이 **재대입돼 강화 게이트가 조용히 죽던** 경로. 승인자 선택을
  `main.select_approver` **단일 함수**로 모아 실행기(contained) 확정 뒤 gate-judge 를 **맨 마지막에**
  덧씌우도록 구조적으로 차단. (`test_approver_select.py` 회귀 — 심판 DENY 가 자동승인을 실제 차단함을 검증.)
- **[H2] Sigma 룰 YAML 깨짐**: SQLi 키워드 `' or '1'='1` 의 작은따옴표 미이스케이프로 파싱 불가
  YAML 생성 → SIEM 적재 실패. 작은따옴표 doubling(`''`) 이스케이프.
- **[H3] Suricata 룰 적재 불가**: `|nc `·`;id` 의 `|`(hex 구분자)·`;` 미이스케이프. content 특수바이트를
  `|HH|` hex-escape(`_suricata_content`).
- **[H4] HTB 통합 네트워크 장애 시 크래시**: `_urllib_post` 가 `HTTPError` 만 잡아 `URLError`/타임아웃이
  `except HtbError` 를 뚫고 run 전체를 죽임. `URLError`/`TimeoutError`/`OSError` → `HtbError` 승격(토큰 미노출).
- **[M1] 가설 '막힘' 임계 불일치**: 경고/audit 임계가 고정 `replan_after` 였는데 `stuck()`/`focus()` 는
  가설별 `budget(h)` 사용 → 저예산 가설은 경고가 영영 안 뜸. 임계를 `budget(h)` 로 통일.
- **[M2] 재개 시 오프라인 정적분석 중복 재실행**: `_analyze_offline_files` 가 복원 finding 을 안 봐서
  file/strings/nm 를 재실행. 복원분을 skip 집합에 포함(생성 전용이라 안전경계는 무관, 낭비 제거).
- **[M3/M4] Results Verifier 교정 위치·래퍼**: `_insert_flag` 가 env-prefix(`PROXY=1 nmap`)·래퍼
  (`sudo`/`proxychains`) 뒤가 아닌 첫 토큰 뒤에 삽입하던 것 → 실제 바이너리 뒤로. `binary_of` 에
  `skip_wrappers` 옵션 추가(교정·기법 라벨이 `sudo nmap` 도 인식).
- **[M5] 교정 멱등성**: `_has_token` 이 결합형 단축플래그(`-sSL` 의 `-L`)를 못 봐 `-L` 중복 삽입하던 것 수정.

### 문서(Docs) — 코드와 모순되던 서술 정정(정직성 §3)
- `ARCHITECTURE.md §9`: gate_judge(2.19.0)를 "미반영 T2-f" 로 두던 모순 → **A9 ADR 신설**(구현·적용지점 명시).
- `RESEARCH.md`: Results Verifier "미구현"(→2.14.0 구현)·TF-IDF "코사인 아님"(→2.17.0 결선) 정정.
- `CHANGELOG [2.13.0]`: `test_hypothesis_ev` 라벨 20→21 오기 정정(합계는 기존에도 정상).

### 테스트(Tests)
- 신규 `test_approver_select.py`(9)·`test_audit_fixes.py`(8, M1/M2 회귀). 기존 스위트 보강:
  detections(+8, Sigma/Suricata 이스케이프)·results_verify(+4, 삽입위치·멱등)·htb_platform(+5,
  URLError·submit-flags 안전필터)·gate_judge(+2, base 거부 완화불가 직접 검증).
- 전체 **130 스위트 | 2883 passed, 0 failed**.

## [2.22.0] — 2026-10-12

### 추가(Added) — G1. HTB 통합: VPN 프리플라이트 + 플래그 자동제출 + 머신 스폰 (opt-in)
라인레벨 감사의 redcat2 'HTB 부트스트랩' 축. **전부 opt-in**, 당신 HTB 계정 토큰으로 **권한 확인
CTF 자산**에만 쓴다(§4). 해커톤 '최소 y/n' 목표에 직결.
- **`htb_platform.py` 신설**:
  - `HtbClient.submit_flag`(POST `machine/own` `{flag,id,difficulty}`)·`spawn_machine`(POST
    `vm/spawn` `{machine_id}`) — 엔드포인트는 공개 클라이언트(pyhackthebox) 기준, `HTB_API_BASE`
    로 덮어쓰기 가능. http 계층 주입 가능(테스트는 네트워크 없이 요청 구성만 검증).
  - `vpn_preflight` — 대상이 HTB 대역인데 tun/tap 미탐지면 조언(로컬·비파괴).
  - `clamp_difficulty`(10~100, 10단위).
- **CLI**: `--htb-machine-id`·`--htb-spawn`(실행 전)·`--submit-flags`(실행 후)·`--htb-difficulty`.
- **안전**: 토큰은 `HTB_TOKEN` env 에서만 읽고 **로그·오딧·오류 메시지에 절대 노출 안 함**.
  제출은 **공략 유래(exploit-derived) 플래그만**(미끼·로컬·추론 유래 제외). 전부 기본 OFF.
- 신규 `test_htb_platform.py` **19건**. 전체 **128 스위트 | 2846 passed, 0 failed**.

## [2.21.0] — 2026-10-12

### 추가(Added) — G2. export-first 정적 리버싱 (redcat2 doctrine/60 이식)
라인레벨 감사의 redcat2 'export-first 리버싱' 축. rev/pwn/forensic 첨부 바이너리를 받으면
**정적 분석**(바이너리 비실행)으로 일괄 추출해 자동 투입한다(기존엔 도구만 등록돼 있고 워크플로
없었음).
- **`reversing.py` 신설**: `export_first_commands(path)` — file·strings(ascii+wide)·nm·checksec·
  objdump -d·`r2 -A`(정적) 순서 생성. **바이너리를 실행하지 않음**(gdb 실행·`./바이너리`·
  ltrace/strace 제외 — 신뢰 불가 파일 실행 금지). 경로 shlex 인용(주입 차단).
- **오케스트레이터**: 첨부파일 분석 경로(열린 포트 없음)에서 `_analyze_offline_files` 가 바이너리
  마다 export-first 명령을 3관문에 투입(최대 10개·예산 비계상 budgeted=False·재귀 교정 억제).
- 신규 `test_reversing.py` **11건**. 전체 **127 스위트 | 2827 passed, 0 failed**.

## [2.20.0] — 2026-10-12

### 추가(Added) — auto-relaunch 래퍼 (redcat2 run.sh MAX_RESTARTS 이식, opt-in)
라인레벨 감사의 redcat2 '크래시→저장 지점 재시작' 축. 무인 자율 실행 중 미처리 예외로 죽으면
저장된 상태에서 `--resume` 으로 이어 재시작한다(완주 보조).
- **`relaunch.py` 신설**: `run_with_relaunch(orchestrator, max_restarts)` — 예외 시 `resume=True`
  로 전환해 저장 지점부터 재시도(가벼운 백오프·상한). KeyboardInterrupt/SystemExit 은 재시작
  없이 전파(의도적 종료 존중). 상한으로 bound(결정적 크래시는 N회 후 전파 — 무한루프 없음).
- CLI `--max-restarts N`(기본 **0=끔** — 버그를 재시작으로 가리지 않도록 opt-in).
- 신규 `test_relaunch.py` **10건**. 전체 **126 스위트 | 2816 passed, 0 failed**.

## [2.19.0] — 2026-10-12

### 추가(Added) — T2-f. 승인 게이트 LLM 폴백 심판 (opt-in·강화 전용, ARTEX intercept.Judge)
라인레벨 감사에서 ARTEX 의 '룰 미매칭 도구콜 운영안전 심판(ALLOW/ASK/DENY)' 미반영 확인.
이를 승인제에 **강화 전용·fail-safe** 로 이식한다 — 보안 게이트를 **더 엄격하게만** 만든다.
- **`gate_judge.py` 신설**: `judging_approver(base, router)` 가 **규칙이 이미 자동승인할 명령에만**
  LLM 심판(`gate_verdict` → ALLOW/ASK/DENY)을 물어, DENY=차단·ASK=사람확인으로 조정. 규칙이
  거부/사람확인을 요구한 명령(검증 실패·범위 밖·동적 코드)은 **심판을 호출조차 안 함**(완화 불가).
  심판 오류·모호 응답·라우터 없음 → 기존 자동승인 유지(fail-safe, 일시 LLM 장애가 진행 막지 않음).
- `LLMRouter.gate_verdict`/`HybridRouter.gate_verdict`(싼 티어·폴백). CLI `--gate-judge`(기본 OFF).
- 프롬프트 인젝션 하드닝(명령 문자열 안 지시문 불복). 가장 엄격 판정 우선(DENY>ASK>ALLOW).
- 신규 `test_gate_judge.py` **14건**. 전체 **125 스위트 | 2806 passed, 0 failed**.

## [2.18.0] — 2026-10-12

### 추가(Added) — T2-e. Deadline pause/resume (LLM 재시도 대기 시간 예산서 제외)
라인레벨 감사(BoxPwnr Deadline)에서 확인된 실질 공백. `_time_up()` 이 단조시계 절대비교만 해서,
LLM 일시 장애로 재시도 백오프 대기가 길면 '실제 작업' 시간이 줄어도 예산이 소진됐다. 이제
재시도로 '대기'한 시간만큼 마감을 뒤로 민다(일시 네트워크 블립이 작업 시간을 깎지 않게).
- `ollama_provider.slept_sec` — 재시도 백오프 대기 누적. `LLMRouter.slept_sec`(provider 보고)·
  `HybridRouter.slept_sec`(두 백엔드 합) 프로퍼티(total_cost 와 동형).
- `orchestrator._time_up` — `clock >= deadline + slept_sec` 로 대기 시간 제외(예산 무제한이면
  무관·불변). 상한은 재시도 백오프 cap 으로 bound(폭주 없음).
- 신규 `test_deadline_pause.py` **11건**. 전체 **124 스위트 | 2792 passed, 0 failed**.

## [2.17.0] — 2026-10-12

### 추가(Added) — T2-b 기법 taxonomy(ATT&CK) + T2-c TF-IDF 코사인 관련도
라인레벨 감사의 CTF-Abacus(step별 기법 분류)·AutoPentester/Anomaly(벡터 관련도 부재) 지적을
**stdlib 범위**에서 결정적으로 보강(외부 임베딩·의존 없음).
- **[T2-c]** `tfidf.py` 신설(stdlib TF-IDF 코사인 — 희귀 용어 가중·길이 정규화).
  `knowledge.relevant_notes` 가 노트 2개 이상이면 키워드 개수 대신 TF-IDF 코사인으로 랭킹
  (매칭 없으면 앞 N개 폴백 — 동작 보존, 코퍼스 작아 매 호출 재구성해 교체/추가에도 최신).
- **[T2-b]** `technique.py` 신설 — 실행한 '명령'을 ATT&CK 기법으로 라벨링(nmap→T1046,
  ffuf→T1595.003, hydra→T1110, searchsploit→T1588.005 …). `coverage()` 는 ran 된 명령의
  distinct 기법. 라이트업 블루팀 섹션에 '실행 트레이스 ATT&CK 커버리지'로 노출(생성 전용).
  (detections.py 의 CWE→기법 매핑과 상보 — 이쪽은 '실제 돌린 명령' 기준.)
- 신규 `test_tfidf_technique.py` **19건**. 전체 **123 스위트 | 2781 passed, 0 failed**.

## [2.16.0] — 2026-10-12

### 추가(Added) — T2-a 전제 가설 가지치기 + T2-d 궤적 드리프트 supervisor
라인레벨 감사의 MazeRunner(비선형 재계획·blocked 가지치기)·redcat2(궤적 드리프트 critic) 부분
반영분을 **비례적·결정적**으로 보강(전면 태스크 DAG·별도 LLM critic 은 ADR A3/A4 로 미채택 —
순효과 마이너스. 그 '핵심 축'만 기존 구조에 얹는다).
- **[T2-a]** `Hypothesis.depends_on`(전제 가설 ID) + `HypothesisLedger.dep_blocked()`:
  전제 가설이 '기각'되면 하류 가설을 `focus()` 에서 보류(하류 가지치기). 자기참조·미존재 ID
  무시. `apply_update`/`from_dict` 가 depends_on 주고받음(최대 4개).
- **[T2-d]** `recommend.propose` 에 **가설 레벨** 드리프트 권고 추가(명령 레벨 반복 권고와 별개):
  막힌 가설이 2개 이상이고 쫓을 신선한 가설이 없으면(래빗홀) '가설 전면 재검토' advisory
  (source=supervisor). 결정적·조언 전용 — 자동 실행/재계획 아님(사람이 선택).
- 신규 `test_phase_prune.py` **11건**. 전체 **122 스위트 | 2762 passed, 0 failed**.

## [2.15.0] — 2026-10-12

### 추가(Added) — T1-c. 배포형 탐지 산출물 (ARTEX detections 식 블루팀 룰셋, 클린룸)
라인레벨 감사에서 ARTEX 의 최대 미반영 축으로 꼽힌 '돌려볼 수 있는 탐지 산출물'을 구현한다.
기존 `defense.py` 는 '취약점→탐지/완화'를 **산문 표**로만 만들었는데, 이제 탐지/공략된
CWE·CVE·대상에서 **실제 배포 가능한 룰**을 생성한다(§7 블루팀·SIEM/Snort·Suricata 지표).
- **`detections.py` 신설**(생성 전용·방어용):
  - `sigma_rules` — CWE별 Sigma YAML(웹서버 로그 범용, ATT&CK 태그).
  - `suricata_rules` — 네트워크 의미 CWE 의 HTTP content 매칭 룰(sid 1000000+).
  - `navigator_layer` — ATT&CK Navigator layer JSON(매핑 기법 색칠).
  - `misp_event` — MISP 이벤트 유사 IoC(대상·탐지 CVE, `to_ids=False`·외부공유 금지).
  - `host_triage_script` — **읽기 전용** 침해 분류 셸(id·ss·ps·sudo -l·SUID·cron·last — 수집만).
- **결선**: `writeup._defense_mirror` 가 미러 표 뒤에 배포형 산출물 섹션을 덧붙임(두 템플릿 공통).
- 근거 없으면(CWE·CVE·대상 없음) 정직하게 생략(지어내지 않음, §3).
- 신규 `test_detections.py` **22건**(규칙·Navigator/MISP JSON 유효·triage 읽기전용·근거없음
  생략·Sigma 맵 결손 CWE 무예외). 전체 **121 스위트 | 2751 passed, 0 failed**.

## [2.14.0] — 2026-10-12

### 추가(Added) — T1-a. 출력구동 Results Verifier (실행 후 명령 교정·재시도)
라인레벨 감사에서 확인된 AutoPentester 핵심 축 미반영분. `command_fixer.py` 가 실행 *전*
타겟만 복구한다면, 이제 실행 *후* 출력/오류를 보고 '거의 맞았는데 한 끗 빠진' 명령을
결정적 규칙으로 교정해 1회 재시도한다(불완전 명령으로 한 번의 시도를 통째로 버리는 낭비 감축).
- **`results_verify.py` 신설**: `corrective_command(cmd, out)` — 고신뢰 소수 규칙만.
  (1) nmap 호스트 다운/필터 응답 → `-Pn`, (2) curl https 자가서명·검증실패 → `-k`,
  (3) curl 3xx 리다이렉트 → `-L`. 애매하면 교정 안 함(과잉 재시도 방지).
- **오케스트레이터 결선**: `_process` 끝에서 `_maybe_corrective_retry` — 교정본을 **3관문에
  재투입**(생성 전용). 유한·예산보호: 원 명령당 1회(`_verify_retried`), 전역 상한 8회
  (`_verify_budget_left`), 교정본은 KB 열거 예산 비계상(budgeted=False)·재귀 금지
  (corrective=True), 시간 소진 시 생략.
- 신규 `test_results_verify.py` **13건**(규칙·멱등·재투입·재귀방지·예산상한). 전체
  **120 스위트 | 2729 passed, 0 failed**.

## [2.13.0] — 2026-10-11

### 추가(Added) — T1-b. 가설 기대값(EV) 점수화 (redcat2 confidence×impact÷cost 이식)
라인레벨 감사에서 확인된 부분 갭. 가설 선택이 상/중/하 서수 + 고정 막힘 임계(2회)뿐이라,
'맞으면 공략이 크게 전진하지만 확인이 싼' 고가치 가설과 저가치 가설을 같은 무게로 다뤘다.
redcat2 교리의 **confidence×impact÷cost** 기대값을 승인제 구조에 맞춰 **결정적(규칙 기반)**
으로 이식한다.
- `Hypothesis` 에 `impact`·`cost`(상/중/하) 필드 + `ev` 프로퍼티:
  `(신뢰도priority × 영향impact ÷ 비용cost) × 최근결과보정(misses 감쇠)`.
- `focus()` 를 EV 내림차순(동률 ID)으로 — 완전히 막히기 전에 misses 가 쌓인 가설을 자동
  후순위로 밀어 신선한 각도를 먼저 쓴다.
- `budget()` 가변 증거예산: 영향 큰·비용 낮은 가설엔 더 많은 시도, 반대는 빨리 포기(고정 2회 →
  가설별). `stuck()` 이 이를 사용.
- 분석가 프롬프트·`apply_update`·`from_dict`·`context_lines` 가 impact·cost 를 주고받음.
- **하위호환**: 전부 '중'·misses=0 이면 EV∝priority·budget==replan_after 라 기존 순서·임계와
  동일(실행·판정 로직과 무관, 방향성만). 신규 `test_hypothesis_ev.py` **21건**. 전체
  **119 스위트 | 2716 passed, 0 failed**.

## [2.12.0] — 2026-10-11

### 수정(Fixed) — 문서 정직성 교정 (논문·ARTEX 장점 반영도 전수 라인레벨 감사)
업로드 자료(논문 5편 + ARTEX·redcat2·BoxPwnr) 전수를 소스와 **라인레벨 대조**한 결과,
반영도 자체는 높았으나 **참조 문서의 과장·과소·오귀속 표현 6건**을 확인해 교정한다(§3 정직성).
코드 로직 변경 없음 — 문서·버전만.
- **A6 성격 정정**: `judge.py` 는 ARTEX 'LLM-judge' 를 **충실 이식**한 것이 아니라, ARTEX 의
  실제 `llm_judge`(룰 미매칭 도구콜의 운영안전 심판 ALLOW/ASK/DENY)와 **목적이 다른** 결과검증
  루브릭으로 **재목적화**한 클린룸 파생임을 명시(ARCHITECTURE §9 A6).
- **A5·A6 ADR 승격**: 과거 ADR 아닌 변경이력에만 있던 두 결정을 `ARCHITECTURE.md §9` 에 ADR 로 기재.
- **RESEARCH.md 과장 정정**: (a) `--sandbox` 셸을 'PTY-유사'→'명령 단위 one-shot(세션 비보존)'
  으로, (b) `command_fixer.py` 를 'Results Verifier 전면'→'타겟 복구만(출력구동 재생성 미구현)'
  으로, (c) 'RAG'·요약을 '키워드/서명·트렁케이트(벡터·청크병합 아님)'로 한정.
- **과소기재 보완**: Anomaly-Agent 의 외부 위협인텔(KRM) 대응으로 `enrich.py`(NVD/CVE/CWE) 추가 기재.
- 코드/테스트 변경 없음. 전체 **118 스위트 | 2695 passed, 0 failed** (불변).

## [2.11.1] — 2026-10-11

### 수정(Fixed) — 단계별 열거 예산 공정배분 (max_enum 잠식 HIGH 버그)
핵심 파이프라인 전수 감사에서 확인된 구조적 결함. `_spent` 가 전역합산이라 KB 열거 예산
(`max_enum`/`max_llm`)이 **단계 전체에서 공유**됐고, 순서상 먼저 도는 enum 단계가 예산을
독식하면 access/privesc/lateral 의 열거 예산이 **0 으로 굶었다**. boot2root 는 privesc/
lateral 열거가 핵심이라 치명적이었다. 이제 **각 단계가 독립 예산**을 받는다(option A 공정
배분 — 더 철저, 전역 `cost_cap` 은 여전히 달러 상한으로 작동).
- `orchestrator._spent`: `phase` 필터 추가(주면 그 단계에서만 쓴 시도 수 집계). 호출부
  두 곳(`_enum_round`·`_llm_round` 예산 산출)에 현재 단계 키 전달. finding 은 이미
  `phase` 를 보유 → 데이터 변경 없이 집계만 단계 분리.
- 하위호환: `phase=None`(기본) 은 기존 전역 합산 그대로. `budgeted=False`(소비 스테이지)·
  `skipped`(미설치) 제외 의미 불변.
- 신규 `test_phase_budget.py` **9건** + `test_s5_budget.py` 예산 단언을 단계별로 교정.

## [2.11.0] — 2026-10-11

### 추가(Added) — Ollama 재시도/백오프 (견고성 — 서킷브레이커 조기 트립 완화)
개선 감사(BoxPwnr 참고)에서 확인된 견고성 공백. Ollama 백엔드는 재시도가 전무해 일시
네트워크 블립(연결거부·타임아웃) 1회가 하드 오류로 집계됐고, 2연속이면 서킷브레이커가
트립됐다. 이제 **전이성 오류만** 지터드 지수백오프로 소수 재시도(상한으로 예산 보호).
- `ollama_provider`: `complete` 를 `_once`(단발)+재시도 루프로 분리. 전이성(URLError·
  TimeoutError·OSError·깨진 JSON·5xx)만 재시도, **4xx 클라이언트 오류는 즉시 전파**(재시도
  무의미). 백오프 `base*2^n + 지터`, cap 으로 제한. `_sleep` 주입 가능(테스트 no-op).
- Claude 는 anthropic SDK 가 이미 재시도(max_retries) → 이중재시도 방지 위해 손대지 않음.
  2.10.1 서킷브레이커 반개방 복구와 짝: 재시도로 트립 자체를 줄이고, 트립돼도 복구된다.
- 신규 `test_ollama_retry.py` **9건**. 전체 **117 스위트 | 2683 passed, 0 failed**.

## [2.10.2] — 2026-10-11

### 수정(Fixed) — 구조 감사 확인 오케스트레이터/상태 실버그 6종
핵심 파이프라인 전수 감사(오케스트레이션 루프·예산·상태모델·resume)에서 확인된 결함 수정.
- **[MED] time budget 내부루프 미강제**(`orchestrator.py`): `_time_up()` 이 단계 수준에서만
  점검돼, `_enum_round`/`_llm_round` 실행 루프와 병렬 `_attempt_batch` 는 목표만 보고 시간은
  안 봤다 → 느린 명령(최대 180s) 연쇄로 `--time-budget` 을 수십 분 초과. 세 루프에 `_time_up()`
  중단 + 배치는 시간 소진 시 미실행.
- **[MED] resume 가 world.loot 유실**(`state.py`·`orchestrator.py`): `loot` 가 영속·복원되지
  않아, 1차 실행에서 돌던 lateral 이 재개 후 `_prereq_met("lateral")`(bool(loot)) 퇴행으로 조용히
  생략. SessionState 에 `loot` 추가 + `_persist`/`_restore` 왕복.
- **[MED] world.to_dict 가 learned 누락**(`world.py`): 자율학습 지식이 컨텍스트·성장판정엔 쓰면서
  export 엔 빠져 SSOT 불일치. `to_dict` 에 `learned` 추가(JSON schema 1.9).
- **[LOW] add_flag access 상승이 value 가드 밖**(`world.py`): `add_flag("root","")` 가 플래그
  없이 access 를 올릴 수 있던 잠재 구멍 → 상승을 value 기록 안으로.
- **[LOW] _record_flag dedup 이 value 만**(`orchestrator.py`): `(kind,value)` 로 교정 — user·root
  가 우연히 같은 값이어도 둘 다 보존.
- **[LOW] _ran_total 이 skipped LLM finding 을 진행으로 집계**(`orchestrator.py`): enum 과 동일하게
  skipped 제외.
- 신규 `test_audit_fixes_core.py` **15건**. 전체 **116 스위트 | 2674 passed, 0 failed**.

## [2.10.1] — 2026-10-11

### 수정(Fixed) — 구조 감사에서 확인된 LLM 계층 실버그 3종
핵심 파이프라인 전수 감사(라우터·프로바이더·가설엔진·비용)에서 확인된 실제 결함 수정.
- **[HIGH] 서킷브레이커 영구차단 → 반개방 복구**(`llm/router.py`): `HybridRouter.disabled` 가
  '쓰기 전용'이라 일시 장애(529/타임아웃 2연속)가 **세션 전체 능력상실**로 굳었다(재활성 경로
  전무). 쿨다운(기본 3콜 건너뜀) 후 1회 재탐색 → 성공 시 차단 해제, 재실패 시 재차단. 성공은
  언제나 서킷을 해제한다.
- **[MED] 비용 과소집계(캐시 토큰 이중차감)**(`llm/pricing.py`): `input_tokens` 는 이미 캐시
  읽기/생성을 제외한 '비캐시' 입력 수인데 여기서 또 빼 비캐시 입력을 0 으로 깎았다 → `total_cost`
  과소 → `cost_cap` 늦게 발동 → **예산 초과**. `non_cached_in = max(0, prompt_tokens)` 로 교정.
- **[MED] 기대한 거부(403/404)를 강제 miss**(`hypotheses.py`): `target_rejected` 면 `match_signal`
  을 건너뛰고 무조건 miss → "403 이면 인증 필요 확인" 같이 **거부 자체를 기대한 가설**이 맞고도
  오탐 stuck/freeze 됐다. 거부라도 기대 신호가 실제로 보이면 hit, 기대 안 한 거부만 miss.
- 신규 `test_audit_fixes_llm.py` **12건** + `test_llm_cost.py` 캐시 의미 교정. 전체 **115 스위트
  | 2659 passed, 0 failed**.

## [2.10.0] — 2026-10-11

### 추가(Added) — 제품→CVE 자동발견 (NVD 역질의) · KB 룰 없이도 신종 취약점 수면 위로
라이브 검증(connected.htb / FreePBX 16.0.40.7)이 드러낸 근본 갭 해결. 기존 CVE 수집은
**'이미 아는 CVE ID' 만** NVD 에서 조회(`enrich_cve`/`?cveId=`) — 제품→CVE 역방향이 없어, KB
룰이 없는 제품은 버전을 정확히 탐지하고도 "매칭 PoC 없음"으로 묻혔다. 이제 **탐지된 제품/버전으로
NVD 를 역질의**해 자동으로 CVE 를 발견한다. 발견은 자동, 실행은 아님(제안으로만 노출 — 생성 경계).
- **`enrich.discover_by_product(product, version)`**: NVD `keywordSearch` → **CPE 적용범위 필터**
  (`versionStart/End Including/Excluding` 파싱 — 과매칭 배제) → CVSS 내림차순·최신순 상위 N.
  버전범위 판정 헬퍼 `_version_applies`/`_vtuple`(경계 포함/제외 정확 처리).
- **오케스트레이터 결선**: `_discovery_targets`(web_product + 서비스 배너, 버전 있는 제품만·최대 4,
  중복 제거) → 발견 CVE 를 `report.discovered_cve` 에 싣고 enrich 파이프라인에 합류 → 리포트 노출.
- **리포트**: 터미널 VULN 패널에 '🔎 자동발견 CVE' 행 + CVE 레퍼런스에 🔎 배지. JSON schema 1.8
  (`discovered_cve`).
- 신규 `test_cve_discovery.py` **16건**(역탐색·버전필터·랭킹·PoC·가드·음성). 전체 **114 스위트 |
  2646 passed, 0 failed**.

## [2.9.3] — 2026-10-11

### 추가(Added) — 취약점 KB: FreePBX endpoint 비인증 SQLi→RCE (CVE-2025-57819)
라이브 검증(connected.htb, FreePBX 16.0.40.7)에서 드러난 KB 갭 보강. searchsploit·기존 KB에
없어 '버전은 정확히 탐지하고도 매칭 PoC 없음'으로 멈추던 FreePBX 16 최신 RCE를 취약점 KB에
추가 → 다음 실행부터 자동 매칭.
- `knowledge/vulns/common-services.json`: FreePBX endpoint 모듈 `/admin/ajax.php` 비인증
  SQLi+인증우회→RCE 항목(영향 endpoint <15.0.66/16.0.89/17.0.3, CISA KEV, Metasploit 모듈).
- `enrich.py` `CWE_NAMES`: `CWE-288`(Authentication Bypass Using an Alternate Path or Channel) 등재.
- 코드 로직 변경 없음(KB 데이터 + CWE 카탈로그). 전체 113 스위트 | 2630 passed, 0 failed.

## [2.9.2] — 2026-10-11

### 문서(Docs) — 새 환경 설치는 기본(default) 브랜치 기준으로 명확화
새 PC·VM 스냅샷에서 셋업할 때 **기본(default) 브랜치**로 클론/최신화하도록 설치 문서를 정리한다
(브랜치명 하드코딩 없이 `git clone`/`git pull` 이 자동 선택 — 리네임 안전).
- `README.md`·`docs/QUICKSTART.md`·`docs/USAGE.md` 설치부에 `git clone … ~/HTB_AUTO_AGENT` +
  최신화용 `git -C ~/HTB_AUTO_AGENT pull --ff-only` 추가.
- 브랜치 주석: `claude/*` 작업 브랜치는 CI·리뷰 중 임시 강제동기될 수 있어 로컬 실행용으로
  체크아웃하지 말 것(최신 릴리스는 항상 기본 브랜치에 병합) 명시.
- 코드 변경 없음(문서·버전만).

## [2.9.1] — 2026-10-11

### 추가(Added) — A8. 소스-그라운드 드리프트 테스트 (ARTEX 'source-grounded drift tests' 반영)
장점 반영 감사에서 '부분'이던 A8 을 전용 스위트로 승격. **출하 KB 전수**(`knowledge/rules/*.json`·
`knowledge/vulns/*.json`)를 코드가 실제로 쓰는 계약에 접지시켜 '침묵 드리프트'를 테스트 타임
실패로 올린다. 동기: 룰/취약점 로더는 잘못된 스키마를 **stderr 경고로만** 흘리거나(알 수 없는
phase/os) **아예 침묵 드롭**(`_load_vuln_dir`: name/service 없으면, `_load_rule_dir`: ports 비정수면)
해서, `phase:"foothold"` 같은 오타가 들어가도 런타임이 조용히 degrade 할 뿐 CI 는 초록으로 남았다.
- **`test_kb_grounding.py` 신설 26건**: 룰 phase ⊆ `PENTEST_PHASES`·when.os ⊆ `_VALID_OS`·
  when.ports 정수(침묵 드롭 방지)·죽은 룰 없음(빈 suggest 면 note 필수); 취약점 severity 열거·
  CVE/CWE 형식·**정직성 접지(운영 취약점 노트 '출처' 인용, §3/§4 경계의 구조적 가드)**;
  로더 전수 적재(객체 수 == 적재 수)·실제 API 무예외 적재; **음성 테스트**로 가드 민감도 입증.
- 코드·KB 변경 없음(테스트·문서만). 전체 **113 스위트 | 2630 passed, 0 failed**.

### 문서(Docs) — A3·A4 설계 결정(ADR) 명문화
ARTEX 장점 감사의 '부분 반영' 두 축을 **현 구조로 이미 실현됐고 전면 재작성은 순효과 마이너스**로
판단, 그 근거를 `docs/ARCHITECTURE.md`에 설계 결정으로 남긴다(추측성 재작성 회피 — 6b 와 동류).
- **A3 이벤트 구동 루프**: `StageScheduler` 의 `key()`(입력 서명) dirty-추적이 곧 이벤트 전파다.
  별도 pub/sub 버스는 간접층만 늘릴 뿐 동일 고정점 동작 → 미채택.
- **A4 플래너/워커 블랙보드**: `WorldModel`=공유 블랙보드, `Orchestrator`=플래너(스케줄·게이팅·
  분석), 스테이지/라운드=워커로 이미 성립. 명시적 클래스 분리는 '이름 바꾸기' 수준 → 미채택.

## [2.9.0] — 2026-10-11

### 추가(Added) — A6. LLM-심판 게이트(opt-in·advisory) — ARTEX 'LLM-judge' 정직성-보존 이식
장점 반영 감사에서 '미반영'이던 ARTEX LLM-judge 아이디어를 **정직성 경계를 지켜** 이식한다.
`--judge` + LLM 라우터가 있을 때만(기본 OFF·비용 0), 종료 시 증거(획득 플래그·출처 판정·권한·
상태·실행 명령)만 보고 '공략으로 목표 달성' 주장이 뒷받침되는지 **별도 LLM 호출로 루브릭 채점**.
- **`judge` 모듈 신설**: `JudgeVerdict`(score·passed·rationale) + 프롬프트 빌더 + 견고한 JSON 파서
  (범위 클램프·비JSON → None 폴백).
- **라우터 `judge()` 메서드**(LLMRouter·HybridRouter) — analyze 와 동일 비용 경로, 강력 모델 우선.
- **오케스트레이터 결선**: `_run_judge` 가 `_assess_flags` 뒤에서 조언을 `report.judge_verdict` 에
  싣는다. **규칙 판정을 절대 덮지 않음** — 심판이 pass 해도 미신뢰 플래그가 goal 로 승격되지 않고,
  fail 해도 공략 유래 플래그가 격하되지 않는다(skeptic 한 겹 추가).
- 리포트 표시(터미널 '🧪 심판(조언)') + JSON 내보내기(schema 1.7, `judge_verdict`). CLI `--judge`.
- 신규 `test_judge.py` **11건**(파싱·라우터 경로·opt-in·규칙 불변·정직성). 전체 **2604 passed**.

## [2.8.0] — 2026-10-11

### 추가(Added) — A5. 타입드 리니지(출처) 그래프 — 평면 evidence 승격 (ARTEX 참고 장점 반영)
장점 반영 감사에서 유일하게 '미반영'으로 꼽힌 ARTEX 아이디어(타입드 리니지 그래프)를 구현한다.
기존 `world.evidence`(사실→출처문자열 평면 dict)를 **병행 타입드 그래프**로 승격(하위호환 유지).
- **`LineageNode`**(종류·출처·부모·콘텐츠해시) + `WorldModel.lineage`(값→노드). `add_cred/
  add_loot/add_vuln/add_learned/add_flag` 가 종류별 노드를 기록(평면 evidence 도 그대로 유지).
- **다중 홉 유래 `chain(value)`** — 부모 엣지를 따라 자식→부모 재구성(사이클 방어). 설정파일
  loot → 그 파일에서 캔 cred 같은 **사실→사실 엣지**를 표현.
- **콘텐츠 해시(A7 보강)** — 노드에 근거 원문 sha256 필드(있을 때). 동일 증거 식별·안정 참조 토대.
- **소비처 결선**: `to_dict` 가 lineage 를 내보내 리포트 JSON 에 포함(report_export), `_with_src`
  가 부모 사슬('← 부모')까지 표시(LLM 컨텍스트·교육). 실행·판단 로직과 무관(표현·내보내기).
- 신규 `test_lineage.py` **17건**. 전체 **2593 passed, 0 failed** (111 스위트).

## [2.7.16] — 2026-10-11

### 정리(Changed) — S5-4. 사장 메서드 제거 · 진행도 계상 정확화 · to_dict 완전성
재감사의 LOW 정리 항목.
- **사장 메서드 `_privesc_analyze_stage` 제거** — 호출부 없음(privesc 벡터 분석은
  `preparations.prepare_privesc` 안에서 `privesc_analyze` 로 직접 수행).
- **`_enum_round` 진행도 계상 정확화** — 반환값을 `len(to_run)` → `slots`(도구 설치된 runnable
  수)로. 도구 미설치(skipped) 후보가 '진행'으로 세어져 라운드 조기종료를 한 라운드 늦추고
  단계를 'skipped-only인데 진행'으로 표시하던 accounting 오류 교정. phase 진행 판정(`grew`)도
  '실제 실행된(비skipped)' finding 기준으로.
- **`WorldModel.to_dict` 에 `web_product`/`web_version` 추가** — 리포트 JSON 내보내기 완전성
  (report_export 가 이미 world.to_dict 사용). `WorldModel.to_dict` 는 사장 아님(report_export·
  test_world 가 사용) — 재감사 보고의 '미사용' 판단을 정정.
- 전체 **2576 passed, 0 failed** (110 스위트). 행위 영향: skipped-only 단계 표기·라운드 종료
  시점만 정정, 정상 경로 불변.

## [2.7.15] — 2026-10-11

### 수정(Fixed) — S5-3. 월드 식별 상태·해시 resume 왕복(S0 resume 퇴행 교정)
재감사가 찾은 resume 퇴행: `_persist` 가 월드 상태를 저장하지 않고 `raw_output` 도 비영속이라,
`--resume` 시 `_run_vuln` 이 `web_product`/`web_version` 을 **손실 요약**(S0 가 피하려던 바로 그것)
에서 재파싱해 ⭐ 버전매칭이 1차 실행보다 조용히 퇴행하고, 수집 해시도 사라져 크랙 준비가 degrade.
- **`SessionState` 에 `web_product`/`web_version`/`found_hashes` 추가**, `_persist` 가 월드·해시에서 저장.
- **`_restore` 가 복원** — `set_web_app` 으로 제품/버전을 직접 복원(요약 재파싱 의존 제거),
  해시는 `_found_hashes` 로 이어붙임. S4 자격증명 왕복과 동일 패턴.
- 신규 `test_s5_world_resume.py` **6건**(저장·복원 각각). 전체 **2576 passed, 0 failed** (110 스위트).

## [2.7.14] — 2026-10-11

### 수정(Fixed) — S5-2. 정직성 가드: world(신뢰 상태)에 공략 유래 플래그만 반영
재감사가 찾은 정직성 가드 역전: `_record_flag` 가 **모든** 스캔 플래그를 `world.add_flag`
(→ `raise_access`)로 무조건 올려, 로컬 출력의 미끼·예시·라이트업 유래 플래그가
`world.access_level` 을 user/root 로 올리고 `_prereq_met` 를 충족시켜(투기적 LLM 라운드 오발)
`context_lines`·`_world_fingerprint` 를 오염시켰다. `goal_reached` 는 verdict 로 보호됐지만
world 상태는 그렇지 않아, 정직성을 가장 지켜야 할 곳에서 report↔world 가 갈렸다.
- **world 쓰기를 `verdict=="exploit-derived"` 로 게이트** — `goal_reached` 와 동일 기준. `report.flags`
  는 '관측된 모든 플래그'를 그대로 담고(사람 확인용), world 는 '신뢰 상태'만 담는다.
- 발판/포착/재개 경로의 공략 유래 플래그는 기존대로 정상 반영(권한 승격·goal 인식 유지).
- 신규 `test_s5_flag_trust.py` **10건**: 미신뢰(local-derived/looked-up) → report만·world 권한
  불변 / exploit-derived → 정상 승격 / 혼합 시 미신뢰 root 로 권한 오염 없음. 전체 **2570 passed**.

## [2.7.13] — 2026-10-11

### 수정(Fixed) — S5-1. 소비 스테이지 예산 분리(max_enum 잠식 HIGH 버그)
전면 재감사(파이프라인 흐름)가 찾은 HIGH 결함: 결정적 소비 스테이지(핑거프린트·버전프로브·
익스조회·웹비밀)가 `report.enum_findings` 에 쌓이는데 `_spent` 가 이를 **KB 열거 예산
(max_enum)에 계상**해, 옵트인 모드(--exploit-exec/--auto-poc)에서 소비 프로브가 예산(기본 6)을
선점하면 `_enum_round` 가 **전 단계·전 라운드에서 한 번도 안 돌던** 버그(LLM 예산은 별도라 가려짐).
- **`EnumFinding.budgeted` 플래그 신설** — 소비 스테이지의 `_attempt(..., budgeted=False)` finding 은
  `_spent` 에서 제외(이미 스케줄러의 제품/호스트별 멱등 가드로 유한). `max_enum` 은 KB 열거만 bound.
- `_gate`/`_attempt` 에 `budgeted` 인자 전달. 4개 소비 스테이지 호출만 False.
- 신규 `test_s5_budget.py` **5건**(단위 `_spent` + 전체 run 에서 소비 프로브가 KB enum 을 안 굶김).
  전체 **2560 passed, 0 failed** (108 스위트).

## [2.7.12] — 2026-10-11

### 문서(Docs) — ARCHITECTURE.md 를 S0~S4 구조에 맞춰 동기화 · 행위 변화 없음
구조 개선(S2 고정점 루프·S3 스케줄러/모듈 분리·S4 SSOT 단일 쓰기)과, 그간 누적돼
문서에 빠져 있던 14개 모듈을 아키텍처 문서에 반영한다(코드 변경 없음).
- **§2 파이프라인**: S2(고정점 반복·`max_sweeps` 안전상한)·S3(의존 선언형 스케줄러)·
  S4(상태원 단일 쓰기 경로) 설명 추가.
- **§4 모듈 지도**: `scheduler`·`preparations`·`flag_assess`(이번 분리) + `verify`·`defense`·
  `web_secrets`·`exploit_fetch`·`exploit_run`·`session_verify`·`shell_session`·`shell_transport`·
  `cred_sources`·`flag_read`·`privesc_analyze`(발판·익스 옵트인 클러스터) 행 추가.
- `test_docs_consistency` 포함 전체 **2555 passed, 0 failed**.

## [2.7.11] — 2026-10-11

### 추가(Added) — S4-4. 상태원(SSOT) 일관성 불변식 가드 · 행위 변화 없음
같은 사실이 여러 컨테이너(WorldModel·OrchestrationReport·SessionState·CredentialVault)에
중복 저장되는 구조에서, **쓰기 단일 경로**(S4-1 자격증명·S4-2 플래그)가 실제로 컨테이너 간
일관성을 지키는지 전체 `run()` 후 교차 검증하는 불변식 테스트를 추가한다. S4-2 의 '발판
플래그가 world 에만 기록' 같은 한쪽-만-갱신 회귀를 구조적으로 잡는 가드.
- 신규 `test_s4_ssot_invariants.py` **6건**: 서비스(world.services==host.open_ports)·자격증명
  (vault ⊆ world.creds)·플래그(report.flags ↔ world.flags 양방향)·발판 플래그 goal 반영 +
  **음성 대조**(world-only 기록이 불변식을 깨는지 — 가드 민감도 입증).
- 읽기 소스 완전 일원화는 소비자(LLM 컨텍스트/리포트/영속)가 서로 달라 고위험·저이득이라
  **의도적으로 하지 않음** — 단일 쓰기 경로 + 이 불변식으로 분기를 차단하는 방식 채택.
- 테스트 전용(src 변경 없음). 전체 **2555 passed, 0 failed** (107 스위트).

## [2.7.10] — 2026-10-11

### 변경(Changed) — S4-3. god-object 해체(2): 플래그 출처 분류·확신도 클러스터를 flag_assess 로 분리
god-object 축소 2단계. 비실행 **플래그 provenance/confidence** 클러스터를 self 의존 없는
자유 함수로 `flag_assess` 모듈에 분리.
- **`flag_assess` 모듈 신설**: `flag_in_external_notes`(kb)·`classify_flag`(workspace·kb)·
  `assess_flags` — 전부 분류·판정 전용(실행 없음). self.workspace/self.kb 를 명시 인자로.
- **오케스트레이터 `_classify_flag`·`_flag_in_external_notes`·`_assess_flags` 는 얇은 위임**
  으로 축소(행위 보존 — `test_autonomous_exec` 가 쓰는 `_classify_flag` 시그니처 유지).
- 신규 `test_flag_assess.py` **7건**. orchestrator.py 2197→2098줄. 전체 **2549 passed, 0 failed**.

## [2.7.9] — 2026-10-11

### 변경(Changed) — S4-3. god-object 해체(1): 준비 생성기 클러스터를 preparations 모듈로 분리
Orchestrator(~2200줄·65 메서드) god-object 축소의 첫 단계. 응집도 높은 **비실행 '준비
생성기' 클러스터**(리버스쉘·클라우드·권한상승 플레이북·privesc 벡터 분석·해시 크래킹)를
self 상태 의존 없는 **자유 함수**로 `preparations` 모듈에 떼어냈다.
- **`preparations` 모듈 신설**: `prepare_revshells`·`prepare_cloud`·`prepare_privesc`·
  `privesc_analyze`·`prepare_crack` — 전부 '명시 인자 → report 변이' 생성 전용(실행·발사 없음).
- **오케스트레이터 메서드는 얇은 위임 래퍼로** 축소(행위 보존). 로직이 클래스 밖으로 나가
  god-object 표면이 줄고, 각 준비 함수를 run() 없이 **단위로 검증** 가능.
- 신규 `test_preparations.py` **9건**(IP 유무·OS 게이팅·sudo -l 벡터·해시 수집). 기존 2533건
  불변 → 외부 행위 보존. 전체 **2542 passed, 0 failed** (105 스위트).
- 비고: 실행 배선 클러스터(`_foothold_stage`·`_acquire_session`·`_exploit_exec_stage`)는
  발사 로직이라 **이번에도 제외**(사용자 커밋 영역). 이후 god-object 해체는 영속/분석 등 다른
  비실행 클러스터로 이어감.

## [2.7.8] — 2026-10-11

### 수정(Fixed) — S4-2. 플래그 상태원 단일 쓰기 경로(_record_flag) · 발판 플래그 누락 교정
구조 감사(상태원 중복 지도)가 플래그를 3곳(`OrchestrationReport.flags`·`WorldModel.flags`·
`SessionState.flags`)에 두고 포착·재개·발판이 제각기 이중쓰기함을 지적했다. 특히 **발판
경로(`_foothold_stage`)는 `world.add_flag` 만 불러**, 발판 세션으로 읽은 user/root 플래그가
`report.flags` 에 안 잡혀 `report.user_flag`/`root_flag`·`goal_reached`(= `report.flag_provenance`
의 exploit-derived 만 인정)가 **그 플래그를 영영 못 보던** 상태원 분기 결함이 있었다.
- **`_record_flag` 신설** — `report.flags`(중복제거) + `flag_provenance` + `world.flags` 를
  단일 경로로 함께 갱신. 포착(`_process`)·재개(`_restore`)·발판(`_foothold_stage`)의 산재
  이중쓰기를 전부 이 경로로 수렴.
- **발판 플래그 교정** — 발판 세션 직독 플래그를 `exploit-derived` provenance 와 함께
  `report.flags` 에 반영 → 이제 보고·goal_reached 가 정상 인식. **발판 세션 획득·전송(RCE 실행)
  로직은 한 줄도 바꾸지 않음** — '이미 읽은' 플래그의 상태 반영 경로만 교정.
- 신규 `test_s4_flag_ssot.py` **12건**: 동시 갱신·중복무시·prov 유무·발판 유래 user+root →
  goal_reached. 전체 **2533 passed, 0 failed** (104 스위트).

## [2.7.7] — 2026-10-10

### 추가(Added) — S0~S3 통합 E2E 회귀(connected.htb/FreePBX 체인) · 행위 변화 없음
구조 개선 S0~S3 가 **'한 번의 자율 실행 안에서'** 의존 체인을 완주하는지 검증하는 통합
테스트를 추가한다(테스트 전용 — src 변경 없음). 기존 단위 테스트는 각 스테이지를 사전
세팅된 world 로 따로 볼 뿐, 전체 `run()` 이 제품·버전을 스스로 발견해 ⭐ 까지 잇는 종단
경로는 커버하지 못했다 — 세션 내내 "고립 재현은 되는데 런타임은 매칭 없음"이던 ⭐52031
증상의 런타임 종단 회귀 가드.
- 신규 `test_e2e_freepbx_chain.py` **8건**: FreePBX vhost 핑거프린트(S0 원본증거) →
  searchsploit 조회 → ⭐ 버전매칭 1순위(52031) 숏리스트·실행계획까지, 전체 `run()` 으로 구동.
  음성 대조(제품 미상 시 ⭐ 없음 — 허위양성 방지) 포함. 네트워크 무접촉(FakeRunner).
- 전체 **2521 passed, 0 failed** (103 스위트).

## [2.7.6] — 2026-10-10

### 수정(Fixed) — S4-1. 자격증명 상태원 왕복(SSOT 비대칭 교정 · 재개 데이터 유실 버그)
구조 감사(상태원 중복 지도)가 찾은 실제 결손: 자격증명은 WorldModel·CredentialVault·
SessionState 3곳에 있는데 **`_persist` 는 `st.credentials` 에 쓰기만 하고 `_restore` 가
되읽지 않아**, `--resume` 재개 세션이 '수확한 자격증명'을 통째로 잃었다(findings·flags·plan·
analysis 는 왕복되는데 자격증명만 write-only였던 비대칭).
- **`CredentialVault.from_list`** 신설 — `to_list` 의 역(직렬화 dict→볼트, `add` 로 중복 제거).
- **`_restore` 가 `prior.credentials` 를 복원** — 볼트(재사용·`{user}/{pass}` 치환)와 월드
  (컨텍스트·prereq·권한레벨)를 startup 시드와 동일 형태로 함께 채운다. CLI·파일 자격증명과의
  중복은 `add`/`add_cred` 가 제거. 재개 세션이 이전 침투의 자격증명을 그대로 이어쓴다.
- 신규 `test_s4_cred_roundtrip.py` **10건**: `from_list` 왕복·중복제거·입력 내성 · resume 시
  볼트+월드 복원·비밀/도메인 보존·권한레벨 승격. 전체 **2513 passed, 0 failed** (102 스위트).
- 비고: 이는 S4(단일 상태원) 로드맵의 **저위험 1차 증분**. god-object 해체·4-컨테이너 통합 등
  고위험 재설계는 사용자 리뷰용으로 분리.

## [2.7.5] — 2026-10-10

### 변경(Changed) — S3. 의존 선언형 스테이지 스케줄러(암묵 스케줄링 → 1급 객체)
구조 감사가 지적한 "결정적 소비 스테이지의 '언제·어떤 순서로·재실행 여부'가 각 스테이지 내부
``_*_probed`` 가드와 호출부 하드코딩 순서에 **흩어져 있어** 순서가 깨지기 쉽고(S1 이 수동
재배치로 임시 교정) 종료 추론이 어렵다"는 문제의 구조 교정. 스케줄링을 선언적 1급 객체로 승격.
- **`scheduler` 모듈 신설**: `Stage(name, run, ready, key)` + `StageScheduler.run_to_fixpoint()`.
  각 스테이지가 전제(`ready`)와 '소비하는 상태 서명'(`key`)을 선언 → 스케줄러가 **생산자→소비자
  순서로, 입력이 바뀐(dirty) 스테이지만, 지역 고정점까지** 실행. 순수 로직(네트워크·LLM 없음).
- **오케스트레이터 결선**: 핑거프린트→버전프로브→익스조회→웹비밀 4개 소비 스테이지를 루프의
  2개 호출부(스윕 전/후)에서 스케줄러로 대체. `_seen` 은 스윕 간 유지 → 전역 멱등
  (기존 `_*_probed` 가드와 동일 의미, 이중 보장). **스테이지 본체·무해/생성 전용 경계 불변.**
- **행위 보존**: 전체 2503건 그린(스케줄러 단위 11건 신설 — 순서·dirty 재실행·고정점·중단·
  `max_passes` 유한성·reset). 기존 2492건 불변 → 리팩터가 외부 행위를 바꾸지 않음을 고정.

## [2.7.4] — 2026-10-10

### 변경(Changed) — S2. 고정점 반복(의존 체인 완주 — 스윕 예산 하드캡 재정의)
구조 감사가 지적한 "제품→버전→익스조회 의존 체인이 낮은 `max_sweeps`(기본 2~3)에 걸려 미완주"
문제의 교정. 스윕 루프를 '상태가 자라는 한 계속 도는' 고정점 반복으로 전환.
- **종료 기준 1차는 '성장 없음'**: `_world_fingerprint` 가 스윕 전후 불변이면 조기 종료(기존 로직
  유지). `max_sweeps` 는 폭주 방지용 **안전 상한(하드캡)** 으로 역할 재정의.
- **실전 기본 상향**: 자율 모드 CLI 기본 스윕을 `_FIXED_POINT_CAP`(10)으로(기존 3) → 깊은 의존
  체인도 완주. 전역 예산(`max_llm`·`max_enum`)·시간 예산·명령 중복제거가 유한성 유지.
- **명시 `--max-sweeps` 는 하드캡으로 존중**(기존 테스트 계약 보존). `max(..., _FIXED_POINT_CAP)`
  로 명시값을 덮어쓰던 중간 구현을 제거 → `max_sweeps=1` 은 정확히 1스윕.
- 회귀: 전체 2492건 그린. 실행 경계·승인 3관문 불변.

## [2.7.3] — 2026-10-10

### 변경(Changed) — S1. 파이프라인 결정성(스테이지 순서·성장 지표)
구조 감사가 지적한 "호출 순서가 데이터 의존 DAG와 반대 → 교차 사실이 항상 한 스윕 늦음" 문제의
저위험 교정(재배치·지표 보강, 재설계 아님).
- **스테이지 재배치**: 생산자 `_web_fingerprint_stage`(제품/버전 식별)를 소비자
  `_version_probe_stage`·`_exploit_lookup_stage` **앞으로** 이동.
- **스윕 내 소비 패스 추가**: enum 단계가 vhost 등록·웹 본문 수신으로 제품을 '이번 스윕에'
  식별하면, 단계 종료 후 핑거프린트·버전프로브·익스조회를 **한 번 더** 돌려 같은 스윕에 반영
  (다음 스윕까지 밀리지 않음). 전부 멱등 — 변화 없으면 no-op.
- **성장 지표 보강**: `_world_fingerprint`·`_plan_fingerprint` 에 `web_product`/`web_version`/
  `len(hosts_map)` 추가 → 웹앱 식별·vhost 등록만 자란 스윕이 '정체'로 오판돼 조기 종료되던
  버그 교정(그 결과 소비 스테이지가 영영 안 돌던 비결정성 해소).
- 회귀 테스트 `test_s1_determinism.py`(7건). 실행 경계·명령 생성 로직 불변.

## [2.7.2] — 2026-10-10

### 수정(Fixed) — S0. capture≠evaluate 구조 버그 교정 (⭐ 버전매칭 근본 수정)
구조 감사 결과: "고립 재현은 매칭되는데 런타임은 '매칭 없음'" 증상의 근본 원인은 **평가를
원본이 아니라 손실 요약본으로** 했기 때문. 핑거프린트/searchsploit 매칭 경로를 원본 증거로 전환.
- **`EnumFinding.raw_output` 신설** — 요약(`output`)과 분리된 분석 전용 원본(상한 20000, 비영속).
- **핑거프린트를 원본에서 수행** — `_run_vuln` 이 `finding.output`(parse_http 엄격 정규식으로 버전이
  걸러진 요약) 대신 `raw_output` 에서 `fingerprint_webapp` 실행 → `web_version` 이 비던 문제 해소.
- **searchsploit 매칭을 원본에서 파싱** — 요약 상위 12행 캡으로 13위 밖 PoC 가 소실되던 문제 해소
  (`_refresh_exploit_shortlist`).
- **`set_web_app` write-once 고착 해소** — 더 구체적 버전(기존을 점표기 접두로 포함, 예 16→16.0.40.7)
  으로 보강. docstring 과 코드 일치. 역방향·무관 값은 기존 유지.
- 회귀 테스트 `test_s0_raweval.py`(11건). 전부 내부 분석 로직 — 실행 경계 불변.

## [2.7.1] — 2026-10-10

### 추가(Added) — D. 공격↔방어 미러 라이트업 (ARTEX 아이디어, 클린룸)
ARTEX 의 "공격↔방어 미러 문서"(각 공격 능력마다 탐지·완화를 짝지음)를 클린룸 재구현.
- **`defense` 모듈**: 실제 **식별·공략한 취약점**(CVE/CWE·vuln 규칙 매칭·웹앱 제품)마다
  **탐지(Blue Team) + 완화(Remediation)** 를 짝지어 표로 생성. CWE 사전(SQLi/RCE/XSS/경로순회/
  업로드/역직렬화/SSRF/인증·인가 등) + 기법 키워드 추론 + 웹앱 n-day 노출 통제. 근거 없는 항목은
  만들지 않음(지어내지 않기, §3).
- **writeup 배선**: HTB v5 라이트업 §7 에 `7.1 포트 기준`/`7.2 취약점별 미러` 로 확장, Tistory
  §12(완화·대응)에 `12.1 취약점별 미러`/`12.2 공통 하드닝` 추가. 사용자 블루팀 템플릿 선호(§7)와 일치.
- 회귀 테스트 `test_defense.py`(11건). 생성 전용 — 문자열만 만든다.

## [2.7.0] — 2026-10-10

### 추가(Added) — A. 적대적 재검증(skeptic) 확신도 레이어
ARTEX(오픈소스 자율 펜테스트 에이전트)의 **retester**(별도 세션 재검증·"요청 한 번 실패 ≠ 해결"·
inconclusive 태도)와 "증거는 하네스가 포착" 원칙을 **클린룸 재구현**(AGPL 코드 미사용, 아이디어만).
- **`verify` 모듈**: 포착된 플래그를 '독립 재현' 관점에서 재채점 — `reproduced`(서로 다른 공략
  유래 명령 ≥2개에서 같은 값) · `single-source`(공략 1개) · `untrusted`(로컬/외부/추론만) ·
  `inconclusive`(형식·출처 불충분). provenance(출처 분류)에 더해 **확신도**를 분리해 LLM 의
  false-positive("풀었다 착각")를 줄인다.
- **오케스트레이터 배선**: 종료 시 `_assess_flags` 가 모든 플래그의 확신도를 `report.flag_confidence`
  에 싣고, 단일 출처 플래그는 **다른 방법으로 재읽기하는 독립 명령**(`xxd`/`od`/`sha256sum` 등,
  생성 전용)을 수동 제안에 1회 남겨 사람이 재현 확인하도록 한다. 신뢰 판정·조기종료 로직은 불변.
- **리포트 표시**: 🔎 PROVENANCE 섹션에 확신도(재현됨/단일 출처/미신뢰/미확정) 추가.
- 회귀 테스트 `test_verify.py`(17건). 전부 생성 전용 — 실행은 기존 3관문을 거친다.

## [2.6.34] — 2026-10-09

### 수정(Fixed)/진단 — ⭐ 매칭 누락 하드닝 + 진단
connected.htb 재실행에서 핑거프린트·vhost 열거는 정상인데 ⭐52031 이 여전히 '매칭 없음'으로
나오는 현상 추적. 파서·매처·숏리스트는 실제 저장 출력으로 재현 시 정상 매칭(has_version_match=
True)인데 런타임은 불일치 → 런타임 상태(version/hits)가 다르다는 뜻. 두 잠재 결함 교정 + 진단 추가:
- **`_refresh_exploit_shortlist` 가 `llm_findings` 도 스캔** — searchsploit 가 LLM 제안으로 실행되면
  llm_findings 에 저장돼 enum 만 보던 집계가 증거를 놓치던 가능성 제거.
- **`web_version` 공백 제거**(`.strip()`) — 접두 매칭 시 공백 혼입에 의한 오불일치 방어.
- **진단 노출**: 매칭 실패 시 제안에 `[진단] version=… · hits=… · hit_versions=[…]` 를 덧붙이고,
  감사 로그에 `shortlist_eval`(version·n_hits·matched·hit_versions) 이벤트 기록 → 다음 실행에서
  실제 런타임 값으로 원인을 특정.

## [2.6.33] — 2026-10-09

### 수정(Fixed) — vhost 미대응으로 자격 수확·핑거프린트가 헛돌던 문제 (connected.htb 재실행)
connected.htb 재실행에서 드러남: 웹앱이 **`connected.htb` vhost 에서만** 응답하는데, 열거가 IP
기본 vhost 를 때려 전부 404/301 로 끝나고 FreePBX 도 식별 못 하던 두 결함을 교정.
- **(A) 웹 비밀 열거 vhost 인식**: `_web_secret_stage` 가 등록된 vhost 로 `-H "Host: <vhost>"` 를
  붙여 **실제 앱**을 때린다(IP-만 프로브는 못 보므로 생략). 호스트명은 인젝션 방지 안전문자만 허용.
- **(B) 결정적 vhost 핑거프린트**: `_web_fingerprint_stage` 신설 — 제품 미상 & vhost 등록 시,
  vhost 로 리다이렉트를 따라가(`-L`) admin 200 본문의 `appver=FreePBX …` 를 코퍼스에 넣어 **LLM
  명령 편차와 무관하게** 제품/버전을 확정한다(302 에서 멈춰 FreePBX 미식별되던 문제 해소). 식별 후
  `_run_vuln` 즉시 반영 → 같은 스윕의 `searchsploit`·웹비밀(amportal.conf)·⭐PoC 로 이어짐.

### 안전(Safety)
- 둘 다 **읽기 전용 GET**(`-s`/`-L`, 쓰기·주입·실행 없음), 3관문 통과, **opt-in**
  (`--exploit-exec`/`--auto-poc`) 전용 → 기본 모드 명령 폭 불변. vhost·제품별 1회(멱등).
- 회귀 테스트 `test_web_secrets.py` 확장(24건): vhost Host 헤더·인젝션 방지·결정적 핑거프린트·
  식별 후 생략·vhost 미등록 생략.

## [2.6.32] — 2026-10-09

### 수정(Fixed) — 발판 채널 의존성 크래시 안전 degrade
- **`ModuleNotFoundError: requests` 로 실행 전체가 죽던 문제 수정**. ② `_foothold_stage` 배선
  이후, 웹 RCE 전송부(`shell_transport.web_http_fn`, `requests` 의존)가 미설치 환경에서
  import 되며 `--exploit-exec --auto-poc` 실행이 통째로 중단됐다(connected.htb 재실행에서 발현).
- `_acquire_session` 이 `shell_transport` import 를 **try/except(ImportError)** 로 감싸, 미설치
  시 크래시 대신 **'발판 미확보'로 안전하게 건너뛰고** 활성화 안내(`pip install requests` /
  `pip install -e ".[exploit]"`)를 수동 제안에 남긴다. requests 가 있을 때의 동작은 불변.
- `pyproject` 에 선택 의존성 그룹 **`exploit = ["requests>=2.25"]`** 추가(웹 RCE 채널용).
- 회귀 테스트 `test_foothold_degrade.py`(5건): import 실패 시 크래시 없음·None 반환·안내 노출·
  foothold_stage 조용한 종료.

## [2.6.31] — 2026-10-09

### 추가(Added) — ③ 발판 전 자격 수확(웹 노출 비밀/백업) + 폐루프
- **`web_secrets` 모듈 + `_web_secret_stage`** — 자동 루트 실패의 한 축(인증 필요 RCE 는 자격
  선확보가 전제)을 겨냥. 웹에 잘못 노출된 설정/백업 파일(`.env`, `config.php.bak`, `.git/config`,
  FreePBX `amportal.conf` 등)을 **읽기 전용 GET**(`curl -s`)으로 열거한다. 본문에서 평문 자격이
  나오면 기존 `_harvest_creds` 가 원시출력에서 `world.creds` 로 수확 → **①(b) 가 인증 필요 PoC
  (예: FreePBX 16 → 52031)를 자동 발사 큐에 올린다**(자격 선확보 → 인증 익스 폐루프 완성).
- **`_harvest_creds` 확장** — 일반 harvest 에 더해 설정파일 특수 키(FreePBX amportal 의
  `AMPDBUSER`/`AMPDBPASS` 등)도 파싱해, 노출된 설정 본문에서 자격을 놓치지 않는다.

### 안전(Safety)
- 전부 **읽기 전용 GET**(쓰기·인증·주입·실행 없음) — gobuster/curl 열거와 동일 위험군, 3관문 통과.
- **옵트인 전용**: 공격 지향 열거라 `--exploit-exec`/`--auto-poc` 일 때만 돈다 → 기본·순수 정찰
  모드의 명령 폭·예산은 불변. 호스트당 1회(멱등).
- 회귀 테스트 `test_web_secrets.py`(16건): 생성 데이터·GET 경계·폐루프(amportal→자격→인증 PoC
  큐잉)·멱등·옵트인 가드·웹 포트 부재 처리.

## [2.6.30] — 2026-10-09

### 수정(Fixed) — ⭐ PoC 자동선택 근본 교정 (connected.htb 회귀)
- **버전매칭 PoC 가 '매칭 없음'으로 오표기되던 근본 원인 수정** — 실전 connected.htb(FreePBX
  16.0.40.7)에서 `FreePBX 16 → 52031.php`(버전 접두 매칭)가 후보에서 누락되던 문제.
  - 원인: `_exploit_lookup_stage` 가 제품당 1회만 돌며 **그 순간의 단일 조회창(`before:`)**으로
    숏리스트를 **한 번만 평가·동결** → 버전이 enum 단계에서 늦게 확정되거나 searchsploit 증거가
    나중에 더 채워지면 조기 평가가 '매칭 없음'으로 굳었다.
  - 해결: 숏리스트 평가를 **`_refresh_exploit_shortlist`** 로 분리해 (1) 리포트 **전체**의
    searchsploit 산출을 모으고, (2) **최종 `web_version`**으로 재평가하며, (3) 매 스윕·종료
    시점에 **갱신**(중복 제안은 마커로 제거, 최신본만 유지). 생성 전용(파싱·제안·`--poc` 큐잉).
- **인증 필요(Authenticated) PoC 인지** — ⭐ 1순위가 인증형(제목 `auth`/잘린 `(Au`)인데 보유
  자격이 없으면 **자동 발사하지 않고** '자격 선확보' 로 안내한다(무인증 자동 익스로 뚫리지 않는
  대상을 헛발사·오표기하지 않음). 자격(`--cred`) 보유 시에는 동일 PoC 를 자동 발사 큐에 올린다.
- 회귀 테스트 추가: `test_exploit_lookup.py` — 전체 증거 재평가·인증 PoC 분기·중복 제거·늦은 버전 확정(8건).

## [2.6.29] — 2026-10-09

### 문서(Docs) — 정확성 교정
- **README/USAGE 의 `--auto-poc` 흐름 설명을 실제 코드 동작에 맞춰 정직하게 교정** — 과대광고 제거:
  - 실행 루프에 **실제로 도는 범위**만 "흐름"으로 표기: ⭐ 버전매칭 PoC 자동선택·발사 → (PoC 가 자격을
    뱉으면) SSH 발판 → 플래그 읽기.
  - **웹 RCE 발판 세션(`_foothold_stage`)** 과 **측면 이동 후보(`lateral_candidates`)** 는 코드에
    **정의만 되어 있고 실행 루프에 아직 배선되지 않음**을 명시(이전 문서는 "한 흐름으로 잇는다"고 과대 기술).
  - `_acquire_session` 채널 설명에서 **리버스셸 수신 경로 삭제**(현재 웹 RCE 분기만 활성 — #129 에서 도달
    불가능 역쉘 분기 제거됨). 역쉘 수신은 실제 경로 확인 후 재추가 예정으로 표기.
  - 이 배선(`_foothold_stage` 호출·소켓/HTTP 실행부)이 **RCE 실행 표면**으로 사용자 리포에서 연결됨을
    USAGE §10.3 비고·README 블록쿼트에 분명히 함.

## [2.6.28] — 2026-10-09

### 문서(Docs)
- **사용법/README 최신화** — 자동 루트 체인(`--exploit-exec` + `--auto-poc`)을 초보자도 바로 쓰도록 보강:
  - README: `--exploit-exec` 절의 구버전 문구("침입은 아직 자동화 안 함") 갱신 + **`--auto-poc` 설명 추가**
    (⭐ 버전매칭 PoC 자동선택·발사 → 발판 세션 → 자격수확 → 플래그, 발판 성립 검증으로 헛발판 배제).
    **초보자용 완전 자동 루트 한 줄**과 각 플래그 뜻을 명시.
  - QUICKSTART: 상황별 한 줄 표에 `🚀 완전 자동 루트 시도` 행 + 플래그 의미 설명 추가.
  - USAGE: **§10.3 PoC 자동 선택·발사(`--auto-poc`)** 신설(켜는 법·하는 일·발판 성립 검증·채널·승인·비고).
- 반영 명령: `assassin <t> --autonomous --llm claude --exploit-exec --auto-poc --html --json`.

## [2.6.27] — 2026-10-09

### 수정(Fixed)
- **`_acquire_session` 도달 불가능 역쉘 분기 제거(CI red 복구)**: 역쉘 분기가 웹 RCE 분기의
  `return None` 뒤에 와서 **절대 실행되지 않는 죽은 코드**였고, 그 안의 세미콜론(E702) 4건이
  ruff 를 red 로 만들었다(+ 페이로드를 `_safe_run` 로 로컬 실행하는 버그). 도달 불가능·린트
  위반 블록을 제거해 CI 복구. **웹 RCE 분기는 보존**(reachable·정상).
- 역쉘 수신 경로는 순서 4(connected.htb 재실행으로 실제 발판 경로 확인) 뒤 올바른 형태
  (리스너 스레드 + 타겟에서 페이로드 실행하는 `fire()` 콜러블 + 성립 검증)로 재추가 예정.

## [2.6.26] — 2026-10-09

### 변경(Changed) — 발판 획득에 성립 검증 적용 (순서 2)
- `_acquire_session`: WebRceSession 을 붙인 뒤 `looks_like_shell(ws.run(verify_probe_command()))`
  로 **실제 셸 성립을 검증** — id/uname 신호가 없으면(엔드포인트에 RCE 미성립) `None` 으로 폐기해
  **거짓 '발판 확보'를 방지**. 엔드포인트도 `self.rce_url`(②의 실제 PoC 가 성립시킨 URL) 우선,
  없으면 기본 config.php 로 유연화.
- import 정렬(I001) 정리.

### 참고(Note)
- `ws.run(...)`·`web_http_fn` 의 실제 HTTP 실행은 RCE 실행 표면(사용자 `_acquire_session`·
  `shell_transport`). 검증기 `session_verify`·세션 추상화는 생성 전용(머지됨).

## [2.6.25] — 2026-10-09

### 추가(Added) — 발판 성립 검증 헬퍼 (자동 루트 체인 보강 1)
- **`session_verify.looks_like_shell(output)`**(생성 전용): `session.run("id")` 출력으로 **진짜
  셸인지 헛발판인지** 판정하는 순수 predicate. WebRceSession 을 붙여도 해당 엔드포인트에 실제
  RCE 가 성립 안 했으면 `run` 이 로그인 페이지 HTML·빈 응답을 돌려주는데(헛발판), 이를 걸러낸다.
  - 생존 신호(`uid=…(…)`·`gid=…`·whoami 한 줄·`uname` Linux)만 True, HTML/form/빈 응답은 False,
    애매하면 보수적으로 False(섣부른 '발판 확보' 금지).
  - `verify_probe_command()` — 무해한 검증 프로브(`id; uname -a`) 문자열 생성.
- **테스트**: `test_session_verify.py`(15) — 진짜 셸·헛발판·혼합·경계 자기점검.

### 안전(Safety)
- 파싱·판정만 — 실행 없음(subprocess/socket/requests 미임포트). 실제 `run("id")` 호출은
  호출측(사용자 `_acquire_session`)의 몫(RCE 실행 표면). 헛발판이면 세션을 `None` 으로 폐기하는
  데 쓴다: `if not looks_like_shell(ws.run(verify_probe_command())): return None`.

## [2.6.24] — 2026-10-09

### 수정(Fixed)
- **치명: `orchestrator.py` import 불가 복구** — 발판 배선 커밋에서 `_foothold_stage` 메서드의
  `def` 들여쓰기가 8칸(클래스 메서드는 4칸)이라 본문과 같은 레벨 → IndentationError 로 모듈
  전체가 import 불가(에이전트 다운)였다. `def` 를 4칸으로 바로잡아 복구(본문 로직 불변).
- `shell_transport.py` 세미콜론 다중문(E702)·메서드 사이 빈 줄/후행 공백 등 린트 정리.
  소켓/HTTP 실행 로직은 그대로 — 포맷만 교정.

### 참고(Note)
- `_foothold_stage` 는 현재 `_acquire_session` 이 `None` 을 돌려 아무 발판도 실행하지 않는 안전
  스텁 상태(import·CI 통과). 실제 발판 획득(리버스셸 수신/웹RCE attach)은 사용자 리포에서
  단계적으로 채운다(RCE 실행 표면). `shell_transport` 는 아직 어디서도 import 되지 않는 휴면
  상태라 `requests` 미설치여도 패키지 로드에 영향 없음.

## [2.6.23] — 2026-10-09

### 추가(Added) — 자동 루트 체인 E단계: 플래그 읽기를 발판 셸로(채널 무관)
- **`flag_read`**(생성 전용): 지금까지 SSH 전용(sshpass)이던 플래그 읽기를 **`ShellSession`
  인터페이스로** 수행 → 리버스셸(B)·웹RCE(C) 발판에서도 **같은 코드로** user.txt/root.txt 수집.
  - `read_flags(session, flag_kind)` — 세션으로 플래그 파일을 읽어 `{kind: value}` 수집.
    user+root 확보 시 조기 종료, `run` 예외 흡수, 죽은/없는 세션은 빈 결과(섣부른 실행 없음).
  - `flag_read_commands(flag_kind)` — boot2root(user/root)·single(CTF) 별 읽기 명령 생성.
- **테스트**: `test_flag_read.py`(16) — 채널 무관 수집·부분수집·조기종료·예외흡수·single·경계.

### 안전(Safety)
- 명령 생성·출력 분류(flag.scan) 글루만 — 실제 실행은 `session.run`→발판 transport(사용자 주입,
  RCE 표면). subprocess/socket 미임포트. 자동 루트 체인 A~E 생성 전용 스캐폴딩 완료.

## [2.6.22] — 2026-10-09

### 추가(Added) — 자동 루트 체인 D단계: 발판 후 자격 수확
- **`cred_sources`**(생성 전용): 웹 RCE 로 www-data 를 얻어도 user.txt 는 보통 다른 유저 소유라
  못 읽는다 — 돌파구인 '설정/DB 자격 → 측면이동'의 재료를 생성.
  - `config_reads(product)` — 발판 셸에서 읽을 설정/민감파일 `cat … 2>/dev/null` 목록
    (freepbx→amportal.conf·manager.conf, wordpress→wp-config.php, drupal→settings.php … + 일반 .env/bash_history/id_rsa).
  - `parse_config_creds(text)` — 일반 harvest + **FreePBX amportal 키**(AMPDBUSER/AMPDBPASS·
    AMPMGRUSER/AMPMGRPASS 짝) 추출, 출처 라벨 포함.
  - `lateral_candidates(creds, users, target)` — 자격×유저로 su/ssh **비번 재사용 교차** 후보
    명령 생성. 셸 인젝션 안전값만 명령에 투입(신뢰불가 출처 방어).
- **테스트**: `test_cred_sources.py`(22) — 파일 목록·amportal/URL 파싱·측면이동 교차·인젝션 필터·경계.

### 안전(Safety)
- 명령/자격 **문자열 생성·파싱만** — cat·su·ssh 실행 안 함(발판 셸 실제 실행은 사용자 ShellSession
  발사=RCE 표면). subprocess/socket/paramiko 미임포트.

## [2.6.21] — 2026-10-09

### 추가(Added) — 자동 루트 체인 C단계: 웹 RCE 명령 채널
- **`shell_session.WebRceSession`**(생성 전용): PoC 가 노출한 'cmd= 엔드포인트'로 임의 명령을
  실행하는 `ShellSession` 구현. 웹 RCE 는 SSH user:pass 가 아니라 **www-data 코드실행**을 주는
  머신형 공략의 흔한 발판 — B의 리버스셸과 함께 '발판 채널'의 두 축.
  - `build_request(cmd)` — 명령을 query/body/header 중 지정 위치에 넣은 HTTP 요청 사양 생성.
  - 명령 프레이밍(완료 마커)·출력 파싱으로 HTML 에 섞인 출력에서도 본문·종료코드 추출.
- **테스트**: `test_shell_session.py` WebRceSession(주입 위치·extra_params·미주입 거부·프레이밍) — 총 42.

### 안전(Safety)
- 실제 HTTP 요청은 **주입된 `http_fn(spec)` 가 수행**(= RCE 실행 표면, 사용자 구현). 이 클래스는
  요청 사양·프레이밍·파싱만 만든다 — requests/urllib/http 미임포트. http_fn 미주입이면 run() 거부.

## [2.6.20] — 2026-10-09

### 추가(Added) — 자동 루트 체인 B단계: 발판 셸 세션 추상화
- **`shell_session.ShellSession`**(생성 전용): 획득한 셸을 채널 종류(SSH one-shot·리버스셸·
  웹RCE)와 무관하게 '한 줄 명령 실행→출력'으로 다루는 공통 인터페이스. 자동 루트 실패의 근본
  원인(발판 채널 부재)을 메우는 **백본**.
  - `CommandRunnerSession` — one-shot 러너(SSH 등) 어댑터. `wrap(cmd)`+`run_fn(wrapped)` 조합만.
  - `ReverseShellSession` — 리버스셸 수신 세션: 리스너 명령·페이로드 생성(revshell 재사용),
    상태관리(INIT/LISTENING/CONNECTED/CLOSED), 명령 프레이밍(완료 마커+종료코드)·마커 파싱.
  - `frame_command`/`strip_marker` — 경계 없는 셸 출력에서 본문·종료코드 분리(ANSI 제거 포함).
- **테스트**: `test_shell_session.py`(28) — ABC·어댑터·프레이밍/파싱·상태전이·경계 자기점검.

### 안전(Safety)
- 이 모듈은 **소켓 I/O·원격 실행을 직접 하지 않는다.** 실제 accept/recv/send 는 사용자가
  `attach(transport)`/`run_fn` 로 주입하는 콜러블의 몫(= RCE 실행 표면). transport 미주입 세션은
  `alive=False` 이며 `run()` 을 명확한 오류로 거부한다(섣부른 실행 방지). 소켓/subprocess 미임포트.

## [2.6.19] — 2026-10-09

### 추가(Added) — 자동 루트 체인 보강 A단계
- **PoC 정확 호출 조립**(`exploit_fetch.build_invocation`, 생성 전용): 받은 PoC '소스'를
  `analyze_poc` 로 정적분석해 **locator 추측보다 정밀한 실행 호출(제안)**을 조립한다.
  transport(http/https/tcp)·LHOST 필요 여부·usage 를 실제 소스에서 판단하고, usage 가 요구하는
  인자 수가 채운 것보다 많으면 **'인자 부족'으로 표시**(섣부른 자동실행 방지)·확신도(high/low) 부여.
  - `PocInvocation{command, usage, needs_lhost, confidence, notes}`.
  - 역쉘 PoC 는 LHOST·리스너 필요를 알리고 발판 세션(B)과 함께 쓰도록 안내.
- **테스트**: `test_exploit_fetch.py` build_invocation(인자 충족/부족·역쉘·usage 미검출) 가드(43).

### 참고(Note)
- 자동 루트 실패의 근본 원인(발판 셸 채널 부재) 보강의 첫 단계. 실제 fetch(`searchsploit -m`)
  실행 후 소스를 읽어 `build_invocation` 으로 명령을 만들고 실행하는 연결은 사용자 리포의
  `--exploit-exec` 스테이지 몫(RCE 실행 표면). 본 모듈은 **문자열·메타 생성만** 한다.

## [2.6.18] — 2026-10-09

### 수정(Fixed) — connected.htb 실전 피드백
- **단독 major 버전 매칭 실패**: 실전에서 `FreePBX 16.0.40.7` 을 탐지하고도 searchsploit 결과
  `FreePBX 16 - Remote Code Execution` 와 **매칭이 안 돼** ⭐ 자동선택을 놓쳤다. 매칭이 **점표기
  버전만** 인식(16.0.x)하고 제목의 **단독 major('16')** 를 못 뽑던 문제. `parse_searchsploit` 가
  제품명 뒤 단독 major(`_MAJOR_RE`, 예 'FreePBX 16'·'Drupal 7')를 버전으로 보강 → `16.0.40.7`
  ↔ `FreePBX 16 RCE`(52031) 가 ⭐ 1순위로 선택된다. (CVE 연도·괄호 숫자·'< 7.7' 등 글자 뒤가
  아닌 숫자는 오탐 억제.)
- **'버전 미상' 오표기**: 버전을 **확인했는데도**(①이 잡음) 매칭 PoC 가 없으면 "버전 미상 — 확인
  후 대조 필요" 로 떠서 ①의 성과를 가렸다. 이제 **버전 확인됨 · 단 매칭 PoC 없음** 으로 정직하게
  구분하고, major 계열 재검색(`searchsploit {prod} {major}`)을 안내한다.

### 추가(Added)
- **테스트**: `test_searchsploit.py` 단독 major 추출·매칭·오탐 억제(connected.htb 회귀), 24건.
  `test_exploit_lookup.py` '버전 확인+매칭 없음' 정직 표기 가드.

## [2.6.17] — 2026-10-09

### 추가(Added)
- **privesc 비대화형(one-shot) 상승 플랜**(`privesc_analyze`, 생성 전용): 각 벡터에 TTY 없는
  one-shot SSH(`sshpass ssh "<cmd>"`)에서도 동작하는 **비대화형 상승 템플릿**을 추가.
  `PrivescVector.oneshot(payload)` 가 `{payload}`(root 로 돌릴 한 줄)·`{bin}` 을 치환해
  '대화형 `/bin/sh` 스폰 없이' payload 를 root 로 실행하는 명령을 생성한다.
  - `oneshot("id")` → uid=0 검증용, `oneshot("cat /root/root.txt")` → **루트 플래그 직독**.
  - 커브셋: find/awk/python(3)/perl/ruby/bash/sh/env/vim/vi/tar/node/docker 의 sudo·suid·cap 형태.
  - 바이너리 **버전 접미 정규화**(`python3.8`→`python3`→`python`)로 sudo/suid 매칭률 개선.
  - `render_vectors` 가 대화형/비대화형 두 줄을 함께 노출.
- **테스트**: `test_privesc_analyze.py` one-shot 생성·버전접미 매칭·payload 치환·경계 가드 추가(37).

### 안전(Safety)
- one-shot 템플릿도 **문자열 생성만** — 실행 없음(RCE/권한상승 표면 없음, 생성 전용 경계).
  ③ 폐루프 발사(사용자 리포)에서 `v.plan` 대신 `v.oneshot("id")`/`v.oneshot("cat /root/root.txt")`
  를 쓰면 one-shot SSH 에서 uid=0 검증·루트 플래그 직독이 성립한다(대화형 플랜의 한계 해소).

## [2.6.16] — 2026-10-09

### 수정(Fixed)
- **치명: `Orchestrator` 생성 불가(NameError)** — `--auto-poc`(②d) 실행 배선에서 `__init__`
  본문의 `self.auto_poc = auto_poc` 는 추가됐으나 **시그니처에 `auto_poc` 파라미터가 누락**돼
  모든 `Orchestrator()` 생성이 `NameError: name 'auto_poc' is not defined` 로 깨지던 문제
  수정(에이전트 전체 실행 불가 상태였음). 시그니처에 `auto_poc: bool = False` 추가.
- 후행 공백(W291) 3곳 정리(`main.py`·`orchestrator.py`), RCE-표면 주석 들여쓰기 정리.
- `--auto-poc` 플래그 추가 반영해 **README CLI 옵션 표 재생성**(gen_cli_docs).

### 추가(Added)
- **테스트**: `test_auto_poc_wiring.py`(6) — `auto_poc` 파라미터 수용(기본 False)·`exploit_exec`
  +`auto_poc` 시 ⭐ 계획 `poc_commands` 자동 투입·꺼짐 시 제안만. NameError 회귀 가드.

### 참고(Note)
- `--auto-poc`/privesc 폐루프 발사 로직은 사용자 리포 커밋(RCE/권한상승 실행 표면). 본 릴리스는
  그 배선의 **실행 차단 버그 수정 + 린트/문서 정합 + 회귀 가드**까지만 포함한다.

## [2.6.15] — 2026-10-09

### 추가(Added)
- **권한상승 벡터 자동 분석**(③ 폐루프 '후보 선정', 생성 전용 `privesc_analyze`): 획득한 셸에서
  이미 실행된 privesc 열거 출력(`sudo -l`·SUID `find`·`getcap`)을 **파싱**해 구체적 상승 벡터를
  **확신도순 랭킹**하고, GTFOBins 식 상승 **제안 명령(문자열)**을 만든다.
  - `analyze_sudo` — NOPASSWD/허용 바이너리·`(ALL) ALL` 전체 sudo 탐지
  - `analyze_suid` — 비표준 SUID 바이너리(표준/무해 목록 제외) 탐지
  - `analyze_capabilities` — `cap_setuid+ep` 인터프리터 탐지
  - `analyze_enum`/`render_vectors` — 통합·중복 제거·랭킹·사람용 요약
  - GTFOBins 커브셋(find/vim/awk/python/perl/tar/… sudo·suid·cap 템플릿) — 공개 문서 기반.
- `orchestrator._privesc_analyze_stage` — Linux 에서 findings 열거 출력을 분석해 랭킹 벡터를
  수동 제안으로 surface(`report.privesc_vectors`).
- **테스트**: `test_privesc_analyze.py`(28) — sudo/suid/capability 파싱·랭킹·중복 제거·경계
  자기점검(실행/네트워크 모듈 미임포트).

### 안전(Safety)
- `privesc_analyze` 는 **파싱·랭킹·제안 문자열 생성만** 한다 — 명령을 **실행하지 않는다**
  (RCE/권한상승 표면 없음, 생성 전용 경계). 제안은 사람이 **획득한 셸에서** 실행한다.
- 폐루프의 '실제 실행 → root 확인 → world 권한레벨 전이 → 재열거'(발사) 연결은 사용자 리포의
  실행 스테이지(`target_shell`) 몫으로 남긴다.

## [2.6.14] — 2026-10-09

### 추가(Added)
- **PoC 정적 분석·실행 '계획 생성'**(② 기반, 생성 전용 `exploit_fetch`): ⭐ 버전 매칭된
  1순위 PoC 에 대해 **받기 명령**(`searchsploit -m <id>`)과 **실행 계획 초안**
  (`--exploit-exec --poc "<인터프리터> <PoC> <타겟/URL> [LHOST]"`)을 자동으로 만들어
  수동 제안에 붙인다. 사람이 `--poc` 문자열을 손으로 타이핑하지 않아도 되도록 '초안'을 생성.
  - `extract_edb_id`/`poc_language`/`analyze_poc`/`fetch_command`/`plan_poc_command`:
    PoC locator·소스에서 EDB-ID·언어·전송방식(http/https/tcp)·필요 인자(RHOST/LHOST)·대상
    버전·위험유형(rce/authbypass/lfi)을 **파싱**하고, 실행 명령 문자열을 **생성**.
  - 웹앱 PoC 는 관측된 베이스 스킴(https 우선)으로 타겟을 URL 화, 역쉘 PoC 는 LHOST
    placeholder(`<공격자 VPN IP>`)를 남긴다.
- **테스트**: `test_exploit_fetch.py`(33) — EDB-ID/언어 추정·정적 분석·계획 생성·경계
  자기점검(실행/네트워크 모듈 미임포트). `test_exploit_lookup.py` 에 실행 계획 제시 가드 추가.

### 안전(Safety)
- `exploit_fetch` 는 **파싱·문자열 생성만** 한다 — PoC 를 **다운로드·실행하지 않는다**
  (RCE 표면 없음, 생성 전용 경계). 생성된 계획은 사람 검토 + 3관문 + `--poc` 로만 실행된다.
  실제 자동 실행(계획 → 발사) 연결은 사용자 리포의 `--exploit-exec` 스테이지 몫으로 남긴다.

## [2.6.13] — 2026-10-09

### 추가(Added)
- **버전 노출 능동 프로브**(① 버전 탐지 강화): 웹앱 **제품은 식별됐으나 버전이 미상**일 때,
  제품별로 문서화된 '버전 노출' 경로를 **무해한 GET**(`curl -sik`)으로 긁어 버전을 집어낸다
  (제품당 1회·멱등). FreePBX(`/admin/config.php`, `/admin/`, `/`)·Elastix·Drupal(`/CHANGELOG.txt`)
  등록. `-i`(헤더 포함)로 받아 `parse_http` 가 활성화되게 하여, 버전이 본문 깊숙이 있어도
  `app_version` 으로 추출된다(200자 트렁케이트에도 생존). 프로브 출력을 `_run_vuln` 이
  재핑거프린트해 월드에 버전을 반영 → 바로 이어지는 공개 익스 조회에서 **⭐ 버전 매칭 PoC
  자동 선택**이 가능해진다.
  - 안전: 프로브는 **조회 GET 뿐**(익스/RCE 아님) — 생성 전용 경계 유지. `exploits.probes_for`.
  - 정직성: 끝내 버전이 안 보이면 **'미상' 유지**(섣부른 단정 금지).
- **베이스 URL 유도**(`_web_bases`): 관측된 열린 웹 포트에서 `scheme://ip[:port]` 를 만든다
  (TLS 판정: 서비스명/포트, 표준 포트는 생략, https 우선).
- **테스트**: `test_version_probe.py`(17) — 레지스트리·베이스 URL·게이트 경유 프로브·버전 추출·
  멱등·미노출 시 미상 유지.

## [2.6.12] — 2026-10-09

### 추가(Added)
- **웹앱 버전 능동 추출**(`parse_http` app_version): HTTP 응답 본문에서 **'알려진 앱 이름 + 인접
  버전'**(FreePBX·WordPress·Joomla·Drupal·Tomcat·Jenkins·Grafana·GitLab·Gitea·phpMyAdmin·Nextcloud·
  osTicket, 2마디 이상 점표기)을 추출해 `summary()` 에 `appver=…` 로 노출 → 핑거프린트가 타겟의
  **실제 버전**을 잡는다. 앱 이름에 인접한 버전만 매칭하므로 라이브러리 버전(bootstrap-3.3.7 등)은
  오탐하지 않는다. 버전이 잡히면 ⭐ PoC 자동 선택이 작동. (버전을 노출하지 않는 설치는 여전히
  '미상' — 그땐 사람이 확인, 과장 없음.)
- **테스트**: `test_observation.py` 앱 버전 추출(노출 시 추출·라이브러리 오탐 없음) 가드.

## [2.6.11] — 2026-10-09

### 수정(Fixed)
- **웹앱 버전 오탐**: 실전에서 `(버전 17.0.2 대조)` 로 뜬 버전이 타겟 값이 아니라 **searchsploit
  결과 제목('FreePBX 17.0.2 - RCE')에서 긁힌 값**이었다. `_run_vuln` 의 핑거프린트 코퍼스에서
  **searchsploit(익스 DB) 출력을 제외** → 버전은 실제 타겟 응답(HTTP 제목·배너·헤더)에서만 신뢰.
- **요약 재파싱 제목 오염**: ⭐ 후보 제목에 `searchsploit: N건 —` 접두·`;` 구분자가 섞였다.
  파서가 선행 요약 접두·`;` 를 제거하도록 정리.

### 변경(Changed)
- **⭐ 자동 선택은 '실제 버전 매칭'이 있을 때만**: 버전 미상이면 임의의 첫 결과를 ⭐로
  오해시키지 않고, '버전 확인 후 대조' 안내(+버전 확인 명령)를 제시한다(정직성). `has_version_match`
  추가. 버전이 식별되고 매칭 후보가 있으면 1순위를 ⭐로 자동 선택하고 `searchsploit -m <id>` 제시.

## [2.6.10] — 2026-10-09

### 수정(Fixed)
- **searchsploit 결과가 200자 트렁케이트로 날아가 PoC 후보가 안 뽑히던 문제**: 실전에서
  `🎯 익스플로잇 후보` 묶음에 note 만 뜨고 ⭐ PoC 후보 목록이 비었다. 원인은 요약기 폴백이
  모든 출력을 200자로 자르는데, searchsploit 표는 헤더 뒤 익스 행('제목 | 경로')이 그 뒤에
  있어 통째로 잘렸던 것. `summarize_tool_output` 에 **searchsploit 전용 요약**을 추가해
  `제목 | 경로` 쌍을 보존(상위 12건) → 하류 `_exploit_lookup_stage` 가 재파싱해 ⭐ 1순위·후보
  목록을 정상 표시한다. 화면 요약도 더 읽기 쉬워짐(`searchsploit: N건 — …`).

## [2.6.9] — 2026-10-09

실전(connected.htb) 피드백 — PoC 후보가 터미널에 안 보이고, 요약된 출력에서 파싱이 어긋나던
문제를 고치고, 1순위 PoC 자동 선택(⭐)을 추가. 실행 경계(생성 전용)는 그대로.

### 수정(Fixed)
- **searchsploit 파싱이 요약(collapsed) 출력에서 어긋남**: `finding.output` 은 요약기가 줄바꿈을
  공백으로 합치는데, 기존 라인 기반 파서가 전체를 1개 항목으로 오인했다. 토큰 기반(정규식)으로
  바꿔 '제목 | locator(경로/URL)' 을 항목별로 정확히 분리(헤더 'Path'·구분선 자동 제외, `-w` URL
  지원). collapsed·raw 둘 다 견고.
- **PoC 후보가 터미널에 안 보임**: 공개 익스 후보가 '기타 안내'로 분류돼 6개 컷오프에 밀려
  숨겨졌다. 전용 묶음 **`🎯 익스플로잇 후보 — PoC 고르기`** 로 맨 위에, 전부 표시(자율 풀이의
  핵심 결정이라 자르지 않음).

### 추가(Added)
- **1순위 PoC 자동 선택(⭐)**: 버전 접두 매칭으로 추려진 후보 중 1순위를 ⭐로 자동 선택하고,
  받아 검토할 명령(`searchsploit -m <edb-id>`)까지 제시. 실제 실행은 사람이 `--exploit-exec
  --poc` 로(생성 전용 경계 유지 — 자동 선택까지, 자동 실행은 옵트인 수동 트리거).
- **테스트**: `test_exploit_view.py`(전용 묶음·전부 표시 회귀 가드) + `test_searchsploit.py`
  collapsed/URL 파싱 가드 + `test_exploit_lookup.py` ⭐·fetch 검증.

## [2.6.8] — 2026-10-09

### 추가(Added)
- **searchsploit 결과 파싱 + 대상 버전 매칭**(`searchsploit.py`): 레지스트리가 자동 실행한
  `searchsploit <product>` 출력을 파싱해(제목·exploit-db locator·제목 내 버전), 핑거프린트된
  `world.web_version` 과 **접두 호환 매칭**으로 '대상 버전에 맞는 PoC'를 앞세워 상위 N개로
  추린다. access 단계 수동 제안에 `# <product> PoC 후보(버전 … 대조)` 로 표시 → 사람/LLM 이
  고를 선택지를 좁혀 준다. 버전 미상이면 상위 후보를 그대로 제시(대조는 사람이).
  · **안전 경계**: 파싱·추림만 — PoC 실행·다운로드·선택을 하지 않는다(생성 전용 유지).
- **테스트**: `test_searchsploit.py`(파서·버전 매칭 11건) + `test_exploit_lookup.py` 통합(후보 추림).

## [2.6.7] — 2026-10-09

### 추가(Added)
- **Exploit 레지스트리 제품별 공략 안내(`note`)**: 레지스트리를 `ExploitEntry(lookup, note)` 로
  확장해, 각 제품(FreePBX·Elastix·WordPress·Joomla·Drupal·Tomcat·Jenkins·Grafana·GitLab·
  Gitea·phpMyAdmin·Nextcloud·osTicket)에 '어디를(패널·경로) 어떤 취약 유형으로 볼지'의 일반
  가이드를 달았다. access 단계의 공개 익스 후보 수동 제안에 이 note 가 함께 표시된다
  (예: FreePBX → admin 패널·recordings/ajax·버전 대조·약한 관리자 자격). `note_for()` 추가.
  · **안전 경계**: note 는 '공략 각도' 설명일 뿐 PoC·익스·실행 명령이 아니다. lookup 은 여전히
    searchsploit 조회만(생성 전용·RCE 표면 금지 유지).

## [2.6.6] — 2026-10-09

### 추가(Added)
- **Exploit 레지스트리(3단계 기반, `exploits.py`)**: 핑거프린트된 웹앱 제품키
  (`world.web_product`, 2.6.4)에 맞는 **공개 익스 '조회' 명령**(searchsploit)을 access 단계에서
  게이트로 올린다(제품당 1회·멱등). 지원: FreePBX·Elastix·WordPress·Joomla·Drupal·Tomcat·
  Jenkins·Grafana·GitLab·Gitea·phpMyAdmin·Nextcloud·osTicket. 조회 결과(버전별 공개 익스
  목록)는 enum_findings 에 남아 다음 분석·명령 생성에 되먹여지고, 특정된 PoC 는 **대상 버전
  대조 후 사람/LLM 이 골라 3관문으로 실행**한다.
  · **안전 경계**: 레지스트리에는 searchsploit **조회 명령만** 담긴다 — 실제 익스 실행 명령·
    PoC 코드·원격 RCE 는 하드코딩하지 않는다(생성 전용 경계·RCE 표면 금지 유지).
- **테스트**: `test_exploit_lookup.py`(레지스트리 데이터·게이트 경유 조회·캡처·멱등, 10건).

## [2.6.5] — 2026-10-09

실제 머신 실행 중 드러난 LLM 신뢰성 문제(하이브리드 두뇌가 400 에러·거절로 사실상
멈춤)와 발판 단계 점검을 다룬다. 안전 경계(생성 전용·3관문)는 그대로.

### 수정(Fixed)
- **LLM 오류 원인 가시화**: HybridRouter 가 백엔드 오류를 80자로 잘라 보관해, API
  400(invalid_request_error)의 **핵심 message 가 가려져 진단 불가**였다. 이제 `_err_text`
  가 anthropic `body.error.message` 를 우선 뽑아 넉넉히(300자) 보관하고, **차단되기 전에도**
  라우팅 요약에 `최근오류: …` 로 1건 노출한다(간헐 400 추적용).
- **빈 content 요청 가드**(ClaudeProvider): 빈 사용자/시스템 프롬프트는 Anthropic API 가
  400 으로 거부한다 — 상태 변화 없는 라운드 등에서 빈 프롬프트가 넘어가면 요청 자체가 실패하므로,
  빈 user 는 최소 지시로 대체하고 빈 system 블록은 생략한다.

### 변경(Changed)
- **exploit-exec 발판 단계(2단계 읽기 되먹임)**: 발판에서 읽은 privesc 열거·플래그 출력을
  스테이지 종료 후 `_run_vuln` 으로 재스캔해 새 크리덴셜·CVE·플래그를 월드/분석에 반영한다
  (다음 분석이 'GTFOBins 다음 수'를 제안하도록). 열거 되먹임만 — 자동 익스 실행이 아니다.
  목표 달성 시 자격 루프를 즉시 빠져나오도록 정리(return→break).

### 추가(Added)
- **테스트**: `test_exploit_exec_stage.py`(1단계 점검 — 스킵 조건·게이트 경유 실행·플래그
  캡처·provenance·sshpass 래핑, 10건), `test_llm_errdiag.py`(오류 진단 노출 회귀 가드, 6건).

## [2.6.4] — 2026-10-09

실제 머신(FreePBX 박스) 실행 피드백 반영 — 열거가 리드를 충분히 파기 전에 멈추지 않도록
자율 enum 예산을 올리고, 관측된 웹앱 제품/버전을 식별해 공개 익스 조회를 자동 구체화한다.

### 추가(Added)
- **웹앱 핑거프린트 → `{product}`/`{version}` 자동 치환**(`vuln.fingerprint_webapp`,
  `WorldModel.set_web_app`, `Orchestrator._fill_fingerprint`): 관측 코퍼스(제목·generator·
  Server/X-Powered-By 헤더·enum 출력)에서 알려진 웹앱(FreePBX·WordPress·Joomla·Drupal·
  Tomcat·Jenkins·Grafana·GitLab·Gitea·phpMyAdmin·Nextcloud·osTicket·Elastix)의 제품키·
  버전을 식별해 월드에 기록한다. KB 제안의 `searchsploit {product} {version}` 같은
  placeholder 가 '관측된 실제 값'(`searchsploit freepbx 15.0.16.75`, 버전 미상이면
  `searchsploit freepbx`)으로 치환돼 **수동 제안이 아닌 자동 실행 후보**가 된다. 미식별이면
  placeholder 를 그대로 둬(섣부른 치환 금지) 기존처럼 수동 제안으로 남긴다. 웹앱 미식별 시
  nmap `-sV` 서비스 제품으로 폴백. 외부 조회 없이 관측 텍스트만 매칭(P1 유지).

### 변경(Changed)
- **자율(`--autonomous`) enum 예산 상향**: `--max-enum` 자율 기본값 10 → **24**. 실제 머신에선
  10개로는 유효 후속 명령이 큐에 남은 채 조기 종료됐다(연결된 리드를 덜 팜). 2.6.2 의 반복
  억제 + 명령 중복제거 + 상태 정체 조기종료가 상한을 안전하게 유지하므로 폭을 넓혔다
  (명시 `--max-enum`/설정값이 있으면 그대로 우선).

## [2.6.3] — 2026-10-09

### 추가(Added)
- **발판 자동 실행(`--exploit-exec`, 옵트인·기본 OFF)**: 확보한 **평문 자격**(열거 또는
  `--cred user:pass`)으로 SSH 발판을 잡아 `user.txt`/`root.txt` 를 자동으로 읽고, 권한상승
  **열거**(`id`·`sudo -l`·SUID·capabilities — 파괴 없음)까지 기존 3관문(검증·범위·승인)을 거쳐
  실행한다. 해시·빈 자격은 건너뛰고, 22번 닫힘·`sshpass` 미설치면 조용히 스킵(감사 로그에 사유).
  침입(익스플로잇) 자체는 아직 자동화하지 않으며(자격이 이미 있는 Easy 머신용), 플래그 확보 시
  🏁 SOLVED 패널에 값·출처(공략 유래=검증)를 표시. OFF 일 때 동작은 이전과 100% 동일.

### 문서(Docs)
- **README·docs/USAGE 최신화**: `--exploit-exec`(§10.2)·🏁 SOLVED 결과화면(§4)·vhost 자동
  이름해석·VM 기본 실행환경 설정(§12)을 반영하고, 전체 CLI 옵션 표를 재생성.

## [2.6.2] — 2026-10-09

### 변경(Changed)
- **LLM 폐루프 집중도 — 반복 억제**: 같은 '종류'(repetition.signature: 바이너리+플래그)
  시도가 이미 3회 이상 '실패'했으면 그 종류의 새 명령을 실행하지 않고 건너뛴다(수동 제안으로
  보관). 기존엔 경고만 했던 산발 반복(예: `curl -s ×8`)을 예산·시간 관점에서 끊어 "다음
  한 수"에 집중. 성공/유의미 출력이 있던 종류는 세지 않음(_gate/_repetition_saturated).

### 추가(Added)
- **FakeFoothold 테스트 하네스**(`tests/test_foothold_harness.py`): exploit-exec 실행
  엔진을 실 타겟 없이 검증하는 복붙용 템플릿. 발판→플래그 캡처→provenance(공략 유래)→
  SOLVED 루프를 결정적으로 테스트. user/root 분리 명령 분류 회귀 가드 포함.

## [2.6.1] — 2026-10-09

### 추가(Added)
- **머신형 자율 풀이 KB 경로**(`knowledge/rules/machine-autosolve.json`, 5규칙): 서비스
  버전→공개 익스 자동 식별(searchsploit), 확인 CVE→공개 PoC 매핑, FreePBX 관리패널
  식별(버전·익스·기본자격), SSH 평문자격 발판→user/root 플래그 읽기(분리 명령으로 kind
  정확 분류), SSH 발판→권한상승 자동 열거. 자율 실행 루프가 '다음 익스/발판/플래그' 를
  규칙으로 인지하게 해 산발적 시도를 줄인다. 모두 suggest(생성) — 실행은 게이트 통과.

## [2.6.0] — 2026-10-09

완전 자동 흐름의 마찰 제거 — vhost 이름해석 자동화, VM 을 기본 실행환경으로 지정 가능,
목표 달성 시 플래그 값 결과화면(🏁 SOLVED). 안전장치(스코프·검증·3관문)는 그대로.

### 추가(Added)
- **🏁 "다 풀었다(SOLVED)" 결과화면**: 목표 달성 시 저장된 user.txt/root.txt(single 은
  플래그) **값**을 결과 맨 끝에 표시(+출처 검증 요약). `--resume` 후에도 유지.
- **vhost 이름해석 자동 등록**: 리다이렉트(`→ http://connected.htb/`)에서 발견한
  호스트명을 **타겟 IP 로 스코프 해석맵에 자동 등록** → 이후 그 vhost 명령이 범위 안으로
  인식돼 프롬프트·스킵이 사라진다. OS 이름해석(`/etc/hosts`)은 쓰기 권한이 있으면 자동
  추가, 없으면 '조용한 반복 실패' 대신 **한 번만 실행할 명령을 1회 안내**. 스코프는 타겟
  IP 로만 묶으므로 범위를 넓히지 않는다.
- **VM 을 기본 실행환경으로**: 설정파일에 `sandbox: "vm"` 과 `vm_ssh`(및 `vm_ssh_key`·
  `vm_ssh_port`·`vm_sudo`·`vm_confine`)를 저장하면 `assassin <IP>` 만으로 그 VM(VMware
  등)에서 실행된다. docker 외 VM 경로를 CLI 플래그 없이 기본화.

### 변경(Changed)
- 첫 실행 안내에 **완전 자동(무프롬프트) = `--autonomous`** 와 격리 실행(docker/vm)을
  또렷하게 안내(초보자 혼동 감소). `--vm-ssh-port` 기본값을 설정 우선(None)으로.

## [2.5.1] — 2026-10-09

최종 마무리 검수(차원별 심층 검수)에서 재현 확인한 결함 수정 + 파괴적 명령 차단 확대.

### 수정(Fixed)
- **자율학습 상태 오염(lateral 전제)**: `_acquire_knowledge` 가 학습 토픽을 `world.loot`
  에 적재해, 자격증명·발판이 없어도 lateral 단계 전제가 충족돼 투기적 LLM 라운드를
  소모하고 성장 지표를 왜곡하던 문제 수정. 학습 지식을 `world.learned` 로 분리.
- **`--resume` 시 provenance 판정 손실**: 재개 시 flag 출처(verdict)를 재계산해
  `looked-up`(라이트업·학습 유래 의심)이 `exploit-derived` 로 승격되거나, 오프라인 공략
  플래그가 `local-derived` 로 강등되던 문제 수정. 첫 실행의 판정을 상태에 보존·복원.
- **정찰 중 Ctrl+C**: 첫 포트스캔 도중 중단 시 raw 트레이스백 + 상태 유실로 `--resume`
  약속이 깨지던 문제 수정. 정찰을 중단 처리로 감싸 상태 저장 후 정상 종료하고, 최상위
  진입점에 Ctrl+C·예외 가드 추가(전체 추적은 `ASSASSIN_DEBUG=1`).

### 안전(Safety)
- **파괴적 명령 차단 확대**: `shred`·`wipefs`·`mkfs`족(`mke2fs`/`mkswap`/`mkfs.*`)·
  `find … -delete|-exec rm`·루트/홈 `chmod`·`chown -R`·디바이스/시스템경로 `dd`·`truncate`·
  리다이렉트 절단(`> /etc/…`)을 토큰 단위로 차단(auto 모드 자동실행 fail-open 해소).
  디바이스 매칭을 loop/dm-/md/sr/disk-by-id/mapper 로 확대. 상대·작업공간 경로는 오탐 없이 통과.

### 추가(Added)
- **`--max-llm`**: LLM 제안 명령 최대 개수 플래그(기본 5, 자율모드 8) — 기존 config 필드를
  CLI 로 노출하고 자율 램프에 포함(다른 한계값과 대칭).

### 변경(Changed)
- 소스 배포(sdist)에 `knowledge/`·`bench/`·문서 포함(`MANIFEST.in`). wheel 은 KB 를 포함하지
  않는다는 제약을 pyproject 주석에 명확화(소스 트리·`pip install -e .`·`--knowledge` 사용).

## [2.5.0] — 2026-10-09

### 추가
- **`--dry-run` 계획 미리보기**: 정찰·분석은 수행하되 제안된 enum/LLM/파일 명령은 **실행하지 않고
  보여만** 준다(게이트까지 통과 → `dry-run: 제안만(미실행)` 비고). 자율 실행 전 무해 점검용.
- **무인 진행 heartbeat**: 스윕마다 1줄 요약(스윕 N/M·경과·enum/LLM 수·플래그·비용) 출력 —
  장시간 완전자율 실행의 폭주 감시·발표 시연 가시성. 비대화형(`quiet`)에선 억제.
- **오타 옵션 제안**: 알 수 없는 CLI 옵션에 `difflib`로 가장 가까운 실제 옵션을 제안
  (예: `--prt` → "혹시 `--lport`?"). 거리가 먼 오타엔 제안하지 않음. `argparse` 기본 오류를 보강.
- **틈새 기법 일반 규칙**(`knowledge/rules/niche-techniques.json`): AD CS 취약 템플릿 탐색(certipy
  ESC)·NoSQL 인젝션·JWT 약점(alg none/키 혼동) — 서비스 키 기반 정석 규칙. 모두 관측 타겟 한정.
- **패킷 분석·웹 프록시 도구 사용성**: 샌드박스에 `tcpdump` 추가(헤드리스 CLI). Wireshark·Burp Suite 는
  GUI 라 자율 실행 대상이 아니며, 자동화 등가물(`tshark`·`tcpdump`·`mitmproxy`·`zaproxy`)로 커버됨을
  `docs/USAGE.md §10.1`에 정리(모든 도구는 레지스트리 등록·`--doctor`/`--install-missing` 연동).
- **성장 공유(G1)** — `--export-stats`/`--import-stats`: 실행 학습 통계(변형 성공률)를 파일로
  주고받아 사용자 간 성장을 compounding. 통계는 `binary+fragment→succ/att` 뿐이라 명령 전체·타겟·
  출력이 담기지 않아 공유해도 안전. `VariantStats.merge()`로 succ/att 합산.
- **역량 등급(G2)** — `--doctor`에 `full/standard/baseline` 등급 + '한 단계 올리는 법' 표시.
  환경별 성능 편차(LLM 백엔드·도구·샌드박스)를 가시화(안전·범위 강제는 모든 등급 동일).
- **통합 최신화(G3)** — `--update`: 공유 시드 동기화 + 권위출처 재학습·승격을 한 명령으로
  (`--offline`이면 네트워크 생략). CVE/CWE 는 실행 시 자동 수집·캐시.
- **KB 버전 태깅(G4)** — `knowledge.KB_VERSION` 신설, `--doctor` 푸터에 표시(동기화 호환·진단 가시화).
- **서비스 열거 일반 규칙 신설**(`knowledge/rules/service-enum.json`): NFS(showmount/마운트)·
  SNMP(snmpwalk/onesixtyone)·WordPress(wpscan) — 머신 비의존 정석 기법 규칙. 업로드 라이트업群의
  **역량 공백 분석**(다루는 서비스·기법 발자국 ↔ 우리 KB/툴 커버리지 대조)으로 식별한 공백만 보강.
  라이트업의 머신별 정답/플래그는 무결성 가드(provenance)상 적재하지 않음 — '정답 암기'가 아니라
  '일반 역량' 강화.
- **샌드박스 툴 커버리지 확대**(`sandbox/Dockerfile`·`scripts/install_tools.sh`): evil-winrm·
  bloodhound.py·wpscan·hydra·telnet·ftp·nfs-common(showmount)·onesixtyone 추가 — 라이트업群이 자주
  쓰는 범용 도구(Windows 셸·AD 경로분석·CMS 열거·NFS/SNMP 열거)의 미설치 공백 해소.
- **네이티브 tool use(구조화 명령 제안)**: Claude 백엔드에서 `propose_commands` 도구를 강제 호출해
  명령 후보를 스키마대로 JSON 으로 받는다(텍스트 파싱 취약성 제거). tool_calls 가 있으면 우선 사용,
  없으면 기존 텍스트 파싱으로 폴백 — Ollama·구버전 프로바이더 호환.
- **플래그 출처 강화(CTF-Abacus 2608.26237)**: `looked-up`(값이 웹학습·자가학습 노트에 그대로
  있었음 — 라이트업·검색 의심) · `reasoning-only`(값이 명령 입력에 있음 — 지어냈을 수 있음) 판정 추가.
  '검증된 풀이율'은 `genuine`(exploit-derived)만 집계. `KnowledgeBase.external_notes()` 추가.
- **Results Verifier(AutoPentester 2510.05605)**: 범위 밖으로 거부될 명령만, 타겟 자리표시자·사설
  (RFC1918)/타겟대역 IP 오타를 바인딩 타겟으로 자동 교정해 복구(공격자 IP·공인/문서 IP 보존).
  교정본도 3관문을 다시 통과. 끄려면 `fix_commands=False`. (`command_fixer.py`)
- **연구 근거 문서** `docs/RESEARCH.md`: 5개 논문(AutoPentester·MazeRunner·CTF-Abacus·HackWorld·
  Anomaly-Agent)의 핵심 기여 ↔ 이 저장소 기능 대응표 + 재구현 시 지킨 안전 경계.
- **열거 서비스별 라운드로빈**: KB 제안을 서비스(태그)별 버킷으로 모아 round-robin 으로 예산 분배 —
  한 서비스가 예산을 독식하지 않고 각 서비스가 먼저 한 번씩 돌 기회를 갖는다(탐색 폭 확대).
- **`--install-missing [카테고리]`**: 빠진 보안 도구를 저장소 공식 `install_tools.sh` 로 자동 설치
  (빠진 도구가 있는 카테고리만 전달). `--doctor` 안내도 이 명령으로 갱신.
- **`--cred-file <경로>`**: 자격증명을 파일에서 일괄 로드(`CredentialVault.load_file`). 인라인 `--cred`
  와 함께 쓸 수 있고, 둘 다 범위·검증 경계를 그대로 거친다.
- **`--list-sessions`**: 저장된 세션(타겟) 목록을 출력(`StateStore.list_targets`) — `--resume` 대상 확인용.
- **실제 Kali 라이브 검증 가이드** `docs/VALIDATION.md` · **문서 일관성 검사**
  (`tests/test_docs_consistency.py`): `assassin` 예시에 쓰인 `--옵션`이 실제 CLI 에 있는지 검사.

### 변경
- **anthropic SDK 플로어 상향**: `anthropic>=0.40` → `anthropic>=1.0`(현행 메이저 1.x 반영;
  `messages.create`·시스템 캐시 블록·tool use 사용은 1.x 호환). requirements 주석도 동반 갱신.
- **OWASP 카탈로그 URL 정규화**: `owasp.org/www-community/*` → `community.owasp.org/*`(OWASP 가
  308 영구 이전). 사전학습 카탈로그 8건 + 승격된 시드 노트 8건 동시 갱신 → 리다이렉트 1홉 절약,
  카탈로그↔시드 정합. `.owasp.org` 하위도메인이라 allowlist 그대로 통과.
- **가격표 출처 스탬프 갱신**(2026-09 → 2026-10; 요율 값은 이미 현행).
- **분석가 티어 적응화**: `analyze()`가 항상 STRONG(opus)을 쓰던 것을, 추론 난이도가 높은 국면
  (첫 분석=가설 기록 없음 · 막힌 가설 존재 · 직전 확신도 '하')에만 STRONG, 평상시 갱신은
  STANDARD(sonnet)로 라우팅 → 분석 비용 절감(난이도-티어 정합). 하이브리드는 여전히 Claude 우선.
- **LLM 라운드 병렬 실행**: `_llm_round`가 제안 명령을 순차 실행하던 것을, 파일 없는 일반 프로브는
  enum 과 동일하게 병렬 배치(게이트 순차→I/O 동시→처리·태깅 순차·결정적), 파일 액션(익스플로잇·
  솔버 스크립트)은 다단계 안전을 위해 순차 유지. 실벽시계 단축.
- **프롬프트 캐싱 적중 개선**: `suggest` 시스템 프롬프트에 호출마다 바뀌는 잔여 예산(max_items)을
  박아 ephemeral 캐시가 매번 미스되던 문제 수정 — 시스템 프롬프트를 고정 상한으로 만들고 라운드별
  실제 상한은 비캐시 영역(사용자 프롬프트·도구 스키마·파싱 절단)으로 전달 → 큰 시스템 블록 재청구 방지.
- **논리적 흐름 — 막힌 국면 투기 억제**: 가설 원장이 있는데 쫓을 대상이 없고(focus 없음) 모든 열린
  가설이 '막힘'이면 같은 상태에서 투기적 LLM 제안 라운드를 건너뛴다(KB 열거는 유지, 다음 스윕서
  상태 성장 시 재개) → 낭비 LLM 호출 절감 + 전이 판단 명시(`llm_round_skipped` 감사 이벤트).
- **사전학습 수집 타임아웃 상향(6초 → 10초)**: `learn.py` fetcher·`ReferenceLearner` 기본 타임아웃을
  상향해 `--learn all` 배치 중 콜드캐시 대용량 페이지(예: OWASP www-community 42KB+)가 전환적으로
  누락되던 문제를 줄인다. allowlist·라이트업 가드·오프라인 폴백은 불변.
- **로컬(Ollama) 기본 모델 현행화**: 티어 기본값을 `llama3.1:8b/70b` → `qwen2.5:7b`(cheap/standard)·
  `llama3.3:70b`(strong)로 교체. 도구 사용·지시이행이 개선된 세대로 정렬하고 setup 추천표·doctor 안내·
  문서도 동반 갱신. 설치돼 있지 않으면 기존대로 설치된 모델로 자동 대체(`model_for`)하고 `OLLAMA_MODEL`
  로 덮어쓸 수 있어 기존 사용자 영향 없음.
- **CHEAP 티어 모델 현행화**: Claude 백엔드 CHEAP 티어를 `claude-haiku-4-5`(구세대, $1/$5) →
  `claude-haiku-5-5`(현행, ≤100K 프롬프트 $0.10/$0.50·컨텍스트 1M)로 교체. CHEAP 은 호출이 가장
  잦은 enum 단계에 매핑되므로 열거 단계 Claude 비용이 크게 감소하고 지시이행 품질도 개선.
  `pricing.py` 에 `claude-haiku-5-5` 요율 추가(미등록 시 비용 0 집계 → 상한 판정 무력화되던 문제 예방).
- **분석가 콜드스타트 방향성**: 가설 기록이 없는 '첫 분석'에서 백지로 시작하지 않고, 관측된 열린
  서비스·포트마다 표준 공격면을 H1~H3 로 먼저 세우도록 분석가 프롬프트에 지침 추가(노출·정보량 큰
  서비스를 H1 로). 호출 시 방향을 갖고 출발 — 이후 호출은 기존대로 가설 원장을 이어서 갱신.
- 화면 잡음 축소(초보자): 리버스쉘 자동 준비는 대표 3종만 표시하고 전체는 `--json`/`--html` 로.

### 수정
- `knowledge/rules/example.json` 규칙에 `phase` 명시 — KB 전 규칙의 phase 결측 0 보장.
- **설정 파일 `sandbox: vm` 거부되던 문제**: `config.SANDBOX_KINDS` 에 `vm` 누락으로, CLI·구현은
  지원하는데 설정 파일로는 거부됐다 — `vm` 추가로 CLI·설정 경로 일치.
- **설정 파일 `time_budget`/`max_cost` 소수 거부되던 문제**: 두 키가 정수 검증(`_INT_KEYS`)에 묶여
  CLI(`type=float`)·dataclass(`float`)와 어긋났다 — 숫자(정수·소수) 검증으로 분리.

### 정리
- **`main()` 갓-함수 분해(591줄 → 65줄)**: CLI 진입부를 얇게 — 단독 명령 디스패치는
  `_dispatch_standalone`, 타겟 실행 경로는 `_run_target` 로 분리(동작 불변). 가독성·기여 용이성↑.
- **핫패스 메서드 분리**: `_llm_round` 의 컨텍스트 조립을 `_suggest_context` 로, `_gate` 의 타겟
  자동교정을 `_apply_command_fix` 로 추출(로직 밀도 완화, 동작 불변).
- **마라톤 세션 메모리 상한**: `finding.output` 1건당 하드 실링(`_MAX_FINDING_OUTPUT`)을 둬
  '보관 출력 총량 = 시도 수(예산 제한) × 상한' 으로 명시적 bound(유일하게 미제한이던 성장 지점 차단).
- **Provider 예외 계약 문서화**: `LLMProvider.complete`/`ClaudeProvider.complete` 가 API 오류를
  예외로 전파함을 명시(HybridRouter 폴백·서킷브레이커·오케스트레이터 라운드 격리가 의존). 직접
  호출자는 try/except 필요 — 삼키지 않음으로써 하이브리드 복원력 보존.
- 핫패스 private 헬퍼(`_tool_ok`·`_run_vuln`) 의도 docstring 보강.
- 미사용·중복 코드 제거: `ScopeGuard.detect_attacker_ips`(= `environment.detect_vpn_ips` 중복 사본),
  `observation.compressor.summarize_nmap_host`·`render_observation`·`recommend_followup`,
  `command_validator.validate_hex`, `ui.color_enabled`(getter). HTTP fetcher 중복
  (`enrich`·`learn`)은 공용 헬퍼(`util.http_get_text`)로 통합. `Enricher.cwe_url` 은 리포트/라이트업의
  CWE 참조에 연결.

## [2.4.1] — 2026-10-08

### 추가
- **VM 실행 샌드박스 `--sandbox vm`**: 에이전트가 명령을 실행하는 환경을 Docker 외에 **SSH 로 접속한
  가상머신/공격호스트**에서도 돌릴 수 있다(`--vm-ssh user@host` [`--vm-ssh-key`·`--vm-ssh-port`]).
  파이프·스크립트·실도구를 VM 에서 실행하고, 작업공간 파일은 scp 로 올린다. `--vm-confine`(+`--vm-sudo`)
  이면 접속 직후 VM 에 egress 방화벽(타겟 대역만)을 적용·검증해 docker 처럼 완전자율 동적 실행까지
  자동 허용(그 VM 네트워크를 타겟으로 제한하므로 전용 풀이 VM 에서만). 없으면 contained=False 로
  동적 실행은 수동 제안. `--doctor` 에 '실행 샌드박스' 점검 추가(none/docker/vm 고르는 법 안내).

### 추가
- **라이브 벤치 공개세트 확장 + VM/외부 타겟**: 공개 CTF 세트(picoCTF·Dreamhack·HTB Starting
  Point)에서 흔한 기법류를 **원본으로 재구성**해 문제를 늘렸다(복사 아님). loopback 추가 —
  `web-cookie-admin`(권한 쿠키 우회)·`web-lfi-flag`(경로 순회/LFI)·`net-banner-flag`(nc 배너
  상호작용). docker 추가 — `smb-anon-share`·`mysql-empty-root`·`snmp-public`(실서비스).
  그리고 **`kind: "vm"`** — 컨테이너가 아닌 실제 머신(HTB·Dreamhack 머신, VirtualBox/VMware/
  libvirt VM)을 타겟으로. 주소는 `challenge.json` 의 `address` 또는 환경변수 `ASSASSIN_VM_<이름>`
  으로 지정(머신마다 IP 가 달라 파일 수정 없이 덮어쓰기), 선택적 `start_cmd`/`stop_cmd` 로
  부팅/정리(우리가 부팅한 경우에만 종료). `bench/live/vm-htb-example/`(템플릿·README).
- **지식베이스 경로 cwd 독립**: 기본값이 '실행한 폴더의 ./knowledge' 였던 것을, 없으면 패키지에
  번들된 `knowledge/` 로 자동 해석(어느 디렉터리에서 실행해도·설치본에서도 동작). `pyproject.toml`
  에 `package-data` 추가(일반 설치 시 번들 데이터 포함).

### 수정
- 포트스캔 폴백 서비스 추정에서 1337 을 `unknown` 으로(CTF pwn 규칙 매칭) — nc 상호작용 유도.
- `tests/run_all.py`: 스위트당 제한시간(`ASSASSIN_TEST_SUITE_TIMEOUT`, 기본 300초) + 각 스위트
  stdin=/dev/null(대화형 input() 블록 방지) — 네트워크 대기·stdin 상속으로 멈추던 문제 해소.
- 설치 스모크 CI 잡: 새 가상환경 설치 후 소스 밖(다른 cwd)에서 `assassin --doctor`·`--bench`·
  별칭 동작 확인(지식경로 cwd 독립·엔트리포인트 검증).
- 테스트 네트워크 차단: `ASSASSIN_NO_NET=1`(run_all 기본)이면 기본 fetcher(enrich·kb_sync·learn·
  web_search)가 실제 요청을 보내지 않는다(주입 fake fetcher 는 영향 없음) — CI 안정성.

## [2.4.0] — 2026-10-08

완전자율(--autonomous)에서 **실제 익스플로잇까지 자동 수행**할 수 있도록 실행 계층을 넓혔습니다.
기존에는 명령을 한 줄씩(셸 비경유)만 실행해 파이프·스크립트·대화형 세션·첨부파일 분석이 불가능했고,
리버스쉘·권한상승·크래킹은 '생성만' 했습니다. 안전 경계(범위 밖·파괴명령 차단)는 그대로 유지합니다.

### 추가

- **라이브 벤치마크 `--live-bench [DIR]`**: 가짜 응답(오프라인 `--bench`)이 아니라 **실제 취약
  서비스를 띄우고 진짜 도구로 풀어** 성공률·pass@k·검증된 풀이율·시간을 측정한다(발표/심사용
  신뢰 수치). 타겟 종류 두 가지 — `loopback`(파이썬 서비스를 전용 127.0.0.x·표준 포트에 기동,
  nmap 없이 소켓 폴백으로 발견·curl 등 실도구로 풀이) / `docker`(challenge 의 Dockerfile 로
  컨테이너를 전용 IP·표준 포트에 기동, FTP/Redis 등 실서비스; 데몬 없으면 명확히 알리고 건너뜀).
  번들 문제 `bench/live/`(web-robots-hidden·web-header-leak·web-source-comment·ftp-anon·redis-key).
  집계·표·JSON·시도별 감사 로그(`--replay`)는 `--bench` 와 같은 구조 재사용.
- **포트스캔 폴백(nmap 미설치 대응)**: nmap 이 없을 때 순수 파이썬 TCP-connect 스캔으로 열린
  포트를 찾아 정찰이 진행되게 한다(바인딩된 타겟만 스캔 — 범위 밖 불가). 흔한 포트 서비스 추정 +
  짧은 배너. nmap 이 있으면 항상 nmap 사용. (`tools/portscan_fallback.py`, `ReconExecutor` 통합)
- **샌드박스 실행기 `--sandbox {none,shell,docker}`**: `docker` 는 Kali 컨테이너 안에서 `bash -c` 로
  실행(파이프·리다이렉트 가능)하고, 컨테이너 egress 를 **타겟 대역(/32)만 허용**하도록 iptables 로
  강제합니다(기본 DROP). 명령은 비root `agent` + no-new-privileges 로 돌아 정책을 바꿀 수 없습니다
  (`sandbox/Dockerfile`, `scripts/build_sandbox.sh`). `shell` 은 로컬 bash(네트워크 미강제).
- **작업공간 + 첨부파일 `--files PATH`**: 챌린지 소스·바이너리·덤프를 작업공간 `files/` 로 가져오고
  (zip·tar 는 zip-slip 방어로 안전하게 해제), LLM 이 소스를 읽고 취약 지점을 찾습니다. 열린 포트가
  없어도(rev/crypto/forensic) 파일 분석으로 진행합니다.
- **LLM 스크립트 작성·실행**: LLM 이 JSON 응답에 `file:{path,content}` 를 넣으면 익스플로잇·디코더·
  솔버 스크립트를 작업공간에 쓰고 실행합니다. 네트워크가 실행 계층에서 강제되는(docker) 때만 자동
  실행하고, 그 외에는 수동 제안으로 남깁니다. 작성 파일은 감사 로그에 해시·본문과 함께 남습니다.
- **완전자율 승인**: egress 강제 샌드박스에서는 동적·원격 코드 실행(파이프→셸 등)도 자동 승인합니다
  (`auto_approve_contained`) — 정적 검사로 내용을 알 수 없어도 네트워크가 타겟으로 묶여 있기 때문.

### 안전

- **셸 연산자 게이트**: 셸 비경유 실행기에서 파이프·리다이렉트(`|`, `>`, `&&`, `;`)가 인자로 넘어가
  조용히 오작동하던 문제를 실행 전에 거부합니다(따옴표 밖 연산자만 판별, `shell_operators()`).
- **표준입력 차단**: 모든 실행기가 stdin 을 닫아 `nc` 등 입력 대기 도구가 터미널을 가로채거나
  타임아웃까지 멈추지 않습니다.
- **플래그 출처 보정**: 에이전트가 작성한 스크립트 본문이나 명령 문자열 자체에 들어 있는 플래그는
  '로컬 유래(사람 확인)'로 강등해, LLM 이 지어낸 값이 '공략 유래'로 집계되지 않게 합니다.

## [2.3.0] — 2026-10-08

초보자가 처음 실행할 때 막히는 지점과 긴 출력을 정리했습니다.

### 변경

- **인자 없이 실행**: 긴 옵션 목록 대신 시작 3단계(`--doctor` → `--setup-llm` → `assassin <IP>`)를 보여 줍니다.
- **도움말 `--help`**: 옵션을 그룹(시작하기 / 대상·플랫폼 / 실행 방식 / LLM / 시간·한도 / 결과물 / 지식·학습 / 단독 도구)으로 묶고, 짧은 사용법·예시·한국어 문구, 읽기 쉬운 자리표시(`USER:PASS`, `CIDR`, `IP`)로 바꿨습니다.
- **타겟 거부 힌트**: 호스트명이면 `--platform ctf` 명령을, 범위 밖 IP 면 권한 안내와 HTB Target IP 안내를 보여 줍니다(범위 판단은 그대로이고, 대상 IP 를 넣은 우회 명령은 만들지 않습니다).
- **nmap 미설치**: 정찰을 4번 헛돌린 뒤 '호스트 응답 없음'으로 끝나던 것을, 시작 전에 설치 명령과 함께 바로 알려 줍니다. 정찰이 한 번도 실행되지 못하면 '도구/실행 환경 문제(대상 문제 아님)'로 표시합니다.
- **수동 제안**: 묶음마다 앞의 6개만 보여 주고, 같은 꼬리표와 옵션만 덧붙인 변형은 숨깁니다(전체는 `--html`/`--json`).
- **다음 선택지**: 같은 문구가 반복되던 항목을 종류별 한 줄(못 돌린 명령 N개 → `--resume`, 자격증명 필요 → `--cred`)로 묶었습니다.
- **한눈에 보기**: 출력 맨 끝에 결과·서비스·찾은 것·실행 현황·다음에 할 일(최대 3개)을 한 박스로 보여 줍니다.
- **화면 잡음**: 의도적으로 보존한 참고 규칙의 지식베이스 경고를 매 실행 화면에서 숨기고, 내 PC 의 AWS 자격증명 확인 명령을 웹 서비스마다 제안하지 않게 했습니다(`aws` 서비스에서만).
- **박스 정렬**: 여러 줄 안내가 들어가도 박스가 깨지지 않습니다.

## [2.2.0] — 2026-10-08

초보자도 Claude·로컬 LLM(Ollama)을 명령 하나로 연결할 수 있습니다.

### 추가

- **LLM 연결 마법사 `--setup-llm`**: 질문에 답하면 연결부터 확인·저장까지 끝납니다.
  - 백엔드 선택(하이브리드 권장 / Claude만 / 로컬만).
  - Claude: `anthropic` 패키지 확인(설치는 동의 시) → API 키 입력(화면 비표시) → 실제 1회 호출 → 성공한 키만 저장.
  - 로컬: Ollama 설치·서버 확인 → 받아 둔 모델 표시 → PC 메모리에 맞는 모델 추천 → `ollama pull`(동의 시) → 실제 1회 호출.
  - 기본 설정(`~/.config/assassin/config.json`)에 백엔드·로컬 모델·비용 상한(기본 $2)을 저장합니다.
- **`--llm-test`**: 환경 진단에 짧은 실제 호출을 더해 틀린 키·없는 모델·막힌 네트워크를 미리 잡습니다.
- **키 보관**: `~/.config/assassin/credentials`(폴더 700·파일 600, 원자적 쓰기). 실행 시 환경변수로 올리고, 이미 환경변수가 있으면 그쪽이 우선합니다.
- **설정 키**: `llm.ollama_model`, `llm.ollama_host`(환경변수 `OLLAMA_MODEL`·`OLLAMA_HOST`가 우선).

### 변경

- `--config`가 없으면 마법사가 저장한 기본 설정을 자동으로 읽습니다(우선순위 CLI > 환경변수 > 설정 파일 > 기본값, 한 번만 끄기는 `--llm none`).
- `--doctor`가 Claude 키를 가린 값과 출처(환경변수/키 파일)로 보여 주고, 미연결 항목에 `assassin --setup-llm` 안내를 붙입니다.
- LLM 사용 불가 메시지에 마법사 안내를 붙였습니다.

### 안전

- 키는 화면에 가린 값(`sk-ant-…abcd`)만 보이고, 상태 파일·감사 로그·리포트·라이트업에 남지 않습니다(실행 산출물 전수 검사 테스트).
- 패키지 설치·모델 다운로드는 항상 먼저 묻습니다(엔터=아니오). Ollama 설치 스크립트(파이프→셸)는 자동 실행하지 않고 명령만 안내합니다.
- 실제 호출 테스트는 "OK 한 단어로 답하라" 수준의 짧은 요청입니다(공격 명령 아님).

## [2.1.0] — 2026-10-08

하이브리드 LLM이 매번 처음부터 다시 생각하지 않고, 세운 가설을 따라 방향을 유지하며 진행합니다.

### 추가

- **가설 기록(계획 원장, `hypotheses.py`)**: 분석가가 세운 가설 H1~H4의 상태(대기/검증중/확인/기각)·확인 방법·기대 신호·시도한 명령·근거를 들고 갑니다.
  - 분석가 재호출은 **갱신 모드**입니다. 이전 기록과 막힌 가설을 넘기고, 같은 ID는 유지한 채 상태만 바꾸게 합니다.
  - 상태 파일에 저장되어 `--resume` 후에도 계획이 이어집니다.
- **지금 할 일 1개**: 명령 생성(hybrid면 로컬 우선)에는 분석 전문 대신 가설 하나와 확인 방법·기대 신호·이미 해 본 명령만 줍니다.
- **기대 신호 대조**: 결과를 기대 신호와 규칙으로 비교해(LLM 없이) 가설 상태를 갱신하고, 비고에 `H1 신호 일치〔추정〕`/`불일치`를 남깁니다.
- **막힘 → 재계획**: 같은 가설이 2회 연속 어긋나면 `막힘`으로 표시하고 분석가에게 재계획을 요청합니다.
- **가설 보드**: 결과 요약(PLAN)·HTML 대시보드·라이트업에 표시하고, 실행 재생에 계획 갱신·가설 대조·막힘 단계를 보여 줍니다.
- **벤치 LLM 호출 수**: `--bench`에 시도당·풀이 1건당 LLM 호출 수를 추가했습니다.

### 변경

- **재분석 조건**: 명령이 하나 더 실행된 것만으로는 분석가를 다시 부르지 않습니다. 새 크리덴셜·서비스·수집물·취약점·권한·플래그, 가설 확인·기각·막힘 때만 다시 부릅니다. 분석가가 가설을 주지 못하면 예전 방식(결과가 늘 때마다 재판단)으로 돌아갑니다.
- **리포트 JSON 스키마 1.6**: `plan`(가설 기록)을 추가했습니다(하위 호환).

### 안전 (바뀌지 않음)

- 가설 상태는 명령 제안의 방향에만 쓰입니다. 모든 명령은 그대로 검증 → 범위 → 승인 3관문을 거치고, 플래그 출처·목표 달성은 실행 결과로만 판정합니다.
- LLM이 준 가설 문구·기대 신호는 신뢰하지 않는 데이터로 다룹니다(길이 제한, HTML 이스케이프).

## [2.0.0] — 2026-10-08

첫 정식 릴리스. 해커톤·레드팀 교육 용도에 맞춰 시간·비용 관리, 성능 측정, 재생, 초보자 화면을 갖췄습니다.

### 추가

- **시간·비용 상한**
  - `--time-budget 분`: 제한 시간이 지나면 새 명령을 멈추고 산출물을 정리합니다.
  - `--max-cost USD`: LLM 누적 추정 비용이 넘으면 LLM 호출을 멈추고 규칙 기반으로 계속합니다.
- **성능 측정 `--bench`**: 오프라인 모의 문제 12개(easy 6 · medium 5 · hard 1)로 성공률을 측정합니다.
  - 검증된 풀이율(대상과 상호작용해서 얻은 플래그만 인정)과 승인 부담을 함께 보고합니다.
  - 결과는 `results.json`과 문제별 실행 기록으로 남깁니다.
- **실행 재생 `--replay`**: 감사 로그(JSONL)를 단계별로 넘겨 보는 HTML로 만듭니다.
  - 내용은 `textContent`로만 렌더링합니다(XSS 방지).
- **실패 피드백**: 막힌 이유(blockers)를 다음 LLM 라운드 문맥으로 넘깁니다.
- **반복 경고**: 앞서 실패한 것과 같은 종류의 명령이면 승인 전에 `⟳` 경고를 띄웁니다. 경고만 할 뿐 실행을 막지는 않습니다.
- **사실 출처 표시**: 크리덴셜·취약점·수집물마다 어디서 알게 됐는지(도구·버전 매칭 등)를 기록합니다.
- **사람 관찰 입력 `--observe`**: 건너뛴 명령 대신 사람이 직접 확인한 내용(브라우저 화면 등)을 기록합니다.
  - 기록에는 `사람 관찰` 표시가 붙어 에이전트가 검증한 결과와 구분됩니다.
- **다관점 분석가**: 레드팀·개발자·인프라·방어 관점에서 가설 H1–H4를 세우고 계획을 만듭니다.
- **HTTP 요약 단서**: 본문의 주석, 내부 링크, 평문 경로를 최대 5개까지 요약에 남깁니다.
- **승인 화면**: 명령마다 `목적` 한 줄을 보여 줍니다. 검토가 필요한 명령에는 더 안전한 2단계 `대안`을 함께 제시합니다.
- **발표·입문 자료**: `scripts/showcase.sh`(데모 → 벤치 → 재생 HTML → 대시보드를 한 번에)와 1쪽 분량의 [docs/QUICKSTART.md](docs/QUICKSTART.md)를 추가했습니다.
  - 라이브 데모를 7단계로 확장했습니다(승인 목적·대안, 성능 측정 단계 추가).
- **라이선스**: MIT.

### 변경

- **목표 도달 시 종료**: exploit 단계에서 얻은 플래그로만 목표 도달을 판정합니다.
- **재개·중단**: `--resume`이 실행한 명령·결과·플래그를 복원합니다. Ctrl+C로 멈추면 상태를 저장하고 종료 코드 130으로 끝납니다.
- **하이브리드 라우터**
  - 연속 오류가 난 백엔드는 차단(circuit breaker)하고, LLM 거부 응답도 따로 집계합니다.
  - 라우팅·비용 요약을 보고서에 넣습니다.
  - Ollama 모델이 없으면 설치된 모델로 자동 대체합니다.
- **리포트 JSON 스키마 1.5**: `goal_reached`, `llm_routing`, `timed_out`, `elapsed_sec`, `cost_capped`를 추가했습니다(하위 호환).
- **코드 품질**: ruff·mypy 경고를 0건으로 정리했습니다. CI에서 두 검사를 차단 게이트로 바꾸고 버전을 고정했습니다.
- **문서**: 문서에 박혀 있던 테스트 개수를 지우고, 실행할 때 요약이 나오도록 바꿨습니다.

### 안전 (바뀌지 않음)

- 모든 명령은 **검증 → 범위 → 승인** 3관문을 통과해야 실행됩니다. LLM은 검증기·범위·출처 판정을 덮어쓸 수 없습니다.
- 리버스쉘·권한상승·크래킹·클라우드 도구는 **명령 생성까지만** 합니다. 실행은 사람이 결정합니다.
- 승인받지 않은 셸을 계속 열어 두지 않습니다.
- `scope_guard.py`는 타입 주석만 손봤고, 범위 테스트로 동작이 그대로인 것을 확인했습니다.
- BoxPwnr(AGPL-3.0)에서는 아이디어만 참고했고 코드는 가져오지 않았습니다(클린룸 재구현).
