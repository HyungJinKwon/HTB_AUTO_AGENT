# 논문 반영 노트

기준일 2026-10-06. 읽은 논문 5편에서 이 저장소에 **적용한 것**과 **일부러
안 한 것**을 기록한다. 발표의 "어떤 조치를 왜 취했는가" 근거다.

읽은 논문:
- **MazeRunner** (2608.14216) — 비선형 블랙박스 펜테스트, Strategist-Executor-
  **Reviewer** 3에이전트 + Task&Clue 캐시. HTB 10대, 20M 토큰, writeup 금지.
- **ctf-abacus** (2608.26237) — 플래그 **provenance**(획득 경로) 감사. "플래그가
  나타났는가"가 아니라 "익스플로잇 이후 관측됐는가"가 solve 의 기준.
- **AutoPentester** (2510.05605) — 5모듈(Summarizer/Analyzer/Generator/**Verifier**/
  Report). Results Verifier 가 불완전 명령 80~97% 감소. RAG 가 성능 기여.
- **HackWorld** (2510.12200) — 컴퓨터-유즈 에이전트의 웹취약점 공략 벤치. GUI 중심.
- **Anomaly-Agent** (Memory-Augmented…) — IoT/IIoT **방어적** 이상탐지. 공격 루프와
  목적이 다름.

세 논문 모두 우리와 **같은 조건**(HTB·토큰예산·writeup 금지)에서 측정 — 설계 판단의
근거로 쓸 수 있다.

---

## 적용함

### 1. 플래그 provenance — ctf-abacus
`verify.flag(earned=…)` 가 플래그를 `genuine`(선행 Foothold 있음) / `undemonstrated`
(플래그는 맞으나 공략 증거 없음)로 태깅한다. `Attempt`·`FlagHit`·리포트까지 전달.
- **왜**: 플래그를 '찾은' 것과 '공략해서 얻은' 것을 구분해야 정직하다(룰 2-4 교차검증,
  G6 발표 증빙). undemonstrated 는 리포트에 ⚠️ 로 표시 — 성공처럼 포장하지 않는다.
- 선행 익스플로잇(ξ) = 원장의 비-flag Foothold. 보수적 기본값은 undemonstrated.

### 2. Clue(환경 단서) 수집 — MazeRunner
`clues.ClueStore` 가 도구 출력에서 호스트명·사용자명·경로·해시·소프트웨어 버전을
뽑아 누적하고, 익스플로잇 후보 생성 시 LLM 컨텍스트로 되먹인다.
- **왜**: MazeRunner 가 짚은 **Contextual Amnesia**(유한 컨텍스트가 단서를 잊음) 대응.
  교차단계 재사용 — enum 에서 본 사용자명을 privesc 에서 쓴다.
- 플래그 형식(32hex)은 단서가 아니라 플래그이므로 그 맥락은 hash 에서 제외.

> MazeRunner 의 세 병목 중 나머지 둘은 이미 대응돼 있었다:
> **Depth-First Trap** → `exploit_loop` 의 `refute_cap`·`surface_exhausted`·점수 감쇠.
> **Error Misattribution** → `attempt` 의 inconclusive/refuted 구분, 전제조건≠반증.

---

## 일부러 안 함 (ponytail)

- **3에이전트 재작성(MazeRunner) / 5모듈(AutoPentester)**: 우리 단일 `ExploitLoop`
  이 이미 생성→선택→준비→실행→검증→기록을 돈다. 아이디어(리뷰·단서)만 흡수하고
  구조는 안 바꿨다 — 533개 테스트를 버릴 이유가 없다.
- **Results Verifier 의 '명령 자동 교정'**: 지금은 `command_validator`+`Gate` 가
  불완전·위험 명령을 **거부**만 한다. 교정까지는 LLM 몫으로 두되, 반복되면 추가 검토.
- **RAG/KB 채우기(AutoPentester)**: 효과가 크다고 보고됐으나 **콘텐츠 작업**이지
  코드가 아니다. G3(빈 KB)로 추적 중. 측정 하네스 선행 후 채운다.
- **HackWorld 의 GUI 공략 / Anomaly-Agent 의 방어 탐지**: 범위 밖.

## 남은 후보 (측정 후 판단)
Reviewer 를 별도 LLM 호출로 둘지(토큰 비용 ↔ depth-first 탈출 정밀도), 단서를
자동 액션(예: 발견한 사용자명으로 자동 cred-spray)으로 승격할지 — 둘 다 실제 머신
측정 없이 정하지 않는다.
