# 연구 근거 — 논문 아이디어의 (안전) 재구현 대응표

ASSASSIN 의 설계는 자동 모의해킹·CTF 에이전트 최신 연구의 **장점만** 가져와, 이 도구의 핵심
원칙(승인제 3관문 · 외부 라이트업 미참조 · 유한 루프 · 증거기반 판단)에 맞게 재구현한 것이다.
아래는 각 논문의 핵심 기여와 그에 대응하는 이 저장소의 기능이다. (논문 번호는 arXiv ID)

| 논문 | 핵심 기여 | 이 저장소의 대응 기능 |
|---|---|---|
| **AutoPentester** (2510.05605) | Strategy Analyzer(PTT·findings CoT) · RAG Generator · **Results Verifier**(틀린 명령 교정) · **Repetition Identifier** · Summarizer | `llm/router.py` 분석가(가설 병렬·공격경로) · `knowledge.py` **경량 RAG**(단계별 규칙·키워드 관련도 노트 — 벡터 임베딩/코사인 아님) · `command_fixer.py`(Results Verifier의 **부분 반영** — 실행 *전* 범위 밖 명령의 타겟 자리표시자·오입력 IP 자동 교정만; 논문의 '출력 읽고→불완전 진단→명령 재생성→재시도' 출력구동 루프는 미구현) · `repetition.py` 반복 감지(서명 기반·벡터 아님) · `observation/summarize.py` 토큰 절감 요약(구조화 파서+트렁케이트 — 청크+오버랩 LLM 병합 아님) |
| **MazeRunner** (2608.14216) | Strategist-Executor-**Reviewer** 3-에이전트 · **Task/Clue 영속 캐시** · 비선형 재계획·**브랜치 전환**(depth-first 함정 탈출) · 전제 복구·blocked 가지치기 · PTY 상호작용 | `hypotheses.py` 가설 원장(병합 갱신·기대신호 대조·연속 불일치 N회 '막힘'→재계획) · `world.py` 월드모델(영속 상태·증거) · `orchestrator.py` 재진입 스윕(A1)·단계 게이팅(A2) · `recommend.py` 다음 선택지(막힘·대기 근거) · `--sandbox vm`/docker 셸 실행(**명령 단위 one-shot** `bash -c`/ssh — 논문의 PTY 대화형 세션과 달리 로그인후 컨텍스트 보존·명령 체이닝은 미구현). 단, `blocked` 하류 가지치기·상류 백트랙 브랜치는 가설 원장·스케줄러로 **근사**할 뿐 명시적 태스크 DAG 는 아님 |
| **CTF-Abacus** (2608.26237) | 플래그 **trace-level provenance** — genuine-solve vs recalled/**looked-up**/reasoning-origin 구분으로 벤치 무결성 확보 | **`provenance.py`**: `exploit-derived`(대상 상호작용 출력) / `local-derived` / **`looked-up`**(웹학습·ingest 노트에 있던 값) / **`reasoning-only`**(명령 입력에 있던 값) / `unverified`. 벤치 '검증된 풀이율'은 `genuine`(exploit-derived)만 집계 |
| **HackWorld** (2510.12200) | 실제 취약 웹앱 CTF 로 평가 · **정답 경로 없음 → 능동 탐색** · 도구 선택·오케스트레이션을 핵심 평가축으로 | **`livebench.py`** 실서비스 라이브 벤치(loopback/docker/vm, 공개세트 기법 재구성) · `llm/router.py` **네이티브 tool use**(구조화 명령 제안) · 가설 기반 탐색(고정 경로 아님) |
| **Anomaly-Agent** (IoT SHAP, Memory-Augmented) | ReAct 추론-행동 루프 · **장기 메모리(LTM)**·관련도 검색 · 설명가능성(왜) | `knowledge.py` 관련도 기반 노트(경량 RAG — 키워드 교집합, 시맨틱/recency 하이브리드 아님)·`--ingest`/`--learn` 누적 학습 · **`enrich.py`**(NVD/CVE/CWE 외부 위협인텔 자동수집 = KRM 대응) · `world.py` 사실별 근거(evidence·타입드 리니지: '어느 명령에서 나왔나' — 단 논문 SHAP 특징기여도와는 다른 '출처 추적'식 설명가능성) |

## 재구현 시 지킨 안전 경계(논문과 다른 점)

- **승인제 3관문 유지**: 어떤 LLM 제안·교정 명령도 검증→범위→승인을 반드시 통과한다.
  Results Verifier 의 자동 교정도 '범위 밖으로 버려질 명령'만 복구하며, 교정 후 3관문을 다시 통과한다.
- **외부 라이트업 미참조**: HTB 라이트업은 출처 불문 차단(웹학습 가드). 사용자 ingest 자료에 플래그가
  있었다면 `looked-up` 으로 표시해 '공략'과 구분한다(CTF-Abacus 의 문제의식).
- **유한 루프**: 단계·라운드·스윕·명령 수에 상한이 있어 무한 재시도가 없다.
- **생성 전용 경계**: 리버스쉘·권한상승·크래킹·클라우드 열거는 '생성만' 하고, 실제 실행은 권한 확인
  대상에서 사용자가(또는 egress 강제 샌드박스에서) 한다.
