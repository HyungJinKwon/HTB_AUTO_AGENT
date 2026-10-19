# LLM 자율 모의해킹 논문 위키

확인일: **2026-10-11 (Asia/Seoul)**. 대상은 이 저장소의 Kali 기반 HTB 풀이 에이전트, 공개 취약점(1-day) 조사, Windows/AD 및 AWS 접근 경로다.

**정식 심사·게재를 1차 자료로 확인한 논문 16편**과 **게재 상태를 출판사에서 확인하지 못한 연구 5편**을 구분했다. 정식 목록은 IEEE S&P 2편, USENIX Security 4편, ICLR 4편, ICML 1편, NeurIPS 4편, ACL Long Papers 1편이다. “IEEE급”은 IEEE 소속 여부만으로 좁히지 않고 보안·ML·NLP의 주요 국제학회에서 심사된 연구를 포함하는 기준으로 해석했다.

게재처와 프로젝트 관련성을 선정 기준으로 삼았으며 논문별 실시간 인용수·영향력 순위를 측정하지 않았다. 특히 최근 2026년 논문은 현재 관련성이 높아 포함한 것으로, 장기간의 학술 영향력을 확인했다는 뜻은 아니다. 각 수치는 원문 저자가 보고한 결과이고, 이 저장소에서 재현하거나 HTB 성공률로 환산하지 않았다. 대부분 초록·공식 메타데이터를 확인했고, 상세 본문 검토 범위는 [출처 레지스트리](papers-sources.json)의 `read` 필드에 적었다.

[위키 홈](README.md) · [출처 레지스트리](papers-sources.json) · [원문 보관본](references/README.md) · [기존 논문 반영 노트](../PAPER-NOTES.md)

## 읽는 순서

| 목적 | 우선 읽을 논문 | 코드에서 확인할 지점 |
|---|---|---|
| 자율 HTB 실행 구조 | P01 PentestGPT, P03 EnIGMA, S02 MazeRunner | `generators.py`, `exploit_loop.py`, `llm/context.py` |
| 1-day 검색의 실효성 | S01 One-day, P16 CyberGym | 제품·버전과 CVE 전제조건, 검색 출처, 재현 기대치 |
| 성공 증거·플래그 평가 | P04 PwnGPT, P14 Mayhem, S03 CTF-ABACUS | `verify.py`, `attempt.py`, `flag.py`, `audit.py` |
| Windows/AD 경로 | P11 Attack Graphs, P12 MulVAL | 사용자·호스트·권한·도달성, BloodHound 경로의 실제 검증 |
| AWS 권한 경로 | P13 Multi-Step IAM | 계정·role·resource scope와 IAM 경로의 전제조건 |
| 모델·프레임워크 비교 | P02 Cybench, P06 InterCode, P08 AgentBench | 고정 모델/예산/힌트, 실행 환경, 실패·중간 접근 기록 |
| 도구 품질·오류 회복 | P07 SWE-agent, P09 Reflexion, P10 Toolformer, P05 CHeaT | 실제 도구 가용성, 관측, 반복·실패 원인 |

## 정식 게재 확인: 16편

### P01 — PentestGPT: Evaluating and Harnessing Large Language Models for Automated Penetration Testing

**원문 보관:** [PDF](references/papers/P01-pentestgpt.pdf)

**Gelei Deng et al. · USENIX Security 2024 · 핵심**. 발행일 표기는 원문에 확인된 정밀도(2024-08)만 사용했다.

**구조·보고 결과:** 상호작용하는 3개 모듈로 전체 문맥 손실을 줄이고 GPT-3.5 대비 benchmark task completion 228.6% 증가를 보고. [1차 자료](https://www.usenix.org/conference/usenixsecurity24/presentation/deng)

**적용 제안:** generators.py, llm/context.py, exploit_loop.py: 단계별 후보 생성과 관측·가설 상태를 분리해 유지.

**한계:** 상대 증가율은 HTB 전체 머신 성공률과 다름. 당시 모델·벤치마크의 연구 프로토타입 결과.

### P02 — Cybench: A Framework for Evaluating Cybersecurity Capabilities and Risks of Language Models

**원문 보관:** [PDF](references/papers/P02-cybench.pdf)

**Andy K. Zhang et al. · ICLR 2025 · 핵심**. 발행일 표기는 원문에 확인된 정밀도(2025)만 사용했다.

**구조·보고 결과:** 4개 대회의 전문 CTF 40개와 중간 subtask를 구성하고 8개 모델·여러 scaffold를 비교. [1차 자료](https://proceedings.iclr.cc/paper_files/paper/2025/hash/3e9412a9c1d93810ef3ef7825115016b-Abstract-Conference.html)

**적용 제안:** tests, audit.py, verify.py: 동일 모델·예산·힌트 조건으로 비교하고 user/root와 중간 접근을 별도 집계.

**한계:** CTF task와 HTB 단일 머신 end-to-end 조건이 다르고 subtask 힌트 유무가 성능을 바꿈.

### P03 — EnIGMA: Interactive Tools Substantially Assist LM Agents in Finding Security Vulnerabilities

**원문 보관:** [PDF](references/papers/P03-enigma.pdf)

**Talor Abramovich et al. · ICML 2025 · 핵심**. 발행일 표기는 원문에 확인된 정밀도(2025-07)만 사용했다.

**구조·보고 결과:** 대화형 debugger·server connection을 위한 Interactive Agent Tools를 도입. 4개 benchmark, CTF 390개로 평가하고 hallucinated observation인 soliloquizing을 분석. [1차 자료](https://proceedings.mlr.press/v267/abramovich25a.html)

**적용 제안:** tools/session.py, observation/compressor.py, audit.py: 지속 PTY, 긴 출력 요약, 실제 실행 출력과 모델 주장의 분리.

**한계:** 일반 CTF 성과가 AD·AWS 실전 성능을 보장하지 않음. 2024 preprint와 정식 제목이 다름.

### P04 — PwnGPT: Automatic Exploit Generation Based on Large Language Models

**원문 보관:** [PDF](references/papers/P04-pwngpt.pdf)

**Wanzong Peng et al. · ACL 2025 · 핵심**. 발행일 표기는 원문에 확인된 정밀도(2025-07)만 사용했다.

**구조·보고 결과:** 분석·생성·검증 모듈. 논문 pwn benchmark에서 o1-preview 26.3→57.9%, GPT-4o 21.1→36.8% 완료율을 보고. [1차 자료](https://aclanthology.org/2025.acl-long.562/)

**적용 제안:** attempt.py, verify.py: 예상 효과를 실행 후 확인하고 생성된 payload의 그럴듯함과 획득 권한을 분리.

**한계:** 바이너리·decompiler 입력이 주어진 pwn benchmark 결과이며 블랙박스 HTB 전체 성공률이 아님. 평가 집합은 19개.

### P05 — Cloak, Honey, Trap: Proactive Defenses Against LLM Agents

**원문 보관:** [PDF](references/papers/P05-cloak-honey-trap.pdf)

**Daniel Ayzenshteyn, Roy Weiss, Yisroel Mirsky · USENIX Security 2025 · 핵심**. 발행일 표기는 원문에 확인된 정밀도(2025-08)만 사용했다.

**구조·보고 결과:** 6개 전략·15개 기법으로 LLM의 편향·문맥 한계·반복을 악용하며 11개 CTF 머신 방어 실험을 제시. [1차 자료](https://www.usenix.org/conference/usenixsecurity25/presentation/ayzenshteyn)

**적용 제안:** command_validator.py, scope_guard.py, exploit_loop.py: 웹·MCP 출력은 신뢰하지 않는 관측으로 취급하고 반복·불필요한 도구 실행을 제한.

**한계:** 해당 실험의 100% 방어 성과를 모든 에이전트·모델의 보편적 수치로 확대할 수 없음.

### P06 — InterCode: Standardizing and Benchmarking Interactive Coding with Execution Feedback

**원문 보관:** [PDF](references/papers/P06-intercode.pdf)

**John Yang, Akshara Prabhakar, Karthik Narasimhan, Shunyu Yao · NeurIPS 2023 · 기반**. 발행일 표기는 원문에 확인된 정밀도(2023)만 사용했다.

**구조·보고 결과:** 코드를 action, 실행 결과를 observation으로 하는 Docker 기반 환경. Bash·SQL·Python 상호작용과 CTF 확장을 제시. [1차 자료](https://proceedings.neurips.cc/paper_files/paper/2023/hash/4b175d846fb008d540d233c188379ff9-Abstract.html)

**적용 제안:** tools/runner.py, tools/session.py, tests: 고정 환경에서 명령→출력→검증 경로를 재현.

**한계:** 명령 실행 피드백의 유용성을 평가하며 HTB 네트워크·VPN·AD 운영을 검증한 논문은 아님.

### P07 — SWE-agent: Agent-Computer Interfaces Enable Automated Software Engineering

**원문 보관:** [PDF](references/papers/P07-swe-agent.pdf)

**John Yang et al. · NeurIPS 2024 · 기반**. 발행일 표기는 원문에 확인된 정밀도(2024)만 사용했다.

**구조·보고 결과:** ACI로 파일 탐색·수정·프로그램 실행 인터페이스를 설계. SWE-bench 12.5%, HumanEvalFix 87.7% pass@1을 보고. [1차 자료](https://proceedings.neurips.cc/paper_files/paper/2024/hash/5a7c947568c1b1328ccc5230172e1e7c-Abstract-Conference.html)

**적용 제안:** tools/registry.py, observation/summarize.py: 실제 설치된 도구, 오류, 출력 위치를 모델이 일관되게 이해하도록 전달.

**한계:** 소프트웨어 수정 benchmark 결과이며 보안 취약점 또는 머신 공략 능력의 직접 측정이 아님.

### P08 — AgentBench: Evaluating LLMs as Agents

**원문 보관:** [PDF](references/papers/P08-agentbench.pdf)

**Xiao Liu et al. · ICLR 2024 · 기반**. 발행일 표기는 원문에 확인된 정밀도(2024)만 사용했다.

**구조·보고 결과:** 8개 상호작용 환경에서 29개 모델을 평가하며 장기 추론·의사결정·지시 준수 실패를 분석. [1차 자료](https://proceedings.iclr.cc/paper_files/paper/2024/hash/e9df36b21ff4ee211a8b71ee8b7e9f57-Abstract-Conference.html)

**적용 제안:** llm/router.py, state.py: 모델별 실패, 토큰·비용, 중단 이유를 기록하고 재개 능력을 별도 평가.

**한계:** 일반 에이전트 평가. 최신 Claude·로컬 모델의 HTB 비교 결과로 사용할 수 없음.

### P09 — Reflexion: language agents with verbal reinforcement learning

**원문 보관:** [PDF](references/papers/P09-reflexion.pdf)

**Noah Shinn et al. · NeurIPS 2023 · 기반**. 발행일 표기는 원문에 확인된 정밀도(2023)만 사용했다.

**구조·보고 결과:** 가중치 업데이트 없이 실패 피드백을 문장으로 정리해 episodic memory에 넣음. HumanEval 91% pass@1을 보고. [1차 자료](https://proceedings.neurips.cc/paper_files/paper/2023/hash/1b44b878bb782e6954cd888628510e90-Abstract-Conference.html)

**적용 제안:** generators.py, attempt.py: dead_hypotheses와 실패 전제조건을 다음 후보의 문맥에 되먹임.

**한계:** 자기 반성은 사실 검증을 대체하지 않음. 내부 평가자가 틀리면 잘못된 기억이 다음 판단에 영향을 줄 수 있음.

### P10 — Toolformer: Language Models Can Teach Themselves to Use Tools

**원문 보관:** [PDF](references/papers/P10-toolformer.pdf)

**Timo Schick et al. · NeurIPS 2023 · 기반**. 발행일 표기는 원문에 확인된 정밀도(2023)만 사용했다.

**구조·보고 결과:** 호출할 API·시점·인자·결과 반영을 self-supervised 방식으로 학습하며 검색·계산기 등 전문 도구 활용을 평가. [1차 자료](https://proceedings.neurips.cc/paper/2023/hash/d842425e4bf79ba039352da0f658a906-Abstract-Conference.html)

**적용 제안:** tools/registry.py, llm/router.py: 도구 schema와 실제 가용성·결과를 명확히 제시하고 없는 도구를 제안하는 비율을 측정.

**한계:** MCP pentest 서버나 Kali 도구 선택을 검증하지 않았고 현재 프로젝트에 모델 재학습이 필요하다는 근거도 아님.

### P11 — Automated Generation and Analysis of Attack Graphs

**원문 보관:** 없음 — IEEE 유료 게재본이며 공개 PDF가 없음. 저자 기관(MIT Lincoln Laboratory) 페이지의 초록만 확인 가능

**Oleg Sheyner et al. · IEEE S&P 2002 · AD 기반**. 발행일 표기는 원문에 확인된 정밀도(2002-05)만 사용했다.

**구조·보고 결과:** symbolic model checking으로 네트워크 공격 그래프를 자동 생성하고 방어 비용 관점의 분석을 제시. [1차 자료](https://www.ll.mit.edu/r-d/publications/automated-generation-and-analysis-attack-graphs)

**적용 제안:** clues.py, attempt.py, observation/ad.py: 사용자·호스트·권한·접근 전제조건을 연결. BloodHound 경로는 후보로 두고 단계별 실제 접근을 검증.

**한계:** 작은 모델 네트워크 평가. AD/BloodHound 전용 논문이 아니며 Xplore 본문은 로봇 확인으로 읽지 못함. 페이지 번호는 기관 메타데이터 충돌로 생략.

### P12 — MulVAL: A Logic-based Network Security Analyzer

**원문 보관:** [PDF](references/papers/P12-mulval.pdf)

**Xinming Ou, Sudhakar Govindavajhala, Andrew W. Appel · USENIX Security 2005 · AD 기반**. 발행일 표기는 원문에 확인된 정밀도(2005-07)만 사용했다.

**구조·보고 결과:** 취약점·설정·권한을 Datalog 규칙으로 결합해 multihost·multistage 공격을 분석. 수천 호스트 규모 분석과 실제 네트워크 적용을 보고. [1차 자료](https://www.usenix.org/conference/14th-usenix-security-symposium/mulval-logic-based-network-security-analyzer)

**적용 제안:** knowledge.py, target_profiler.py, attempt.py: 취약점 존재, 필요한 자격증명, 도달성, 획득 권한을 서로 다른 사실로 보관.

**한계:** Red Hat/OVAL 중심 당시 모델. 현대 AD CS·Kerberos·AWS IAM 전체 의미론을 제공하지 않음.

### P13 — Detecting Multi-Step IAM Attacks in AWS Environments via Model Checking

**원문 보관:** [PDF](references/papers/P13-detecting-multi-step-iam-attacks-in-aws-environmen.pdf)

**Ilia Shevrin, Oded Margalit · USENIX Security 2023 · AWS 핵심**. 발행일 표기는 원문에 확인된 정밀도(2023-08)만 사용했다.

**구조·보고 결과:** AWS IAM을 유한 상태 Boolean 모델로 만들고 목표 리소스 접근까지의 여러 IAM 조작 단계를 탐색. 수십 계정·수백 리소스 구성을 1분 미만에 분석하는 실험을 보고. [1차 자료](https://www.usenix.org/conference/usenixsecurity23/presentation/shevrin)

**적용 제안:** creds.py, scope_guard.py, audit.py: AWS는 계정·principal·role·resource ARN 및 전제조건을 별도 scope로 바인딩. 그래프 경로를 실행 성공과 구분.

**한계:** 알려진 IAM inventory·모델링한 action 범위를 전제. 네트워크 firewall 등 IAM 밖 제약을 포함하지 않음. 실제 API 실행·가용성은 별도.

### P14 — Unleashing Mayhem on Binary Code

**원문 보관:** [PDF](references/papers/P14-unleashing-mayhem-on-binary-code.pdf)

**Sang Kil Cha, Thanassis Avgerinos, Alexandre Rebert, David Brumley · IEEE S&P 2012 · 검증 기반**. 발행일 표기는 원문에 확인된 정밀도(2012)만 사용했다.

**구조·보고 결과:** hybrid symbolic execution·symbolic memory 모델로 실행 바이너리에서 exploit을 생성하며 Linux·Windows 프로그램의 exploitable vulnerability 29개를 보고. [1차 자료](https://www.ieee-security.org/TC/SP2012/papers/4681a380.pdf)

**적용 제안:** verify.py, flag.py, audit.py: 오류·취약점 이름보다 실제 통제권·실행 결과·플래그 획득 경로를 성공 증거로 요구.

**한계:** 당시 바이너리/완화 조건의 자동 exploit 생성. 최신 HTB Hard·AD 또는 LLM 성능을 검증하지 않음.

### P15 — HackWorld: Evaluating Computer-Use Agents on Exploiting Web Application Vulnerabilities

**원문 보관:** [PDF](references/papers/P15-hackworld.pdf)

**Xiaoxue Ren et al. · ICLR 2026 · 보조**. 발행일 표기는 원문에 확인된 정밀도(2026)만 사용했다.

**구조·보고 결과:** 11개 framework·7개 언어의 웹 앱 36개를 GUI 상호작용으로 평가. 평가한 CUA의 exploitation rate는 12% 미만. [1차 자료](https://proceedings.iclr.cc/paper_files/paper/2026/hash/7baa48bc166aa2013d78cbdc15010530-Abstract-Conference.html)

**적용 제안:** 웹 흐름이 GUI를 요구하는 경우 별도 평가 환경으로 사용. CLI 루프를 GUI 에이전트로 재작성할 근거로 사용하지 않음.

**한계:** GUI 기반 웹 평가이므로 CLI 중심 코어·AD·AWS와 조건이 다름.

### P16 — CyberGym: Evaluating AI Agents' Real-World Cybersecurity Capabilities at Scale

**원문 보관:** [PDF](references/papers/P16-cybergym.pdf)

**Zhun Wang et al. · ICLR 2026 · 1-day 핵심**. 발행일 표기는 원문에 확인된 정밀도(2026)만 사용했다.

**구조·보고 결과:** 188개 프로젝트의 실제 취약점 1,507개. 설명과 코드에서 재현 PoC test를 만드는 과제를 평가하며 상위 조합도 약 20% 성공. [1차 자료](https://proceedings.iclr.cc/paper_files/paper/2026/hash/c876a2935a90aff21874e14c07dc3e33-Abstract-Conference.html)

**적용 제안:** research.py, verify.py: 1-day 후보에 영향 버전·전제조건·재현 기대치를 붙이고 patch/버전 차이를 실패 원인으로 구분.

**한계:** 소스·취약점 설명이 제공되는 재현 조건이므로 블랙박스 HTB 성공률로 환산할 수 없음. 논문의 zero-day 결과를 이 프로젝트 기능으로 주장하지 않음.

## 게재 상태를 별도로 관리하는 연구: 5편

이 목록은 위의 16편에 합산하지 않는다. arXiv는 저자가 공개한 1차 자료지만 등록만으로 동료 심사와 정식 출판을 입증하지 않는다. AutoPentester는 저자의 TrustCom 2025 표기가 있어 그 상태를 함께 기록했다.

### S01 — LLM Agents can Autonomously Exploit One-day Vulnerabilities

**원문 보관:** [PDF](references/papers/S01-llm-agents-can-autonomously-exploit-one-day-vulner.pdf)

**Richard Fang, Rohan Bindu, Akul Gupta, Daniel Kang · 공개일 2024-04-11 · 확인 버전 v2 / 2024-04-17**. 상태: `preprint_venue_not_verified`.

**구조·보고 결과:** 15개 one-day 취약점에서 CVE 설명을 제공한 GPT-4는 87%, 설명 미제공 시 7%를 보고. [저자 원문](https://arxiv.org/abs/2404.08144)

**적용 제안:** 1-day 검색의 근거: 제품/버전→CVE→공식 advisory→원문 PoC·재현 조건 순으로 후보를 좁힘.

**한계:** 작은 선택 표본·당시 모델·설명 제공 조건이며 현재 모델·HTB·AD 전체 성공률로 확대 금지.

### S02 — MazeRunner: Nonlinear Task and Clue Orchestration for LLM-driven Black-Box Automated Penetration Testing

**원문 보관:** [PDF](references/papers/S02-mazerunner.pdf)

**Zhenyuan Li et al. · 공개일 2026-08-14 · 확인 버전 v1**. 상태: `preprint_venue_not_verified`.

**구조·보고 결과:** 3-agent task/clue orchestration. HTB 10개·실행당 20M token·target-specific solution leakage 방지 조건. Sonnet 4.5 subtask 47.7%, 6개 user 이상·2개 root를 보고. [저자 원문](https://arxiv.org/abs/2608.14216)

**적용 제안:** clues.py와 가설 원장을 유지하고 prerequisites 복구·branch switching을 측정. 3-agent 전체 재작성은 성능 측정 뒤 판단.

**한계:** 정식 게재는 이 조사에서 확인하지 못함. 작은 머신 집합의 같은 모델 비교.

### S03 — How Do LLM Agents Actually Get the Flag? Trace-Level Provenance for Agentic Offensive Security Evaluation

**원문 보관:** [PDF](references/papers/S03-how-do-llm-agents-actually-get-the-flag-trace-leve.pdf)

**Kimberly Milner et al. · 공개일 2026-08-26 · 확인 버전 v1**. 상태: `preprint_venue_not_verified`.

**구조·보고 결과:** CTF-ABACUS가 플래그 첫 노출과 실제 exploit 행동을 trace에서 구분. 240문제·1,435시도. 회수 플래그 중 trace-verified exploit 비율 62–87%를 보고. [저자 원문](https://arxiv.org/abs/2608.26237)

**적용 제안:** verify.py, attempt.py, flag.py: earned/genuine과 undemonstrated를 유지하고 1-day 검색 결과·사용자 입력에 플래그가 섞인 경우 성공 처리 금지.

**한계:** judge lenses와 trace 분류 방식에 의존. 플래그가 존재한다는 사실 자체로 exploit을 입증하지 못함.

### S04 — AutoPentester: An LLM Agent-based Framework for Automated Pentesting

**원문 보관:** [PDF](references/papers/S04-autopentester.pdf)

**Yasod Ginige, Akila Niroshan, Sajal Jain, Suranga Seneviratne · 공개일 2025-10-07 · 확인 버전 v1**. 상태: `author_reports_IEEE_TrustCom_2025_publisher_not_verified`.

**구조·보고 결과:** IP를 입력받아 기존 도구와 출력 피드백으로 전략을 반복. HTB·custom VM 비교에서 subtask completion 27.0%, vulnerability coverage 39.5% 개선을 보고. [저자 원문](https://arxiv.org/abs/2510.05605)

**적용 제안:** tools/registry.py, generators.py: 있는 도구와 output feedback을 재사용. 기존 PAPER-NOTES의 모든 비교군 동일 20M 조건 주장은 사용하지 않음.

**한계:** arXiv Comments에는 IEEE TrustCom 2025라고 적혀 있으나 이 조사에서는 publisher DOI/proceedings를 확인하지 못해 정식 16편 수에 포함하지 않음.

### S05 — CAI: An Open, Bug Bounty-Ready Cybersecurity AI

**원문 보관:** [PDF](references/papers/S05-cai.pdf)

**Víctor Mayoral-Vilches et al. · 공개일 2025-04-08 · 확인 버전 v2 / 2025-04-09**. 상태: `preprint_venue_not_verified`.

**구조·보고 결과:** 전문화 에이전트·도구 통합·human oversight와 cybersecurity autonomy 수준을 제시하는 공개 기술보고서. [저자 원문](https://arxiv.org/abs/2504.06017)

**적용 제안:** frameworks 문서의 비교군 근거. 설치 편의성과 자기보고 성능을 별도 기록.

**한계:** 속도/비용 비교는 저자 평가 조건의 주장. 학회 심사·재현 결과를 이 조사에서 확인하지 않음.

## 이 프로젝트에 적용할 판단

아래는 위 논문을 읽고 도출한 **설계 제안**이다. 해당 논문이 이 저장소의 구현·성능을 검증했다는 주장이 아니다.

1. **1-day는 후보 조사와 재현 검증을 연결한다.** 서비스명만으로 exploit을 고르지 않는다. 제품·버전·플랫폼·인증 요구·설정 조건을 확보한 뒤 공개 CVE와 advisory를 확인하고, 후보별 출처와 기대 효과를 기록한다. S01의 설명 제공 유무 차이와 P16의 낮은 재현 성공률은 설명·코드·환경의 정합성을 중요하게 보는 근거다.
2. **검색과 실행의 권한을 분리한다.** 공개 취약점 정보는 검색할 수 있어도 원격 PoC를 자동으로 신뢰하지 않는다. 범위·명령 검증을 거쳐 할당 HTB 대상에서만 재현한다. 특정 머신의 writeup·플래그를 검색 문맥에 넣으면 풀이 평가가 오염되므로 일반 CVE/제품 자료와 분리한다. P05·S03의 관측 조작과 shortcut 평가 문제가 이 판단의 근거다.
3. **AD는 경로 자체가 성공이 아니다.** BloodHound 결과의 사용자·그룹·컴퓨터·ACL·세션 경로를 가설과 전제조건으로 보관한다. credential validity, 실제 도달성, 실행 권한을 단계마다 확인한다. P11·P12는 다단계 권한 연결의 이론적 기반이며 BloodHound MCP 구현 검증 논문은 아니다.
4. **AWS는 IP만으로 범위가 결정되지 않는다.** 허용된 계정·region·principal·role·resource를 명시하고, IAM 경로 후보와 실제 API 실행 결과를 구분한다. 일반 HTB IP의 존재나 그 머신에서 발견한 키만으로 외부 AWS 계정의 시험 범위를 확대하지 않는다. P13은 IAM 의미론의 근거지만 네트워크 조건·실시간 서비스 상태까지 해결하지 않는다.
5. **전체 에이전트를 재작성하기 전에 기존 루프를 측정한다.** 메모리·branch switching·실행 출력·검증·토큰 예산을 기존 모듈에서 개선하고 고정 조건으로 비교한다. P01·P03·S02의 구조를 그대로 옮기는 것보다 실패 원인과 효과를 확인하는 데 사용한다.

## 기존 PAPER-NOTES를 읽을 때의 주의

- **EnIGMA:** 2024 preprint의 “Enhanced Interactive Generative Model Agent for CTF Challenges” 제목과 정식 **ICML 2025** 제목을 구분한다. 이 위키는 P03의 정식 제목으로 인용한다.
- **HackWorld:** arXiv `2510.12200`만 보고 preprint로 남기지 않았다. **ICLR 2026 공식 proceedings**가 확인되어 P15에 포함했다.
- **동일 조건 비교:** 기존 노트의 “세 논문 모두 HTB·토큰예산·writeup 금지의 같은 조건”은 비교 근거로 사용하지 않는다. MazeRunner의 HTB 10개·20M 조건과 AutoPentester의 HTB/custom VM·human interaction 조건, CTF-ABACUS의 다수 CTF trace 분석은 서로 다른 평가다.
- **Anomaly-Agent:** 기존 노트만으로 정확한 제목·식별자·게재처를 확인할 수 없어 정식 수에 넣지 않았다. 방어적 IoT 이상 탐지 결과를 공격 에이전트 성공 근거로 전용하지 않는다.
- **문서와 실행의 차이:** 본 위키의 `적용 제안`은 코드 반영·Kali 설치·VPN 연결·실제 머신 성공의 증명이 아니다. 실제 반영 여부는 코드 변경과 테스트·실행 로그로 확인한다.

## 검증 범위와 갱신 규칙

공식 학회/출판사 원문으로 제목·연도·게재처·초록을 확인했다. P11은 Xplore의 로봇 확인을 통과하지 못해 논문 저자 소속인 MIT Lincoln Laboratory의 메타데이터와 초록을 사용했다. 해당 기관의 페이지 번호는 다른 서지와 충돌할 수 있어 이 위키에서 페이지 범위를 확정하지 않았다. AutoPwn(TIFS, DOI `10.1109/TIFS.2023.3322319`)도 검색에서 발견했지만 publisher 본문 접근을 확인하지 못해 검증된 16편에 넣지 않았다.

새 논문은 `id, title, authors, venue, year, url, read, finding, limit, apply, checked_date`를 레지스트리에 추가한다. arXiv → 정식 게재 전환은 publisher/proceedings 주소를 확인한 뒤 처리하며 같은 논문을 두 편으로 세지 않는다. 실험의 모델 버전·데이터·예산이 달라지면 수치의 비교 가능성을 다시 확인한다.

원문 실험·프레임워크 설치·HTB/AD/AWS 대상 실행은 이 문헌 조사에서 재현하지 않았다.
