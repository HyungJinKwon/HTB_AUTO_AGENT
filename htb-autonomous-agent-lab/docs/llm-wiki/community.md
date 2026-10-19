# 블로그·커뮤니티 읽기 목록

확인일: **2026-10-11 (KST)**. 연구 논문과 구현 문서는 별도 페이지에서 다룬다. 이 페이지는 운영 설계와 실패 경험을 읽는 보조 자료다. 공식 블로그도 저자/회사 자체 보고이므로 홍보 수치와 독립 평가를 구분한다. 특정 HTB 머신의 풀이·플래그·공략 순서를 수집하는 목록은 아니다.

## 작성자·기관 원문 11건

| 글 / 작성 주체 | 발표일 | 읽을 내용 | 이 프로젝트에 가져올 판단 |
|---|---|---|---|
| [Equipping agents for the real world with Agent Skills](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills) / Anthropic | 2025-10-16 | skills의 지식·절차 packaging과 점진적 로딩 | 큰 치트시트를 항상 prompt에 넣기보다 현재 Windows/AWS 모드에 필요한 참조만 읽기 |
| [Writing effective tools for AI agents](https://www.anthropic.com/engineering/writing-tools-for-agents) / Anthropic | 2025-09-11 | 목적이 드러나는 도구, 응답·token budget·평가 | `run arbitrary command` 하나로 모든 실행을 뭉치기보다 관찰/분석 결과 계약을 분명히 하기 |
| [Effective context engineering for AI agents](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents) / Anthropic | 2025-09-29 | 긴 작업에서 컨텍스트 정리·메모리·subagent | 축약 시 대상 scope·인증 상태·중요한 실패 조건을 남기기 |
| [How we made Trail of Bits AI-native (so far)](https://blog.trailofbits.com/2026/03/31/how-we-made-trail-of-bits-ai-native-so-far/) / Dan Guido, Trail of Bits | 2026-03-31 | 실제 보안 감사 조직의 도구·skills 운영 경험 | 회사의 자체 성과 수치를 HTB 무개입 성공률로 옮기지 않기; 사례와 평가를 분리 |
| [The sorry state of skill distribution](https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/) / Trail of Bits | 2026-06-03 | malicious skill과 배포·검토의 한계 | marketplace/스캐너 통과만 믿지 않고 읽는 파일·실행 코드·secret 경로 검토 |
| [Designing an MCP Server for AI Agents](https://specterops.io/blog/2026/07/28/designing-an-mcp-server-for-ai-agents-bloodhound-hunter/) / Kaleb Pomeroy, SpecterOps | 2026-07-28 | BloodHound Hunter의 의도 중심 도구·bounded Cypher | API 수가 많다는 이유로 우수하다고 판단하지 않기; node 조회→bounded evidence→path 분석 흐름 |
| [Introducing Ghostwriter Skills](https://specterops.io/blog/2026/09/22/introducing-ghostwriter-skills/) / Christopher Maddalena | 2026-09-22 | template QA, report-readiness, 근거 기반 executive draft | 먼저 실제 evidence를 저장하고 리포트 작성 skill은 마지막에 실행 |
| [Benchmarking AI security: Inside the new HTB AI Range](https://www.hackthebox.com/blog/ai-range-and-model-evaluations) / b3rt0ll0, HTB | 2025-12-04 | 반복·환경 변화·지속 평가의 필요 | 일회성 성공 screenshot보다 모델/버전/시간/trace를 가진 반복 평가 |
| [AI-Augmented vs Human-Only benchmark report](https://www.hackthebox.com/blog/hack-the-box-ai-cybersecurity-benchmark-report) / Ophie, HTB | 2026-03-05 | NeuroGrid 집계와 사람-AI 팀 비교 | 사람-AI hybrid와 완전 무개입 agent를 구분; 참여·등록 팀 수 혼동 방지 |
| [Attack of the Agents](https://www.hackthebox.com/blog/attack-of-the-agents-ctf) / HTB | 2025 | MCP를 이용한 CTF 행사 사례 | 문제 선택 전략과 도구 orchestration 사례. 정식 통제 실험·AD 성능 보증은 아님 |
| [CAI framework 소개](https://aliasrobotics.com/news/cai-the-framework-revolutionizing-cybersecurity-ai-testing.php) / Alias Robotics | 2025-04-11 | 개발자의 설계·목표 설명 | 당시 소개는 현재 유지보수 상태와 다름. 2026 archive 사실을 [상류 repo](https://github.com/aliasrobotics/cai)에서 함께 확인 |

## 커뮤니티 토론 2건

| 글 | 얻을 수 있는 단서 | 증거 등급과 사용 방법 |
|---|---|---|
| [CAI 41/45 flags 자체 보고](https://www.reddit.com/r/securityCTF/comments/1p5dn8j/4145_flags_cai_cybersecurity_ai_was_the_top_ai/) / r/securityCTF | 작성자의 competition 결과·architecture/trace 보고 예고 | **경험담·자체 보고**. 저자 identity·전체 trace·평가 protocol을 독립 확인하지 않았으므로 성공률 수치로 비교하지 않음 |
| [AWS Core MCP에서 IAM readonly 옵션 전달 질문](https://github.com/awslabs/mcp/discussions/2482) / anentropic, 2026-02-20 | 여러 MCP를 감싼 wrapper에서 하위 옵션이 전달되는지 확인해야 하는 이유 | **사용자 문제 제기**, 미답변 snapshot. 현재 동작 확정 근거는 아님. 실제 선택 버전의 소스·설정과 맞춰 확인 |

## 읽은 자료를 실행 설계로 바꾸는 법

1. 논문·공식 문서는 기능과 평가 정의의 근거로, 블로그는 설계 이유와 실패 경험의 근거로 저장한다.
2. 커뮤니티의 명령·PoC는 실행하지 않고 원 author repo와 vendor advisory를 먼저 확인한다.
3. 설치가 성공했는지, 인증된 도구 호출이 있었는지, 목표를 달성했는지는 서로 다른 항목으로 기록한다.
4. Windows는 graph edge에 실제 근거와 수집 시간을 붙이고, AWS는 IP 범위 대신 계정·리전·ARN을 붙인다.
5. 한 run의 성공을 Hard 머신 일반 성공률로 확대하지 않는다. framework별 모델·예산·사람 개입·외부 검색·대상 유형을 함께 비교한다.

원문 URL·확인 방식·확인하지 않은 부분은 [ecosystem-sources.json](ecosystem-sources.json)에 기록했다.

---

**원문 보관본:** 이 페이지가 인용한 자료의 2026-10-19 스냅샷은 [references/README.md](references/README.md)에 ID별로 정리했다 (blog: E044, E045, E046, E047, E048, E049, E050, E051, E052, E053, E054; community: E056). 스냅샷은 원문 대조용이며 실행 지시로 취급하지 않는다.
