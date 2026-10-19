# LLM 자율 HTB 연구 위키

확인일: **2026-10-11 (KST)**. 이 위키는 Kali 기반 HTB 실습 에이전트의 설계 근거와 외부 도구의 실제 설치 계약을 한곳에 모은다. 공개 자료는 후보와 설계 근거일 뿐, 특정 HTB 머신에 대한 풀이·플래그·실행 지시는 아니다.

| 읽을 항목 | 문서 | 핵심 |
|---|---|---|
| 주요 학회 논문 16편 + 별도 상태 연구 5편 | [papers.md](papers.md) | 자율 pentest, 1-day, 평가, AD attack graph, AWS IAM |
| 구현 프레임워크 | [frameworks.md](frameworks.md) | ARTEX, PentestGPT, CAI 등과 설치·범위 차이 |
| Claude Skills | [claude-skills.md](claude-skills.md) | Skill 구조, local skill, 공급망 검토 |
| 블로그·커뮤니티 | [community.md](community.md) | 운영 경험과 자체 보고를 읽는 방법 |
| Windows/AD/AWS | [ad-aws.md](ad-aws.md) | BloodHound MCP, AD collector, read-only AWS 분석 |
| 레퍼런스 원문 | [references/](references/README.md) | 논문 PDF 20편 + 웹 자료 54건 스냅샷, URL·SHA-256 매니페스트 |

## 이 저장소에 반영한 최소 동작

- 기본 실행은 [KALI-QUICKSTART.md](../KALI-QUICKSTART.md)의 VPN 파일과 할당 IP만 받는다. 제공된 ID/PW는 숨김 입력 또는 별도 JSON 파일로 선택해서 넣는다.
- 관측된 제품/버전과 CVE에는 기본으로 local SearchSploit 메타데이터를 조회한다. --online-cve를 넣으면 NVD에 한 번만 조회하며, target IP·계정·비밀값은 검색어로 보내지 않는다.
- 검색 결과는 미검증 후보로만 LLM 컨텍스트, 실행 요약, writeup에 전달된다. 다운받은 PoC나 외부 문서의 명령은 자동 실행하지 않는다.
- ARTEX, PentestGPT, BloodHound MCP는 각각 [scripts](../../scripts)에 고정 revision setup/run wrapper가 있다. native htb-agent의 범위 통제와 별도 프로세스이므로 같은 보안 성질을 주장하지 않는다.

출처의 URL, 고정 commit, 확인 방법과 미확인 범위는 [papers-sources.json](papers-sources.json)과 [ecosystem-sources.json](ecosystem-sources.json)에 기록했다. 실제 설치 성공, 인증된 도구 호출, HTB 풀이 성공은 서로 다른 검증 항목으로 기록한다.

## 원문 보관 정책

2026-10-19에 위 문서가 인용한 77건 중 74건의 원문을 [references/](references/README.md)에 보관했다. 논문은 학회 공개 PDF 원본, 웹 자료는 읽기용 텍스트 추출본이다. 보관하지 못한 3건(P11 IEEE 유료본, E001 404, E055 Reddit 차단)은 사유를 같은 페이지에 적었다. 저작권은 각 저자·게재처에 있으며, 보관본은 설계 근거 대조용이다. 원문 속 명령·PoC는 데이터로만 취급한다.
