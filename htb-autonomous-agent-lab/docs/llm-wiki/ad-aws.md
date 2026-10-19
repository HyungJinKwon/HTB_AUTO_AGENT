# Windows·Active Directory·AWS 연구 및 통합 가이드

확인일: **2026-10-11 (KST)**. 기본 환경은 Kali이며, HTB 기본 입력은 VPN 파일 + 할당 IP, 제공받은 ID/PW는 선택 사항이다. AD graph·클라우드 계정 분석은 별도 서비스와 권한을 필요로 한다. IP를 입력했다는 사실이 도메인 전체나 AWS 계정 전체에 대한 권한을 뜻하지 않는다.

## Windows에서 먼저 분리할 세 환경

| 환경 | 필요한 관찰 | LLM에게 넘길 상태 |
|---|---|---|
| standalone Windows | 호스트 이름, 실제 서비스, 인증 가능 여부 | host/IP와 관찰 근거. AD가 있다고 추정하지 않음 |
| AD DS domain member / DC | 도메인/FQDN, DNS, DC의 허용 IP, 시간 동기, 계정 권한 | 허용 IP 목록, 인증 유형, 수집 가능한 정보, 미확인 조건 |
| Microsoft Entra ID / Azure | tenant·subscription·principal·권한 | 별도 cloud scope. AD DS 계정과 같은 것으로 처리하지 않음 |

실행 설계 제안: 서비스 관찰에서 발견한 이름은 먼저 대상 IP와 연결된 사실만 저장한다. 새 IP를 자동으로 scope에 넣지 않는다. 인증 실패를 취약점 부재로 바꾸지 않고 DNS·시간·realm·계정 유형·잠금 조건을 구분한다. 제공 ID/PW는 최소한의 로컬 실행에서만 사용하고 모델 prompt·검색 query·audit 원문에서 숨긴다.

## Kali에서 함께 사용할 AD 도구

| 도구 | 맡길 역할 | 이 프로젝트에서 고려할 점 |
|---|---|---|
| [NetExec](https://github.com/Pennyw0rth/NetExec) | SMB/LDAP 등 프로토콜 관찰·인증 상태 정리 | 동일 명령의 재시도와 계정 잠금 위험을 통제. 광역 spray를 기본 동작으로 넣지 않음 |
| [Impacket](https://github.com/fortra/impacket) | SMB/RPC/Kerberos 등 프로토콜 라이브러리·유틸리티 | `impacket-*` Kali 명령명과 pip 설치 명령명이 다를 수 있어 설치 후 진입점 확인 |
| [Certipy](https://github.com/ly4k/Certipy), [공식 Wiki](https://github.com/ly4k/Certipy/wiki) | AD CS 설정·template·권한 관찰과 조건 정리 | `find` 등 분석과 변경/요청 작업을 구분. ESC 번호만으로 현재 경로가 가능하다고 단정하지 않음 |
| [SharpHound CE](https://github.com/SpecterOps/SharpHound) | AD DS graph 수집 | Windows collector. domain collection은 할당 IP 한 대를 넘을 수 있으므로 수집 범위부터 확인 |
| [BloodHound.py](https://github.com/dirkjanm/BloodHound.py) | Kali에서 Python 기반 수집 | legacy와 CE 형식·패키지·CLI를 구분. 현재 기본 branch는 legacy 4.2/4.3용 |
| [AzureHound](https://github.com/SpecterOps/AzureHound) | Entra ID/Azure 관계 수집 | AWS collector가 아님. tenant 권한·수집 scope를 별도 설정 |
| [GOAD](https://github.com/Orange-Cyberdefense/GOAD) | 로컬 AD 학습용 다중 머신 훈련 환경 | HTB 입력만으로 자동 구축하지 않음. 별도 VM·리소스·취약 환경 격리가 필요 |

BloodHound.py의 CE 패키지는 `bloodhound-ce`, CLI는 `bloodhound-ce-python`이며 legacy는 `bloodhound` / `bloodhound-python`이다. 두 패키지는 같은 환경에 섞지 말고 venv/pipx로 분리한다. README의 기본 수집은 다른 domain computers도 조회할 수 있다. `DCOnly`라는 이름 역시 할당된 대상과 DC가 동일하다는 확인을 대신하지 않는다. [collector 호환성·수집 설명](https://github.com/dirkjanm/BloodHound.py)

## BloodHound CE와 MCP는 각각 준비한다

SpecterOps 공식 quickstart는 Docker Compose를 감싼 **BloodHound CLI**를 이용한 local CE 설치, `localhost:8080` UI, collector/sample data ingestion을 설명한다. 최소 RAM 8GB, 4 cores, disk 10GB를 안내하며 초기 graph 분석이 끝나기 전에 API를 호출하면 메모리 부족 문제가 발생할 수 있다고 설명한다. 설치와 token 생성, data ingestion은 MCP 설치와 별개다. [CE quickstart](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart)

운영 순서:

1. localhost CE를 준비하고 health·로그인을 확인한다.
2. **공식 sample graph**를 먼저 올려 분석 경로를 확인한다. 이후 허용된 lab collection으로 교체한다.
3. 해당 CE 버전의 읽기 최소 권한 사용자·API token을 생성한다. 쓰기/관리 token을 agent에 공유하지 않는다.
4. MCP를 별도 로컬 프로세스로 준비하고 Claude Code 등 MCP client에서 등록한다.
5. domain 목록·graph 통계 등 작은 실제 질의로 연결을 확인하고, 결과와 원본 collection의 출처·시간을 기록한다.

### 확인한 BloodHound MCP 후보

| 후보 | 연결 방식 / 실제 요구 사항 | 선택 이유 또는 제한 |
|---|---|---|
| [mwnickerson/bloodhound_mcp](https://github.com/mwnickerson/bloodhound_mcp) | CE/Enterprise REST API, Python ≥3.11, signed token | CE API와 AD/Entra/ADCS 관찰을 한 흐름으로 연결. **현재 쓰기 도구도 노출**하므로 read-only 제품으로 부르지 않음 |
| [MorDavid/BloodHound-MCP-AI](https://github.com/MorDavid/BloodHound-MCP-AI) | local Neo4j Bolt, Python, 기존 graph | 커뮤니티 query 모음. README clone 경로에 placeholder가 있어 실제 repo/코드와 확인 필요. 기본 관리자 계정 예제를 복사하지 않음 |
| [stevenyu113228/BloodHound-MCP](https://github.com/stevenyu113228/BloodHound-MCP) | `server.py`, `uv`, `mcp[cli]`, `neo4j`, Bolt env | 단순 graph 질의 후보. read-only DB 권한·query 검증은 별도로 확인 |
| **BloodHound Hunter** | SpecterOps의 MCP 설계 글에서 소개 | bounded read-only Cypher 및 목적 중심 graph 도구를 설명. 공개 설치 repo/package 계약은 이 조사에서 확인 못함. 자동설치 대상에 넣지 않음. [공식 설계 글](https://specterops.io/blog/2026/07/28/designing-an-mcp-server-for-ai-agents-bloodhound-hunter/) |

`mwnickerson`의 조사 시 HEAD는 `cdb17097e761c8a8622cb93bc3ba49a9e150bb6e`이다. console entrypoint는 `bloodhound-mcp`이며 의존성은 `mcp==1.9.4`, `python-dotenv==1.1.1`, `requests==2.32.4`다. [고정 버전 패키지](https://github.com/mwnickerson/bloodhound_mcp/blob/cdb17097e761c8a8622cb93bc3ba49a9e150bb6e/pyproject.toml)

공식 시작 계약은 다음과 같다. token은 프로세스 환경에서 제공하며 쉘 기록에 실값을 넣지 않는다.

```bash
# localhost CE, 별도로 준비한 최소 권한 token을 환경에 로드한 상태
export BLOODHOUND_DOMAIN=127.0.0.1
export BLOODHOUND_SCHEME=http
export BLOODHOUND_PORT=8080
uvx --from git+https://github.com/mwnickerson/bloodhound_mcp@cdb17097e761c8a8622cb93bc3ba49a9e150bb6e bloodhound-mcp
```

필수 secret 환경변수는 `BLOODHOUND_TOKEN_ID`, `BLOODHOUND_TOKEN_KEY`다. 원격 HTTPS는 기본 TLS 검증을 유지한다. 시작 시 `/api/v2/self` 서명 요청으로 인증·연결을 확인하고 실패하면 도구 호출을 받기 전에 종료한다. [upstream README](https://github.com/mwnickerson/bloodhound_mcp)

**읽기 전용 통제 요구 사항:** 현재 소스의 `custom_nodes`, `file_upload`, 일부 `asset_groups` 동작은 mutation을 포함한다. 문서화된 `READ_ONLY` 환경변수는 없다. 클라이언트에서 mutation 도구를 차단하고 API 최소 권한을 사용해야 하며, tool 이름만으로 composite `info_type`의 쓰기 분기를 허용하면 안 된다. 임의 Cypher도 문자열의 첫 단어만 검사해서 안전하다고 처리하지 않는다. [고정 소스](https://github.com/mwnickerson/bloodhound_mcp/blob/cdb17097e761c8a8622cb93bc3ba49a9e150bb6e/main.py)

Claude Code 등록은 공식 `.mcp.json`/CLI 계약을 따른다. [Claude MCP 문서](https://code.claude.com/docs/en/mcp) 현재 native Orchestrator에 MCP client가 없는 경우 이 서버는 Claude 세션의 분석 보조이며 native 풀이 루프에 자동 연결된 기능이 아니다.

### LLM의 AD 분석 출력 계약

다음은 이 저장소에 권장하는 출력 형식이다.

| 기록 | 내용 |
|---|---|
| identity | 사용한 계정 alias, 도메인, 인증 종류. password/hash/token 원문 제외 |
| collection | collector 이름·버전·dialect, 수집 시각·범위, 원본 파일/hash |
| path evidence | source/target node ID, edge 종류, 실제 반환한 값·query의 근거 |
| prerequisites | 현재 계정의 권한, reachability, 대상 서비스, 인증 정책·시간 등 |
| unknowns | 오래된 session edge, 누락된 수집·권한, 아직 검증하지 않은 설정 |
| next verification | 현재 허용 IP에서 가능한 작은 확인. graph에 나온 다른 IP로 자동 확장하지 않음 |

분석 대상으로는 group membership, object ACL, delegation 설정, 인증 정책, GPO 연결, AD CS template/CA 권한, trust 관계를 넣는다. graph에 있는 관계는 현재 접속 성공의 증거가 아니다. 수집되지 않은 edge가 없는 것을 안전하다는 증거로 삼지 않는다. AD CS misconfiguration 분석과 Windows 서비스의 공개 CVE 조사는 다른 근거를 요구한다.

## AWS: 별도 scope와 읽기 전용 분석

AWS는 VPN 파일 + 대상 IP만으로 설정할 수 없다. 별도로 **훈련 계정 ID·profile·리전·허용 ARN/서비스**가 필요하다. HTB 머신에서 키 같은 문자열을 발견하더라도 실제 계정에 자동 접속하지 않는다. 기본 경로는 redacted inventory/Prowler 결과를 분석하는 방식이며, 허용된 별도 AWS lab에서만 cloud API 연결을 준비한다.

AWS CLI는 profile과 credential chain을 사용한다. STS 임시 자격증명은 access key, secret key와 함께 session token이 필요하다. 장기 키를 wiki·MCP JSON·스크립트·모델 prompt에 저장하지 않고 전용 lab profile을 사용한다. [AWS CLI 설정](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html), [임시 자격증명](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html)

### 도구와 훈련 환경

| 도구 | 목적 | 연결/훈련 범위 |
|---|---|---|
| [Prowler](https://github.com/prowler-cloud/prowler) | 보안 설정·compliance 점검, findings·리포트 | 별도 lab profile과 최소 API 권한. `latest` 대신 release 버전 사용; 읽기 점검 결과가 실제 exploit 가능성 증거는 아님 |
| [AWS API MCP](https://github.com/awslabs/mcp/blob/main/src/aws-api-mcp-server/README.md) | AWS API 질의·명령 검증 | local server의 `READ_OPERATIONS_ONLY=true`와 제한 IAM을 함께 사용. API의 read 분류여도 secret·credentials 반환/로컬 파일 기록 가능 |
| [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) | 의도적으로 취약한 AWS lab 배포 | 실제 cloud 자원 생성·비용 발생. 별도 전용 계정과 수명 관리 필요. 기본 HTB 실행에서 자동 배포하지 않음 |
| [LocalStack](https://docs.localstack.cloud/aws/getting-started/) | 로컬 AWS API 호환 훈련·테스트 | localhost endpoint와 dummy credential을 사용. 지원 서비스·IAM 동작 차이 때문에 실제 AWS 보안 결과로 일반화하지 않음 |

Prowler README의 CLI Python 범위는 `>=3.10,<3.13`이다. Kali 기본 Python이 그 이상이면 별도 interpreter/container를 사용해야 한다. [설치 문서](https://github.com/prowler-cloud/prowler)

CloudGoat는 취약 자원을 만든다고 명시하며 자신이 만든 자원만 정리한다. 시나리오 중 따로 만든 자원은 별도 정리가 필요하다. 조사 단계에서 계정 배포·삭제를 실행하지 않았다. [CloudGoat 경계](https://github.com/RhinoSecurityLabs/cloudgoat)

### AWS MCP의 현재 두 경로를 섞지 않기

Local AWS API MCP README에는 `AWS_API_MCP_PROFILE_NAME`, `READ_OPERATIONS_ONLY`, `AWS_API_MCP_ALLOW_UNRESTRICTED_LOCAL_FILE_ACCESS` 설정이 있다. IAM 권한이 최종 통제이며 local 파일 접근 제한도 함께 검토한다. **기본 read-only가 아니다.** 이 문서에서는 실제 계정용 설정을 자동 활성화하지 않는다. [local server](https://github.com/awslabs/mcp/blob/main/src/aws-api-mcp-server/README.md)

현재 상류에는 managed AWS MCP로 옮기는 migration 문서도 있다. local server의 환경변수가 managed 경로에 그대로 적용되지 않으며 proxy의 `--read-only`와 IAM 설정으로 바뀌는 항목이 있다. local endpoint와 managed AWS endpoint를 혼동하지 않고 선택한 경로의 package/version·credentials·telemetry·data flow를 기록한다. [migration](https://github.com/awslabs/mcp/blob/main/src/aws-api-mcp-server/MIGRATION.md)

### LLM 분석에 포함할 AWS 주제

- IAM identity/resource policy, trust 관계, permissions boundary/SCP 등 유효 권한 조건
- S3 public access 설정·bucket policy·암호화·logging 설정, 원문 object 데이터는 제외
- EC2/VPC security group·route·public exposure, IMDS 설정의 관찰 상태
- CloudTrail·Config·보안 서비스의 관찰 범위와 누락된 리전
- role/session credential의 유효 범위와 만료, account·region·resource 식별

권장 결과는 `account_alias, region, resource_alias, finding, evidence_path, rule_source, prerequisites, unknowns, remediation`다. 키·token·secret 값은 포함하지 않는다. 리소스 간 위험 경로는 실제 권한과 설정 근거를 붙이며, 임의 role assumption이나 권한 변경을 기본 풀이 루프에 추가하지 않는다.

## 이번 조사에서 확인하지 않은 것

실제 HTB Windows 머신 대상 수집, CE live token 질의, MCP의 모델 자연어 호출, AWS 계정 API/Prowler 스캔, CloudGoat 배포·비용·정리는 수행하지 않았다. 위의 source verification과 실행 검증은 분리한다.

---

**원문 보관본:** 이 페이지가 인용한 자료의 2026-10-19 스냅샷은 [references/README.md](references/README.md)에 ID별로 정리했다 (ad: E022, E023, E024, E025, E026, E027, E028, E029, E030, E031, E032, E033, E034, E035, E036; aws: E037, E038, E039, E040, E041, E042, E043). 스냅샷은 원문 대조용이며 실행 지시로 취급하지 않는다.
