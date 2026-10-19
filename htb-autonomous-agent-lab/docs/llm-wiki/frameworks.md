# 자율 보안 에이전트 프레임워크 비교

확인일: **2026-10-11 (KST)**. 대상은 본인에게 할당된 HTB 머신 및 로컬 훈련 환경이다. 아래의 설치 경로는 공식 README·패키지 메타데이터를 확인한 결과이며, 실제 Kali에서 모든 프레임워크를 실행했다는 뜻은 아니다. 성공률과 속도는 서로 다른 데이터셋·모델·개입 조건을 그대로 비교하지 않는다.

## 선택 기준과 준비 상태

| 프레임워크 | 이 프로젝트에 도움이 되는 부분 | 공식 준비 요건 / 진입점 | 이 저장소에서의 통합 상태 |
|---|---|---|---|
| **ARTEX / artex-ko** | 작업·자산 그래프, 멀티 에이전트, 실행 기록·리포트 UI | Go + Node/npm + PostgreSQL, `start.sh` | 기존 `scripts/artex.sh`가 한국어판 고정 커밋 소스 빌드·DB·localhost UI를 담당. 설치/실행 세부는 [ARTEX 문서](../ARTEX.md) |
| **PentestGPT** | 세션·memory와 supervisor/executor 구조, Claude Code/Codex 백엔드 비교 | Python 3.12+, uv, 인증된 백엔드; nested `pentestgpt-agent` | README와 실제 CLI가 달라 **소스 진입점**을 기준으로 연결. 별도 프로세스이며 코어 Orchestrator 통합은 아님 |
| **CAI** | 에이전트 handoff·도구·추적을 가진 연구 비교군 | 분리한 Python 환경, `cai-framework`, 모델 설정; `cai` | **상류 archived**. 기본 자동설치 대상보다 재현용 고정 버전 후보 |
| **BoxPwnr** | Kali 컨테이너, 플랫폼 어댑터, trace·비용·시간 제한, 여러 CLI solver | Docker + uv + submodule; `uv run boxpwnr` | README 기준 첫 실행 컨테이너 빌드·필요 VPN 연결을 지원. HTB API/대상 이름 등 자체 입력 계약이 있어 현재 IP 런처와 동일하지 않음 |
| **Strix** | 웹/소스 중심 동적 점검, 격리 실행, 결과 뷰어·MCP 도구 제한 | 실행 중 Docker + 모델 인증; `strix` | 웹 애플리케이션 비교군. Windows AD 전체 풀이 능력의 근거로 사용하지 않음 |
| **HackSynth** | Planner/Summarizer 분리, 컨텍스트 축약 실험 | 별도 venv + requirements, Hugging Face/Neptune 설정; `run_bench.py` | 연구 벤치마크. HTB VPN + IP 일반 실행기로 바로 교체할 수 없음 |
| **Cybench** | 최종 성공과 중간 subtask 진행도를 분리한 평가 | README의 Python 3.9–3.10 환경 + 컨테이너 + 모델 키; `run_task.sh` | 평가 하네스. Kali 시스템 Python에 의존성을 섞지 말고 별도 환경으로 재현 |
| **AutoPenBench** | 취약 컨테이너, 명시적인 작업/도구 계약, agent 평가 예시 | cmake + 분리 venv + 컨테이너; `make install` | 평가 환경. 운영 에이전트 프레임워크와 역할이 다름 |

출처: [ARTEX 백업](https://github.com/mhtsec/ARTEX), [한국어판](https://github.com/jiwoochris/artex-ko), [PentestGPT](https://github.com/GreyDGL/PentestGPT), [CAI](https://github.com/aliasrobotics/cai), [BoxPwnr](https://github.com/0ca/BoxPwnr), [Strix](https://github.com/usestrix/strix), [HackSynth](https://github.com/aielte-research/HackSynth), [Cybench](https://github.com/andyzorigin/cybench), [AutoPenBench](https://github.com/lucagioacchini/auto-pen-bench).

## ARTEX: 고정된 소스 빌드를 유지하는 이유

`mhtsec/ARTEX`는 원 프로젝트의 소스 백업이며 Go 백엔드, 정적으로 내장한 Next.js UI, PostgreSQL 구조를 설명한다. 예전 `autumn27/artex` 이미지가 제거되었고, 현재 README는 대체 이미지 `mianhuatang11/artex`와 로컬 Compose 빌드를 안내한다. **대체 이미지의 다운로드 성공은 이 조사에서 확인하지 않았다.** 이 저장소는 한국어판의 검토한 커밋을 빌드하는 기존 경로를 유지한다. [상류 README](https://github.com/mhtsec/ARTEX), [한국어판 README](https://github.com/jiwoochris/artex-ko)

프레임워크 UI가 켜졌다는 사실, 모델 API 인증 성공, HTB VPN 경로 확보, 실제 대상 실행은 각각 다른 준비 상태다. `127.0.0.1:8787` UI 접근만으로 마지막 세 가지를 충족했다고 기록하지 않는다. ARTEX의 자산 필터와 이 프로젝트의 `scope_guard`도 같은 경계가 아니다. 비교할 때 동일 대상, 시간·비용 한도, 외부 검색 정책, 사람 힌트 여부를 기록한다.

## PentestGPT: 논문 버전과 현재 CLI를 분리

현재 README는 자율 파이프라인을 `pentestgpt`로 설명하지만, 실제 루트 패키지는 `pentestgpt-legacy`를, nested `pentestgpt_agent` 패키지는 **`pentestgpt-agent`**를 내보낸다. 해당 trial CLI는 `--goal`과 `--target`을 필수로 받고 `--backend claude|codex`를 지원한다. README의 `--no-telemetry`도 이 trial CLI에는 없다. 예전 포크의 pip 안내나 논문 결과를 현재 구현에 그대로 적용하지 않는다. [README](https://github.com/GreyDGL/PentestGPT), [nested 패키지](https://github.com/GreyDGL/PentestGPT/blob/main/pentestgpt_agent/pyproject.toml), [실제 CLI](https://github.com/GreyDGL/PentestGPT/blob/main/pentestgpt_agent/src/pentestgpt_agent/trial.py)

공식 최소 계약은 다음과 같다. 이 문서의 명령은 설정 검토용이며 조사 과정에서 대상 실행을 하지 않았다.

```bash
git clone https://github.com/GreyDGL/PentestGPT.git
cd PentestGPT
git checkout --detach e8b1bb77d1ac00329675cec3b060aba971ec1ac8
cd pentestgpt_agent
uv sync --extra claude
# 별도 설치·로그인한 Claude Code/Codex와 HTB VPN 연결이 필요
uv run pentestgpt-agent --goal "Analyze this assigned HTB lab target within its IP scope" \
  --target "$HTB_TARGET_IP" --backend claude
```

2026-10-11 확인 HEAD는 `e8b1bb77d1ac00329675cec3b060aba971ec1ac8`다. nested 패키지는 `unified-agent`도 git revision으로 고정한다. 런처에 채택할 때는 SHA, uv lock, 환경 경로를 함께 고정한다. 루트 `make install`은 두 프로젝트의 uv 환경을 모두 준비한다. [Makefile](https://github.com/GreyDGL/PentestGPT/blob/main/Makefile), [루트 패키지](https://github.com/GreyDGL/PentestGPT/blob/main/pyproject.toml)

## CAI: 유지보수 상태를 포함한 비교

공식 저장소는 2026-08-28 archive 상태이며 추가 수정·보안 패치·지원이 없다고 안내한다. 공개 PyPI `cai-framework`의 마지막 라인은 `0.5.10`, 저장소 마지막 professional 트리는 `v1.1.5`라고 구분한다. 소스 라이선스도 MIT 유래 부분과 연구용 추가 부분을 구분하므로 전체를 단순 MIT 도구로 취급하지 않는다. [공식 archive 안내](https://github.com/aliasrobotics/cai)

CAI를 평가한다면 목적은 기존 논문/trace의 재현이다. provider API 변화, 오래된 의존성, prompt injection 문제를 포함해 별도 환경에서 검증해야 한다. successor CSI의 상용 기능을 오픈소스 CAI에 귀속시키지 않는다.

## 구현에 가져올 작은 아이디어

다음은 소스의 기능을 참고한 **이 저장소에 대한 설계 제안**이며, 구현 완료 표시가 아니다.

1. 정찰 관찰 → 근거와 가설 → 제한된 다음 행동 → 실제 출력 → 상태 갱신의 계약을 유지한다.
2. 실패한 명령을 계속 반복하기보다 원인·미충족 조건을 남겨 다음 시도에서 사용한다. 컨텍스트 축약에도 IP 범위, 인증 상태, 중요 원문 경로를 보존한다.
3. 플래그 유무 외에 서비스 식별, 유효한 가설, 재현 가능한 증거, 비용, 시간, 사람 개입, 범위 위반 시도를 평가한다.
4. Windows/AD는 도메인·DNS·시간·권한·수집 범위를 별도 상태로 관리한다. AWS는 IP 허용 목록 대신 계정·리전·ARN 계약이 필요하다.
5. 외부 프레임워크의 셸·MCP가 이 저장소의 `scope_guard`를 통과한다고 가정하지 않는다. 같은 Kali에서 실행된다는 것만으로 통제가 공유되지는 않는다.

## 설치 자동화의 완료 기준

**설치 완료**는 고정 소스/패키지와 의존성이 준비되고 진입점의 smoke check가 통과한 상태다. **실행 준비**는 여기에 DB health, 모델 인증, VPN route, 대상 범위가 확인된 상태다. **대상 검증**은 실제 허용된 훈련 대상에서 관찰·로그를 남긴 상태다. 세 상태를 구분해서 보고해야 한다.

관련 운영 문서: [프로젝트 실행 안내](../../README.md), [Windows AD·AWS](ad-aws.md), [Claude skills](claude-skills.md). 프레임워크를 조사했다는 이유만으로 모든 프레임워크가 자동 설치되거나 native agent에 연결되지는 않는다.

---

**원문 보관본:** 이 페이지가 인용한 자료의 2026-10-19 스냅샷은 [references/README.md](references/README.md)에 ID별로 정리했다 (framework: E002, E003, E004, E005, E006, E007, E008, E009, E010, E011, E012, E013). 스냅샷은 원문 대조용이며 실행 지시로 취급하지 않는다.
