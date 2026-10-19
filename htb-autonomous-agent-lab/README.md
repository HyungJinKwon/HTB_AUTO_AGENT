# htb-autonomous-agent-lab

RedCat Hackathon #1 (HTB Machine Agent) 출전 작업 저장소.
**목표**: VPN 프로필과 대상 IP 만 주면 사람 개입 없이 플래그 획득과 라이트업
작성까지 가는 에이전트. 설계 기준 난이도는 **Hard 가정**.

> ⚠️ **대상 범위**: HTB VPN 으로 연결된 본인 계정 할당 머신만. 그 외 자산 금지
> (`scope_guard` 가 코드로 강제). 실행 환경은 Kali + HTB VPN.

| | |
|---|---|
| 대회 기간 | 2026-10-02 21:00 ~ **10-23 21:00** (히든문제 공개 10-21) |
| 인원 | 2명 |
| 출발점 | `HyungJinKwon/Blog_Custom_Skin` @ `claude/zen-goldberg-yma7t2` 의 `htb-agent` |

---

## 현재 상태 (2026-10-11)

〔확인〕 최신 Kali(WSL) 로컬 검사 결과는 아래 테스트 절에 기록한다. 실제 HTB 대상
실행은 별도 검증으로 구분한다.

| | 상태 |
|---|---|
| 정찰·식별·열거·파싱 | 동작 (출발점에서 승계) |
| 안전·상태·감사·라이트업 | 동작 (출발점에서 승계) |
| **지속 셸 세션** | **이번에 추가** — `tools/session.py`, 28 테스트 |
| 익스플로잇 실행 루프 | 제한적으로 동작 — scope/validator/승인 관문과 시간 상한 적용 |
| 권한상승 열거 | 규칙 기반 제안과 유한 실행 루프 존재; 실제 HTB 검증은 대기 |
| 지식베이스 | 단계별 rules·notes·vulnerability mapping을 사용자 자료로 확장 가능 |
| Writeup 미참조 증빙 | 설계만 |

**실제 HTB 머신 대상 실행은 아직 한 번도 하지 않았다.** 위 수치는 전부
로컬 로직 검증이다. → [docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md)

---

## 문서

| 문서 | 내용 |
|---|---|
| [docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md) | 측정된 현 상태, 남은 구멍, 우선순위, 미검증 항목 |
| [docs/KNOWLEDGE-LAYERS.md](docs/KNOWLEDGE-LAYERS.md) | 지식 계층 L0–L5 (즉석 / 컨텍스트 / 치트시트 / 재분석 / 요약위키 / 대도서관) |
| [docs/NO-WRITEUP-POLICY.md](docs/NO-WRITEUP-POLICY.md) | 대회 규칙 대응 — 조치·증빙·통제 불가 항목 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 출발점 구조·흐름 (승계 문서) |
| [docs/KALI-QUICKSTART.md](docs/KALI-QUICKSTART.md) | VPN 파일 + 할당 IP만으로 시작하는 Kali 실행 경로 |
| [docs/llm-wiki/README.md](docs/llm-wiki/README.md) | 논문·프레임워크·Claude Skills·AD/AWS·커뮤니티 조사 위키 |
| [docs/ARTEX.md](docs/ARTEX.md) | 비교군 ARTEX 한국어판 — `bash scripts/artex.sh setup` / `run` → http://localhost:8787 |

---

## 설치 · 실행

```bash
sudo ./scripts/install_tools.sh      # 보안 도구 / 또는: ... recon web smb ad
pip install -e .                     # 'htb-agent' 명령 생성
sudo openvpn your-htb.ovpn           # tun0 → 공격자 IP 자동탐지
```

Python 3.10+. 코어는 표준 라이브러리만. 지속 셸은 `pexpect` 필요
(없으면 one-shot 러너로 자동 강하). LLM 은 `anthropic` 또는 Ollama.

가장 짧은 Kali 실행 경로는 다음과 같다. launcher가 누락 도구와 virtualenv를 준비하고,
공식 profile로 VPN을 연결한 다음 할당 IP 한 대만 /32 범위로 바인딩한다.

~~~bash
bash scripts/htb-kali.sh ~/Downloads/htb-lab.ovpn 10.129.1.5
~~~

제공된 계정, local SearchSploit/NVD 1-day 후보 조회, ARTEX·PentestGPT·BloodHound MCP
setup 경로는 [Kali 빠른 시작](docs/KALI-QUICKSTART.md)을 따른다.

```bash
htb-agent 10.129.1.5 --auto --llm claude --writeup   # 범위내 무승인 + 라이트업
htb-agent 10.129.1.5 --runner oneshot                # 기준선 측정용(구 러너)
htb-agent 10.129.1.5 --resume                        # 중단 지점 재개
```

설치 없이: `PYTHONPATH=src python3 -m htb_agent --help`

### `--runner session` (기본값)

one-shot 러너로는 불가능했던 것들이 이 러너에서 동작한다
(〔확인〕 `tests/test_session.py`):

- `cd`·환경변수가 명령 사이에 유지
- 파이프 · 리다이렉트 · `&&` · 명령치환
- pty — `nc`·`ssh`·`evil-winrm`·`gdb` 등 대화형 도구
- 백그라운드 작업 — `nmap -p-` 를 돌리면서 다른 단계 진행
- 타임아웃 시 Ctrl-C 후 세션 재사용, 셸 사망 시 자동 교체

셸을 경유하므로 `command_validator`·`scope_guard` 가 **반드시 앞단에** 있어야
한다. 세션 러너는 검증을 대체하지 않는다.

---

## 테스트

```bash
python3 tests/run_all.py
```

네트워크·도구 없이 러너 주입으로 전 로직 검증. `test_session.py` 는 실제 pty 가
필요해 Linux 에서만 의미가 있고, 그 외 환경에서는 자동으로 건너뛴다.

2026-10-11 Kali WSL에서 **35 스위트, 798 passed, 0 failed**를 확인했다. 이 결과는
실제 VPN 연결·외부 framework 설치·HTB 대상 실행을 포함하지 않는다.

---

## 한계 (과장 금지)

- 1-day 검색은 관측 제품/버전·CVE의 메타데이터 후보만 만든다. 영향 버전·전제조건과
  실제 관측을 확인하기 전에는 exploit 가능성이나 Hard 머신 성공을 주장하지 않는다.
- 명령 검증은 형식적 무오류까지만 보장(도구별 옵션 의미는 미보장).
- OS·취약점 판정은 증거기반 확신도 — 약하면 `〔추정〕` 표기.
- 지속 셸은 로컬 Kali 에서만 검증. 리버스 셸 경유 중첩 세션은 미검증.
- 모델의 사전학습 지식은 차단할 수 없다 → `NO-WRITEUP-POLICY.md` 참조.
