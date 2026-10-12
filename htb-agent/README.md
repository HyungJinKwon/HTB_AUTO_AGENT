# ASSASSIN — 승인제 자동 풀이 에이전트 (HTB · Dreamhack · CTF)

```
▄▀█ █▀ █▀ ▄▀█ █▀ █▀ █ █▄░█
█▀█ ▄█ ▄█ █▀█ ▄█ ▄█ █ █░▀█
```

레드팀 학습·모의해킹·CTF 연습용. **권한이 확인된 대상에 한정**해 동작하는,
승인제(Human-in-the-loop) 자동 풀이 보조 에이전트. **명령은 `assassin`** (`htb-agent` 는 하위호환 별칭).

### ⚡ 모드 한눈에 (자주 쓰는 명령)

| 상황 | 명령 |
|---|---|
| 처음 써 보기(위험한 것만 확인) | `assassin 10.129.1.5` |
| 모든 명령 보며 배우기 | `assassin 10.129.1.5 --manual` |
| 해커톤(최대 자율+시간제한) | `assassin 10.129.1.5 --autonomous --time-budget 45 --writeup --html` |
| 샌드박스에서 실제 익스까지 | `assassin 10.129.1.5 --autonomous --sandbox docker --llm hybrid` |
| 🚀 완전 자동 루트 시도(발판·플래그까지) | `assassin 10.129.1.5 --autonomous --llm claude --exploit-exec --auto-poc --html --json` |
| CTF/Dreamhack 문제 | `assassin chall.host:1337 --platform ctf --category web` |

### 📚 문서 안내

| 문서 | 내용 |
|---|---|
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | 1쪽 빠른 시작(설치·상황별 한 줄·화면 읽는 법) — **처음이라면 여기부터** |
| [docs/USAGE.md](docs/USAGE.md) | 전체 사용법(설치·모드·플랫폼·발판 실행·산출물·트러블슈팅) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 구조·다이어그램·모듈 지도 |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) · [docs/VALIDATION.md](docs/VALIDATION.md) | 운영 / Kali 수용 테스트 |

> 아래는 모드별 상세 설명입니다. 바로 실행하려면 위 표 또는 QUICKSTART 로 충분합니다.

**플랫폼 프로파일** `--platform {htb,dreamhack,ctf}`:
- `htb` (기본): HTB VPN 대역 강제 · boot2root(user.txt/root.txt, 32-hex/HTB{})
- `dreamhack` / `ctf`: 챌린지 단일 타겟(host:port/URL) 바인딩 · Jeopardy 단일 플래그
  (DH{}/flag{}/CTF{} 등 `TAG{}` 자동 인식, `--flag-prefix` 로 추가)

> 터미널 출력은 블루/네이비 팔레트의 색상·박스·정렬 UI 로 렌더링됩니다
> (비-TTY·파이프·`NO_COLOR` 환경에서는 색 자동 비활성 → 로그/CI 안전).

> ⚠️ **대상 범위**: 대회/플랫폼이 명시한 권한 확인 대상만. 그 외 자산 사용 금지
> (Scope Guard 가 코드로 강제 — 가드가 해석하지 못하는 주소 표기는 기본 확인 대상).
> 실제 공격 실행은 사용자 Kali 환경에서.

**승인 모드**(기본=스마트): 범위내·검증통과 명령은 자동 실행, 검증실패(파괴명령 포함)는
자동 거부, **범위 밖만 사람 확인**. `--auto`(완전자동)·`--manual`(완전수동)로 조절.
탐지된 CVE/CWE 는 **공식 출처(NVD·GitHub PoC)에서 자동 수집·캐시**(`--no-enrich`/`--offline`).

> **능동적 완전자동 모드**: `assassin 10.129.1.5 --autonomous`(별칭 `--hackathon`) —
> 한 명령으로 최대 자율 풀이. 범위내 자동승인 + 깊은 재진입 스윕(3) + 병렬 열거(4) +
> 변형 학습 + 전 자동준비(리버스쉘·클라우드·권한상승·크래킹)를 묶어 목표(flag/root)까지
> 스스로 추진합니다. 두뇌까지 쓰려면 `--llm hybrid` 추가. **안전 경계는 유지** —
> 범위 밖·파괴명령은 여전히 게이트. `--manual` 은 autonomous 보다 우선합니다.
>
> **샌드박스에서 실제 익스플로잇까지(`--sandbox docker`)**: 완전자율로 파이프·스크립트·
> 대화형 도구까지 쓰려면 egress 강제 샌드박스를 켭니다. Kali 컨테이너 안에서 `bash -c` 로
> 실행하되 **네트워크는 타겟 대역만** 허용(iptables 기본 DROP), 명령은 비root 로 돌아 정책을
> 바꿀 수 없습니다. 이 안에서는 LLM 이 쓴 익스플로잇/솔버 스크립트를 자동 실행하고, 동적·원격
> 코드 실행(파이프→셸 등)도 자동 승인합니다(범위는 컨테이너 방화벽이 강제).
> 이미지 빌드: `./scripts/build_sandbox.sh`. 샌드박스 없이(기본 `none`)는 셸 연산자·스크립트
> 실행이 수동 제안으로 남습니다.
>
> ```bash
> ./scripts/build_sandbox.sh                                   # 최초 1회(Kali 이미지 빌드)
> assassin 10.129.1.5 --autonomous --sandbox docker --llm hybrid
> # Dreamhack/CTF 첨부파일(소스·바이너리) 분석까지:
> assassin chall.dreamhack.io:8080 --platform dreamhack --category pwn \
>          --files ./prob.zip --autonomous --sandbox docker --llm hybrid
> ```
>
> **챌린지 첨부파일(`--files`)**: 제공 소스·바이너리·덤프를 작업공간 `files/`(읽기 전용)로
> 가져오면 LLM 이 먼저 읽고 취약 지점을 찾습니다. zip·tar 는 안전하게 풀고, 열린 포트가
> 없는 문제(rev/crypto/forensic)도 파일 분석으로 진행합니다.

> **발판 자동 실행(`--exploit-exec`, 옵트인·기본 OFF)**: 확보한 **평문 자격**(열거로 나오거나
> `--cred user:pass` 로 직접 준 것)으로 **SSH 발판을 잡아 `user.txt`/`root.txt` 를 자동으로 읽고**,
> 권한 상승 **열거**(`id`·`sudo -l`·SUID·capabilities — 파괴 없음)까지 기존 3관문(검증·범위·승인)을
> 거쳐 실행합니다. 해시·빈 값은 건너뜁니다. `--autonomous` 와 함께면 무프롬프트, 없으면 각 명령 y/n.
> **플래그를 확보하면** 결과 맨 끝에 **`🏁 다 풀었다(SOLVED)`** 패널이 떠 user.txt/root.txt(또는
> 단일 플래그) **값을 크게 보여 주고 출처(공략 유래=검증)를 함께 표시**합니다. 22 번 닫힘·자격 없음·
> `sshpass` 미설치면 조용히 건너뜁니다. `--exploit-exec` 없으면 동작은 지금과 100% 동일합니다.
>
> **PoC 자동 선택·발사(`--auto-poc`, `--exploit-exec` 와 함께·옵트인)**: 핑거프린트된 웹앱 버전에
> **맞는 공개 PoC(⭐ 1순위)를 자동 선택**해 실행 큐에 올리고, PoC 가 자격을 뱉으면 **SSH 발판**으로
> 접속해 플래그 읽기까지 잇습니다. 발판이 **실제로 성립했는지 검증**(`id`/`uname` 신호)해 헛발판은
> 버리므로, 성립 안 하면 조용히 발판 미확보로 끝납니다(섣부른 단정 없음). 권한 확인 대상 전용.
> ⚠️ 그 다음 단계인 **웹 RCE 발판 → 설정/DB 자격 수확 → 측면 이동**은 코드에 **정의돼 있으나 아직
> 실행 루프에 배선되지 않았습니다**(`_foothold_stage`·`lateral_candidates`). 이 배선과 발판 채널의
> 실제 네트워크 실행부(소켓/HTTP)는 **RCE 실행 표면**이라 사용자 리포에서 연결합니다 — 자세히는
> [docs/USAGE.md §10.3](docs/USAGE.md).
>
> ```bash
> # 자격을 확보한 Easy 머신 → 접속·플래그 읽기·권한상승 열거까지 자동, SOLVED 화면에 값 출력
> assassin 10.129.1.5 --cred svc:Summer2024 --exploit-exec --autonomous
>
> # 🚀 완전 자동 루트 시도(초보자용 한 줄): 정찰→버전→⭐PoC 자동선택→발판→플래그까지 + 결과물 저장
> assassin 10.129.1.5 --autonomous --llm claude --exploit-exec --auto-poc --html --json
> ```
>
> 위 한 줄의 플래그 뜻 — `--autonomous`(무프롬프트 완전자동) · `--llm claude`(Claude 두뇌) ·
> `--exploit-exec`(발판 실제 실행 켜기) · `--auto-poc`(⭐ PoC 자동 선택·발사) ·
> `--html`/`--json`(대시보드·기계판독 결과 저장).

---

## 진행 흐름 (모의해킹 단계 순서)

```
타겟 바인딩 → 정찰(RECON) → 식별(Linux/Win-AD) → 열거 → 초기 침투(user.txt)
          → 권한 상승(root.txt) → 측면 이동 → 취약점(CVE/CWE) → 리포트/라이트업
```

모든 실행 명령은 **① 검증 → ② 범위 → ③ 승인** 3관문을 통과해야 실행됩니다.
범위 안이라도 **동적·원격 코드 실행**(파이프→셸, `eval`, `IEX`, 명령 치환 등)은 자동실행하지
않고 사람 검토로 넘깁니다(`--auto`/`--autonomous` 에선 수동 제안으로 강등).
취약점(CVE/CWE)은 마지막 한 번이 아니라 **단계마다 반영**되어 다음 단계 판단에 바로 쓰이고,
목표(Jeopardy=플래그 1개, HTB=user+root)를 대상 상호작용 출력에서 확보하면 남은 단계는
`생략(목표 달성)` 으로 조기 종료합니다. 도구 미설치로 건너뛴 명령은 명령 수 상한을 쓰지 않습니다.
단계·라운드·명령 수에 상한이 있어 무한루프가 없습니다. 각 명령은 도구별로
**유효·안전한 옵션 조합 변형(경우의 수)** 을 몇 가지 더 시도해(`--variants`),
한 가지 방식만 보고 포기하지 않습니다 — 변형도 유한하며 3관문을 그대로 통과합니다.

**처음이라면 [docs/QUICKSTART.md](docs/QUICKSTART.md)(1쪽 빠른 시작)부터.** 처음부터 끝까지의 사용법은 [docs/USAGE.md](docs/USAGE.md) (설치·모드·플랫폼·지식 자동 반영·산출물·트러블슈팅).
발표·연습은 `./scripts/showcase.sh` 한 번으로 데모·성능 측정·재생 HTML·대시보드를 만듭니다.
구조·다이어그램·모듈 지도는 **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** 참고.
실제 Kali 에서 처음부터 끝까지 검증(수용 테스트)하려면 **[docs/VALIDATION.md](docs/VALIDATION.md)**
(단계별 명령·기대 결과·체크리스트·기록표).

---

## 설치 (Kali / Ubuntu)

최신 Kali·Ubuntu 는 시스템 파이썬이 **PEP 668(externally-managed)** 로 잠겨 있어 `pip install` 이
거부됩니다. **venv(가상환경)** 에 설치한 뒤, 명령을 `~/.local/bin` 에 **심링크**해 어느 디렉터리에서나
`assassin` 이 바로 먹히게 하는 것이 가장 깔끔합니다(venv 를 매번 activate 하지 않아도 됨).

```bash
# 새 PC·VM 스냅샷 — 저장소 기본(default) 브랜치로 클론 (clone 은 기본 브랜치를 자동 체크아웃)
git clone https://github.com/HyungJinKwon/HTB_AUTO_AGENT.git ~/HTB_AUTO_AGENT
# (이미 받아둔 경우 최신화) git -C ~/HTB_AUTO_AGENT pull --ff-only
cd ~/HTB_AUTO_AGENT/htb-agent
sudo ./scripts/install_tools.sh            # 보안 도구 전체(BloodHound·S3 등) / 또는: ... recon web smb ad

python3 -m venv .venv                      # 가상환경 생성(PEP 668 우회)
source .venv/bin/activate
pip install -e ".[claude]"                 # 에이전트 + Claude(anthropic) 설치 → 'assassin' 생성

# 어디서나 쓰도록 ~/.local/bin 에 심링크(venv 를 매번 켜지 않아도 됨)
mkdir -p ~/.local/bin
ln -sf ~/HTB_AUTO_AGENT/htb-agent/.venv/bin/assassin  ~/.local/bin/assassin
ln -sf ~/HTB_AUTO_AGENT/htb-agent/.venv/bin/htb-agent ~/.local/bin/htb-agent
grep -q 'local/bin' ~/.zshrc || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc; hash -r
assassin --version                         # 어디서든 동작하면 성공

sudo openvpn your-htb.ovpn                 # (HTB) tun0 → 공격자 IP 자동탐지
```

Python 3.10+ (코어는 표준 라이브러리만, 외부 의존성 없음). `[claude]` 는 Claude API(anthropic)를 함께 설치합니다 —
규칙 기반만 쓰거나 로컬 Ollama 만 쓸 거면 `pip install -e .` 로 충분합니다.

> **bash 사용자**는 `~/.zshrc` 대신 `~/.bashrc` 로 바꾸세요(Kali 기본 셸은 zsh). `[claude]` 의 대괄호는
> zsh 에서 glob 으로 해석되므로 반드시 따옴표로 감쌉니다(`".[claude]"`).
> **설치 없이** 한 번만 돌려 보려면 `cd htb-agent` 에서 `PYTHONPATH=src python3 -m htb_agent ...` 로 실행.
> **브랜치**: 새 PC·VM 스냅샷에서는 위처럼 **기본(default) 브랜치**를 그대로 쓰세요(`clone`/`pull` 이 자동 선택).
> `claude/*` 작업 브랜치는 CI·리뷰 중 임시로 강제동기될 수 있으니 로컬 실행용으로 체크아웃하지 마세요.

## 실행

설치(`pip install -e .`) 후에는 어디서나 `assassin` 명령을 쓸 수 있습니다.
**처음이라면 먼저 `assassin --doctor`** 로 환경(도구·VPN·LLM)을 점검하세요.
LLM(Claude·로컬 Ollama)은 **`assassin --setup-llm`** 마법사로 한 번에 연결합니다 — 질문에 답하면 키 입력(화면 비표시·600 권한
저장)·로컬 모델 추천·실제 1회 호출 확인·기본 설정 저장까지 끝나고, 이후엔 `--llm` 없이 실행해도 연결된 LLM 을 씁니다.

```bash
# 승인제 포트스캔+열거 (명령마다 3분할 해설 + 승인)
assassin 10.129.1.5   # (htb-agent 도 동일 — 하위호환 별칭)

# 범위내 자동승인 + 자격증명(→ 초기 침투·플래그 승격) + 라이트업 생성
assassin 10.129.1.5 --auto --cred administrator:Passw0rd --writeup

# 결과 내보내기: 기계판독 JSON + 블루/네이비 HTML 대시보드
# (HTML 상단 '한눈에 보기': 진행 결과·3관문 지표·플래그 출처·지식 기반·LLM 라우팅·안전 경계·단계 진행 + 분석(병렬 가설) — 발표/심사용)
assassin 10.129.1.5 --json --html   # <state-dir>/report_<타겟>.{json,html}

# 명령당 옵션 조합 변형(경우의 수) 수 조절 (기본 2, 1=변형끔)
assassin 10.129.1.5 --variants 3

# Dreamhack / CTF 챌린지 (단일 타겟 + flag{} 모드)
assassin web-chall.dreamhack.games:8080 --platform dreamhack
assassin http://ctf.example.com/chall --platform ctf --flag-prefix myctf
assassin chall.dreamhack.io:8080 --platform dreamhack --category pwn --llm hybrid   # 카테고리 힌트로 LLM 유도

# 승인 모드: 완전자동 / 완전수동 / 오프라인(CVE 자동수집 끔)
assassin 10.129.1.5 --auto
assassin 10.129.1.5 --manual
assassin 10.129.1.5 --offline

# LLM 두뇌 / 중단 후 재개 / 설정 파일
assassin --setup-llm                                 # LLM 연결 마법사(처음 한 번) → 기본 설정 저장
assassin --llm-test                                  # LLM 실제 호출 테스트(틀린 키·없는 모델 확인)
assassin 10.129.1.5 --llm hybrid                     # 하이브리드(Ollama+Claude 라우팅/폴백)
assassin 10.129.1.5 --llm claude --llm-tier standard
assassin 10.129.1.5 --resume                         # 실행된 명령은 다시 돌리지 않고 이어서
assassin 10.129.1.5 --config config/config.example.json
```

> **하이브리드 LLM(`--llm hybrid`)**: 열거·일반은 로컬(Ollama) 우선, 권한상승·분석은 강력(Claude) 우선으로
> 라우팅하고 실패·빈 응답·거절 시 상대 백엔드로 폴백합니다. 같은 백엔드가 연속 2회 오류를 내면 그 세션 동안
> 건너뛰고(서킷 브레이커), Ollama 에 티어 모델(예: strong=`llama3.3:70b`)이 없으면 설치된 모델로 대체해 시작 시
> `로컬 모델 대체: strong→qwen2.5:7b` 로 알립니다. 실행 끝에 `라우팅: 로컬 N · 강력 N · 폴백 N · 거절 N · 빈응답 N ·
> 오류 N · 미응답 N` 이 표시됩니다.
>
> **분석가(다관점·병렬 가설)**: 레드팀·개발자·인프라 운영자·방어 관점으로 가설 2~4개(H1…)를 세워 병렬로 비교하고
> 검증 계획을 냅니다. 결과 비고에는 `가설 H1 · 근거: …` 로 어떤 가설을 검증했는지 남습니다.
>
> **방향성(가설 기록)**: 분석가(Claude)가 세운 가설은 **가설 기록**으로 저장되고, 다음 분석은 처음부터 다시 쓰지 않고
> 이 기록을 **갱신**합니다. 명령 생성(로컬 우선)에는 분석 전문 대신 **지금 할 일 1개**(가설·확인 방법·기대 신호·이미
> 해 본 명령)만 줍니다. 결과는 기대 신호와 규칙으로 대조해 가설을 `확인`/`검증중`으로 갱신하고, 같은 가설이 **2회 연속**
> 어긋나면 `막힘`으로 표시해 분석가에게 재계획을 요청합니다. 재분석은 새 크리덴셜·서비스·취약점·권한·플래그,
> 가설 확인·기각·막힘 때만 일어나고, `--resume` 하면 가설 기록도 이어집니다. 화면·HTML·라이트업에 **가설 보드**가
> 표시됩니다. 가설 상태는 방향 잡기용〔추정〕이며 플래그·목표 판정에는 쓰지 않습니다.
>
> **중단·종료코드**: 실행 중 Ctrl+C 는 그때까지의 결과를 저장하고 `status=interrupted` 로 끝납니다(같은 명령에
> `--resume`). 종료코드: 0=완료 · 1=미완(열린 포트 미확보 등) · 2=인자/설정/범위 오류 · 130=사용자 중단.

전체 옵션: `assassin --help` (설치 전: `PYTHONPATH=src python3 -m htb_agent --help`).

> **완성형 지식으로 시작**: 카탈로그 59개 주제 전체(+ADCS·Linux/Windows 권한상승 = 번들 시드 62개)의 **종합 레퍼런스 번들 시드**(개요·핵심
> 기법/열거·표준 도구/명령·블루팀 탐지·완화·권위 출처)가 저장소에 포함되어, 누가
> clone 해도 **오프라인에서 동일하게 심화 지식을 가진 완성형 상태로 시작**한다(CI
> 불변식으로 완비·깊이·섹션 강제). 웹 취약점·AD 공격체인·서비스 열거·전술 전반 포괄.
> **일괄 온라인 보강**: `assassin --learn all` — 59개 주제의 최신 본문을 권위
> 출처에서 한 번에 덧씌움(오프라인이면 출처 포인터만, 시작 지식은 번들 시드가 보장). 36개 주제는
> 2차 출처(CWE/CAPEC 정의·OWASP 치트시트·Wireshark/Nmap·MDN)를 함께 학습해 관점을 넓힙니다.
> **성장 공유(검토 후 승격)**: 학습 노트(`learned-*.md`)는 환경마다 달라 커밋하지 않으므로,
> 그대로 두면 사람마다 성장이 따로 일어난다. `assassin --promote <주제|all>` 은 그중 **품질 관문**
> (권위 출처 · 충분한 요약 · 웹페이지 군더더기 없음 · 라이트업 신호 없음)을 통과한 항목만 번들 시드의
> `## 최신 보강(승격)` 섹션으로 옮긴다(사람이 다듬은 본문은 그대로, 같은 출처는 교체, 주제당 3건 상한).
> 결과 diff 를 커밋·PR → 리뷰·CI(같은 관문 재검사) 통과로 병합되면 **모든 사용자의 시작 지식이 함께 자란다.**
> 카탈로그에서 교체·삭제된 출처의 승격분은 다음 승격 때 자동 정리되고, 내용이 같으면 최초 승격일을 유지한다.
> **자동 반영(손 안 대도 됨)**: ① 공유 — GitHub Actions `KB 자동 승격`(매주 월 03:17 KST, 수동 실행 가능)이
> `--learn all` → `--promote all` → **전체 테스트 검증** 후 PR 을 열고 자동 병합한다(저장소 설정: Actions 쓰기 권한 +
> "Allow GitHub Actions to create and approve pull requests"). ② 로컬 — 타겟을 실행하면 **하루 1회** 공유 저장소의
> 최신 시드를 조회해 로컬과 다른 것만 받고, 같은 품질 검증(필수 섹션·권위 출처·승격 관문·크기·해시)을 통과한 것만
> `knowledge/shared_seeds/`(git 추적 안 함) 캐시에 적용한다. 데이터만 받고 코드는 받지 않으며, 추적 파일을 건드리지
> 않아 git pull 충돌이 없다. 로컬에서 편집 중(미커밋)인 시드는 덮어쓰지 않고, 이후 git pull 로 시드가 바뀌면 캐시본은
> 자동으로 무시된다. 즉시 동기화: `assassin --kb-sync` · 끄기: `--no-kb-sync` / `--offline` / `ASSASSIN_NO_KB_SYNC=1`.
> **내 자료 학습**: `assassin --ingest ./my-writeups/` — .md/.txt/.pdf 파일/디렉터리를
> 지식베이스 노트로 학습(원문 보존). 본인이 올린 자료는 **참조 허용** — RAG 가 풀이 중 참조(P1 금지는 외부 라이트업 자동수집뿐).
> **자율 지식 획득**: `assassin <target> --learn-gaps` (autonomous 모드 기본 활성) —
> 풀이 중 **모르는 기술/제품을 만나면 스스로 권위 출처에서 찾아 배워** KB 에 즉시
> 반영한다(예: MongoDB 관측 → NoSQLi 지식 자동 연결·학습). 매핑 불가한 용어는
> 지어내지 않고 '미해석 공백'으로 기록(수동 조사 안내). allowlist·P1 유지.
> **인터넷 검색 학습**: `assassin <target> --web-learn` (autonomous 기본 활성 · 공백 탐지 `--learn-gaps` 를 함께 켬) —
> 카탈로그 밖 '미해석 공백'을 **넓은 인터넷 검색**으로 학습해 KB 에 반영한다. 단
> **HTB 라이트업은 출처 불문(공식·제3자) 전부 차단**(HTB 라이트업은 오직 사용자
> 본인 ingest 로만 유입). 일반 기법 아티클·공식 문서는 허용하되 **교차검증**(출처 신뢰등급 A/B 또는 독립 출처 상호확인 + 보안 관련성) 통과분만 채택. 가져온 내용은 노트로만
> 저장(실행 안 함, 신뢰불가 데이터). 오프라인에선 생략.

> **자가학습**(권위 출처만, 라이트업 미참조): `assassin --learn kerberoasting`
> (MITRE ATT&CK·OWASP·PortSwigger·RFC 등 허용 도메인 → 지식베이스 노트로 축적,
> `--learn list` 로 주제 목록). 도구·공격기법·개념/정의·프로토콜을 학습합니다.

> **리버스쉘 페이로드 생성**(실행 안 함): `assassin --revshell 10.10.14.5:4444`
> (bash/nc/python3/php/powershell/socat 등 + 리스너·안정화 힌트).
> **자동 준비**: 풀이 실행 중 공격자 IP(tun0 자동탐지 또는 `--attacker-ip`)가 확보되면
> 초기 침투용 리버스쉘 페이로드를 **별도 명령 없이 자동 생성**해 리포트·라이트업·
> JSON/HTML 에 포함합니다(생성만 — 실제 셸 획득은 권한 확인 대상에서 사용자가 직접,
> 리스너 포트는 `--lport`, 기본 4444).
> **AWS/S3 열거 자동 준비**: 풀이 중 호스트명/도메인이 확보되면 **버킷명 후보 +
> 비인증 점검 명령(aws s3 ls --no-sign-request·curl·s3scanner·cloud_enum·자격증명 확인)을
> 자동 생성**해 리포트·라이트업·JSON/HTML 에 포함합니다(생성만 — AWS 엔드포인트는
> 타겟 범위 밖이라 실행은 사용자가 권한 확인 자산에서 직접). 단독 실행: `assassin --cloud acme.htb`.

> **권한 상승 플레이북 자동 준비**: OS(Linux/Windows/AD) 식별 시 **포스트-익스플로잇
> 권한상승 열거·점검 체크리스트(sudo -l·SUID·capabilities·cron·커널·토큰·서비스
> 오구성·LinPEAS/WinPEAS + 커널/탐지CVE 기반 LPE 후보)를 자동 생성**해 리포트·
> 라이트업·JSON/HTML 에 포함합니다(생성만 — 획득한 대상 셸에서 사용자가 직접 실행).
> 단독 실행: `assassin --privesc linux`.

> **해시 크래킹 자동 준비**: 실행 출력·크리덴셜에서 **해시(Kerberoast/AS-REP/
> NetNTLMv2/유닉스 crypt/NT 등)를 자동 수집·식별해 john·hashcat 명령(올바른
> 모드/포맷·워드리스트)을 자동 생성**합니다(생성만 — 크래킹은 사용자 환경에서 실행).
> 단독 실행: `assassin --crack '$krb5tgs$23$...'`.

> **데모(네트워크·실도구 없이 전체 흐름 보기)**: `python3 scripts/demo.py`
> · **발표용 라이브 시연**: `python3 scripts/demo.py --live [--pace 2]` — 범위 밖 바인딩 거부 →
> 정찰·식별 → 열거 → **3관문 작동(검토 강등·범위 밖 미실행·통계)** → 지식(완성형 시작·검증 공유) → 산출의 6단계를 순서대로 보여줌
> (라이트업 저장: `python3 scripts/demo.py --write out/`). 실전 운영·트러블슈팅은
> **[docs/OPERATIONS.md](docs/OPERATIONS.md)** 참고.

> **성능 측정 — 오프라인 vs 라이브**:
> - `assassin --bench` : 가짜 응답(오프라인 모의 문제)으로 빠르게 회귀 측정(실제 통신 없음).
> - `assassin --live-bench` : **실제 서비스를 띄우고 진짜 도구로 풀이** — 발표/심사용 신뢰 수치
>   (성공률·pass@k·검증된 풀이율·시간). `--attempts N`·`--llm hybrid` 적용. 체인 풀이(예:
>   robots→숨은 경로, 쿠키 우회, LFI)는 `--llm` 을 켜야 풀립니다(KB만으로는 직접 노출형만).
>
> `bench/live/` 문제 종류(`challenge.json` 의 `kind`):
> - **loopback** — 파이썬 취약 서비스를 전용 127.0.0.x·표준 포트에 기동. 어디서나 실행(nmap 없이
>   소켓 폴백·`curl`/`nc` 로 풀이). web(robots·헤더·소스주석·쿠키우회·LFI)·misc(nc 배너).
> - **docker** — challenge 의 Dockerfile 로 실서비스 컨테이너를 전용 IP·표준 포트에 기동. 데몬
>   없으면 건너뜀. ftp(익명)·redis(비인증)·smb(게스트)·mysql(빈 root)·snmp(public).
> - **vm** — 컨테이너가 아닌 실제 머신(HTB·Dreamhack 머신, VirtualBox/VMware/libvirt VM). 주소는
>   `address` 또는 `ASSASSIN_VM_<이름>=<IP>` 로 지정, 선택적 `start_cmd`/`stop_cmd` 로 부팅/정리.
>   자세히는 `bench/live/vm-htb-example/README.md`.
>
> ```bash
> assassin --live-bench --attempts 3 --llm hybrid        # 전체(loopback + 가능한 docker) pass@3
> assassin --live-bench --attempts 1                      # KB만(규칙기반) 기준선
> ASSASSIN_VM_VM_FOREST=10.129.10.5 assassin --live-bench --llm hybrid   # 실제 VM(권한 확인 자산만)
> ```
> 문제 추가는 `bench/live/<이름>/` 에 `challenge.json` + 타겟(파이썬 `target.py` 또는 `Dockerfile`)만.

---

## 핵심 특징

| 분류 | 내용 |
|---|---|
| 안전 | Target-Binding 범위강제 · 명령 검증(문법·base64·해시·포트·파괴명령) · 승인 게이트(스마트/auto/manual) · **능동적 완전자동(`--autonomous`)** · 신뢰불가 출처 인젝션 차단 |
| 관측 | nmap·HTTP(쿠키·보안헤더·로그인폼·CMS)·gobuster/ffuf/feroxbuster/nikto/whatweb·smb·ldap·dns/snmp 파싱 · **vhost/도메인 자동 이름해석**(리다이렉트에서 호스트명 발견 시 범위 자동 등록 + 권한 있으면 `/etc/hosts` 자동 기입 → 프롬프트·중단 없이 진행) |
| 식별 | Linux vs Windows-AD 증거기반 판정(확신도) · 플랫폼 프로파일(HTB/Dreamhack/CTF) |
| 지능 | 지식베이스(사용자 학습·자가학습으로 성장, 관련도 기반 노트 주입=경량 RAG) · 단계 순서 오케스트레이터 · **월드 모델(구조화 상태 단일 상태원, LLM 컨텍스트 주입)** · **웹앱 핑거프린트(제목·배너·헤더 → 제품/버전 식별 → `searchsploit {product} {version}` 자동 치환)** · **반복·재진입 스윕(유한)** · **단계 게이팅(권한레벨 전제조건)** · 옵션 조합 변형 + **실행결과 기반 변형 학습** · **병렬 열거(I/O)** · LLM(Claude/Ollama/**하이브리드**(서킷 브레이커·라우팅 집계)·플랫폼/카테고리 인식·**다관점 분석가(병렬 가설·계획)**·**JSON 출력 계약**·**적응형 tier 승격**) · **목표 달성 조기 종료** · **권위출처 자가학습(`--learn`/일괄 `--learn all`)·자료 수집(`--ingest`)** |
| 목표 | CVE/CWE 탐지·매핑 + **자동 수집(NVD)** · user.txt/root.txt·CTF 단일 플래그 · **🏁 SOLVED 결과 패널(목표 달성 시 플래그 값·출처 표시)** · **리버스쉘 생성(`--revshell`) + 자동 준비(공격자 IP 확보 시)** · **AWS/S3 열거 자동 준비(`--cloud`, 호스트명 확보 시 버킷후보+점검 생성)** |
| 공격 | **리버스쉘·AWS/S3·권한상승·해시크래킹 자동 준비(생성 전용)** — 공격자 IP/호스트명/OS/해시 확보 시 페이로드·열거·LPE 체크리스트·john/hashcat 명령 자동 생성(`--revshell`/`--cloud`/`--privesc`/`--crack`) · **발판 자동 실행(`--exploit-exec`, 옵트인)** — 확보한 평문 자격으로 SSH 접속해 플래그 읽기·권한상승 열거를 3관문 거쳐 실행 · **Exploit 레지스트리** — 핑거프린트된 웹앱 제품(FreePBX 등)에 맞는 공개 익스 **조회(searchsploit)** 를 access 단계에서 자동 생성(조회만 — PoC 실행은 버전 대조 후 게이트) |
| 운영 | 중단/재개(실행된 명령 복원·Ctrl+C 저장) · **시간 예산(`--time-budget`)·비용 상한(`--max-cost`)** · 크리덴셜 볼트(해시 PtH) · 감사 로그 · 설정 파일 · 도구 설치 스크립트 · **환경 자가진단(`--doctor`)** |
| 산출 | 라이트업 자동 생성(htb-ctf-writeup-v5 / Tistory 13섹션) · **결과 내보내기(JSON·HTML 대시보드)** · **실행 재생 뷰어(`--replay`)** |
| 평가 | **성능 측정(`--bench`)** — 오프라인 모의 문제로 성공률·pass@N·명령 수·시간·비용. 개선 효과를 숫자로 확인(해커톤 발표) |

원칙: 승인제 · **외부 라이트업 미참조(사용자 자료·권위 출처만)** · 무한루프 금지 · 증거기반(〔확인〕/〔추정〕).

> 기본 동봉 학습 규칙: `knowledge/rules/htb-startingpoint-tier0.json` — 사용자가 제공한
> HTB Starting Point Tier 0(Meow·Fawn·Dancing·Redeemer·Explosion·Preignition·Mongod·Synced)
> 라이트업에서 학습한 서비스별 비인증/약한자격 점검 규칙(telnet·ftp·smb·redis·mongodb·rsync·rdp·web).
> 학습데이터를 더 넣을수록 제안이 풍부해집니다(성장).
>
> 동봉 **공개 취약점 지식**(특정 머신 라이트업 아님 · 출처 NVD/MITRE/벤더):
> `knowledge/vulns/common-services.json` — 배너/버전 탐지형 원격 서비스 CVE
> (Exim·Webmin·Tomcat Ghostcat·Grafana·Jenkins·Confluence·Spring·Struts·Drupal·PHP-CGI),
> `knowledge/rules/linux-privesc.json` · `windows-privesc.json` — 권한상승·측면이동 방법론
> (SUID/sudo/capabilities·PwnKit·Dirty Pipe/COW·Kerberoast·Zerologon·DCSync·PtH, 전부 승인제·크리덴셜 게이트),
> `knowledge/rules/htb-attack-techniques.json` — 확충 공격기법(웹: JWT·NoSQLi·GraphQL·
> SSRF→IMDS·CORS·요청 스머글링 / AD: ADCS ESC1·제약없는 위임, 출처 PortSwigger/OWASP/MITRE/SpecterOps).

---

## 테스트

```bash
cd htb-agent && python3 tests/run_all.py     # 전체 스위트(끝에 '총 N 스위트 | N passed' 요약)
```

네트워크·도구 없이도 러너 주입으로 전 로직 검증. CI(GitHub Actions)가 push/PR 마다
**파이썬 3.10~3.13 매트릭스**로 테스트+컴파일+README CLI 옵션 표 최신 여부(게이트) + ruff/mypy(비차단) 수행.
버전 확인: `assassin --version`. 변경 이력: [CHANGELOG.md](CHANGELOG.md).

## 라이선스

[MIT](LICENSE) — 권한이 확인된 대상(HTB·CTF·인가된 진단)·교육·연구 목적에 한해 사용하세요.

---

## 한계 (과장 금지)

- 명령 검증은 "형식적 무오류 + 실행 가능 형태"까지 보장(도구별 옵션 의미·해시 정답은 미보장).
- OS/취약점 판정은 증거기반 확신도 — 약하면 `〔추정〕` 표기.
- LLM 비용은 추정치. 실제 공격·VPN 은 Kali 환경 전용.

## 전체 CLI 옵션

<!-- CLI-OPTIONS:START (scripts/gen_cli_docs.py 가 자동 생성 — 직접 수정 금지) -->
| 옵션 | 설명 |
|---|---|
| `--version` | 버전 표시 |
| `--doctor` | 환경 자가진단(도구·LLM·VPN 점검, 스캔 안 함). 완전 초보자 권장 첫 실행 |
| `--install-missing` `CATS` | 빠진 보안 도구를 install_tools.sh 로 자동 설치(카테고리 지정 가능: 'recon web smb …'). 저장소의 공식 스크립트만 실행, 루트 필요 |
| `--setup-llm` | LLM 연결 마법사: Claude(API 키)·로컬 LLM(Ollama 모델)을 질문에 답하며 연결하고 실제 1회 호출로 확인 → 기본 설정 저장(이후 --llm 생략 가능). 키는 ~/.config/assassin 에 600 권한 |
| `--llm-test` | 환경 자가진단 + LLM 실제 호출 테스트(짧은 요청 1회 — 틀린 키·없는 모델·막힌 네트워크 확인) |
| `--revshell` `LHOST:LPORT` | 리버스쉘 페이로드 생성(실행 안 함). 'IP:PORT' 또는 'PORT'(공격자 IP 자동/--attacker-ip). 권한 확인 대상 전용 |
| `--learn` `TOPIC` | 권위 출처 자가학습(도구·공격기법·개념·프로토콜)을 지식베이스에 저장. 예: --learn kerberoasting / burp / http. 전체 일괄: --learn all. 목록: --learn list |
| `--promote` `TOPIC` | 로컬 학습 노트(learned-&lt;주제&gt;.md) 중 품질 관문을 통과한 항목을 번들 시드의 '최신 보강(승격)' 섹션으로 승격. 결과를 커밋·PR 하면 모든 사용자에게 공유. 예: --promote sqli / 전체: --promote all |
| `--list-sessions` | 저장된 세션(타겟) 목록 출력 — --resume 대상 확인용(타겟 없이 단독 실행) |
| `--kb-sync` | 공유 저장소의 최신 번들 시드를 지금 동기화(검증 통과분만 로컬 캐시에 적용). 타겟 실행 시에는 하루 1회 자동 |
| `--update` | 최신화 원클릭: 공유 시드 동기화 + 권위출처 재학습·승격(--offline 이면 네트워크 생략) |
| `--export-stats` `파일` | 실행 학습 통계(변형 성공률) 내보내기 — 성장 공유용(명령 전체·타겟·출력 미포함) |
| `--import-stats` `파일` | 공유된 실행 학습 통계를 로컬에 병합(성장 공유 — succ/att 합산) |
| `--no-kb-sync` | 실행 시 공유 시드 자동 동기화 끄기(환경변수 ASSASSIN_NO_KB_SYNC=1 도 동일) |
| `--ingest` `PATH` | 사용자 제공 자료(.md/.txt/.pdf 파일 또는 디렉터리)를 지식베이스 노트로 미리 학습. 예: --ingest ./my-writeups/ |
| `--cloud` `NAME` | AWS/S3 열거 자동 준비(생성 안 실행). 호스트명/도메인에서 버킷명 후보+비인증 점검 생성. 예: --cloud acme.htb. 권한 확인 자산 전용 |
| `--privesc` `OS` | 권한상승 플레이북 자동 준비(생성 안 실행). OS 별 열거·점검·LPE 체크리스트 생성. 예: --privesc linux. 획득한 대상 셸에서 직접 실행 |
| `--crack` `HASH` | 해시 크래킹 자동 준비(생성 안 실행). 해시 종류 식별 + john/hashcat 명령 생성. 예: --crack '$krb5tgs$23$...'. 권한 확인 자산 해시 전용 |
| `--bench` `SUITE` | 로컬 모의 문제로 풀이 성공률·명령 수·시간·비용 측정(오프라인, 실제 통신 없음). SUITE 생략 시 번들 문제 세트. --attempts N 으로 반복(pass@N), --llm 으로 LLM 비교 |
| `--attempts` `N` | --bench/--live-bench 에서 문제당 시도 횟수(기본 1) |
| `--live-bench` `DIR` | 실제 서비스(loopback 파이썬 / docker 컨테이너 / vm 외부·가상머신)를 띄우거나 붙어 진짜 도구로 풀이 — 성공률·검증된 풀이율·시간 측정. DIR 생략 시 bench/live. docker 타겟은 데몬 필요. --attempts·--llm 적용 |
| `--replay` `JSONL` | 감사 로그(JSONL)를 단계별 재생 HTML 로 변환(이전/다음/자동 재생). 예: --replay state/audit_10.129.1.5.jsonl → 같은 이름의 .html |
| `--platform` | 플랫폼 프로파일 (기본 htb). dreamhack/ctf=단일 타겟+flag{} 모드 |
| `--category` | Jeopardy 카테고리 힌트(web/pwn/rev/crypto/forensic/misc). CTF/Dreamhack 에서 LLM 제안을 카테고리에 맞게 유도 |
| `--flag-prefix` `PREFIX` | 우선 인식할 플래그 접두 (반복 가능, 예: --flag-prefix DH). 플랫폼 기본값에 추가 |
| `--range` `CIDR` | 허용 타겟 CIDR (반복 가능). 생략 시 플랫폼 기본(HTB만 대역 강제) |
| `--attacker-ip` `IP` | 공격자 VPN IP (반복 가능). 생략 시 tun0 자동탐지 |
| `--files` `PATH` | 챌린지 첨부파일/디렉터리(반복 가능, zip·tar 는 안전하게 풀어 둠). 작업공간 files/ 에 복사되어 LLM 이 소스를 읽고 분석. 포트가 없어도 파일 분석으로 진행 |
| `--lport` `PORT` | 리버스쉘 리스너 포트(자동 준비 페이로드용, 기본 4444) |
| `--cred` `USER:PASS` | 자격증명 'user:pass' / 'user:pass:domain' / 'user:pass:domain:nthash' (반복 가능). Pass-the-Hash 는 'user:&lt;32hex&gt;' 또는 'user::domain:&lt;NT\|LM:NT&gt;'. {user}/{pass}/{domain}/{hash} 제안을 실행 후보로 승격 |
| `--cred-file` `경로` | 자격증명 JSON 파일에서 일괄 로드(인라인 --cred 와 함께 사용 가능). 형식: {"username":..,"password":..,"domain":..,"nt_hash":..} 또는 그 목록 |
| `--config` | 설정 파일(.json/.yaml). 우선순위: CLI &gt; 설정파일 &gt; 기본값 |
| `--autonomous`, `--hackathon` | 능동적 완전자동 모드: 범위내 자동승인 + 깊은 재진입 스윕 + 병렬 열거 + 변형학습 + 전 자동준비. 목표(flag/root)까지 스스로 추진(안전 게이트 유지) |
| `--poc` `CMD` | 옵트인: searchsploit 결과에서 고른 '공개 PoC 한 줄'을 게이트로 실행(반복 가능). 권한 확인 대상 전용. 버전 대조 후 사용 |
| `--auto-poc` | ⭐ 버전매칭 1순위 PoC 실행계획을 자동으로 --poc 큐에 투입(권한 확인 대상 전용) |
| `--sandbox` | 명령을 '어디서' 실행할지: none=로컬 셸 비경유(기본, 파이프 불가) · shell=로컬 bash(파이프 O, 네트워크 강제 X) · docker=Kali 컨테이너+egress 방화벽 · vm=SSH 로 접속한 가상머신/공격호스트. 스크립트 작성·동적 실행 자동은 egress 강제된 docker 또는 'vm --vm-confine' 에서만 |
| `--sandbox-image` `IMAGE` | docker 샌드박스 이미지(기본 assassin-sandbox:latest — scripts/build_sandbox.sh) |
| `--vm-ssh` `USER@HOST` | --sandbox vm: 명령을 실행할 VM 의 SSH 접속 대상(예: kali@192.168.56.10) |
| `--vm-ssh-key` `KEYFILE` | --sandbox vm: SSH 개인키 파일(미지정 시 ssh 기본·에이전트 사용) |
| `--vm-ssh-port` `PORT` | --sandbox vm: SSH 포트(기본 22) |
| `--vm-sudo` | --sandbox vm: VM 에서 egress 정책 적용 등에 sudo 사용(--vm-confine 과 함께) |
| `--vm-confine` | --sandbox vm: 접속한 VM 에 egress 방화벽(타겟 대역만)을 적용해 docker 처럼 완전자율 동적 실행을 자동 허용. 그 VM 네트워크를 타겟으로 제한하므로 전용 풀이 VM 에서만 |
| `--auto` | 완전 자동: 범위내+검증통과만 실행, 범위 밖은 조용히 건너뜀(무프롬프트) |
| `--manual` | 완전 수동: 모든 명령을 실행 전 확인(승인제 최대) |
| `--dry-run` | 계획 미리보기: 정찰·분석은 하되 제안된 명령은 '실행하지 않고' 보여만 준다(무해 점검) |
| `--exploit-exec` | 옵트인(기본 OFF): 확보한 평문 자격으로 SSH 접속해 플래그 읽기·권한상승 열거를 게이트를 거쳐 자동 실행(권한 확인 대상 전용) |
| `--catch-revshell` | 옵트인(기본 OFF): 웹 RCE 로 발판이 안 잡힐 때 리버스셸로 발판 잡기 — --exploit-exec 발판 단계에서 준비된 리버스셸 payload 의 콜백을 소켓 리스너로 수신해 발판 세션화(공격자 IP/포트 확보 시). 성립 검증 통과분만 인정. 소켓 수신은 RCE 실행 표면 — 권한 확인 대상 전용 |
| `--judge` | 옵트인(기본 OFF): 종료 시 LLM-심판이 '공략 달성' 주장이 증거로 뒷받침되는지 별도 채점(조언만 — 규칙 판정·목표 달성을 덮지 않음). LLM 필요 |
| `--gate-judge` | 옵트인(기본 OFF): 자동 모드에서 더 신중하게 — 자동승인될 명령을 LLM 심판이 ALLOW/ASK/DENY 로 재검토해 더 엄격하게만 조정(완화 불가·오류 시 기존 동작). LLM 필요 |
| `--max-restarts` `N` | 옵트인(기본 0=끔): 미처리 예외로 죽으면 저장 지점부터 --resume 로 최대 N회 자동 재시작(무인 완주 보조). 사용자 중단은 제외 |
| `--htb-machine-id` `ID` | HTB 머신 ID(--htb-spawn/--submit-flags 에 필요) — 머신 페이지 URL 끝 숫자 |
| `--htb-spawn` | 옵트인: 실행 전 HTB 머신 스폰(vm/spawn). HTB_TOKEN env + --htb-machine-id 필요 |
| `--submit-flags` | 옵트인: 공략으로 획득한 플래그를 HTB 에 자동 제출(machine/own). HTB_TOKEN env + --htb-machine-id 필요(권한 확인 자산 한정 §4) |
| `--htb-difficulty` `N` | 플래그 제출 시 난이도 투표(10~100, 기본 30) |
| `--no-enrich` | CVE/CWE 자동 수집(NVD/GitHub) 비활성 |
| `--learn-gaps` | 자율 지식 획득: 풀이 중 모르는 기술을 권위 출처에서 자동 학습해 KB 에 즉시 반영(allowlist·P1 유지). autonomous 모드에선 기본 활성 |
| `--no-learn-gaps` | 자율 지식 획득 비활성(autonomous 모드에서도 끔) |
| `--web-learn` | 인터넷 검색 학습: 카탈로그 밖 '미해석 공백'을 웹 검색으로 학습해 KB 반영(--learn-gaps 를 함께 켬). HTB 라이트업(공식·제3자)은 가드로 차단. autonomous 기본 활성 |
| `--no-web-learn` | 인터넷 검색 학습 비활성(autonomous 모드에서도 끔) |
| `--offline` | 오프라인: 네트워크 수집 금지(캐시만 사용) |
| `--enrich-cache` | CVE 캐시 디렉토리 (기본 &lt;knowledge&gt;/cve_cache) |
| `--max-attempts` | 포트스캔 폴백 최대 시도 (기본 4, 무한루프 방지) |
| `--max-enum` | enum 자동실행 최대 개수 (기본 6, 무한확장 방지) |
| `--max-llm` | LLM 제안 명령 최대 개수 (기본 5, 자율모드 8) |
| `--max-rounds` | ENUM/LLM 반복 라운드 수 (기본 2, 무한루프 방지) |
| `--max-sweeps` | 단계 재진입 스윕 수 (기본 2). 새 관측·크리덴셜로 이전 단계 재시도. 상태 정체 시 조기종료(유한) |
| `--max-parallel` | 열거 명령 동시 실행 수 (기본 1=순차). 독립 명령의 I/O 만 병렬 — 게이트·결과처리는 순차로 안전 |
| `--variants` | 명령당 옵션 조합 변형 수 (기본 2, 1=변형끔). 경우의 수 시도 |
| `--time-budget` `분` | 해커톤 시간 예산(분). 마감이 되면 진행 중 단계를 마치고 남은 단계를 생략한 뒤 상태를 저장한다(--resume 으로 이어감). 기본: 무제한 |
| `--max-cost` `USD` | LLM 누적 추정 비용 상한(달러). 넘으면 LLM 호출을 멈추고 규칙 기반으로 계속 진행한다. 기본: 무제한 |
| `--observe` | 사람 관찰 입력: 건너뛴(미승인) 명령 대신 브라우저 등으로 직접 확인한 내용을 적어 기록에 반영한다('사람 관찰'로 표시, 에이전트 검증 결과와 구분). 대화형 실행용 |
| `--knowledge` | 지식베이스 디렉토리 (기본 ./knowledge). 사용자 규칙/노트로 성장 |
| `--llm` | LLM 두뇌 백엔드 (기본 none=규칙기반). claude=API, ollama=로컬, hybrid=둘을 단계 난이도로 라우팅+폴백·연속 오류 백엔드 차단·라우팅 집계 |
| `--llm-tier` | LLM 기본 티어(기본 standard). 명령 생성은 단계별 티어 우선(열거=cheap·침투=standard·권한상승/측면=strong), 저확신 시 자동 승격 |
| `--state-dir` | 세션 상태 저장 디렉토리 (기본 ./state) |
| `--resume` | 저장된 상태에서 재개 (RECON 재사용 · 실행된 명령·결과·플래그 복원, 다시 실행 안 함). Ctrl+C 로 중단한 세션도 이어감 |
| `--no-save` | 상태 저장 안 함 |
| `--log-file` | 감사 로그(JSONL) 경로. 생략 시 &lt;state-dir&gt;/audit_&lt;타겟&gt;.jsonl |
| `--no-audit` | 감사 로그 비활성 |
| `--writeup` | 풀이 라이트업 Markdown 생성(경로 생략 시 writeup_&lt;타겟&gt;.md) |
| `--writeup-format` | 라이트업 형식: htb(기본, htb-ctf-writeup-v5) / tistory(13섹션) |
| `--json` | 결과를 기계판독 JSON 으로 내보내기(경로 생략 시 &lt;state-dir&gt;/report_&lt;타겟&gt;.json) |
| `--html` | 결과를 HTML 대시보드로 내보내기(블루/네이비, 경로 생략 시 &lt;state-dir&gt;/report_&lt;타겟&gt;.html) |
<!-- CLI-OPTIONS:END -->
