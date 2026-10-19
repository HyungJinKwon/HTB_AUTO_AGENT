# ARTEX 한국어판 — 비교군 에이전트

[ARTEX](https://github.com/mhtsec/ARTEX)(상류 소스 백업, 중국어 UI)를 한국어로 옮긴
[jiwoochris/artex-ko](https://github.com/jiwoochris/artex-ko)를 우리 `htb-agent` 옆에
**별도 프로세스로** 띄운다. Go 백엔드와 Next.js UI로 된 멀티 에이전트 자율 침투
시스템이고, 화면과 산출물(탐지 결과·요약·리포트)이 한국어로 나온다. 쓰임새는 같은
HTB 머신에서 `htb-agent`와 결과를 비교하는 비교군이다.

코드는 이 저장소에 넣지 않는다(AGPL-3.0). 스크립트가 고정 커밋을 `~/artex-ko`에 클론해서
빌드한다.

## 설치 (Kali / WSL)

```bash
bash scripts/artex.sh setup
```

- 커밋 `310fbb5`(2026-10-10 빌드 확인)를 클론한다. 다른 커밋을 쓰려면 `ARTEX_REF=<sha>`,
  중국어 원본을 쓰려면 `ARTEX_REPO=https://github.com/mhtsec/ARTEX.git`을 지정한다.
- Go가 없으면 `apt install golang-go`를 실행한다. 버전이 모자라면 `GOTOOLCHAIN=auto`가
  go.mod에 적힌 버전을 받아 온다.
- 웹 정적 빌드, 바이너리 컴파일(`-tags embedui`) 순서로 진행한다.
- PostgreSQL은 컨테이너 `artex-pg`(`127.0.0.1:5433`, 볼륨 `artex-pgdata`)로 띄운다.
  비밀번호는 무작위로 만들고 `~/artex-ko/config.json`(권한 600)에 적는다.
- `setup`을 다시 실행하면 재빌드하며 DB와 데이터는 유지된다. `run`은 실행 파일과
  config가 이미 있으면 재빌드하지 않고 바로 시작한다.

상류 README에는 컨테이너 이미지 경로도 안내되어 있다. 이 저장소는 재현 가능한 비교를 위해
고정한 한국어 fork 소스 빌드를 선택한다. 상류 image의 현재 가용성·호환성은 이 저장소에서
실행 검증하지 않았으므로 자동 대체 경로로 사용하지 않는다.

## 실행

```bash
export ANTHROPIC_API_KEY=sk-ant-...     # UI 의 「LLM」 페이지에서 넣어도 된다
bash scripts/artex.sh run               # → http://localhost:8787
```

1. 처음 들어가면 `/setup`에서 관리자 비밀번호를 정한다.
2. 「LLM」 페이지에서 모델 프로파일을 확인한다. 기본 모델은 `claude-opus-4-8`이고,
   `ARTEX_LLM_MODEL` 환경 변수나 UI에서 바꿀 수 있다.
3. 「작업」에서 대상 IP로 작업을 만든다. 작업 지시에 "한국어로 작성"을 적으면 출력이
   한국어로 더 잘 유지된다.

- UI는 `127.0.0.1`에만 바인딩한다. VPN 상대 머신이나 tailnet에서는 UI에 접근할 수 없다.
  Windows 브라우저에서는 WSL localhost 포워딩으로 접속한다.
- VPN(`sudo openvpn ...`)은 같은 Kali에서 먼저 연결해 둔다. 네이티브 프로세스라서
  tun0와 Kali 도구를 그대로 쓴다.
- 중지는 Ctrl-C. DB도 내리려면 `docker stop artex-pg`.
- 완전히 지우려면: `docker rm -f artex-pg && docker volume rm artex-pgdata && rm -rf ~/artex-ko`

## ⚠️ 우리 통제 밖이다 — 대회 규칙과 맞춰 볼 것

| 우리 장치 | ARTEX 에서는 |
|---|---|
| `scope_guard`(대상 범위를 코드로 강제) | **없음.** 상류에서 RoE 범위 강제가 제거됐다(`guard/guard.go` 주석). |
| `NO-WRITEUP-POLICY` A2(외부 송신 차단) | **없음.** 에이전트의 Bash·WebFetch가 인터넷에 나갈 수 있다. |
| A4 감사 로그(`audit_*.jsonl`) | 따로 남는다(ARTEX 「승인 기록」·「LLM 기록」·「트래픽」). |
| A5 사람 입력 차단 | 「대화」로 사람이 힌트를 넣을 수 있다. |

운용 규칙:

- **작업마다 범위를 건다.** 작업 상세의 「작업 단위 자산 가로채기 / 허용」에 `허용 · CIDR 대역`
  으로 할당받은 IP(`/32`)를 넣는다. 허용 규칙이 하나라도 있으면 화이트리스트로 동작한다.
  단, 이 규칙은 **자산 그래프에 추가되는 대상만** 거른다. Bash 명령 자체를 막지는 않는다.
- 「에이전트」의 **웹 검색은 끈 채로 둔다**(기본값이 꺼짐). 켜면 머신 writeup에 닿을 수 있다.
- 무개입 측정 런에서는 「대화」로 힌트를 넣지 않는다. 넣었다면 결과에 그 사실을 적는다.
- 대회에서 외부 에이전트를 써도 되는지는 규정을 먼저 확인한다. 이 문서는 그 판단을 대신하지 않는다.
- 2026-10 국내 보도에 따르면 원본 ARTEX가 실제 금융기관 공격에 쓰인 정황이 있다(artex-ko
  README). HTB VPN에서 할당받은 머신 외에는 절대 겨누지 않는다.
