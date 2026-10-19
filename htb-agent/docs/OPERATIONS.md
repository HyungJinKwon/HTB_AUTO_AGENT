# ASSASSIN 실전 운영 가이드 (Kali)

> 권한이 확인된 대상(HTB·Dreamhack·CTF·인가된 진단)에서만 사용. 실제 공격/VPN 은
> 사용자 Kali 환경 전용. 데모(네트워크 없이 흐름 확인)는 `python3 scripts/demo.py`.
> 명령은 **`assassin`** (옛 `htb-agent` 도 동일하게 동작하는 별칭).

---

## 0. 시작

**설치는 한곳에서** — venv + 심링크 설치 절차는 [QUICKSTART.md §1](QUICKSTART.md)(또는 상세
[USAGE.md §2](USAGE.md)). 이 문서는 **설치 이후의 실전 운영·트러블슈팅**에 집중한다.

```bash
assassin --doctor                        # ① 환경 점검(도구·VPN·LLM) — 스캔 안 함
sudo openvpn your-lab.ovpn               # ② (HTB) tun0 → 공격자 IP 자동탐지
assassin 10.129.1.5                      # ③ 첫 실행(HTB, 초록불이면 바로)
assassin chall.site:1337 --platform ctf  #    CTF/Dreamhack
```

`--doctor` 가 알려주는 대로 빠진 것만 채우면 된다. 막히면 아래 트러블슈팅(§4) 참고.

> 설치 직후 또는 발표 전, **처음부터 끝까지 검증**하려면 [VALIDATION.md](VALIDATION.md)
> (오프라인 흐름 → 도구/VPN → 실제 HTB 머신 → 샌드박스(docker/vm) → 라이브 벤치 → 산출물,
> 단계별 기대 결과와 체크리스트).

---

## 2. 운영 흐름 (한눈에)

```
타겟 바인딩 → RECON(nmap -sC -sV, 실패 시 -Pn/-sT/-p- 폴백) → 식별(Linux/Win-AD) → 열거(KB+LLM)
   → 초기침투(user) → 권한상승(root) → 측면이동 → 취약점(CVE/CWE 자동수집) → 리포트/라이트업
```

모든 실행 명령은 **① 검증 → ② 범위 → ③ 승인** 3관문 통과 후에만 실행된다.
취약점(CVE/CWE)은 단계마다 반영되어 다음 단계·분석가가 바로 활용한다. 목표(Jeopardy=플래그 1개·
접두 지정 시 그 접두, HTB=user+root)를 **대상 상호작용 출력**에서 확보하면 남은 단계는
`생략(목표 달성)` 으로 조기 종료한다(로컬 명령 출력의 미끼 문자열은 무시). 한 번 `진행` 한 단계는
이후 스윕에서도 `진행` 으로 남는다. 도구 미설치로 건너뛴 명령은 명령 수 상한을 쓰지 않는다.
단계·라운드·명령 수에 상한이 있어 무한루프가 없다. **종료코드**: 0 완료 · 1 미완(열린 포트 미확보 등) ·
2 인자/설정/범위 오류 · 130 Ctrl+C 중단.

---

## 3. 승인·플랫폼 모드

| 모드 | 명령 | 동작 |
|---|---|---|
| 스마트(기본) | `assassin <t>` | 범위내+검증통과 자동실행 · 파괴명령 자동거부 · 범위밖만 사람확인 |
| 완전자동 | `assassin <t> --auto` | 범위밖은 조용히 건너뜀(무프롬프트) |
| 완전수동 | `assassin <t> --manual` | 모든 명령 실행 전 확인 |
| 능동적 완전자동 | `assassin <t> --autonomous` (=`--hackathon`) | 범위내 자동승인 + 깊은 스윕·병렬 열거·변형 학습·자동 학습 · 범위밖 실행 안 함 · `--manual` 이 우선 |

| 플랫폼 | 명령 | 특징 |
|---|---|---|
| HTB(기본) | `--platform htb` | VPN 대역 강제 · boot2root(user/root, 32-hex/HTB{}) |
| Dreamhack/CTF | `--platform dreamhack` / `ctf` | 단일 타겟(host:port/URL) · Jeopardy 단일 플래그(flag{}/DH{}) |

LLM 두뇌(선택): `--llm hybrid`(Ollama+Claude) · `--llm claude` · `--llm ollama`. 하이브리드는 열거·일반을
로컬, 권한상승·분석을 강력 모델로 라우팅하고 실패·거절 시 폴백한다(§4.4). 분석가는 레드팀·개발자·인프라
운영자·방어 관점으로 가설 2~4개를 병렬 비교해 계획을 세운다. CVE 자동수집: 기본 활성(NVD/GitHub) ·
끄기 `--no-enrich` · 오프라인 `--offline`.

---

## 4. 트러블슈팅

### 4.1 공격자 IP(VPN) 미탐지
- 증상: 프리플라이트 "VPN IP 미탐지 — HTB VPN 연결/수동지정 필요" · 세션 패널 공격자IP "(없음)"
  (리버스쉘 자동 준비 생략). 탐지는 tun0 뿐 아니라 모든 tun/tap 인터페이스를 본다.
- 조치: VPN 연결 확인(`ip a`) 후 `--attacker-ip <VPN IP>` 로 수동 지정.

### 4.2 범위 위반(ScopeViolation)
- 증상: 명령이 대상 외 IP/호스트를 포함해 거부됨.
- 원인(설계): Scope Guard 가 바인딩된 타겟/대역 밖 통신을 코드로 차단.
- 조치: HTB 는 허용대역(`--range`) 확인. CTF/Dreamhack 은 `--platform` 지정으로
  단일 타겟 바인딩(대역 강제 해제, host:port/URL 허용).

### 4.3 도구 미설치(NO_BINARY 경고)
- 증상: 결과 비고 `건너뜀: '<도구>' 미설치` (검증기 경고 `'<도구>' 미설치 — 실제 실행환경(Kali 등)에서
  확인 필요`). 건너뛴 명령은 열거/LLM 예산을 쓰지 않는다.
- 조치: `sudo ./scripts/install_tools.sh [카테고리]`. 카테고리:
  `recon web smb ad creds cloud pivot wordlist traffic re pwn forensic llm`.

### 4.4 LLM 백엔드 사용 불가
- 증상: `hybrid 사용 불가: ollama(Ollama 연결 실패(http://localhost:11434): …) /
  claude(anthropic SDK 미설치 (pip install anthropic))`. 다른 사유 예: `ANTHROPIC_API_KEY 환경변수 미설정`,
  `Ollama 에 설치된 모델 없음(ollama pull qwen2.5:7b)`.
- 먼저: `assassin --doctor` 로 어느 백엔드가 왜 안 되는지 확인(복붙 설치 힌트 제공).
- 일괄 설치: `sudo ./scripts/install_tools.sh llm` (anthropic 설치 + ollama 안내).
- 조치: Claude=`pip install anthropic` + `export ANTHROPIC_API_KEY=sk-...`.
  Ollama=`ollama serve` + `ollama pull qwen2.5:7b`(다른 모델은 `export OLLAMA_MODEL=...`,
  원격 서버는 `export OLLAMA_HOST=http://ip:11434`).
- strong 티어 기본 모델(`llama3.3:70b`)이 없으면 설치된 모델로 자동 대체된다(시작 시
  "로컬 모델 대체: strong→…" 표시). 한 백엔드가 연속 2회 오류면 세션 동안 건너뛰며(서킷 브레이커),
  실행 끝 `라우팅: 로컬 N · 강력 N · 폴백 N · 거절 N · 빈응답 N · 오류 N · 미응답 N` 으로 어느
  백엔드가 응답·거절·실패했는지 확인한다.
- 둘 중 하나만 있어도 hybrid 가 단일 백엔드로 동작. LLM 없이도 규칙기반(`--llm none`,
  기본값)으로 완전 동작.

### 4.5 CVE 자동수집이 비어 있음
- 원인: `--offline`/`--no-enrich`, 네트워크 차단, 또는 캐시 없음.
- 조치: 온라인에서 1회 실행 시 `<knowledge>/cve_cache` 에 캐시됨. 이후 오프라인 재사용.

### 4.6 중단 후 재개
- `--resume`: 저장된 RECON 재사용(재스캔 생략) + 이전에 **실행된** 명령·결과·플래그·수동 제안
  복원(다시 실행 안 함). 거부·미설치로 못 한 명령은 이번에 다시 판단. 예산은 이번 실행 기준.
  실행 중 Ctrl+C → 결과 저장 후 `status=interrupted`·종료코드 130 → 같은 명령에 `--resume`.
  `--no-save` 로 저장 끔.

---

## 5. 지식베이스로 '성장'시키기

에이전트는 외부 라이트업을 참조하지 않는다(P1 — 웹 학습도 HTB 라이트업은 출처 불문 차단).
지식은 번들 시드·권위 출처 학습·사용자 자료로 자란다.

- 규칙: `knowledge/rules/*.json` — `{"name","when":{os,ports,services},"suggest":[...],"phase"}`
- 취약점: `knowledge/vulns/*.json` — `{"name","service","version_contains","cve","cwe","suggest"}`
- 노트: `knowledge/notes/**/*.md|.txt` — 자유 서술(하위 `learned/`·`ingested/` 포함).

**지식 성장·공유 파이프라인**
- 번들 시드: `notes/learned/seed-*.md` 62개(카탈로그 59주제 + ADCS·Linux/Windows 권한상승) —
  오프라인에서도 동일 시작 지식.
- 권위 출처 학습: `--learn <주제|all>` (36개 주제는 CWE/CAPEC·OWASP 치트시트·Wireshark/Nmap·MDN 2차 출처 포함).
- 승격: `--promote <주제|all>` — 품질 관문 통과분만 시드의 `## 최신 보강(승격)` 으로(주제당 3건 상한).
- 공유 자동화: GitHub Actions `KB 자동 승격`(매주 월 03:17 KST) = `--learn all → --promote all → 전체 테스트` 후 PR 자동 병합.
- 로컬 자동 동기화: 타겟 실행 시 하루 1회 검증 통과 시드만 `knowledge/shared_seeds/` 캐시에 적용
  (즉시 `--kb-sync`, 끄기 `--no-kb-sync`/`--offline`/`ASSASSIN_NO_KB_SYNC=1`).
- 사용자 자료: `--ingest PATH`. 풀이 중 자율 학습: `--learn-gaps` / `--web-learn`(autonomous 기본).

동봉 공개지식(출처 NVD/MITRE): `vulns/common-services.json`, `rules/linux-privesc.json`,
`rules/windows-privesc.json`. 자세한 방법론은 `knowledge/notes/privesc-and-cves-methodology.md`.

---

## 6. 산출물

- 라이트업: `--writeup`(htb-ctf-writeup-v5) · `--writeup-format tistory`(13섹션).
  CVE 레퍼런스(NVD/CVSS/PoC)·블루팀 탐지지표(SIEM/Snort/Wireshark)가 자동 포함된다.
- 결과 내보내기: `--json`(기계판독, 외부 도구·파이프라인 연계) · `--html`(블루/네이비
  대시보드, 외부 의존 0). 경로 생략 시 `<state-dir>/report_<타겟>.{json,html}`.
- 감사 로그(JSONL): 기본 `<state-dir>/audit_<타겟>.jsonl` · 끄기 `--no-audit`.

---

## 7. 안전 수칙 (요약)

- 권한이 확인된 자산만. 범위 밖 금지(코드로 강제).
- **기본은 생성 전용** — 익스플로잇·권한상승·크래킹은 '탐지 + 수동 제안'까지만 자동화한다.
  실제 익스 실행은 **옵트인(`--full-auto` / `--exploit-exec` / `--auto-poc` / `--catch-revshell` /
  `--priv-env`)** 으로만 켜지며, 그때도 3관문(검증·범위·승인)과 ScopeGuard(인가 대상) 하에서만 동작한다.
  `--priv-env`(환경조작: NFS 수확·`/etc/hosts` 등록)의 기본은 rootless(sudo·마운트 없음)이고, sudo 는
  rootless 불가 시의 `-n` 폴백(ro·타겟 IP 한정·비대화형)뿐이다.
- 과장 금지: OS/취약점 판정은 증거기반 확신도, 약하면 `〔추정〕` 표기.
