# 학습 시드(심화): pivoting

> 종합 레퍼런스(확립된 보안 지식 · 권위 출처 검증가능). 라이브 최신화: `assassin --learn pivoting`. P1: 머신별 라이트업 미참조.

## 개요
피벗/터널링(T1090): 장악 호스트 경유로 내부망 도달.

## 핵심 기법 · 열거
- SSH 로컬/원격/동적(SOCKS) 포워딩·chisel·ligolo-ng·sshuttle
- proxychains 로 도구 터널링·포트포워딩

## 표준 도구 · 명령
```
ssh -D 1080 user@<pivot>         # 동적 SOCKS → proxychains
ssh -L 8080:127.0.0.1:80 user@<pivot>
chisel server -p 8000 --reverse  # 공격자
chisel client <lhost>:8000 R:socks   # 피벗
```

## 블루팀 탐지
비정상 내부 포워딩·SOCKS 트래픽·장기 SSH 터널·chisel 바이너리.

## 완화
네트워크 분할·egress 통제·비정상 포워딩 탐지·호스트 격리.

- 출처(검증): https://attack.mitre.org/techniques/T1090/

## 최신 보강(승격)

> `assassin --promote` 품질 관문을 통과한 권위 출처 발췌. 수정·삭제는 PR 리뷰로. 사람이 다듬은 위 섹션이 우선한다.

### ATT&CK T1090 Proxy
- 출처: https://attack.mitre.org/techniques/T1090/
- 승격일: 2026-10-18
- 요약: Proxy Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap.[1] Adversaries use these types of proxies to manage command and control communications, reduce the number of simultaneous outbound network connectio
