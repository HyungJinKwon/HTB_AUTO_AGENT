# Kali HTB 빠른 시작

이 저장소의 기본 경로는 **HTB OpenVPN 파일 + 할당 IP**다. Kali Linux 또는 Kali WSL에서 실행한다. 선택으로 제공된 ID/PW를 넣을 수 있지만, 기본 실행에는 필요하지 않다.

## 1. 입력 검사와 실행

~~~bash
chmod 600 ~/Downloads/htb-lab.ovpn
bash scripts/htb-kali.sh ~/Downloads/htb-lab.ovpn 10.129.1.5 --validate-only

# 누락 도구, Python venv, 코어를 준비하고 VPN을 연결한 뒤 실행한다.
bash scripts/htb-kali.sh ~/Downloads/htb-lab.ovpn 10.129.1.5
~~~

launcher는 표준 HTB 10.10.10.0/23 또는 10.129.0.0/16의 단일 IP만 받고, 실행 명령에는 그 IP의 /32 범위를 전달한다. OpenVPN profile의 local hook/plugin과 대화형 VPN credential profile은 거부한다. 후자는 직접 VPN을 연결한 뒤 native 명령을 사용한다.

~~~bash
sudo openvpn --config ~/Downloads/htb-lab.ovpn
python3 -m venv .venv
.venv/bin/pip install -e '.[session]'
.venv/bin/htb-agent 10.129.1.5 --range 10.129.1.5/32 --auto --writeup
~~~

## 2. 선택 ID/PW

비밀번호를 shell history나 process argument에 넣지 않으려면 username만 넣는다. 실행 시 한 번 숨김 입력된다.

~~~bash
bash scripts/htb-kali.sh ~/Downloads/htb-lab.ovpn 10.129.1.5 \
  --username alice --domain corp.local
~~~

여러 계정 또는 NT hash가 필요하면 권한 600의 JSON file을 사용한다.

~~~bash
chmod 600 ~/private/htb-creds.json
bash scripts/htb-kali.sh ~/Downloads/htb-lab.ovpn 10.129.1.5 \
  --credentials-file ~/private/htb-creds.json
~~~

~~~json
[
  {"username": "alice", "password": "replace-locally", "domain": "corp.local"},
  {"username": "svc-backup", "nt_hash": "replace-locally", "domain": "corp.local"}
]
~~~

현재 버전은 state file에 password/hash를 저장하지 않고 복원 가능한 자격증명도 만들지 않는다. 이 변경 전 생성한 state file은 민감정보가 있을 수 있으므로 별도로 점검·삭제한 뒤 재실행한다.

## 3. 1-day 후보 조사

local SearchSploit JSON 메타데이터 조회는 기본 활성이다. 관측된 banner의 제품/버전과 발견된 CVE만 질의하고, 결과를 검증 전 후보로 표시한다.

~~~bash
# NVD에는 관측 제품/버전 또는 CVE만 한 번 보낸다. target IP는 보내지 않는다.
bash scripts/htb-kali.sh ~/Downloads/htb-lab.ovpn 10.129.1.5 --online-cve

# 로컬 SearchSploit 조회를 끄려면
bash scripts/htb-kali.sh ~/Downloads/htb-lab.ovpn 10.129.1.5 --no-one-day
~~~

NVD 후보나 SearchSploit 결과는 영향을 받는 버전, prerequisite, 실제 service observation으로 검증해야 한다. 공개 PoC 다운로드·실행은 이 경로가 자동으로 하지 않는다.

## 4. LLM과 비교 프레임워크

Anthropic API key가 있는 경우 launcher는 Claude를 기본 선택한다. 없으면 규칙 기반 코어가 실행된다.

~~~bash
export ANTHROPIC_API_KEY='set-in-your-shell-or-secret-manager'
bash scripts/htb-kali.sh ~/Downloads/htb-lab.ovpn 10.129.1.5 --llm claude
~~~

선택한 framework는 native run 전에 fixed revision으로 setup된다.

| 목적 | 준비/실행 | 경계 |
|---|---|---|
| ARTEX | bash scripts/artex.sh run | run이 setup을 자동 수행한다. 별도 UI이고 native scope guard를 상속하지 않는다. |
| PentestGPT | bash scripts/pentestgpt.sh run 10.129.1.5 --allow-unscoped-framework | run이 setup을 자동 수행한다. 별도 framework라 명시적 acknowledgement가 필요하다. |
| BloodHound MCP | bash scripts/bloodhound_mcp.sh run --allow-upstream-mutations | run이 setup을 자동 수행한다. upstream에 mutation 도구가 있어 read-only라고 부르지 않는다. |

HTB launcher에서 local framework checkout만 함께 준비하려면 --framework artex, --framework pentestgpt, 또는 --framework bloodhound-mcp를 준다. framework의 UI/MCP client 연결과 native HTB run은 각각 별도 동작이다.

BloodHound MCP는 별도로 준비한 local CE와 최소 권한 lab token을 필요로 한다. BLOODHOUND_DOMAIN, BLOODHOUND_TOKEN_ID, BLOODHOUND_TOKEN_KEY를 protected environment에서 제공하고, 실제 AD collection의 IP 범위는 target IP와 별도 승인한다. 자세한 순서는 [llm-wiki/ad-aws.md](llm-wiki/ad-aws.md)를 따른다.

AWS는 HTB VPN 파일과 IP만으로 설정되지 않는다. 별도 training account, profile, region, 허용 resource scope가 있어야 하며 기본 HTB launcher는 AWS API나 CloudGoat를 자동으로 실행하지 않는다.
