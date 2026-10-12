# 실행: htb-agent 디렉토리에서  python3 tests/test_cred_sources.py
#
# D단계 — 발판 후 자격 수확: 설정파일 위치·제품 키 파싱·측면이동 후보 생성(생성 전용).
import sys
sys.path.insert(0, "src")
from htb_agent.cred_sources import (                                # noqa: E402
    config_reads, lateral_candidates, parse_config_creds)

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== config_reads (읽을 설정/민감파일 cat 명령) ===")
fp = config_reads("freepbx")
check("freepbx → amportal.conf 포함", any("/etc/amportal.conf" in c for c in fp))
check("전부 cat 조회(실행/삭제 아님)", all(c.startswith("cat ") for c in fp))
check("일반 민감파일(.env·bash_history)도 포함",
      any(".env" in c for c in fp) and any("bash_history" in c for c in fp))
check("미지정 → 일반만(제품 경로 없음)",
      "/etc/amportal.conf" not in " ".join(config_reads()))
check("중복 제거", len(config_reads("freepbx")) == len(set(config_reads("freepbx")))
      and len(config_reads("wordpress")) == len(set(config_reads("wordpress"))))
check("미등록 제품 안전(일반만)", all(c.startswith("cat ") for c in config_reads("nginx")))

print("\n=== parse_config_creds (FreePBX amportal + 일반) ===")
AMPORTAL = """# amportal.conf
AMPDBHOST=localhost
AMPDBENGINE=mysql
AMPDBNAME=asterisk
AMPDBUSER=freepbxuser
AMPDBPASS=S3cr3tDBpw
AMPMGRUSER=admin
AMPMGRPASS=amp109rules
"""
creds = parse_config_creds(AMPORTAL)
cd = {(u, p) for u, p, _ in creds}
check("AMPDBUSER/AMPDBPASS 짝 추출", ("freepbxuser", "S3cr3tDBpw") in cd)
check("AMPMGRUSER/AMPMGRPASS 짝 추출", ("admin", "amp109rules") in cd)
check("출처 라벨에 amportal", any("amportal" in lbl for _, _, lbl in creds))

# 일반 URL 자격도 함께
URLCFG = "DB_URI=mysql://webapp:hunter2@localhost/app\n"
c2 = parse_config_creds(URLCFG)
check("URL 자격 추출", ("webapp", "hunter2") in {(u, p) for u, p, _ in c2})
check("빈 입력 안전", parse_config_creds("") == [])

print("\n=== lateral_candidates (측면이동 su/ssh 재사용 후보) ===")
cand = lateral_candidates([("freepbxuser", "S3cr3tDBpw")], ["root", "guly", "fidelio"], "10.129.1.5")
check("자격 그대로 ssh 후보", any("freepbxuser@10.129.1.5" in c for c in cand))
check("비번 재사용: 다른 시스템 유저에도 교차", any("guly@10.129.1.5" in c for c in cand))
check("전부 sshpass ssh 후보", all(c.startswith("sshpass -p ") for c in cand))
check("타겟 반영", all("10.129.1.5" in c for c in cand))
# 셸 인젝션 안전필터: 메타문자 든 자격은 명령에 안 넣음
inj = lateral_candidates([("ev;il", "p`whoami`")], ["root"], "10.129.1.5")
check("인젝션 자격은 명령 제외", not any("ev;il" in c or "whoami" in c for c in inj))
# 선행 '-' 인자 인젝션: ssh 가 값을 옵션(-oProxyCommand=…)으로 오인하지 않도록 제외
argi = lateral_candidates([("-oProxyCommand=id", "pw")], ["-x"], "10.129.1.5")
check("선행 '-' 유저/비번은 제외", not any("ProxyCommand" in c for c in argi))
check("빈 입력 안전", lateral_candidates([], [], "10.0.0.1") == [])

print("\n=== 생성 전용 경계(불변) 자기점검 ===")
import htb_agent.cred_sources as cs  # noqa: E402
for mod in ("subprocess", "socket", "os", "paramiko", "requests"):
    check(f"실행/네트워크 모듈 미임포트: {mod!r}", not hasattr(cs, mod))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
