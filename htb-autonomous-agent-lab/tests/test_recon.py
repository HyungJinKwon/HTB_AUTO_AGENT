# 실행: htb-agent 디렉토리에서  python3 tests/test_recon.py
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner
from htb_agent.tools.recon import ReconExecutor, auto_approve_in_scope, PORTSCAN_PLAN
from htb_agent.approval import explain_command

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

UP = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""
DOWN = """<?xml version="1.0"?><nmaprun><host><status state="down" reason="no-response"/>
<address addr="10.129.1.5"/></host></nmaprun>"""

def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g

print("=== 폴백 체인 ===")
# 기본은 다운, -Pn 에서 성공 → 2회차 성공
r = FakeRunner(lambda c: UP if "-Pn" in c else DOWN)
rep = ReconExecutor(guard(), r, auto_approve_in_scope).run_portscan()
check("1 -Pn 폴백으로 성공", rep.status == "success")
check("1 열린포트 {22,80}", set(rep.host.open_ports) == {22, 80})
check("1 러너 2회 호출(기본→-Pn)", len(r.calls) == 2)

# 첫 스캔에서 바로 성공 → 1회만
r = FakeRunner(lambda c: UP)
rep = ReconExecutor(guard(), r, auto_approve_in_scope).run_portscan()
check("2 첫 시도 성공시 조기중단(1회)", len(r.calls) == 1 and rep.status == "success")

print("\n=== 무한루프 방지(유한 상한) ===")
# 전부 다운 → 계획 소진 후 에스컬레이션, 호출 <= 계획 길이
r = FakeRunner(lambda c: DOWN)
rep = ReconExecutor(guard(), r, auto_approve_in_scope).run_portscan()
check("3 전부실패 → 에스컬레이션", rep.status == "escalate")
check("3 호출 횟수 = 계획 길이(유한)", len(r.calls) == len(PORTSCAN_PLAN))
check("3 자동 반복 안 함(상한 준수)", len(r.calls) <= len(PORTSCAN_PLAN))
# max_attempts 로 더 줄이기
r = FakeRunner(lambda c: DOWN)
rep = ReconExecutor(guard(), r, auto_approve_in_scope, max_attempts=2).run_portscan()
check("4 max_attempts=2 상한 적용", len(r.calls) == 2)

print("\n=== 승인제 ===")
# 승인 거부 → 러너 호출 0, 에스컬레이션
r = FakeRunner(lambda c: UP)
rep = ReconExecutor(guard(), r, lambda *a: False).run_portscan()
check("5 거부 시 실행 안 함(호출 0)", len(r.calls) == 0)
check("5 거부 시 에스컬레이션", rep.status == "escalate")
check("5 모든 시도 ran=False", all(not a.ran for a in rep.attempts))

print("\n=== 3분할 해설 ===")
ex = explain_command("nmap -sV -oX - 10.129.1.5")
check("6 바이너리 추출", "바이너리 : nmap" in ex)
check("6 옵션 추출", "-sV" in ex and "-oX" in ex)
ex2 = explain_command("msfvenom LHOST=10.10.14.5 LPORT=443 -f elf")
check("6 환경변수형 인자 표기", "LHOST=10.10.14.5" in ex2)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
