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

print("\n=== 오프라인(ASSASSIN_NO_NET): 실 러너는 실제 스캔 생략(행 방지) ===")
import os
class _RealStub:
    """real_exec=True 실 러너 모사 — run() 이 호출되면 기록(가드가 막으면 호출 0)."""
    real_exec = True
    def __init__(self): self.calls = []
    def has_tool(self, b): return True
    def run(self, command, timeout=120):
        self.calls.append(command)
        return FakeRunner(lambda c: UP).run(command)
_old = os.environ.get("ASSASSIN_NO_NET")
os.environ["ASSASSIN_NO_NET"] = "1"
try:
    rs = _RealStub()
    rep = ReconExecutor(guard(), rs, auto_approve_in_scope).run_portscan()
    check("NO_NET+실러너: 실제 nmap/소켓 미호출(행 방지)", rs.calls == [])
    check("NO_NET+실러너: escalate(호스트 없음)", rep.status == "escalate" and rep.host is None)
    check("NO_NET+실러너: 어떤 시도도 ran=False", all(not a.ran for a in rep.attempts))
    # FakeRunner(real_exec=False)는 NO_NET 이어도 생략 안 함 — 가짜 결과 그대로(테스트 불변식 보존)
    rf = FakeRunner(lambda c: UP)
    repf = ReconExecutor(guard(), rf, auto_approve_in_scope).run_portscan()
    check("NO_NET+가짜러너: 가드 비적용(가짜 결과로 성공)", repf.status == "success")
finally:
    if _old is None: os.environ.pop("ASSASSIN_NO_NET", None)
    else: os.environ["ASSASSIN_NO_NET"] = _old

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
