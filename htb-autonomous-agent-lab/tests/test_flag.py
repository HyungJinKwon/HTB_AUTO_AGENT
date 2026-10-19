# 실행: htb-agent 디렉토리에서  python3 tests/test_flag.py
import sys
sys.path.insert(0, "src")
from htb_agent.flag import extract_flags, is_flag_command, classify_flag, scan
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.creds import CredentialVault
from htb_agent.orchestrator import Orchestrator

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 추출/분류 ===")
check("32-hex 추출", "a"*32 in extract_flags("flag: " + "a"*32))
check("TAG{} 추출", "HTB{p0wn3d}" in extract_flags("got HTB{p0wn3d} here"))
check("require_fmt 는 hex 제외", extract_flags("a"*32, require_fmt=True) == [])
check("user.txt → user", classify_flag("cat ~/user.txt") == "user")
check("root.txt → root", classify_flag("type ...Administrator...root.txt") == "root")
check("플래그 명령 인식", is_flag_command("cat /home/bob/user.txt"))

print("=== scan 오탐 방지 ===")
# 플래그 명령이 아니면 32-hex(해시)는 플래그로 안 잡음
check("비플래그 명령의 hex 무시", scan("hashid 5f4dcc3b5aa765d61d8327deb882cf99", "5f4dcc3b5aa765d61d8327deb882cf99") == [])
# 플래그 명령이면 hex 캡처 + 분류
hits = scan("cat ~/user.txt", "the flag is " + "a"*32)
check("플래그 명령서 hex 캡처", hits and hits[0].value == "a"*32 and hits[0].kind == "user")
# TAG{} 는 명령 무관 항상
check("TAG{} 항상 캡처", scan("echo test", "HTB{abc}") != [])

print("=== 오케스트레이터 플래그 획득 ===")
AD = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.10"/><ports>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
<port protocol="tcp" portid="5985"><state state="open"/><service name="winrm"/></port>
</ports><hostscript><script id="smb-os-discovery" output="OS: Windows Server 2019"/></hostscript>
</host></nmaprun>"""
def runner(cmd):
    if cmd.startswith("nmap"): return RunOutput(cmd, stdout=AD)
    if "user.txt" in cmd: return RunOutput(cmd, stdout="b2f5ff47436671b6e533d8dc3614845d")
    if "root.txt" in cmd: return RunOutput(cmd, stdout="ffffffffffffffffffffffffffffffff")
    return RunOutput(cmd, stdout="ok")
g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.10")
v = CredentialVault.from_cli(["administrator:Passw0rd"])
rep = Orchestrator(g, FakeRunner(runner), KnowledgeBase.load(), auto_approve_in_scope,
                   vault=v, max_enum=12, is_tool_available=lambda b: True).run()
check("user 플래그 획득", rep.user_flag == "b2f5ff47436671b6e533d8dc3614845d")
check("root 플래그 획득", rep.root_flag == "ffffffffffffffffffffffffffffffff")
check("요약에 FLAG 섹션", "🚩 플래그" in rep.summary() and "user.txt:" in rep.summary())
check("메시지에 플래그 상태", "플래그[user=O root=O]" in rep.message)

print("\n=== 볼트 없으면 플래그 명령은 수동(미획득) ===")
g2 = ScopeGuard.from_cidr_strings(); g2.bind_target("10.129.1.10")
rep2 = Orchestrator(g2, FakeRunner(runner), KnowledgeBase.load(), auto_approve_in_scope,
                    is_tool_available=lambda b: True).run()
check("볼트 없으면 user 플래그 미획득", rep2.user_flag is None)
check("플래그 명령 수동 제안에 존재", any("user.txt" in s for s in rep2.manual_suggestions))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
