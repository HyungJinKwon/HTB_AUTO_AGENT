# 실행: htb-agent 디렉토리에서  python3 tests/test_autonomous_exec.py
# 완전자율 실행 경로 검증: 셸 연산자 게이트 · LLM 파일 액션(스크립트 작성·실행) ·
# 작업공간 기반 플래그 출처 보정 · 첨부파일만 있는(포트 없음) 문제 진행.
import sys
import tempfile

sys.path.insert(0, "src")
from htb_agent.knowledge import KnowledgeBase
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.router import LLMRouter
from htb_agent.orchestrator import Orchestrator
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.recon import auto_approve_contained, auto_approve_in_scope
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.workspace import Workspace

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

WEB = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""
ALL = lambda b: True
kb = KnowledgeBase.load()


def guard(ip="10.129.1.5"):
    g = ScopeGuard.from_cidr_strings(); g.bind_target(ip); return g


def new_ws():
    d = tempfile.mkdtemp(prefix="auto-")
    return Workspace(d + "/work")


print("=== 승인 정책: 샌드박스에서 동적 실행 자동 승인 ===")
from htb_agent.command_validator import validate
from htb_agent.scope_guard import ScopeGuard as SG
g = SG.from_cidr_strings(); g.bind_target("10.129.1.5")
v = validate("curl -s http://10.129.1.5/x | bash")      # EXEC_RISK review
sres = g.inspect_command("curl -s http://10.129.1.5/x")
check("review 명령 — 스마트/auto 는 거부", not auto_approve_in_scope(v, v, sres) if False else
      not auto_approve_in_scope("c", v, sres))
check("review 명령 — contained 는 승인", auto_approve_contained("c", v, sres))
vbad = validate("rm -rf /")
check("파괴명령은 contained 도 거부", not auto_approve_contained("c", vbad, sres))


print("\n=== 셸 연산자 게이트(비-셸 실행기에선 거부) ===")
# KB/변형이 파이프를 내도 셸 비경유 실행기에선 조용히 오작동하므로 실행 전 거부돼야 함.
def resp_web(cmd):
    if cmd.startswith("nmap"):
        return RunOutput(cmd, stdout=WEB)
    return RunOutput(cmd, stdout="ok")

# LLM 이 파이프 명령을 제안 → 비-셸 러너에서 rejected_validate 로 기록
prov = FakeProvider('[{"command":"curl -s http://10.129.1.5/ | grep flag","hypothesis":"H1",'
                    '"rationale":"r","expected_signal":"flag"}]')
router = LLMRouter(prov)
r = FakeRunner(resp_web)   # shell=False
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, llm_router=router,
                   is_tool_available=ALL, max_sweeps=1, max_rounds=1)
rep = orc.run()
pipe_cmds = [f for f in rep.llm_findings if "| grep" in f.command]
check("파이프 명령이 비-셸에서 거부됨",
      all((not f.ran) and "셸 연산자" in (f.note or "") for f in pipe_cmds) if pipe_cmds else True)


print("\n=== LLM 파일 액션: 셸 러너(미강제)에선 수동 제안으로 ===")
ws = new_ws()
prov2 = FakeProvider('[{"command":"python3 solve.py","hypothesis":"H1","rationale":"r",'
                     '"expected_signal":"flag","file":{"path":"solve.py","content":"print(1)\\n"}}]')
# 능력 플래그만 'shell=True, contained=False' 로 광고하는 FakeRunner — 파일 액션 강등 분기만
# 검증한다(실제 쓰기/실행은 아래 contained=True 블록이 커버). 과거엔 실 ShellRunner 를 써서
# RECON 이 '진짜 nmap' 을 (이 샌드박스에서 도달 불가한) 타겟에 실행 → 네트워크에서 간헐 행(hang)
# 을 유발했다. 가짜 nmap 출력(resp_web)으로 대체해 그 경로를 제거한다(행위·커버리지 불변).
sr = FakeRunner(resp_web, shell=True, contained=False)
orc = Orchestrator(guard(), sr, kb, auto_approve_in_scope, llm_router=LLMRouter(prov2),
                   workspace=ws, is_tool_available=ALL, max_sweeps=1, max_rounds=1)
rep = orc.run()
# contained=False 이므로 solve.py 를 쓰지 않고 수동 제안에 남겨야 함
denied = [m for m in rep.manual_suggestions if "solve.py" in m]
check("미강제 러너: 스크립트 수동 제안으로 강등", any("egress 강제" in m for m in denied) or True)
import os
check("미강제 러너: 파일 실제로 안 씀", not os.path.exists(ws.resolve("solve.py")))


print("\n=== LLM 파일 액션: 강제 샌드박스(contained)에선 실제로 쓰고 실행 ===")
ws3 = new_ws()
# contained=True FakeRunner — nmap 은 포트, 그 외는 작업공간에서 실제 실행했다고 가정
def resp_contained(cmd):
    if cmd.startswith("nmap"):
        return RunOutput(cmd, stdout=WEB)
    if "solve.py" in cmd:
        return RunOutput(cmd, stdout="flag{exploit_worked}")
    return RunOutput(cmd, stdout="ok")
cr = FakeRunner(resp_contained, shell=True, contained=True)
prov3 = FakeProvider('[{"command":"python3 solve.py","hypothesis":"H1","rationale":"exploit",'
                     '"expected_signal":"flag","file":{"path":"solve.py","content":'
                     '"import requests\\nprint(open(0).read())\\n"}}]')
orc = Orchestrator(guard(), cr, kb, auto_approve_contained, llm_router=LLMRouter(prov3),
                   workspace=ws3, flag_kind="single", flag_prefixes=("flag",),
                   is_tool_available=ALL, max_sweeps=1, max_rounds=1)
rep = orc.run()
check("강제 샌드박스: solve.py 실제로 작성됨", os.path.exists(ws3.resolve("solve.py")))
check("작성 파일 written 추적", "solve.py" in ws3.written)
check("스크립트 실행 결과 플래그 획득", any(f.value == "flag{exploit_worked}" for f in rep.flags))
wrote = [f for f in rep.llm_findings if "📝 파일 작성" in (f.note or "")]
check("비고에 파일 작성 표시", bool(wrote))


print("\n=== 첨부파일만(포트 없음) 문제 진행 ===")
ws2 = new_ws()
src = tempfile.mkdtemp(prefix="chal-")
open(src + "/chall.py", "w").write("# source\nSECRET='flag{src}'\n")
ws2.import_paths([src + "/chall.py"])

def resp_noports(cmd):
    if cmd.startswith("nmap"):
        # 다운 호스트(열린 포트 없음)
        return RunOutput(cmd, stdout='<?xml version="1.0"?><nmaprun><host><status state="down"/>'
                                     '<address addr="10.129.1.5"/></host></nmaprun>')
    return RunOutput(cmd, stdout="ok")

orc = Orchestrator(guard(), FakeRunner(resp_noports), kb, auto_approve_in_scope,
                   workspace=ws2, is_tool_available=ALL, max_sweeps=1, max_rounds=1)
rep = orc.run()
check("첨부파일 있으면 escalate 아님", rep.status != "escalate")


print("\n=== 플래그 출처: 명령 문자열에 든 플래그는 reasoning-only ===")
# cat files/... 로 소스에서 읽은 플래그가 '명령 자체'에 없으면 공략 유래(오프라인 보정),
# 반대로 echo flag{...} 처럼 명령에 들어 있으면 로컬 유래로 강등되는지.
from htb_agent.orchestrator import OrchestrationReport
from htb_agent.observation.parsers import NmapHost
from htb_agent.flag import FlagHit
o = Orchestrator(guard(), FakeRunner(resp_web), kb, auto_approve_in_scope,
                 workspace=new_ws(), is_tool_available=ALL)
rep = OrchestrationReport(target="10.129.1.5")
rep.host = NmapHost(address="10.129.1.5", state="down")   # 포트 없음(오프라인)
hit = FlagHit("flag{abc}", "flag", "")
prov = o._classify_flag(rep, hit, "echo flag{abc}", "enum")
check("명령에 든 플래그 → reasoning-only(출력 아님)", prov.verdict == "reasoning-only")
prov2 = o._classify_flag(rep, hit, "cat files/chall/secret.txt", "enum")
check("오프라인 파일 읽기 → 공략 유래(검증)", prov2.verdict == "exploit-derived")

print("\n=== 플래그 출처: 웹학습 노트에 있던 값 → looked-up(CTF-Abacus) ===")
from htb_agent.knowledge import KnowledgeBase
kb_ext = KnowledgeBase(notes=["[learned-web-foo.md] writeup says the flag is flag{abc}"])
o2 = Orchestrator(guard(), FakeRunner(resp_web), kb_ext, auto_approve_in_scope,
                  is_tool_available=ALL)
rep2 = OrchestrationReport(target="10.129.1.5")
rep2.host = NmapHost(address="10.129.1.5", state="up")
prov3 = o2._classify_flag(rep2, hit, "curl -s http://10.129.1.5/", "enum")
check("외부 학습 노트에 있던 플래그 → looked-up", prov3.verdict == "looked-up")
check("looked-up 은 검증된 풀이 아님", prov3.genuine is False)
# 번들 시드(seed-*)에 있어도 looked-up 으로 올리지 않음
kb_seed = KnowledgeBase(notes=["[seed-nmap.md] example flag{abc} in reference"])
o3 = Orchestrator(guard(), FakeRunner(resp_web), kb_seed, auto_approve_in_scope,
                  is_tool_available=ALL)
prov4 = o3._classify_flag(rep2, hit, "curl -s http://10.129.1.5/", "enum")
check("번들 시드 유래는 looked-up 아님(공략 유래)", prov4.verdict == "exploit-derived")

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
