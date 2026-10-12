# 실행: htb-agent 디렉토리에서  python3 tests/test_reversing.py
#
# [G2] export-first 정적 리버싱 — 바이너리를 실행하지 않는 정적 도구만 생성, 3관문에 투입.
import sys
from types import SimpleNamespace

sys.path.insert(0, "src")
from htb_agent import reversing  # noqa: E402
from htb_agent.knowledge import KnowledgeBase  # noqa: E402
from htb_agent.orchestrator import OrchestrationReport, Orchestrator  # noqa: E402
from htb_agent.scope_guard import ScopeGuard  # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402
from htb_agent.world import WorldModel  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


print("=== export_first_commands: 정적 도구 집합 ===")
cmds = reversing.export_first_commands("/tmp/chal")
bins = [c.split()[0] for c in cmds]
check("file·strings·nm·objdump·checksec·r2 포함",
      {"file", "strings", "nm", "objdump", "checksec", "r2"} <= set(bins))
check("file 이 먼저(가벼운 식별 우선)", bins[0] == "file")
check("빈 경로 → 빈 목록", reversing.export_first_commands("") == [])

print("\n=== 바이너리를 '실행'하지 않음(정적만) ===")
joined = " ".join(cmds).lower()
forbidden = ["gdb ", "ltrace", "strace", "./", "qemu", "wine ", "python "]
check("동적 실행 명령 없음", not any(f in joined for f in forbidden))
# r2 는 -A(정적 분석)만, 디버그(-d) 아님
check("r2 는 정적(-A), -d(디버그) 아님", "-a" in [t.lower() for t in
      next(c for c in cmds if c.startswith("r2")).split()] and " -d " not in
      " " + next(c for c in cmds if c.startswith("r2")) + " ")

print("\n=== 경로 안전 인용(주입 차단) ===")
q = reversing.export_first_commands("/tmp/a b;rm -rf x")
check("공백·세미콜론 경로는 인용됨", all("'/tmp/a b;rm -rf x'" in c for c in q))

print("\n=== 통합: 첨부 바이너리 → 정적 분석이 3관문에 투입됨 ===")
T = "10.129.1.5"
ran = []
def fake(cmd):
    ran.append(cmd)
    return RunOutput(cmd, stdout="ELF 64-bit")
g = ScopeGuard.from_cidr_strings()
g.bind_target(T)
orc = Orchestrator(g, FakeRunner(fake), KnowledgeBase(rules=[], notes=[]), auto_approve_in_scope,
                   is_tool_available=lambda b: True, quiet=True)
rep = OrchestrationReport(target=T)
rep.world = orc.world = WorldModel(target=T)
orc.workspace = SimpleNamespace(root="/work", imported=["files/chal.bin"])
orc._analyze_offline_files(rep)
cmds_run = [f.command for f in rep.enum_findings]
check("file 명령이 투입됨", any(c.startswith("file ") and "chal.bin" in c for c in cmds_run))
check("objdump 디스어셈블 투입됨", any(c.startswith("objdump -d") for c in cmds_run))
check("정적 분석 finding 은 예산 비계상(budgeted=False)",
      all(not f.budgeted for f in rep.enum_findings))
check("전체 경로 사용(root+rel)", any("/work/files/chal.bin" in c for c in cmds_run))

print("\n=== 첨부 없으면 아무것도 안 함 ===")
orc2 = Orchestrator(g, FakeRunner(fake), KnowledgeBase(rules=[], notes=[]), auto_approve_in_scope,
                    is_tool_available=lambda b: True, quiet=True)
rep2 = OrchestrationReport(target=T)
rep2.world = orc2.world = WorldModel(target=T)
orc2.workspace = None
orc2._analyze_offline_files(rep2)
check("workspace 없으면 no-op", rep2.enum_findings == [])

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
