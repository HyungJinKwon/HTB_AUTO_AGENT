# 실행: htb-agent 디렉토리에서  python3 tests/test_lateral.py
#
# 측면 이동(lateral) 후보 생성(생성 전용) — 수확 크리덴셜/NT 해시 × 열린 서비스 → 재사용·PtH
# 후보 명령 문자열. 실행·발사 없음. (1) lateral.generate 규칙 (2) preparations.prepare_lateral
# (3) 오케스트레이터 _prepare_lateral 배선(크리덴셜/해시 수집).
import sys
from types import SimpleNamespace

sys.path.insert(0, "src")
from htb_agent import (
    lateral,  # noqa: E402
    preparations,  # noqa: E402
)

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


T = "10.129.1.5"


print("=== generate: 크리덴셜 재사용(열린 서비스별) ===")
cands = lateral.generate(T, [("svc", "P@ss")], [], [22, 445, 8080])
cmds = [c.command for c in cands]
check("SSH(22) nxc 재사용 후보", any(c == f"nxc ssh {T} -u svc -p P@ss" for c in cmds))
check("SMB(445) nxc 재사용 후보", any(c == f"nxc smb {T} -u svc -p P@ss" for c in cmds))
check("미지원 포트(8080)는 후보 없음", not any("8080" in c for c in cmds))
check("전부 cred-reuse 기법", all(c.technique == "cred-reuse" for c in cands))

print("\n=== generate: 특수문자 크리덴셜은 shlex 인용(주입 차단) ===")
inj = lateral.generate(T, [("a d", "p;rm -rf /")], [], [445])
check("공백/세미콜론 인용됨", inj and "'a d'" in inj[0].command and "'p;rm -rf /'" in inj[0].command)

print("\n=== generate: NT 해시 → Pass-the-Hash(SMB/WinRM) ===")
NT = "a" * 32
pth = lateral.generate(T, [], [("admin", NT)], [445, 5985, 22])
pcmds = [(c.service, c.command) for c in pth]
check("SMB PtH 후보(-H)", ("smb", f"nxc smb {T} -u admin -H {NT}") in pcmds)
check("WinRM PtH 후보(-H)", ("winrm", f"nxc winrm {T} -u admin -H {NT}") in pcmds)
check("SSH 는 PtH 비대상(제외)", not any(s == "ssh" for s, _ in pcmds))
check("전부 pass-the-hash 기법", all(c.technique == "pass-the-hash" for c in pth))

print("\n=== generate: 네이티브 클라이언트(mysql/postgres) ===")
nat = lateral.generate(T, [("root", "toor")], [], [3306, 5432])
ncmds = [c.command for c in nat]
check("mysql 재사용 후보", any(cmd.startswith(f"mysql -h {T} -u root -ptoor") for cmd in ncmds))
check("postgres 재사용 후보", any("psql -h " + T in cmd and "PGPASSWORD=toor" in cmd for cmd in ncmds))

print("\n=== generate: 근거 없으면 빈 목록(지어내지 않음) ===")
check("크리덴셜 없음 → 빈 목록", lateral.generate(T, [], [], [22, 445]) == [])
check("열린 서비스 없음 → 빈 목록", lateral.generate(T, [("u", "p")], [], []) == [])
check("타겟 없음 → 빈 목록", lateral.generate("", [("u", "p")], [], [22]) == [])

print("\n=== generate: 상한(폭주 방지) ===")
many_creds = [(f"u{i}", f"p{i}") for i in range(20)]
capped = lateral.generate(T, many_creds, [], [22])
check("크리덴셜 상한 적용(≤6)", len({c.command for c in capped}) <= 6)

print("\n=== render_markdown ===")
md = lateral.render_markdown(cands)
check("후보 있음 → 명령 라인 포함", "nxc ssh" in md and "측면 이동 후보" in md)
check("후보 없음 → 정직한 생략 안내", "없음" in lateral.render_markdown([]))

print("\n=== preparations.prepare_lateral: report 반영 + manual_suggestion ===")
rep = SimpleNamespace(host=SimpleNamespace(open_ports=[22, 445]),
                      lateral_candidates=[], manual_suggestions=[])
events = []
audit = SimpleNamespace(event=lambda name, **kw: events.append((name, kw)))
preparations.prepare_lateral(rep, T, [("svc", "pw")], [], audit)
check("report.lateral_candidates 채워짐", len(rep.lateral_candidates) >= 2)
check("manual_suggestions 에 후보 블록", any("측면 이동 후보" in s for s in rep.manual_suggestions))
check("lateral_prepared audit 이벤트", any(n == "lateral_prepared" for n, _ in events))

print("\n=== prepare_lateral: 근거 없으면 생략 ===")
rep2 = SimpleNamespace(host=SimpleNamespace(open_ports=[22]),
                       lateral_candidates=[], manual_suggestions=[])
preparations.prepare_lateral(rep2, T, [], [], audit)
check("크리덴셜/해시 없음 → 생략", rep2.lateral_candidates == [])

print("\n=== 오케스트레이터 _prepare_lateral 배선(크리덴셜/해시 수집) ===")
from htb_agent.knowledge import KnowledgeBase  # noqa: E402
from htb_agent.orchestrator import OrchestrationReport, Orchestrator  # noqa: E402
from htb_agent.scope_guard import ScopeGuard  # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402
from htb_agent.world import WorldModel  # noqa: E402

g = ScopeGuard.from_cidr_strings()
g.bind_target(T)
orc = Orchestrator(g, FakeRunner(lambda c: RunOutput(c, "")), KnowledgeBase(rules=[], notes=[]),
                   auto_approve_in_scope, is_tool_available=lambda b: True, quiet=True)
orc.world = WorldModel(target=T)
NTH = "b" * 32
orc.world.add_cred("svc:secret")                 # 평문 → cred-reuse
orc.world.add_cred(f"administrator:{NTH}")       # user:HASH(꺾쇠 없음 — 실제 저장 형식) → PtH
rep3 = OrchestrationReport(target=T)
rep3.host = SimpleNamespace(open_ports=[445, 5985])   # open_ports 만 참조됨
orc._prepare_lateral(rep3)
techs = {c.technique for c in rep3.lateral_candidates}
check("평문 크리덴셜 → cred-reuse 후보", "cred-reuse" in techs)
check("user:HASH(꺾쇠 없음) → pass-the-hash 후보", "pass-the-hash" in techs)
check("PtH 후보가 올바른 NT 해시 사용", any(NTH in c.command
      for c in rep3.lateral_candidates if c.technique == "pass-the-hash"))
# 감사 B-MED1: NT 해시를 평문 비밀번호(-p)로 스프레이하는 가짜 후보가 없어야 함
reuse_cmds = [c.command for c in rep3.lateral_candidates if c.technique == "cred-reuse"]
check("NT 해시가 -p(평문)로 스프레이되지 않음",
      not any(f"-p {NTH}" in cmd for cmd in reuse_cmds))
check("cred-reuse 는 평문(svc)만", all("svc" in cmd for cmd in reuse_cmds))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
