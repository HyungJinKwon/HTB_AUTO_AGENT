# 실행: htb-agent 디렉토리에서  python3 tests/test_report_view_sections.py
#
# render_summary 섹션 분해(_view_*) 회귀 가드 — 풍부한 리포트에서 모든 섹션이 렌더되고,
# 스파인이 섹션 렌더러를 올바른 순서로 이어 붙이는지(헤딩 출현 순서) 확인한다. 분해 전후
# 바이트 동일성은 리뷰 시 골든 diff 로 검증했고, 여기선 섹션 존재·순서·_rr 1회 공유를 고정한다.
import sys
from types import SimpleNamespace

sys.path.insert(0, "src")
from htb_agent import cloud, crack, lateral, privesc, report_view, revshell  # noqa: E402
from htb_agent import provenance as pv  # noqa: E402
from htb_agent.flag import FlagHit  # noqa: E402
from htb_agent.hypotheses import Hypothesis, HypothesisLedger  # noqa: E402
from htb_agent.orchestrator import EnumFinding, OrchestrationReport  # noqa: E402
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


def rich_report():
    r = OrchestrationReport(target="10.129.1.5", flag_kind="boot2root")
    r.status = "done"
    r.recon = SimpleNamespace(summary=lambda: "  recon", attempts=[])
    r.profile = SimpleNamespace(summary=lambda: "  profile")
    w = WorldModel(target="10.129.1.5"); w.add_cred("svc:pw"); w.raise_access("user")
    r.world = w
    r.plan = HypothesisLedger(items=[Hypothesis(id="H1", text="t", priority="상")])
    r.analysis = "분석"
    r.acquired_knowledge = ["x → X"]
    r.enum_findings = [EnumFinding(command="nmap t", ran=True, output="open", phase="enum")]
    r.llm_findings = [EnumFinding(command="curl t", ran=True, output="200", phase="access")]
    r.flag_provenance = [pv.classify("user", "HTB{u}", "curl t/flag", "access")]
    r.detected_cve = ["CVE-2021-1"]
    r.flags = [FlagHit("HTB{u}", "user", "발판")]
    r.revshells = revshell.generate("10.10.14.9", 4444)
    r.revshell_lhost = "10.10.14.9"; r.revshell_lport = 4444
    cp = cloud.generate(["acme.htb"]); r.cloud_candidates = cp.candidates; r.cloud_checks = cp.checks
    pl = privesc.build("linux", "10.10.14.9", []); r.privesc_steps = pl.steps
    r.crack_jobs = crack.prepare(["$1$a$b"])
    r.lateral_candidates = lateral.generate("10.129.1.5", [("svc", "pw")], [], [445])
    r.manual_suggestions = ["searchsploit X  # 익스 후보", "nmap --script vuln t   # (수동)"]
    return r


print("=== render_summary: 모든 섹션 렌더(크래시 없음) ===")
out = report_view.render_summary(rich_report())
for name, marker in [("RECON", "RECON"), ("PROFILE", "PROFILE"), ("STATE", "STATE"),
                     ("PLAN", "PLAN"), ("ANALYSIS", "ANALYSIS"), ("LEARN", "LEARN"),
                     ("PROVENANCE", "PROVENANCE"), ("VULN", "VULN"), ("FLAG", "플래그 (FLAG)"),
                     ("revshell", "리버스쉘"), ("cloud", "AWS/S3"), ("privesc", "권한 상승"),
                     ("crack", "해시 크래킹"), ("lateral", "측면 이동"), ("manual", "수동 제안")]:
    check(f"{name} 섹션 존재", marker in out)

print("\n=== 섹션 순서 보존(스파인 선언 순서) ===")
order = ["RECON", "PROFILE", "STATE", "PLAN", "ANALYSIS", "LEARN", "PROVENANCE",
         "VULN", "플래그 (FLAG)", "리버스쉘", "AWS/S3", "권한 상승", "해시 크래킹",
         "측면 이동", "수동 제안"]
positions = [out.find(m) for m in order]
check("헤딩이 선언 순서대로 등장", all(a < b for a, b in zip(positions, positions[1:]) if a >= 0 and b >= 0))

print("\n=== 빈 리포트는 헤더만(섹션 없음·크래시 없음) ===")
empty = OrchestrationReport(target="t")
eout = report_view.render_summary(empty)
check("ASSASSIN 헤더 존재", "ASSASSIN" in eout)
check("빈 리포트엔 VULN 섹션 없음", "VULN  (탐지" not in eout)

print("\n=== 섹션 렌더러는 해당 없으면 빈 목록 ===")
from htb_agent import ui  # noqa: E402
check("_view_vuln 빈 → []", report_view._view_vuln(empty, ui) == [])
check("_view_lateral 빈 → []", report_view._view_lateral(empty, ui) == [])

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
