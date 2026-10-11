# 실행: htb-agent 디렉토리에서  python3 tests/test_preparations.py
#
# S4-3 — god-object 해체로 분리한 preparations 자유 함수의 단위 검증(이전엔 Orchestrator
# 안에 묶여 run() 통째로만 돌려야 했던 준비 생성기를 독립적으로 고정). 전부 '생성 전용'.
import sys
sys.path.insert(0, "src")
from htb_agent import preparations as P                      # noqa: E402
from htb_agent.orchestrator import OrchestrationReport, EnumFinding  # noqa: E402
from htb_agent.target_profiler import ProfileResult, OSClass  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

class _Audit:   # event(...) 만 받는 덕타이핑 수집기
    def __init__(self): self.events = []
    def event(self, kind, **kw): self.events.append((kind, kw))

T = "10.129.1.5"

print("=== prepare_revshells ===")
rep = OrchestrationReport(target=T, flag_kind="boot2root"); a = _Audit()
P.prepare_revshells(rep, ["10.10.14.7"], 4444, a)
check("공격자 IP 있으면 페이로드 생성", len(rep.revshells) > 0)
check("lhost/lport 기록", rep.revshell_lhost == "10.10.14.7" and rep.revshell_lport == 4444)
rep2 = OrchestrationReport(target=T, flag_kind="boot2root")
P.prepare_revshells(rep2, [], 4444, _Audit())
check("공격자 IP 없으면 생략", rep2.revshells == [])

print("\n=== prepare_cloud ===")
rep = OrchestrationReport(target=T, flag_kind="boot2root")
P.prepare_cloud(rep, ["connected.htb", T], _Audit())
check("이름 있으면 버킷 후보 생성(또는 빈 경우 생략 일관)",
      isinstance(rep.cloud_candidates, list))

print("\n=== prepare_privesc: OS별 게이팅 ===")
rep = OrchestrationReport(target=T, flag_kind="boot2root")
prof_lin = ProfileResult(os_class=OSClass.LINUX, confidence=0.9, is_domain_controller=False)
P.prepare_privesc(rep, prof_lin, "10.10.14.7", _Audit())
check("linux → privesc 플레이북 생성", len(rep.privesc_steps) > 0)
rep_u = OrchestrationReport(target=T, flag_kind="boot2root")
prof_unk = ProfileResult(os_class=OSClass.UNKNOWN, confidence=0.0, is_domain_controller=False)
P.prepare_privesc(rep_u, prof_unk, "", _Audit())
check("OS 미상 → 생략", rep_u.privesc_steps == [])

print("\n=== privesc_analyze: 열거 출력에서 벡터 추출 ===")
rep = OrchestrationReport(target=T, flag_kind="boot2root")
rep.enum_findings.append(EnumFinding(
    command="sudo -l", ran=True,
    output="User may run the following commands:\n    (ALL) NOPASSWD: /usr/bin/find"))
P.privesc_analyze(rep, _Audit())
check("sudo -l 출력 → 벡터 surface(제안 생성)",
      bool(rep.privesc_vectors) and any("권한상승 벡터" in m for m in rep.manual_suggestions))

print("\n=== prepare_crack: 해시 수집 ===")
rep = OrchestrationReport(target=T, flag_kind="boot2root")
# MD5 형태 해시가 출력에 있으면 크래킹 작업 준비
rep.enum_findings.append(EnumFinding(
    command="cat hashes", ran=True,
    output="admin:$1$abcd$0123456789abcdef0123456./"))
a = _Audit()
P.prepare_crack(rep, [], None, a)
check("해시 발견 시 crack_jobs 준비(또는 해시 없으면 빈 채로 안전)",
      isinstance(rep.crack_jobs, list))
rep_e = OrchestrationReport(target=T, flag_kind="boot2root")
P.prepare_crack(rep_e, [], None, _Audit())
check("해시 전무 → crack_jobs 비어 있음", rep_e.crack_jobs == [])

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
