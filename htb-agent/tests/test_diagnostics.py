# 실행: htb-agent 디렉토리에서  python3 tests/test_diagnostics.py
# 실패 진단(원인 분류·대상/환경 구분·오판 방지 표시) — 사람 판단 보조.
import sys
sys.path.insert(0, "src")
from htb_agent import diagnostics as dx
from htb_agent.tools.runner import RunOutput

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


print("=== HTTP 상태 → 대상 응답 ===")
d = dx.diagnose("curl -i http://t/admin", RunOutput("c", stdout="HTTP/1.1 403 Forbidden\r\n\r\n"))
check("403 → 대상 응답", d and d.category == "http-403" and d.is_target)
d = dx.diagnose("curl -i http://t/x", RunOutput("c", stdout="HTTP/1.1 404 Not Found\r\n\r\n"))
check("404 → 대상 응답(경로 부재)", d and d.category == "http-404" and d.is_target)
d = dx.diagnose("curl -i http://t/", RunOutput("c", stdout="HTTP/1.1 401 Unauthorized\r\n\r\n"))
check("401 → 인증 필요", d and d.category == "http-401" and d.is_target)
d = dx.diagnose("curl http://t/", RunOutput("c", stdout="HTTP 429 Too Many Requests"))
check("429 → 환경(레이트리밋, 경로 실패 아님)", d and d.category == "http-429" and not d.is_target)
d = dx.diagnose("curl http://t/", RunOutput("c", stdout="HTTP/1.1 500 Internal Server Error\r\n\r\n"))
check("5xx → 대상 응답", d and d.category == "http-5xx" and d.is_target)

print("\n=== 성공/정상 → 진단 없음 ===")
check("200 정상 → None", dx.diagnose("curl -i http://t/", RunOutput("c", stdout="HTTP/1.1 200 OK\r\n\r\n<html>ok</html>")) is None)
check("유의미 출력 → None", dx.diagnose("nmap t", RunOutput("c", stdout="80/tcp open http")) is None)

print("\n=== 환경/네트워크 실패 → is_target False ===")
d = dx.diagnose("curl http://t/", RunOutput("c", error="curl: (7) Connection refused"))
check("연결 거부 → 환경", d and d.category == "conn-refused" and not d.is_target)
d = dx.diagnose("curl http://t/", RunOutput("c", error="timed out", timed_out=True))
check("타임아웃 → 환경", d and d.category == "timeout" and not d.is_target)
d = dx.diagnose("curl http://host/", RunOutput("c", error="curl: (6) Could not resolve host"))
check("DNS 실패 → 환경", d and d.category == "dns" and not d.is_target)
d = dx.diagnose("nmap t", RunOutput("c", error="exec: nmap: not found"))
check("실행 실패(미설치) → 환경", d and d.category == "launch-failed" and not d.is_target)
# 실행은 됐으나 stderr 에 네트워크 신호
d = dx.diagnose("curl http://t/", RunOutput("c", stdout="", stderr="connection refused"))
check("stderr 네트워크 신호 → 환경", d and not d.is_target)

print("\n=== 빈 결과 → 중립(환경) ===")
d = dx.diagnose("gobuster dir -u http://t", RunOutput("c", stdout="   "))
check("빈 출력 → empty-result(환경)", d and d.category == "empty-result" and not d.is_target)

print("\n=== 오판 방지: 환경 실패는 포기 신호 아님 ===")
diags = [
    dx.FailureDiagnosis("timeout", "x", False),
    dx.FailureDiagnosis("conn-refused", "x", False),
    dx.FailureDiagnosis("http-404", "x", True),
]
sig = dx.abandonment_signals(diags)
check("환경 실패는 신호에서 제외", "timeout" not in sig and "conn-refused" not in sig)
check("대상 거부만 집계", sig.get("http-404") == 1)
# 대상이 2회+ 거부해야 '재검토 후보'
diags2 = [dx.FailureDiagnosis("http-403", "x", True)] * 2
check("대상 2회 거부 → 집계 2", dx.abandonment_signals(diags2).get("http-403") == 2)

print("\n=== 오케스트레이터 통합(진단이 리포트에 실림) ===")
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.orchestrator import Orchestrator

LINUX_WEB = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""
def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target("10.129.1.5"); return g
def responder(c):
    if c.startswith("nmap"): return RunOutput(c, stdout=LINUX_WEB)
    if c.startswith("curl"): return RunOutput(c, stdout="HTTP/1.1 403 Forbidden\r\n\r\n")  # 대상 거부
    return RunOutput(c, stdout="ok")
rep = Orchestrator(guard(), FakeRunner(responder), KnowledgeBase.load(),
                   auto_approve_in_scope, is_tool_available=lambda b: True).run()
check("done 유지", rep.status == "done")
check("blockers 에 대상 거부(403) 기록",
      any(d.category == "http-403" and d.is_target for _, d in rep.blockers))
check("리포트 요약에 BLOCKERS 섹션", "BLOCKERS" in rep.summary(verbose=True))
check("요약에 대상/환경 구분 문구", "경로 실패 아님" in rep.summary(verbose=True) or "대상 응답" in rep.summary(verbose=True))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
