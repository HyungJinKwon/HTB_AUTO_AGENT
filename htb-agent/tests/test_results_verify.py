# 실행: htb-agent 디렉토리에서  python3 tests/test_results_verify.py
#
# [T1-a] 출력구동 Results Verifier — 실행 후 출력을 보고 '한 끗 빠진' 명령을 교정해 1회 재시도.
# (1) results_verify.corrective_command 규칙(결정적) (2) 오케스트레이터 재투입(생성전용·유한).
import sys

sys.path.insert(0, "src")
from htb_agent import results_verify  # noqa: E402
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


def RO(cmd, stdout="", stderr=""):
    return RunOutput(cmd, stdout=stdout, stderr=stderr)


print("=== 규칙: nmap 호스트 다운/필터 → -Pn ===")
r = results_verify.corrective_command("nmap 10.129.1.5", RO("nmap 10.129.1.5",
    "Note: Host seems down. If it is really up, but blocking our ping probes...\nNmap done"))
check("교정본에 -Pn 삽입", r and r[0] == "nmap -Pn 10.129.1.5")
check("-Pn 이미 있으면 교정 안 함",
      results_verify.corrective_command("nmap -Pn 10.129.1.5", RO("x", "host seems down")) is None)

print("\n=== 규칙: curl TLS 자가서명 → -k ===")
r2 = results_verify.corrective_command("curl -s https://10.129.1.5/",
    RO("c", stderr="curl: (60) SSL certificate problem: self signed certificate"))
check("교정본에 -k 삽입", r2 and r2[0] == "curl -k -s https://10.129.1.5/")
check("-k 이미 있으면 교정 안 함", results_verify.corrective_command(
    "curl -k https://10.129.1.5/", RO("c", stderr="self signed certificate")) is None)

print("\n=== 규칙: curl 3xx 리다이렉트 → -L ===")
r3 = results_verify.corrective_command("curl -s http://10.129.1.5/",
    RO("c", "HTTP/1.1 301 Moved Permanently\nLocation: https://10.129.1.5/"))
check("교정본에 -L 삽입(리다이렉트 상한 포함)",
      r3 and r3[0] == "curl -L --max-redirs 2 -s http://10.129.1.5/")
check("egress 경계: -L 에 --max-redirs 상한 동반", r3 and "--max-redirs" in r3[0])

print("\n=== 규칙: 303/307/308 리다이렉트도 → -L(감사 A-LOW9) ===")
r303 = results_verify.corrective_command("curl -s http://10.129.1.5/",
    RO("c", "HTTP/1.1 303 See Other\nLocation: /next"))
check("303 See Other → -L 삽입", r303 and r303[0] == "curl -L --max-redirs 2 -s http://10.129.1.5/")
r308 = results_verify.corrective_command("curl -s http://10.129.1.5/",
    RO("c", "HTTP/1.1 308 Permanent Redirect\nLocation: /next"))
check("308 Permanent Redirect → -L 삽입", r308 and r308[0] == "curl -L --max-redirs 2 -s http://10.129.1.5/")
# 이미 --max-redirs 가 있으면 중복 추가하지 않음
rcap = results_verify.corrective_command("curl -s --max-redirs 5 http://10.129.1.5/",
    RO("c", "HTTP/1.1 301 Moved\nLocation: https://10.129.1.5/"))
check("기존 --max-redirs 중복 추가 안 함", rcap and rcap[0].count("--max-redirs") == 1)

print("\n=== no-op: 교정 근거 없는 출력 ===")
check("정상 출력엔 교정 없음",
      results_verify.corrective_command("nmap 10.129.1.5", RO("x", "22/tcp open ssh")) is None)
check("빈 출력엔 교정 없음", results_verify.corrective_command("nmap x", RO("x", "")) is None)

print("\n=== 통합: 오케스트레이터가 교정본을 3관문에 재투입(생성전용·유한) ===")
T = "10.129.1.5"

def fake(cmd: str) -> RunOutput:
    c = cmd or ""
    if c.startswith("nmap -Pn"):
        return RunOutput(c, stdout="22/tcp open ssh")           # 교정본은 성공
    if c.startswith("nmap"):
        return RunOutput(c, stdout="Note: Host seems down. blocking our ping probes\nNmap done")
    return RunOutput(c, stdout="ok")

g = ScopeGuard.from_cidr_strings()
g.bind_target(T)
orc = Orchestrator(g, FakeRunner(fake), KnowledgeBase(rules=[], notes=[]), auto_approve_in_scope,
                   is_tool_available=lambda b: True, quiet=True)
rep = OrchestrationReport(target=T)
rep.world = orc.world = WorldModel(target=T)
orc._attempt(rep, rep.enum_findings, f"nmap {T}", "enum")
cmds = [f.command for f in rep.enum_findings]
check("원본 nmap 실행됨", f"nmap {T}" in cmds)
check("교정본 nmap -Pn 재투입됨", f"nmap -Pn {T}" in cmds)
corr = [f for f in rep.enum_findings if f.command == f"nmap -Pn {T}"][0]
check("교정본은 예산 비계상(budgeted=False)", corr.budgeted is False)
check("교정본은 실제로 실행됨", corr.ran)

print("\n=== 재귀 방지: 교정본은 또 교정되지 않음 ===")
# 교정본(nmap -Pn)은 -Pn 이 이미 있어 규칙상 교정 대상 아님 + corrective=True 가드.
# 같은 종류의 교정이 2회 이상 쌓이지 않는지(원본당 1회) 확인.
n_pn = sum(1 for f in rep.enum_findings if f.command == f"nmap -Pn {T}")
check("교정본은 1개만(원본당 1회)", n_pn == 1)

print("\n=== 전역 예산 상한 ===")
orc2 = Orchestrator(g, FakeRunner(fake), KnowledgeBase(rules=[], notes=[]), auto_approve_in_scope,
                    is_tool_available=lambda b: True, quiet=True)
rep2 = OrchestrationReport(target=T)
rep2.world = orc2.world = WorldModel(target=T)
orc2._verify_retried = set()   # run() 미경유 — 초기화됨 표시
orc2._verify_budget_left = 0   # 예산 소진 상태
orc2._attempt(rep2, rep2.enum_findings, f"nmap {T}", "enum")
check("예산 0 이면 교정 재투입 안 함",
      f"nmap -Pn {T}" not in [f.command for f in rep2.enum_findings])

print("\n=== 삽입 위치: env-prefix·래퍼 뒤 삽입(감사 M3/M4) ===")
# env-prefix(PROXY=1 nmap): 첫 토큰(PROXY=1) 뒤가 아니라 '실제 바이너리' 뒤에 삽입돼야 함.
rp = results_verify.corrective_command("PROXY=1 nmap 10.129.1.5",
    RO("x", "host seems down\nNmap done"))
check("env-prefix 보존·바이너리 뒤 삽입", rp and rp[0] == "PROXY=1 nmap -Pn 10.129.1.5")
# 래퍼(sudo): 래퍼를 바이너리로 오인하지 않고 nmap 을 인식·교정, 삽입도 nmap 뒤.
rs = results_verify.corrective_command("sudo nmap 10.129.1.5",
    RO("x", "host seems down\nNmap done"))
check("sudo 래퍼 뒤 nmap 인식·교정", rs and rs[0] == "sudo nmap -Pn 10.129.1.5")
# proxychains 래퍼 + curl TLS
rpc = results_verify.corrective_command("proxychains curl -s https://10.129.1.5/",
    RO("c", stderr="self signed certificate"))
check("proxychains 래퍼 뒤 curl 인식·교정",
      rpc and rpc[0] == "proxychains curl -k -s https://10.129.1.5/")

print("\n=== 멱등: 결합형 단축플래그 인식(감사 M5) ===")
# curl -sSL 은 이미 -L 포함(-sSL 의 L) → 리다이렉트여도 -L 중복 삽입 안 함.
ri = results_verify.corrective_command("curl -sSL http://10.129.1.5/",
    RO("c", "HTTP/1.1 301 Moved Permanently\nLocation: https://x/"))
check("-sSL 에 -L 포함 인식 → 중복 교정 안 함", ri is None)

print("\n=== 단축플래그 대소문자 구분: -K(설정파일) ≠ -k(--insecure) (감사 B-LOW4) ===")
# curl -K(대문자, 설정파일)는 -k(소문자, TLS 검증생략)와 다르다 → 자가서명 교정을 삼키면 안 됨.
rk = results_verify.corrective_command("curl -K my.cfg https://10.129.1.5/",
    RO("c", stderr="curl: (60) SSL certificate problem: self signed certificate"))
check("-K 는 -k 로 오인 안 함 → -k 교정 적용", rk and rk[0] == "curl -k -K my.cfg https://10.129.1.5/")

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
