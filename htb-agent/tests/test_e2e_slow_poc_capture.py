# 실행: htb-agent 디렉토리에서  python3 tests/test_e2e_slow_poc_capture.py
#
# ★ '가짜 주입이 아닌' 실 프로세스 실행 검증 — 실제 머신에서 user 플래그를 못 찾던 바로 그 경로.
# 배경(실측 재발 방지): watchTowr CVE-2025-57819 PoC 는 ① 배너를 먼저 찍고 ② SQLi 로 cron 을
#   주입한 뒤 ③ 웹셸이 떨어질 때까지 '최대 120s 폴링'하고 ④ 성공 시 드롭된 웹셸 URL 을 늦게 출력한다.
#   그 URL 접미사는 '랜덤'이라 추측이 불가능 → 반드시 그 늦은 출력 줄을 '캡처'해야 발판이 선다.
#   그런데 (가) 러너 기본 타임아웃(180s)이 폴링+주입+정리를 못 버티고 (나) python stdout 이 파이프
#   연결 시 '블록버퍼링'되어, 늦게 나오는 성공 URL 줄이 (중단·버퍼에) 유실돼 '배너만' 보고 끊겼다.
# 이 테스트는 (1) 모듈의 run_timeout 이 실제로 러너까지 플럼되는지 (2) '배너 → 지연 → 늦은 URL'
#   을 내는 '진짜 서브프로세스 PoC' 를 '진짜 ShellRunner' 로 돌려 rce_url 이 캡처되는지(=발판 성립)
#   를 검증한다. 표준 라이브러리만 사용(외부 의존성 없음) → 기본 test CI 매트릭스에서 함께 돈다.
import os
import stat
import sys
import tempfile

sys.path.insert(0, "src")

from htb_agent import exploit_modules as em                 # noqa: E402
from htb_agent.knowledge import KnowledgeBase               # noqa: E402
from htb_agent.orchestrator import OrchestrationReport, Orchestrator  # noqa: E402
from htb_agent.scope_guard import ScopeGuard                # noqa: E402
from htb_agent.tools.recon import auto_approve_contained    # noqa: E402
from htb_agent.tools.runner import RunOutput                # noqa: E402
from htb_agent.tools.sandbox import ShellRunner             # noqa: E402
from htb_agent.world import WorldModel                      # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


T = "10.129.245.100"   # HTB 대역(스코프 허용). PoC 는 이 URL 을 '출력'만 하고 접속하지 않는다.
SUFFIX = "Ab3Xk9Lm2Q"
# watchTowr 실 성공 출력 형식: '[+] VULNERABLE - webshell found: <base>this-is-an-ioc-not-
# actually-watchTowr-<rand>.php?cmd=hostname'. 캡처는 쿼리스트링 앞 .php 까지.
EXPECT_URL = f"http://{T}/this-is-an-ioc-not-actually-watchTowr-{SUFFIX}.php"


def make_orc(runner):
    g = ScopeGuard.from_cidr_strings()
    g.bind_target(T)
    orc = Orchestrator(g, runner, KnowledgeBase.load(), auto_approve_contained,
                       is_tool_available=lambda b: True, quiet=True,
                       exploit_exec=True, auto_poc=True)
    orc.world = WorldModel(target=T)
    orc.world.web_product = "freepbx"
    orc._active_exploit_module = em.match("freepbx", "16.0.40.7")
    return orc


# ── (1) run_timeout 플럼 검증 — 모듈이 선언한 상한이 러너 run(timeout=) 까지 전달되는가 ──
print("=== run_timeout 플럼: 모듈 run_timeout(300) → 러너 실행 상한 ===")


class RecordingRunner:
    """run(timeout=) 로 받은 값을 기록하는 러너(실행 흉내). 폴링형 PoC 출력(배너+늦은 URL)을 반환."""
    shell = True; contained = False; real_exec = False
    def __init__(self):
        self.timeouts: dict[str, int] = {}
    def has_tool(self, b): return True
    def run(self, command: str, timeout: int = 120) -> RunOutput:
        self.timeouts[command] = timeout
        if "poc" in command:
            return RunOutput(command, stdout=(
                "banner art line\n[*] injecting cron via SQLi...\n"
                f"[+] VULNERABLE - webshell found: {EXPECT_URL}?cmd=hostname\n[*] cleanup\n"))
        return RunOutput(command, stdout="")


rec = RecordingRunner()
orc = make_orc(rec)
poc_cmd = orc._active_exploit_module.build_invocation("/tmp/poc.py", T, scheme="http")
orc.poc_commands = [poc_cmd]
rep = OrchestrationReport(target=T)
orc._exploit_run_stage(rep, None)
check("PoC 호출에 python3 -u (unbuffered) 포함", poc_cmd.startswith("python3 -u "))
check("PoC 실행이 모듈 run_timeout(300)으로 상향 전달됨",
      rec.timeouts.get(poc_cmd) == 300)
check("폴링형 PoC 의 '늦은' 웹셸 URL 을 캡처(rce_url)", getattr(orc, "rce_url", "") == EXPECT_URL)
check("웹 cmd 스펙 = 모듈대로(GET/query/cmd)",
      getattr(orc, "rce_method", "") == "GET" and getattr(orc, "rce_inject", "") == "query"
      and getattr(orc, "rce_cmd_param", "") == "cmd")


# ── (2) 진짜 서브프로세스 PoC — 실 ShellRunner 로 '배너 → 지연 → 늦은 URL' 캡처(가짜 아님) ──
print("\n=== 실 서브프로세스 PoC(ShellRunner): 배너 먼저 → 지연 후 늦은 웹셸 URL 캡처 ===")
tmpdir = tempfile.mkdtemp()
poc_path = os.path.join(tmpdir, "watchTowr-vs-FreePBX-CVE-2025-57819.py")
# 실 PoC 흉내: 배너를 flush 없이 찍고, 잠깐 '폴링'한 뒤(성공 URL 은 늦게), IOC 웹셸 URL 을 출력.
# -u(unbuffered)로 띄우므로 지연 뒤 출력도 안전히 캡처돼야 한다. 인자(-H ...)는 받되 무시.
with open(poc_path, "w") as f:
    f.write(
        "import sys, time\n"
        "sys.stdout.write('  __ ___ banner art (watchTowr)\\n')\n"
        "sys.stdout.write('[*] injecting cron via SQLi; polling for webshell...\\n')\n"
        "time.sleep(1.5)\n"
        f"print('[+] VULNERABLE - webshell found: {EXPECT_URL}?cmd=hostname')\n"
        "print('[*] cleaning up watchTowr-%% cron rows')\n")
os.chmod(poc_path, os.stat(poc_path).st_mode | stat.S_IRUSR)

orc2 = make_orc(ShellRunner(workdir=tmpdir))
inv = orc2._active_exploit_module.build_invocation(poc_path, T, scheme="http")
orc2.poc_commands = [inv]
rep2 = OrchestrationReport(target=T)
orc2._exploit_run_stage(rep2, None)
check("실 서브프로세스 PoC 가 게이트를 통과해 실행됨",
      any(poc_path in (fnd.command or "") for fnd in rep2.enum_findings))
check("실행 출력에 배너와 늦은 URL 이 모두 캡처됨(버퍼 유실 없음)",
      any("VULNERABLE" in (fnd.output or "") and "banner art" in (fnd.output or "")
          for fnd in rep2.enum_findings))
check("실 출력에서 rce_url 캡처 = 발판 성립", getattr(orc2, "rce_url", "") == EXPECT_URL)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
