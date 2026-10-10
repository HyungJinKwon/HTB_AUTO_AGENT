# 실행: htb-agent 디렉토리에서  python3 tests/test_e2e_freepbx_chain.py
#
# E2E 통합 회귀: connected.htb(FreePBX vhost)형 시나리오를 '전체 Orchestrator.run()'으로
# 구동해, 구조 개선(S0 원본증거 핑거프린트 · S1 스테이지 순서 · S2 고정점 완주 · S3 의존
# 스케줄러)이 '한 번의 자율 실행 안에서' 다음 의존 체인을 완주하는지 고정한다:
#
#   vhost 핑거프린트(제품/버전 식별) → 익스 조회(searchsploit) → ⭐ 버전매칭 PoC 숏리스트
#
# 기존 단위 테스트는 각 스테이지를 '사전 세팅된 world'로 따로 검증할 뿐, 전체 run() 이
# 제품·버전을 스스로 발견해 ⭐ 까지 연결하는 통합 경로는 커버하지 않았다. 세션 내내 "고립
# 재현은 되는데 런타임은 매칭 없음"이던 ⭐52031 증상의 '런타임 종단' 회귀 가드.
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard                 # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput     # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope      # noqa: E402
from htb_agent.knowledge import KnowledgeBase                # noqa: E402
from htb_agent.orchestrator import Orchestrator              # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

TARGET = "10.129.245.100"
VHOST = "connected.htb"

# nmap: 443/https 열림(FreePBX 는 TLS vhost).
NMAP = f"""<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="{TARGET}"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Apache httpd"/></port>
</ports></host></nmaprun>"""

# vhost admin 본문: 'FreePBX 16.0.40.7' 가 코퍼스에 들어가야 S0 핑거프린트가 제품+버전 확정.
FREEPBX_BODY = (
    "<html><head><title>FreePBX Administration</title></head>"
    "<body><div class='footer'>FreePBX 16.0.40.7</div>"
    "<!-- appver=16.0.40.7 --></body></html>"
)

# searchsploit freepbx: 16 계열 매칭 PoC(52031) 포함. 제목에 'auth' 신호 없음(무인증).
# 접두 매칭: 대상 '16.0.40.7' ↔ 제목 'FreePBX 16'(단독 major) → _version_matches n=1 매칭.
SS = ("Exploit Title | Path\n"
      " FreePBX 13.0.188 - Remote Command Execution | php/webapps/40434.py\n"
      " FreePBX 16 - Remote Command Execution (modwebrt) | php/webapps/52031.php\n")


def fake(cmd: str) -> RunOutput:
    c = cmd or ""
    if c.startswith("nmap"):
        return RunOutput(c, stdout=NMAP)
    if "searchsploit" in c:
        return RunOutput(c, stdout=SS)
    # vhost 로 때린 웹 요청(핑거프린트 curl 포함)에만 FreePBX 본문을 돌려준다.
    if VHOST in c and ("curl" in c or "http" in c):
        return RunOutput(c, stdout=FREEPBX_BODY)
    return RunOutput(c, stdout="")   # 그 외 열거 명령은 무해한 빈 출력


def run_chain():
    g = ScopeGuard.from_cidr_strings(); g.bind_target(TARGET)
    orc = Orchestrator(
        g, FakeRunner(fake), KnowledgeBase.load(), auto_approve_in_scope,
        hosts_map={VHOST: TARGET},   # vhost 기지(리다이렉트 발견은 test_vhost_autoreg 가 커버)
        flag_kind="boot2root",
        is_tool_available=lambda b: True,
        # auto_poc 만 켠다 — 핑거프린트/웹비밀 등 조회 스테이지를 활성화하되, exploit_exec 의
        # 실제 발판(requests 실망 egress) 경로는 켜지 않아 테스트를 완전 무네트워크로 유지한다.
        # (⭐ 자동 발사 배선은 test_auto_poc_wiring 가 별도 커버.)
        auto_poc=True,
        quiet=True,
    )
    return orc, orc.run()


print("=== 전체 run(): FreePBX 발견 → searchsploit → ⭐ 버전매칭 PoC (S0~S3 통합) ===")
orc, rep = run_chain()
w = rep.world

check("S0: 제품 자동 식별(web_product=freepbx)", w is not None and w.web_product == "freepbx")
check("S0: 버전 원본에서 추출(web_version 16.x)",
      w is not None and w.web_version.startswith("16"))
sugg = rep.manual_suggestions
check("searchsploit 조회가 실행됨",
      any("searchsploit" in (f.command or "")
          for f in rep.enum_findings + rep.llm_findings))
check("S1~S3: ⭐ 버전매칭 1순위 숏리스트 생성", any("⭐ 추천" in m for m in sugg))
check("⭐ 가 올바른 PoC(52031)를 가리킴",
      any("⭐ 추천" in m and "52031" in m for m in sugg))
check("⭐ 1순위에 받기·실행계획(생성 전용 제안)이 구체화됨",
      any("52031" in m and ("실행 계획(제안" in m or "받아 검토" in m) for m in sugg))

print("\n=== 음성 대조: 제품 미식별이면 ⭐ 없음(허위양성 방지) ===")
# vhost 미등록 → 핑거프린트 불가 → 제품 미상 → ⭐ 안 뜸(정직성).
g2 = ScopeGuard.from_cidr_strings(); g2.bind_target(TARGET)
orc2 = Orchestrator(g2, FakeRunner(fake), KnowledgeBase.load(), auto_approve_in_scope,
                    flag_kind="boot2root", is_tool_available=lambda b: True,
                    exploit_exec=True, auto_poc=True, quiet=True)   # hosts_map 없음
rep2 = orc2.run()
check("제품 미상 시 web_product 비어 있음",
      rep2.world is not None and not rep2.world.web_product)
check("제품 미상 시 ⭐ 추천 없음", not any("⭐ 추천" in m for m in rep2.manual_suggestions))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
