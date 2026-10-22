# 실행: htb-agent 디렉토리에서  python3 tests/test_web_secrets.py
#
# ③ 발판 전 자격 수확 — 웹 노출 비밀/백업 파일을 읽기전용 GET 으로 열거(생성 전용),
# 본문에서 자격이 나오면 world.creds 로 수확돼 ①(b) 인증 PoC 폐루프를 활성화하는지 검증.
import sys
sys.path.insert(0, "src")
from htb_agent.web_secrets import exposed_paths, secret_read_commands  # noqa: E402
from htb_agent.scope_guard import ScopeGuard                   # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput       # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope        # noqa: E402
from htb_agent.knowledge import KnowledgeBase                  # noqa: E402
from htb_agent.orchestrator import Orchestrator, OrchestrationReport  # noqa: E402
from htb_agent.world import WorldModel                         # noqa: E402
from htb_agent.observation.parsers import NmapHost, Port       # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

TARGET = "10.129.245.100"

print("=== exposed_paths / secret_read_commands (생성 전용 데이터) ===")
fp = exposed_paths("freepbx")
check("freepbx 제품 경로 포함(amportal.conf)", "amportal.conf" in fp)
check("일반 경로 포함(.env)", ".env" in fp and ".git/config" in fp)
check("선행 슬래시 정규화(중복 제거)", all(not p.startswith("/") for p in fp) and len(fp) == len(set(fp)))
check("미등록 제품도 일반 경로는 제공", ".env" in exposed_paths("nginx"))

cmds = secret_read_commands([f"https://{TARGET}"], "freepbx")
check("curl 읽기전용 GET 만 생성", all(c.startswith("curl -s -k --max-time 10 ") for c in cmds))
check("쓰기/주입/실행 토큰 없음(생성 경계)",
      all(not any(t in c for t in (" -X ", " -d ", "--data", "| sh", "bash -i", "nc -e", ";")) for c in cmds))
check("limit 상한 준수", len(secret_read_commands([f"https://{TARGET}"], "freepbx", limit=5)) == 5)
check("베이스 없으면 빈 목록", secret_read_commands([], "freepbx") == [])
# 여러 베이스면 번갈아 배치(한 베이스 쏠림 방지) — 상위 2개가 서로 다른 베이스
multi = secret_read_commands([f"https://{TARGET}", f"http://{TARGET}"], "freepbx", limit=4)
check("여러 베이스 공평 분배", "https://" in multi[0] and "http://" in multi[1])
# vhost 기반 앱: Host 헤더로 실제 앱을 때린다(IP 기본 vhost 404 회피)
vh = secret_read_commands([f"https://{TARGET}"], "freepbx", vhosts=["connected.htb"])
check("vhost 지정 시 Host 헤더 부착", all('-H "Host: connected.htb"' in c for c in vh))
check("vhost 없으면 Host 헤더 없음", all("Host:" not in c for c in cmds))
# 인젝션 방지: 안전하지 않은 호스트명은 무시(Host 헤더 안 붙음)
bad = secret_read_commands([f"https://{TARGET}"], "freepbx", vhosts=["evil.htb; rm -rf /"])
check("안전하지 않은 vhost 무시", all("Host:" not in c for c in bad))

print("\n=== _web_secret_stage (게이트 경유 + 자격 수확 폐루프) ===")
def guard():
    g = ScopeGuard.from_cidr_strings(); g.bind_target(TARGET); return g

def mk_orc(runner):
    # 웹 비밀 열거는 자동 루트 시도(--exploit-exec/--auto-poc) 옵트인 전용 → 켜서 생성
    o = Orchestrator(guard(), runner, KnowledgeBase.load(), auto_approve_in_scope,
                     flag_kind="boot2root", is_tool_available=lambda b: True,
                     exploit_exec=True, auto_poc=True)
    o._start = o._clock(); o._deadline = None
    o.world = WorldModel(target=TARGET)
    o.world.set_web_app("freepbx", "16.0.40.7")
    return o

def mk_host():
    h = NmapHost(address=TARGET, state="up")
    h.ports = [Port(443, "tcp", "open", service="https")]
    return h

# 노출된 amportal.conf 본문을 돌려주는 러너 → AMPDBUSER/AMPDBPASS 가 world.creds 로 수확
AMPORTAL = "AMPDBUSER=freepbxuser\nAMPDBPASS=S3cr3tDBpw\nAMPDBHOST=localhost\n"
def runner_fn(c):
    if "amportal.conf" in c:
        return RunOutput(c, stdout=AMPORTAL)
    return RunOutput(c, stdout="404 Not Found")

orcA = mk_orc(FakeRunner(runner_fn))
repA = OrchestrationReport(target=TARGET, flag_kind="boot2root")
hostA = mk_host()
orcA._web_secret_stage(repA, hostA)
check("노출 설정 열거가 findings 에 기록", any("amportal.conf" in f.command for f in repA.enum_findings))
check("amportal 자격이 world 로 수확(발판 전 HTTP)",
      any("freepbxuser:S3cr3tDBpw" in c for c in orcA.world.creds))
check("읽기전용 GET 만 실행(POST/주입 없음)",
      all(not any(t in f.command for t in (" -X ", " -d ", ";")) for f in repA.enum_findings))

# 수확된 자격 → ①(b) 가 인증 PoC(52031)를 자동 발사 큐에 올리는 폐루프 확인
orcA.exploit_exec = True
orcA.auto_poc = True
repA.enum_findings.append(type(repA.enum_findings[0])(
    command="searchsploit freepbx", ran=True,
    output=("searchsploit: 1건 — FreePBX 16 - Remote Code Execution (RCE) (Au "
            "| php/webapps/52031.php")))
orcA._refresh_exploit_shortlist(repA, hostA)
check("발판 전 수확 자격 → 인증 PoC 자동발사 큐잉(폐루프)",
      any("52031" in c for c in orcA.poc_commands))

# 호스트당 1회(멱등) — 같은 베이스 재호출 시 추가 열거 없음
n = len(repA.enum_findings)
orcA._web_secret_stage(repA, hostA)
check("호스트당 1회(멱등)", len(repA.enum_findings) == n)

# 웹 포트 없으면 아무것도 안 함
orcB = mk_orc(FakeRunner(runner_fn))
repB = OrchestrationReport(target=TARGET, flag_kind="boot2root")
noweb = NmapHost(address=TARGET, state="up"); noweb.ports = [Port(22, "tcp", "open", service="ssh")]
orcB._web_secret_stage(repB, noweb)
check("웹 포트 없으면 열거 생략", not repB.enum_findings)

# 옵트인 가드: --exploit-exec/--auto-poc 없으면(기본·순수 정찰) 공격 지향 열거 생략
orcC = Orchestrator(guard(), FakeRunner(runner_fn), KnowledgeBase.load(), auto_approve_in_scope,
                    flag_kind="boot2root", is_tool_available=lambda b: True)
orcC._start = orcC._clock(); orcC._deadline = None
orcC.world = WorldModel(target=TARGET); orcC.world.set_web_app("freepbx", "16.0.40.7")
repC = OrchestrationReport(target=TARGET, flag_kind="boot2root")
orcC._web_secret_stage(repC, mk_host())
check("옵트인 없으면 열거 생략(기본 모드 명령폭 불변)", not repC.enum_findings)

print("\n=== _web_fingerprint_stage (vhost 결정적 핑거프린트) ===")
# vhost 로 -L 따라가 FreePBX admin 200 본문을 받으면 web_product 가 결정적으로 잡혀야 한다.
FP_PAGE = ('HTTP/1.1 200 OK\r\n\r\n<html><head><title>FreePBX Administration</title></head>'
           '<body>appver=FreePBX 16.0.40.7</body></html>')
def fp_runner(c):
    if "config.php" in c or 'Host: connected.htb' in c:
        return RunOutput(c, stdout=FP_PAGE)
    return RunOutput(c, stdout="302 Found")

orcF = Orchestrator(guard(), FakeRunner(fp_runner), KnowledgeBase.load(), auto_approve_in_scope,
                    flag_kind="boot2root", is_tool_available=lambda b: True,
                    exploit_exec=True, auto_poc=True)
orcF._start = orcF._clock(); orcF._deadline = None
orcF.world = WorldModel(target=TARGET)          # 제품 미상으로 시작
orcF.hosts_map = {"connected.htb": TARGET}      # vhost 등록됨(리다이렉트 관측 가정)
repF = OrchestrationReport(target=TARGET, flag_kind="boot2root")
orcF._web_fingerprint_stage(repF, mk_host())
check("vhost 로 Host 헤더 + -L 핑거프린트 요청", any('-L' in f.command and 'Host: connected.htb' in f.command for f in repF.enum_findings))
check("admin 페이지 본문에서 제품 결정적 식별", (orcF.world.web_product or "").lower() == "freepbx")
check("버전도 식별(16.0.40.7)", orcF.world.web_version == "16.0.40.7")
# 이미 식별됐으면 재핑거프린트 안 함
n = len(repF.enum_findings)
orcF._web_fingerprint_stage(repF, mk_host())
check("제품 식별 후엔 핑거프린트 생략", len(repF.enum_findings) == n)
# vhost 미등록 → 헤더 프로브(-sI/-I)로 리다이렉트 Location 을 1회 탐색. Location 이 없으면
# vhost 미등록 → 전체 핑거프린트(Host 헤더)로 진행하지 않는다(탐색 프로브 1건만).
orcG = Orchestrator(guard(), FakeRunner(fp_runner), KnowledgeBase.load(), auto_approve_in_scope,
                    flag_kind="boot2root", is_tool_available=lambda b: True,
                    exploit_exec=True, auto_poc=True)
orcG._start = orcG._clock(); orcG._deadline = None
orcG.world = WorldModel(target=TARGET)
repG = OrchestrationReport(target=TARGET, flag_kind="boot2root")
orcG._web_fingerprint_stage(repG, mk_host())
disc = [f for f in repG.enum_findings if "-sI" in f.command or "-I " in f.command]
check("vhost 미등록 → 헤더 프로브로 리다이렉트 1회 탐색", len(disc) == 1)
check("Location 없으면 Host 헤더 핑거프린트 미진행",
      not [f for f in repG.enum_findings if "Host:" in f.command])

# vhost 미등록이어도, 루트가 '다른 호스트'로 302 하면(Location 헤더) 헤더 프로브가 그걸 잡아
# vhost 를 자동 등록하고 그 자리에서 핑거프린트까지 진행한다(웹 리다이렉트 박스 해금).
def redir_runner(c):
    if "-sI" in c or "-I " in c:   # 헤더 프로브 → 다른 vhost 로 302
        return RunOutput(c, stdout="HTTP/1.1 302 Found\r\nLocation: http://enigma.htb/\r\n\r\n")
    if "config.php" in c or "Host: enigma.htb" in c:
        return RunOutput(c, stdout=FP_PAGE)
    return RunOutput(c, stdout="302 Found")
orcH = Orchestrator(guard(), FakeRunner(redir_runner), KnowledgeBase.load(), auto_approve_in_scope,
                    flag_kind="boot2root", is_tool_available=lambda b: True,
                    exploit_exec=True, auto_poc=True)
orcH._start = orcH._clock(); orcH._deadline = None
orcH.world = WorldModel(target=TARGET)          # vhost 미등록으로 시작
repH = OrchestrationReport(target=TARGET, flag_kind="boot2root")
orcH._web_fingerprint_stage(repH, mk_host())
check("헤더 프로브가 302 Location 에서 vhost 자동 등록", (orcH.hosts_map or {}).get("enigma.htb") == TARGET)
check("등록 후 그 vhost 로 핑거프린트 진행", any("Host: enigma.htb" in f.command for f in repH.enum_findings))
check("리다이렉트 vhost 앱에서 제품 결정적 식별", (orcH.world.web_product or "").lower() == "freepbx")

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
