# 실행: htb-agent 디렉토리에서  python3 tests/test_orchestrator.py
import sys
sys.path.insert(0, "src")
from htb_agent.scope_guard import ScopeGuard
from htb_agent.tools.runner import FakeRunner, RunOutput
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.knowledge import KnowledgeBase
from htb_agent.orchestrator import Orchestrator
from htb_agent.target_profiler import OSClass

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

LINUX_WEB = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.5"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2 Ubuntu"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
</ports></host></nmaprun>"""
AD = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.129.1.10"/><ports>
<port protocol="tcp" portid="88"><state state="open"/><service name="kerberos-sec"/></port>
<port protocol="tcp" portid="389"><state state="open"/><service name="ldap"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
<port protocol="tcp" portid="5985"><state state="open"/><service name="winrm"/></port>
</ports><hostscript><script id="smb-os-discovery" output="OS: Windows Server 2019"/></hostscript>
</host></nmaprun>"""
DOWN = """<?xml version="1.0"?><nmaprun><host><status state="down"/><address addr="10.129.1.9"/></host></nmaprun>"""

def guard(ip="10.129.1.5"):
    g = ScopeGuard.from_cidr_strings(); g.bind_target(ip); return g

# nmap 은 포트결과, 그 외(enum 도구)는 간단한 출력
def responder(xml):
    def r(cmd):
        if cmd.startswith("nmap"):
            return RunOutput(cmd, stdout=xml)
        if cmd.startswith("curl"):
            return RunOutput(cmd, stdout="HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n<title>Home</title>")
        return RunOutput(cmd, stdout="enum-output-ok")
    return r

kb = KnowledgeBase.load()
ALL_TOOLS = lambda b: True   # 도구 전부 설치됐다고 가정(테스트)

print("=== Linux 웹 호스트 파이프라인 ===")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS)
rep = orc.run()
check("상태 done", rep.status == "done")
check("프로파일 Linux", rep.profile.os_class == OSClass.LINUX)
check("enum 자동실행 발생", any(f.ran for f in rep.enum_findings))
check("curl HTTP 파싱요약", any("HTTP 200" in f.output for f in rep.enum_findings))

print("\n=== Windows-AD 파이프라인 + 수동제안 ===")
r = FakeRunner(responder(AD))
orc = Orchestrator(guard("10.129.1.10"), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS)
rep = orc.run()
check("프로파일 Windows-AD", rep.profile.os_class == OSClass.WINDOWS_AD)
check("BloodHound 등 수동제안 분류", any("bloodhound-python" in s for s in rep.manual_suggestions))
check("크리덴셜 명령 자동실행 안 됨",
      all("evil-winrm" not in f.command for f in rep.enum_findings))

print("\n=== enum 상한(무한확장 방지) ===")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, max_enum=1, is_tool_available=ALL_TOOLS)
rep = orc.run()
ran = [f for f in rep.enum_findings if f.ran]
check("enum 자동실행 max_enum 준수", len(ran) <= 1)

print("\n=== 도구 미설치 → 건너뜀(무한재시도 없음) ===")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, is_tool_available=lambda b: False)
rep = orc.run()
check("미설치 도구 건너뜀", any("미설치" in f.note for f in rep.enum_findings))
check("미설치 시 실행 안 함", all(not f.ran for f in rep.enum_findings))

print("\n=== 리버스쉘 자동 준비(공격자 IP 확보 시 · 생성만) ===")
g = guard()
g.add_attacker_ip("10.10.14.5")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(g, r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS,
                   revshell_port=9001)
rep = orc.run()
check("리버스쉘 자동 생성됨", len(rep.revshells) >= 10)
check("LHOST=공격자IP", rep.revshell_lhost == "10.10.14.5")
check("LPORT=지정포트", rep.revshell_lport == 9001)
check("bash 페이로드 치환", any("/dev/tcp/10.10.14.5/9001" in s.payload for s in rep.revshells))
check("자동 생성은 실행 아님(ran 플래그 무관)",
      all(hasattr(s, "payload") for s in rep.revshells))
check("summary 에 리버스쉘 노출", "리버스쉘" in rep.summary())

print("\n=== 공격자 IP 없으면 리버스쉘 생략 ===")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS)
rep = orc.run()
check("공격자IP 없음 → 리버스쉘 없음", rep.revshells == [])

print("\n=== AWS/S3 열거 자동 준비(호스트명 확보 시 · 생성만) ===")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS,
                   hosts_map={"10.129.1.5": "acme.htb"})
rep = orc.run()
check("버킷 후보 자동 생성", len(rep.cloud_candidates) >= 1)
check("acme 기저 후보 포함", "acme" in rep.cloud_candidates)
check("비인증 S3 점검 명령 준비", any("--no-sign-request" in c.command for c in rep.cloud_checks))
check("자격증명 확인 명령 준비", any("get-caller-identity" in c.command for c in rep.cloud_checks))
check("summary 에 AWS/S3 노출", "AWS/S3" in rep.summary())

print("\n=== 호스트명 없으면(IP뿐) AWS/S3 생략 ===")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS)
rep = orc.run()
check("IP뿐 → 버킷 후보 없음", rep.cloud_candidates == [])
check("IP뿐 → 점검 명령 없음", rep.cloud_checks == [])

print("\n=== 권한상승 플레이북 자동 준비(OS 식별 시 · 생성만) ===")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS)
rep = orc.run()
check("Linux 플레이북 생성됨", len(rep.privesc_steps) >= 8)
check("SUID 열거 단계 포함", any("perm -4000" in s.command for s in rep.privesc_steps))
check("sudo -l 열거 포함", any("sudo -l" in s.command for s in rep.privesc_steps))
check("summary 에 권한상승 노출", "권한 상승 플레이북" in rep.summary())

print("\n=== Windows-AD 권한상승 플레이북 ===")
r = FakeRunner(responder(AD))
orc = Orchestrator(guard("10.129.1.10"), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS)
rep = orc.run()
check("Windows 플레이북 생성됨", len(rep.privesc_steps) >= 7)
check("whoami /priv 포함", any("whoami /priv" in s.command for s in rep.privesc_steps))
check("AD 단계 포함", any(s.category == "AD" for s in rep.privesc_steps))

print("\n=== 해시 크래킹 자동 준비(출력에서 해시 수집 · 생성만) ===")
# 어떤 enum 명령 출력에 Kerberoast TGS 해시가 섞여 나오는 상황을 모사
def hash_responder(cmd):
    if cmd.startswith("nmap"):
        return RunOutput(cmd, stdout=LINUX_WEB)
    if cmd.startswith("curl"):
        return RunOutput(cmd, stdout="HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n"
                         "leak: $krb5tgs$23$*svc$DOM*$deadbeefcafe0011")
    return RunOutput(cmd, stdout="ok")
r = FakeRunner(hash_responder)
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS)
rep = orc.run()
check("해시 크래킹 작업 자동 생성", len(rep.crack_jobs) >= 1)
check("Kerberoast 식별", any(any("Kerberoast" in g.name for g in j.guesses) for j in rep.crack_jobs))
check("hashcat 13100 명령", any(any("13100" in c.command for c in j.commands) for j in rep.crack_jobs))
check("summary 에 해시 크래킹 노출", "해시 크래킹" in rep.summary())

print("\n=== 해시 없으면 크래킹 생략 ===")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS)
rep = orc.run()
check("해시 없음 → 크래킹 작업 없음", rep.crack_jobs == [])

print("\n=== 월드 모델(구조화 상태) 채워짐 ===")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS)
rep = orc.run()
check("report.world 존재", rep.world is not None)
check("서비스 상태 채워짐", len(rep.world.services) >= 2)
check("OS 상태 반영", rep.world.os_class == "linux")
check("summary 에 STATE 노출", "월드 모델" in rep.summary())

print("\n=== 크리덴셜 → 권한레벨 credentialed ===")
from htb_agent.creds import CredentialVault, Credential
vault = CredentialVault([Credential(username="admin", password="pass")])
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS, vault=vault)
rep = orc.run()
check("크리덴셜 상태 반영", len(rep.world.creds) >= 1)
check("권한레벨 credentialed 이상", rep.world.has_access("credentialed"))

print("\n=== A2 단계 게이팅: 전제 미충족 시 대기 ===")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS)
rep = orc.run()
check("enum 은 전제 불필요", not rep.phase_status.get("enum", "").startswith("대기"))
check("크리덴셜 없으면 privesc 대기", rep.phase_status.get("privesc", "").startswith("대기"))
check("이동수단 없으면 lateral 대기", rep.phase_status.get("lateral", "").startswith("대기"))
# _prereq_met 직접 검증
met_e, _ = orc._prereq_met("enum"); check("enum 전제 True", met_e)
met_p, reason_p = orc._prereq_met("privesc")
check("privesc 전제 False+사유", (not met_p) and "크리덴셜" in reason_p)

print("\n=== A2: 크리덴셜 있으면 privesc 전제 충족 ===")
r = FakeRunner(responder(LINUX_WEB))
orc = Orchestrator(guard(), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS,
                   vault=CredentialVault([Credential(username="u", password="p")]))
rep = orc.run()
check("크리덴셜 → privesc 전제 충족(대기 아님)", not rep.phase_status.get("privesc", "").startswith("대기"))
check("_prereq_met privesc True", orc._prereq_met("privesc")[0])

print("\n=== 병렬 열거: 순차와 결과 동일(결정성) ===")
# 동일 시나리오를 순차(max_parallel=1)와 병렬(max_parallel=4)로 실행 → 동일 결과
rseq = FakeRunner(responder(LINUX_WEB))
rep_seq = Orchestrator(guard(), rseq, kb, auto_approve_in_scope, max_variants=3,
                       max_enum=20, is_tool_available=ALL_TOOLS).run()
rpar = FakeRunner(responder(LINUX_WEB))
rep_par = Orchestrator(guard(), rpar, kb, auto_approve_in_scope, max_variants=3,
                       max_enum=20, max_parallel=4, is_tool_available=ALL_TOOLS).run()
seq_cmds = [f.command for f in rep_seq.enum_findings]
par_cmds = [f.command for f in rep_par.enum_findings]
check("병렬=순차 명령 순서 동일", seq_cmds == par_cmds)
check("병렬=순차 실행결과 동일", [f.ran for f in rep_seq.enum_findings] == [f.ran for f in rep_par.enum_findings])
check("병렬에서도 출력 파싱됨", any("HTTP 200" in f.output for f in rep_par.enum_findings))
check("병렬 상태 done", rep_par.status == "done")

print("\n=== 병렬 열거: 플래그·해시·크리덴셜 스캔 유지 ===")
def resp_rich(cmd):
    if cmd.startswith("nmap"):
        return RunOutput(cmd, stdout=LINUX_WEB)
    if cmd.startswith("curl"):
        return RunOutput(cmd, stdout="HTTP/1.1 200 OK\r\n\r\nHTB{par_flag} leak mysql://u:Pw1@db")
    return RunOutput(cmd, stdout="ok")
orcp = Orchestrator(guard(), FakeRunner(resp_rich), kb, auto_approve_in_scope,
                    max_variants=2, max_parallel=4, is_tool_available=ALL_TOOLS)
repp = orcp.run()
check("병렬 플래그 스캔", any(f.value == "HTB{par_flag}" for f in repp.flags))
check("병렬 크리덴셜 수확", any("u:Pw1" in c for c in repp.world.creds))

print("\n=== 안정화: 러너 예외가 라운드를 깨지 않음(순차/병렬) ===")
class RaisingRunner:
    """nmap 은 정상 XML, 그 외(enum)는 예외를 던지는 러너 — 견고성 검증용."""
    def __init__(self, xml):
        self.xml = xml; self.calls = []
    def run(self, command, timeout=120):
        self.calls.append(command)
        if command.startswith("nmap"):
            return RunOutput(command, stdout=self.xml)
        raise RuntimeError("boom (simulated runner failure)")
# 순차
rr = RaisingRunner(LINUX_WEB)
rep = Orchestrator(guard(), rr, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS).run()
check("순차: 러너 예외에도 done", rep.status == "done")
check("순차: 예외 명령은 미실행 표기", any(not f.ran for f in rep.enum_findings))
# 병렬
rr2 = RaisingRunner(LINUX_WEB)
rep2 = Orchestrator(guard(), rr2, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS,
                    max_parallel=4).run()
check("병렬: 러너 예외에도 done", rep2.status == "done")
check("병렬: 배치가 통째로 깨지지 않음(여러 시도 기록)", len(rep2.enum_findings) >= 1)
# 순차(239행)와 동일 강도: _safe_run 이 각 워커 예외를 흡수 → 예외 명령은
# launched=False 로 '미실행' 표기되어야 한다(배치가 통째로 죽지 않음을 입증).
check("병렬: 예외 명령은 미실행 표기", any(not f.ran for f in rep2.enum_findings))
# 러너가 실제로 예외를 던진 enum 명령이 호출되었는지도 확인(시뮬레이션 유효성).
check("병렬: 예외 유발 enum 명령이 실제 호출됨",
      any(not c.startswith("nmap") for c in rr2.calls))

print("\n=== F3 persist-always: 단계 내부 예외에도 진행분 저장(재개 보존) ===")
# 스윕/최종 취약점 단계의 미처리 예외가 _persist 를 건너뛰지 않아야 한다(재개 불변식).
import tempfile as _tmpf
from htb_agent.state import StateStore as _StateStore
with _tmpf.TemporaryDirectory() as _sd:
    _store = _StateStore(_sd)
    _o = Orchestrator(guard(), FakeRunner(lambda c: RunOutput(c, stdout=LINUX_WEB)
                                          if c.startswith("nmap") else RunOutput(c, stdout="ok")),
                      kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS,
                      state_store=_store)
    def _boom(*a, **k):
        raise RuntimeError("boom (simulated _run_vuln failure)")
    _o._run_vuln = _boom   # 단계 내부에서 예외 발생 모사
    _rep = _o.run()
    check("F3: _run_vuln 예외에도 run() 완료", _rep.status == "done")
    check("F3: 예외에도 상태가 저장됨(재개 가능)", _store.exists("10.129.1.5"))
    _loaded = _store.load("10.129.1.5")
    check("F3: 저장분에 RECON 진행 포함", _loaded is not None and _loaded.host is not None)

print("\n=== 자율 지식 획득(learn_gaps) — 관측 기술 자동 학습 ===")
import os as _os, tempfile as _tmp
from htb_agent import learn as _learn
with _tmp.TemporaryDirectory() as _d:
    _lr = _learn.ReferenceLearner(cache_dir=_os.path.join(_d, "learned"),
                                  fetch_fn=lambda u: "<p>authoritative reference body</p>",
                                  enabled=True)
    _kb2 = KnowledgeBase.load()
    rgl = Orchestrator(guard(), FakeRunner(responder(LINUX_WEB)), _kb2,
                       auto_approve_in_scope, is_tool_available=ALL_TOOLS,
                       learner=_lr, learn_gaps=True, max_gap_learn=6).run()
    check("learn_gaps: done 유지", rgl.status == "done")
    # OpenSSH/Apache → ssh/exploit-public-app 로 해석·학습 기록
    check("관측 기술 자동 학습 기록", len(rgl.acquired_knowledge) >= 1)
    check("학습이 KB 에 즉시 반영(노트 증가)", len(_kb2.notes) > len(KnowledgeBase.load().notes))
# learn_gaps 비활성(기본) → 학습 없음
rno = Orchestrator(guard(), FakeRunner(responder(LINUX_WEB)), kb,
                   auto_approve_in_scope, is_tool_available=ALL_TOOLS).run()
check("기본(비활성): 자율학습 없음", rno.acquired_knowledge == [])
# learner 없이 learn_gaps=True → 크래시 없이 미해석 공백만 기록 가능
rnl = Orchestrator(guard(), FakeRunner(responder(LINUX_WEB)), KnowledgeBase.load(),
                   auto_approve_in_scope, is_tool_available=ALL_TOOLS,
                   learner=None, learn_gaps=True).run()
check("learner 없이도 안전(done)", rnl.status == "done" and rnl.acquired_knowledge == [])

print("\n=== RECON 실패 → 에스컬레이션(enum 진입 안 함) ===")
r = FakeRunner(responder(DOWN))
orc = Orchestrator(guard("10.129.1.9"), r, kb, auto_approve_in_scope, is_tool_available=ALL_TOOLS)
rep = orc.run()
check("포트없음 → 에스컬레이션", rep.status == "escalate")
check("enum 미진입", len(rep.enum_findings) == 0)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
