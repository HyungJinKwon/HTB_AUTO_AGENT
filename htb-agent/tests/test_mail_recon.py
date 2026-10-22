# 실행: htb-agent 디렉토리에서  python3 tests/test_mail_recon.py
#
# 메일(IMAP/POP3) 발판 — 수확한 평문 자격으로 로그인해 본문에서 '다음 자격'을 수확하는 경로를
# 실 네트워크 없이(주입된 fetch) 검증. 실측(Enigma): 온보딩 PDF 자격이 webmail 계정이라 SSH
# 분사만으로는 발판이 안 섰던 갭을 메우는 경로.
import sys

sys.path.insert(0, "src")

from htb_agent import mail_recon as mr                       # noqa: E402
from htb_agent.knowledge import KnowledgeBase               # noqa: E402
from htb_agent.orchestrator import OrchestrationReport, Orchestrator  # noqa: E402
from htb_agent.scope_guard import ScopeGuard                # noqa: E402
from htb_agent.tools.recon import auto_approve_contained    # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput    # noqa: E402
from htb_agent.world import WorldModel                      # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


T = "10.129.239.191"
# webmail 본문: '다음 계정' 자격이 평문으로 들어 있다(각 1쌍).
RFC822 = (b"Subject: Welcome to Enigma Corp\r\n"
          b"From: it@enigma.htb\r\n"
          b"Content-Type: text/plain\r\n\r\n"
          b"Hi Kevin,\r\nYour internal service account is ready.\r\n"
          b"username: svc_deploy\r\npassword: D3ploy!2024\r\n")


print("=== 순수 파싱/엔드포인트 ===")
txt = mr.msg_to_text(RFC822)
check("msg_to_text — 제목+본문 추출", "Welcome to Enigma Corp" in txt and "svc_deploy" in txt)
check("has_mail_port — 993 열림이면 True", mr.has_mail_port([22, 80, 993]))
check("has_mail_port — 메일포트 없으면 False", not mr.has_mail_port([22, 80]))
eps = mr._endpoints([110, 143, 993, 995])
check("_endpoints — SSL(993/995) 우선", eps[0][1] in (993, 995) and len(eps) == 4)
check("_endpoints — 닫힌 포트 제외", all(p != 110 for _pr, p, _s, _k in mr._endpoints([143, 993])))


print("\n=== try_mail_logins — 주입 fetch 로 로그인→본문서 다음 자격 수확 ===")
def fake_imap(host, port, user, pw, ssl=True, *a, **k):
    # kevin:Enigma2024! (993/143) 로그인 성공 → welcome 메일 1통
    if user.startswith("kevin") and pw == "Enigma2024!":
        return True, [mr.msg_to_text(RFC822)]
    return False, []
def fake_pop3(host, port, user, pw, ssl=True, *a, **k):
    return False, []

finds = mr.try_mail_logins(T, [("kevin", "Enigma2024!")], open_ports=[993, 143],
                           domain="enigma.htb", fetch_imap=fake_imap, fetch_pop3=fake_pop3)
check("로그인 1건 성립", len(finds) == 1)
check("본문서 다음 자격 수확(svc_deploy:D3ploy!2024)",
      finds and ("svc_deploy", "D3ploy!2024") in finds[0].creds)
check("엔드포인트 라벨 기록", finds and "imaps://" in finds[0].endpoint and "kevin" in finds[0].endpoint)
check("제목 notable 기록", finds and any("Welcome" in n for n in finds[0].notable))

# 틀린 비번이면 로그인 0
none = mr.try_mail_logins(T, [("kevin", "wrong")], open_ports=[993],
                          fetch_imap=fake_imap, fetch_pop3=fake_pop3)
check("틀린 자격 → 로그인 0", none == [])


print("\n=== 오케스트레이터 _mail_harvest_stage — 자격 되먹임 ===")
def base_orc(**kw):
    g = ScopeGuard.from_cidr_strings(); g.bind_target(T)
    orc = Orchestrator(g, FakeRunner(lambda c: RunOutput(c, stdout="")),
                       KnowledgeBase.load(), auto_approve_contained,
                       is_tool_available=lambda b: True, quiet=True,
                       exploit_exec=True, auto_poc=True, **kw)
    orc.world = WorldModel(target=T)
    return orc

class _Host:
    def __init__(self, ports): self.open_ports = ports

orc = base_orc()
orc.world.add_cred("kevin:Enigma2024!", source="NFS PDF")
orc._mail_imap_fn = fake_imap
orc._mail_pop3_fn = fake_pop3
orc._vhost_seen = {"mail001.enigma.htb"}     # 도메인 추정원(→ enigma.htb)
rep = OrchestrationReport(target=T)
orc._mail_harvest_stage(rep, _Host([22, 110, 143, 993, 995]))
check("메일 본문 자격이 world.creds 로 되먹임(svc_deploy:D3ploy!2024)",
      any("svc_deploy:D3ploy!2024" in c for c in orc.world.creds))
check("_mail_domain 추정 — mail001.enigma.htb → enigma.htb", orc._mail_domain() == "enigma.htb")

print("\n=== 게이트 ===")
# (1) 옵트인 꺼짐 → 아무 것도 안 함
g2 = ScopeGuard.from_cidr_strings(); g2.bind_target(T)
orc2 = Orchestrator(g2, FakeRunner(lambda c: RunOutput(c, stdout="")), KnowledgeBase.load(),
                    auto_approve_contained, is_tool_available=lambda b: True, quiet=True,
                    exploit_exec=False, auto_poc=False)
orc2.world = WorldModel(target=T); orc2.world.add_cred("kevin:Enigma2024!")
hit = {"n": 0}
orc2._mail_imap_fn = lambda *a, **k: (hit.__setitem__("n", hit["n"] + 1), (False, []))[1]
orc2._mail_harvest_stage(OrchestrationReport(target=T), _Host([993]))
check("옵트인 꺼짐 → 메일 접근 0", hit["n"] == 0)

# (2) 메일 포트 없으면 생략
orc3 = base_orc(); orc3.world.add_cred("kevin:Enigma2024!")
hit3 = {"n": 0}
orc3._mail_imap_fn = lambda *a, **k: (hit3.__setitem__("n", hit3["n"] + 1), (False, []))[1]
orc3._mail_harvest_stage(OrchestrationReport(target=T), _Host([22, 80]))
check("메일 포트 없음 → 접근 0", hit3["n"] == 0)

# (3) 자격 없으면 생략
orc4 = base_orc()
hit4 = {"n": 0}
orc4._mail_imap_fn = lambda *a, **k: (hit4.__setitem__("n", hit4["n"] + 1), (False, []))[1]
orc4._mail_harvest_stage(OrchestrationReport(target=T), _Host([993]))
check("평문 자격 없음 → 접근 0", hit4["n"] == 0)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
