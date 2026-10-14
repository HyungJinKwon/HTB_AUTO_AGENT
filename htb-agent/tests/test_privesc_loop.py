# 실행: htb-agent 디렉토리에서  python3 tests/test_privesc_loop.py
#
# 발판 세션 위 권한상승 폐루프(Commit 5): 열거→HIGH 벡터 랭킹→one-shot 상승→uid=0→root.txt.
# SSH 전용이던 폐루프를 '획득한 발판 세션'(웹/리버스셸)으로 일반화한 것. 실제 네트워크/소켓 없이
# 스크립트된 FakeSession 으로 session.run 을 흉내내 배선만 검증한다.
import sys

sys.path.insert(0, "src")
from htb_agent.knowledge import KnowledgeBase            # noqa: E402
from htb_agent.orchestrator import OrchestrationReport, Orchestrator  # noqa: E402
from htb_agent.scope_guard import ScopeGuard             # noqa: E402
from htb_agent.tools.recon import auto_approve_in_scope  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402
from htb_agent.world import WorldModel                   # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


T = "10.129.245.100"
ROOTFLAG = "a1b2c3d4e5f6071829304152637485a0"   # 32-hex 루트 플래그


class FakeSession:
    kind = "fake-foothold"

    def __init__(self, responder):
        self._r = responder
        self.cmds = []
        self._alive = True

    @property
    def alive(self):
        return self._alive

    def run(self, cmd):
        self.cmds.append(cmd)
        return self._r(cmd)

    def close(self):
        self._alive = False


def make_orc():
    g = ScopeGuard.from_cidr_strings()
    g.bind_target(T)
    orc = Orchestrator(g, FakeRunner(lambda c: RunOutput(c, "")), KnowledgeBase.load(),
                       auto_approve_in_scope, is_tool_available=lambda b: True, quiet=True,
                       exploit_exec=True, auto_poc=True, flag_kind="boot2root")
    orc.world = WorldModel(target=T)
    orc._deadline = None
    orc._start = 0
    return orc


def sudo_all_responder(cmd):
    """sudo -l 에 (ALL : ALL) ALL → HIGH sudo-all 벡터. one-shot 'sudo id' → uid=0. root.txt 플래그."""
    if "root.txt" in cmd:
        return ROOTFLAG + "\n"
    if "user.txt" in cmd or "flag" in cmd:
        return ""
    if cmd.strip() == "sudo id":
        return "uid=0(root) gid=0(root) groups=0(root)"
    if "sudo -n -l" in cmd or cmd.startswith("id;"):      # PRIVESC_ENUM[0]
        return "uid=1000(user) gid=1000(user)\n(ALL : ALL) ALL\n"
    return ""   # find -perm/getcap 등


print("=== sudo-ALL 발판 → one-shot 상승 → root 전이 + root.txt 기록 ===")
orc = make_orc()
sess = FakeSession(sudo_all_responder)
rep = OrchestrationReport(target=T, flag_kind="boot2root")
orc._privesc_loop(sess, rep)
check("world 가 root 로 전이", orc.world.has_access("root"))
check("root.txt 플래그 기록됨", rep.root_flag == ROOTFLAG)
check("열거 명령(sudo -l)이 세션에서 실행됨",
      any("sudo -n -l" in c or c.startswith("id;") for c in sess.cmds))
check("one-shot 상승(sudo id)이 세션에서 실행됨", "sudo id" in sess.cmds)
check("privesc 시도가 findings 로 기록됨",
      any(f.phase == "privesc" for f in rep.enum_findings))


print("\n=== HIGH 벡터 없음(평범한 유저) → 미상승(발판 유지) ===")
orc2 = make_orc()
sess2 = FakeSession(lambda cmd: "uid=1000(user) gid=1000(user)" if "sudo" in cmd or cmd.startswith("id;")
                    else "")
rep2 = OrchestrationReport(target=T, flag_kind="boot2root")
orc2._privesc_loop(sess2, rep2)
check("상승 벡터 없으면 root 전이 안 함", not orc2.world.has_access("root"))
check("root 플래그 없음", not rep2.root_flag)


print("\n=== 이미 root → 즉시 종료(중복 작업 없음) ===")
orc3 = make_orc()
orc3.world.raise_access("root")
sess3 = FakeSession(lambda cmd: "uid=0(root)")
orc3._privesc_loop(sess3, OrchestrationReport(target=T, flag_kind="boot2root"))
check("이미 root면 열거조차 안 함", not sess3.cmds)


print("\n=== 세션 I/O 오류(OSError) → 크래시 아님(degrade) ===")
orc4 = make_orc()

def _raise(cmd):
    raise OSError("connection reset")

sess4 = FakeSession(_raise)
rep4 = OrchestrationReport(target=T, flag_kind="boot2root")
try:
    orc4._privesc_loop(sess4, rep4)
    ok = True
except Exception:
    ok = False
check("OSError 삼키고 안전 종료", ok and not orc4.world.has_access("root"))

print("\n=== 자격 재사용(sudo -S 비번) → root 전이 + root.txt ===")
PW = "S3cretPW"
def cred_reuse_responder(cmd):
    # sudo -S 비번 입력으로 id → uid=0, root.txt 직독 → 플래그. (일반 sudo -l 엔 gtfo 없음)
    if "sudo -S" in cmd and "root.txt" in cmd:
        return ROOTFLAG + "\n"
    if "sudo -S" in cmd and "id" in cmd:
        return "uid=0(root) gid=0(root) groups=0(root)"
    if "root.txt" in cmd or "user.txt" in cmd or "flag" in cmd:
        return ""
    if "sudo -n -l" in cmd or cmd.startswith("id;"):
        return "uid=1000(user) gid=1000(user)\n(no sudo gtfo here)\n"
    return ""

orc_cr = make_orc()
orc_cr.world.add_cred(f"bob:{PW}", source="test")
sess_cr = FakeSession(cred_reuse_responder)
rep_cr = OrchestrationReport(target=T, flag_kind="boot2root")
orc_cr._privesc_loop(sess_cr, rep_cr)
check("sudo -S 자격재사용으로 root 전이", orc_cr.world.has_access("root"))
check("root.txt 플래그 기록(sudo 직독 포함)", rep_cr.root_flag == ROOTFLAG)
check("sudo -S 명령이 세션에서 실행됨", any("sudo -S" in c for c in sess_cr.cmds))

print("\n=== NT 해시만 있는 자격 → sudo -S 시도 안 함(평문 아님) ===")
orc_nt = make_orc()
orc_nt.world.add_cred("admin:" + "a" * 32, source="test")   # 32-hex NT 해시
sess_nt = FakeSession(lambda c: "uid=0(root)" if "sudo -S" in c else "")
rep_nt = OrchestrationReport(target=T, flag_kind="boot2root")
orc_nt._privesc_loop(sess_nt, rep_nt)
check("NT 해시는 sudo -S 비번으로 안 씀", not any("sudo -S" in c for c in sess_nt.cmds))

print("\n=== docker 그룹 자동 발사 → root + root.txt(벡터 권한 직독) ===")
def docker_responder(cmd):
    if "chroot /mnt" in cmd:                       # docker one-shot(컨테이너 root 컨텍스트)
        return ROOTFLAG + "\n" if "root.txt" in cmd else "uid=0(root) gid=0(root)"
    if "root.txt" in cmd or "user.txt" in cmd or "flag" in cmd:
        return ""   # 현재 유저 cat 은 권한거부
    if "sudo -n -l" in cmd or cmd.startswith("id;"):
        return "uid=1000(user) gid=1000(user) groups=1000(user),998(docker)"
    return ""

orc_dk = make_orc()   # 자격 없음 → 자격재사용 건너뜀, docker 그룹 벡터로 상승
sess_dk = FakeSession(docker_responder)
rep_dk = OrchestrationReport(target=T, flag_kind="boot2root")
orc_dk._privesc_loop(sess_dk, rep_dk)
check("docker 그룹 벡터로 root 전이", orc_dk.world.has_access("root"))
check("docker 권한 one-shot 으로 root.txt 캡처", rep_dk.root_flag == ROOTFLAG)
check("docker chroot one-shot 이 세션에서 실행됨",
      any("chroot /mnt" in c for c in sess_dk.cmds))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
