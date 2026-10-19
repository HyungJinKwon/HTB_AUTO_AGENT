# 실행: htb-agent 디렉토리에서  python3 tests/test_nfs_recon.py
#
# NFS 자동 정찰(옵트인) — 열린 export 를 '읽기전용' 마운트해 자격·SSH 키·플래그를 수확하고,
# 수확한 SSH 키로 타겟에 로그인해 플래그를 읽는 end-to-end 검증(실 네트워크/sudo 없음:
# mounter 는 로컬 디렉터리를 가리키게 주입, ssh 는 FakeRunner 로 흉내). 실측(Enigma)에서
# showmount 로 발견만 하고 마운트를 안 하던 갭을 메우는 경로를 '진짜 파일시스템'으로 검증한다.
import os
import sys
import tempfile

sys.path.insert(0, "src")

from htb_agent import nfs_recon as nr                       # noqa: E402
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
FLAG = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
KEY = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
       "b3BlbnNzaC1rZXktdjEAAAAfake...\n-----END OPENSSH PRIVATE KEY-----\n")


def make_export_dir():
    """가짜 NFS export 트리 — SSH 키·온보딩 자격·유저 플래그·passwd 를 심는다."""
    root = tempfile.mkdtemp(prefix="fake_nfs_")
    os.makedirs(os.path.join(root, "home", "nico", ".ssh"))
    with open(os.path.join(root, "home", "nico", ".ssh", "id_rsa"), "w") as f:
        f.write(KEY)
    with open(os.path.join(root, "home", "nico", "user.txt"), "w") as f:
        f.write(FLAG + "\n")
    with open(os.path.join(root, "onboarding.txt"), "w") as f:
        f.write("Welcome!\nusername: nico\npassword: Sup3rS3cret!\n")
    with open(os.path.join(root, "passwd"), "w") as f:
        f.write("root:x:0:0:root:/root:/bin/bash\nnico:x:1000:1000:Nico:/home/nico:/bin/bash\n")
    return root


print("=== 순수 파싱/스캔 ===")
exports = nr.parse_exports("Export list for 10.129.239.191:\n/srv/nfs/onboarding *\n/srv/share 10.0.0.0/8")
check("showmount 파싱 → export 2개", exports == ["/srv/nfs/onboarding", "/srv/share"])
check("헤더/빈줄 무시, 상대경로 거부", nr.parse_exports("garbage\nnot-a-path foo") == [])

exp = make_export_dir()
fnd = nr.scan_tree(exp, export="/srv/nfs/onboarding")
check("SSH 개인키 발견(내용 마커)", len(fnd.ssh_keys) == 1 and fnd.ssh_keys[0].endswith("id_rsa"))
check("온보딩 자격 수확(nico:Sup3rS3cret!)", ("nico", "Sup3rS3cret!") in fnd.creds)
check("user 플래그 스캔", any(v == FLAG for _k, v in fnd.flags))
check("후보 사용자 수집(home/<user> + passwd uid≥1000)", "nico" in fnd.users)
check("주목 파일 목록 비어있지 않음", bool(fnd.notable))


print("\n=== 오케스트레이터 스테이지(옵트인) — 마운트→수확→SSH키 로그인 ===")


def make_orc(responder, mount_root):
    g = ScopeGuard.from_cidr_strings()
    g.bind_target(T)
    orc = Orchestrator(g, FakeRunner(responder), KnowledgeBase.load(), auto_approve_contained,
                       is_tool_available=lambda b: True, quiet=True,
                       exploit_exec=True, auto_poc=True)
    orc.world = WorldModel(target=T)
    # mounter 주입: 실제 mount 대신 export 디렉터리를 mountpoint 로 '복사 연결'(symlink 트리)
    def fake_mount(ip, export, mp, vers="3"):
        # mp 는 비어있는 tempdir — 가짜 export 내용을 그 안에 심볼릭/복사로 노출
        import shutil
        shutil.rmtree(mp, ignore_errors=True)
        shutil.copytree(mount_root, mp)
        return True, ""
    orc._nfs_mount_fn = fake_mount
    orc._nfs_umount_fn = lambda mp: None
    return orc


# FakeRunner: showmount → export 1개, ssh -i(키) 로그인 → id + user.txt 반환
def responder(cmd):
    if cmd.startswith("showmount"):
        return RunOutput(cmd, stdout="Export list for 10.129.239.191:\n/srv/nfs/onboarding *\n")
    if cmd.startswith("ssh -i") and "nico@" in cmd:
        return RunOutput(cmd, stdout=f"uid=1000(nico) gid=1000(nico)\n{FLAG}\n")
    if cmd.startswith("ssh -i"):
        return RunOutput(cmd, stdout="Permission denied (publickey).", returncode=255)
    return RunOutput(cmd, stdout="")


exp2 = make_export_dir()
orc = make_orc(responder, exp2)
rep = OrchestrationReport(target=T)
# host=None → 포트 게이트 건너뜀(showmount 직접 실행)
orc._nfs_harvest_stage(rep, None)

check("NFS 자격 수확 → world.creds (nico:Sup3rS3cret!)",
      any("nico:Sup3rS3cret!" in c for c in orc.world.creds))
check("SSH 키 보존 복사됨(0600, keystore)",
      getattr(orc, "_nfs_keystore", None) and os.path.isdir(orc._nfs_keystore))
check("SSH 키 로그인 성공 → user 플래그 기록",
      any(getattr(h, "value", None) == FLAG for h in rep.flags) or orc.world.flags.get("user") == FLAG)
check("SSH 키 로그인 crede 기록(nico:<ssh-key..>)",
      any("ssh-key" in c for c in orc.world.creds))


print("\n=== 게이트: 옵트인 아니면 아무 것도 안 함 ===")
g2 = ScopeGuard.from_cidr_strings(); g2.bind_target(T)
orc2 = Orchestrator(g2, FakeRunner(responder), KnowledgeBase.load(), auto_approve_contained,
                    is_tool_available=lambda b: True, quiet=True,
                    exploit_exec=False, auto_poc=False)   # 옵트인 꺼짐
orc2.world = WorldModel(target=T)
calls = {"n": 0}
orc2._nfs_mount_fn = lambda *a, **k: (calls.__setitem__("n", calls["n"] + 1), (True, ""))[1]
rep2 = OrchestrationReport(target=T)
orc2._nfs_harvest_stage(rep2, None)
check("옵트인 꺼짐 → 마운트 시도 0", calls["n"] == 0)


print("\n=== 마운트 실패(sudo 없음) → 수동 안내 폴백 ===")
exp3 = make_export_dir()
orc3 = make_orc(responder, exp3)
orc3._nfs_mount_fn = lambda ip, export, mp, vers="3": (False, "mount.nfs: access denied / sudo: a password is required")
rep3 = OrchestrationReport(target=T)
orc3._nfs_harvest_stage(rep3, None)
check("마운트 실패 → 수동 마운트 안내 1회", any("sudo mount -t nfs" in s for s in rep3.manual_suggestions))
check("마운트 실패 → 자격 수확 없음", not any("nico" in c for c in orc3.world.creds))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
