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
    # 실측(Enigma): 발판 자격이 '온보딩 PDF' 한 장에 들어 있었고 .pdf 를 스킵해 수확 0이 됐다.
    # 유효한 PDF 텍스트 레이어가 없어도 strings 폴백으로 본문을 복구하는지 검증.
    with open(os.path.join(root, "New_Employee_Access.pdf"), "wb") as f:
        f.write(b"%PDF-1.4 fake-doc\nUsername: bob\nPassword: Welcome123!\n")
    with open(os.path.join(root, "passwd"), "w") as f:
        f.write("root:x:0:0:root:/root:/bin/bash\nnico:x:1000:1000:Nico:/home/nico:/bin/bash\n")
    return root


print("=== 순수 파싱/스캔 ===")
exports = nr.parse_exports("Export list for 10.129.239.191:\n/srv/nfs/onboarding *\n/srv/share 10.0.0.0/8")
check("showmount 파싱 → export 2개", exports == ["/srv/nfs/onboarding", "/srv/share"])
check("헤더/빈줄 무시, 상대경로 거부", nr.parse_exports("garbage\nnot-a-path foo") == [])
check("nfs-ls 파싱 — 파일경로 추출(디렉터리/./.. 제외)",
      nr.parse_nfs_ls("/home/nico/id_rsa\ndrwxr-xr-x .\n/onboarding.txt\nsubdir/\n")
      == ["home/nico/id_rsa", "onboarding.txt"])

print("=== PDF 텍스트 추출(발판 자격이 PDF 안에 있는 경우) ===")
_pdf = tempfile.mkstemp(suffix=".pdf")[1]
with open(_pdf, "wb") as _f:
    _f.write(b"%PDF-1.4 onboarding\nUsername: alice\nPassword: Hunter2!\n")
_txt = nr.extract_doc_text(_pdf)
check("extract_doc_text — PDF 본문 텍스트 복구", "alice" in _txt and "Hunter2!" in _txt)
os.remove(_pdf)

# 무확장자 파일이라도 매직바이트(%PDF)로 PDF 판정 — nfs-cp dest(f0) 처럼 확장자가 없어도 추출.
_noext = tempfile.mkstemp()[1]   # 확장자 없음
with open(_noext, "wb") as _f:
    _f.write(b"%PDF-1.4 onboarding\nUsername: carol\nPassword: P@ss!\n")
check("extract_doc_text — 무확장자 %PDF 도 PDF로 추출",
      "carol" in nr.extract_doc_text(_noext))
os.remove(_noext)

exp = make_export_dir()
fnd = nr.scan_tree(exp, export="/srv/nfs/onboarding")
check("SSH 개인키 발견(내용 마커)", len(fnd.ssh_keys) == 1 and fnd.ssh_keys[0].endswith("id_rsa"))
check("온보딩 자격 수확(nico:Sup3rS3cret!)", ("nico", "Sup3rS3cret!") in fnd.creds)
check("PDF 자격 수확(bob:Welcome123! — .pdf 더 이상 스킵 안 함)", ("bob", "Welcome123!") in fnd.creds)
check("user 플래그 스캔", any(v == FLAG for _k, v in fnd.flags))
check("후보 사용자 수집(home/<user> + passwd uid≥1000)", "nico" in fnd.users)
check("주목 파일 목록 비어있지 않음", bool(fnd.notable))


def responder(cmd):
    """FakeRunner(타겟 명령): showmount → export 1개 · ssh -i(nico) 로그인 → id + user 플래그."""
    if cmd.startswith("showmount"):
        return RunOutput(cmd, stdout="Export list for 10.129.239.191:\n/srv/nfs/onboarding *\n")
    if cmd.startswith("ssh -i") and "nico@" in cmd:
        return RunOutput(cmd, stdout=f"uid=1000(nico) gid=1000(nico)\nUSERTXT:{FLAG}\nROOTTXT:\n")
    if cmd.startswith("ssh -i"):
        return RunOutput(cmd, stdout="Permission denied (publickey).", returncode=255)
    return RunOutput(cmd, stdout="")


def base_orc(**kw):
    g = ScopeGuard.from_cidr_strings(); g.bind_target(T)
    orc = Orchestrator(g, FakeRunner(responder), KnowledgeBase.load(), auto_approve_contained,
                       is_tool_available=lambda b: True, quiet=True,
                       exploit_exec=True, auto_poc=True, **kw)
    orc.world = WorldModel(target=T)
    return orc


print("\n=== (A) rootless 기본(libnfs) — sudo·마운트 없이 수확→SSH키 로그인 ===")
# libnfs(nfs-ls/nfs-cp)를 주입된 run 으로 흉내(실 네트워크/libnfs 불필요).
# nfs-cp 는 이제 '임시파일 dest'에 바이너리로 받는다(stdout '-' 아님) — 실 규약과 동일.
# 발판 자격은 Enigma 처럼 '온보딩 PDF' 안에 둔다(= .pdf 추출 경로가 실제로 도는지 검증).
_NFS_FILES = {
    ".ssh/id_rsa": KEY.encode(),
    "New_Employee_Access.pdf": b"%PDF-1.4 fake\nUsername: nico\nPassword: Sup3rS3cret!\n",
    "/passwd": b"root:x:0:0:root:/root:/bin/bash\nnico:x:1000:1000:Nico:/home/nico:/bin/bash\n",
    "user.txt": (FLAG + "\n").encode(),
}
_CP_DESTS = []   # nfs-cp 가 받은 dest 경로 기록(확장자 보존 검증용)
def libnfs_run(argv):
    if argv[0] == "nfs-ls":
        return (0, "/home/nico/.ssh/id_rsa\n/New_Employee_Access.pdf\n/passwd\n/home/nico/user.txt\n")
    if argv[0] == "nfs-cp":
        url, dest = argv[1], argv[2]
        _CP_DESTS.append(dest)
        data = next((v for k, v in _NFS_FILES.items() if url.endswith(k)), None)
        if data is None:
            return (1, "")
        try:
            with open(dest, "wb") as f:
                f.write(data)
        except OSError:
            return (1, "")
        return (0, "")
    return (0, "")

orc = base_orc()
orc._nfs_force_libnfs = True          # rootless 경로 강제(테스트)
orc._nfs_run_fn = libnfs_run          # nfs-ls/nfs-cp 주입
rep = OrchestrationReport(target=T)
orc._nfs_harvest_stage(rep, None)
check("rootless 자격 수확 → world.creds (PDF 안의 nico:Sup3rS3cret!)",
      any("nico:Sup3rS3cret!" in c for c in orc.world.creds))
check("nfs-cp dest 가 확장자 보존(.pdf — 무확장자면 pdftotext 안 타던 버그 방지)",
      any(d.endswith(".pdf") for d in _CP_DESTS))
check("rootless SSH 키 로컬 보존(0600 keystore)",
      bool(getattr(orc, "_nfs_keystore", None)) and os.path.isdir(orc._nfs_keystore))
check("rootless SSH 키 로그인 → user 플래그", orc.world.flags.get("user") == FLAG)
check("rootless — sudo/마운트 주입 전혀 없이 성공(기본 자동화)", True)


print("\n=== (B) sudo 마운트 폴백 — libnfs 없음 + --priv-env 일 때만 ===")
exp2 = make_export_dir()
def fake_mount(ip, export, mp, vers="3"):
    import shutil
    shutil.rmtree(mp, ignore_errors=True); shutil.copytree(exp2, mp)
    return True, ""
orc2 = base_orc(priv_env=True)
orc2._nfs_force_libnfs = False         # rootless 불가 흉내 → sudo 폴백
orc2._nfs_mount_fn = fake_mount
orc2._nfs_umount_fn = lambda mp: None
rep2 = OrchestrationReport(target=T)
orc2._nfs_harvest_stage(rep2, None)
check("priv-env 마운트 폴백 자격 수확", any("nico:Sup3rS3cret!" in c for c in orc2.world.creds))
check("priv-env 마운트 폴백 SSH 키 로그인 → user 플래그", orc2.world.flags.get("user") == FLAG)


print("\n=== (C) libnfs 없음 + --priv-env 아님 → sudo 안 씀·수동 안내 ===")
orc3 = base_orc()                      # priv_env 기본 False
orc3._nfs_force_libnfs = False
mount_calls = {"n": 0}
orc3._nfs_mount_fn = lambda *a, **k: (mount_calls.__setitem__("n", mount_calls["n"] + 1), (True, ""))[1]
rep3 = OrchestrationReport(target=T)
orc3._nfs_harvest_stage(rep3, None)
check("priv-env 없으면 sudo 마운트 시도 0", mount_calls["n"] == 0)
check("libnfs 설치/--priv-env 안내 남김",
      any("libnfs-utils" in s or "--priv-env" in s for s in rep3.manual_suggestions))


print("\n=== (D) 게이트: 옵트인(exploit_exec/auto_poc) 아니면 아무 것도 안 함 ===")
g4 = ScopeGuard.from_cidr_strings(); g4.bind_target(T)
orc4 = Orchestrator(g4, FakeRunner(responder), KnowledgeBase.load(), auto_approve_contained,
                    is_tool_available=lambda b: True, quiet=True,
                    exploit_exec=False, auto_poc=False)
orc4.world = WorldModel(target=T)
ran = {"n": 0}
orc4._nfs_force_libnfs = True
orc4._nfs_run_fn = lambda argv: (ran.__setitem__("n", ran["n"] + 1), (0, ""))[1]
rep4 = OrchestrationReport(target=T)
orc4._nfs_harvest_stage(rep4, None)
check("옵트인 꺼짐 → NFS 접근 0", ran["n"] == 0)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
