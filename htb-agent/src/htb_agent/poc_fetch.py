"""공개 PoC 자동 조달(옵트인) — 내장/사용자 레지스트리가 '선언한 출처'에서만 받는다.

안전 경계(불변):
  · 받는 출처(git URL · exploit-db ID)는 **레지스트리(내장 _MODULES + 사용자 매니페스트)가
    선언한 값만** 쓴다. LLM·타겟 응답·사용자 자유입력 URL 을 clone 하지 않는다(주입 표면 없음).
  · 받기는 '로컬 디스크 조달'(git clone / searchsploit -m)이며 **타겟을 공격하지 않는다** —
    스코프 게이트(타겟 대상 판정)와 독립한 도구 행위다. **옵트인(fetch_pocs)일 때만** 동작한다.
  · 받은 PoC 의 '실행'은 여전히 기존 3관문(_exploit_run_stage)을 거친다 — 이 모듈은 받기만 한다.
  · 받은 코드는 공개 제3자 코드다. 출처 레포가 건전하다는 신뢰 가정은 운영자 책임이다(문서화).
    `ASSASSIN_NO_NET=1` 이면 실제 네트워크 조달을 거부한다(테스트·오프라인 안전).
"""
from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys

# PoC 가 흔히 요구하는 런타임 의존성(공개 PoC 대부분 requests/urllib3 사용). 에이전트 자체의
# 웹 RCE 발판 채널(shell_transport.web_http_fn)도 requests 가 필요하다. 옵트인(익스 실행) 시
# 자동으로 갖춰, '완전 자동'에서 사용자가 수동 pip 설치를 하지 않도록 한다.
COMMON_POC_DEPS = ("requests", "urllib3")

# PoC 실행 출력에서 '빠진 파이썬 모듈'을 뽑는 정규식(ModuleNotFoundError / ImportError 공통).
_MISSING_MOD_RE = re.compile(r"No module named ['\"]([A-Za-z0-9_][A-Za-z0-9_.]*)['\"]")
# PyPI 에 그대로 쓰면 안 되는(표준 라이브러리 등) 이름은 자동 설치하지 않는다 — 오설치 방지.
_STDLIB_DENY = frozenset((
    "os", "sys", "re", "json", "socket", "subprocess", "base64", "hashlib", "ssl",
    "time", "threading", "struct", "collections", "itertools", "typing", "pathlib",
))


def missing_module(text: str) -> str:
    """PoC 출력에서 빠진 '최상위' 모듈명을 반환(없으면 ''). 'pkg.sub' 는 'pkg' 로 축약."""
    m = _MISSING_MOD_RE.search(text or "")
    if not m:
        return ""
    top = m.group(1).split(".", 1)[0]
    return "" if top in _STDLIB_DENY else top


def _pip_install(modname: str, timeout: float = 180.0) -> bool:
    """현재 venv(sys.executable)에 모듈 1개를 설치(쉘 미경유, 리스트 인자). 성공 시 True."""
    try:
        r = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", modname],
                           capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def ensure_module(modname: str, pip_fn=None, audit=None) -> bool:
    """모듈이 import 가능하도록 보장(없으면 현재 venv 에 자동 설치). 이미 있으면 True.

    안전: 모듈명은 `[A-Za-z0-9_-]+` 로 엄격 검증(인자 주입 차단), 표준 라이브러리는 설치 안 함,
    `ASSASSIN_NO_NET=1` 이면 설치하지 않는다(오프라인). pip_fn(name)->bool 주입 시 그걸 쓴다(테스트).
    실행은 현재 venv(sys.executable) 한정 — 시스템 전역을 건드리지 않는다."""
    if not modname or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]*", modname):
        return False
    if importlib.util.find_spec(modname) is not None:
        return True
    if pip_fn is None and os.environ.get("ASSASSIN_NO_NET"):
        if audit is not None:
            audit.event("poc_dep_install", module=modname, ok=False, how="blocked_no_net")
        return False
    ok = bool((pip_fn or _pip_install)(modname))
    if audit is not None:
        audit.event("poc_dep_install", module=modname, ok=ok, how="pip")
    return ok


def ensure_common_deps(pip_fn=None, audit=None) -> None:
    """익스 실행에 흔히 필요한 공용 의존성(requests/urllib3)을 미리 갖춘다(옵트인 경로에서 1회)."""
    for name in COMMON_POC_DEPS:
        ensure_module(name, pip_fn=pip_fn, audit=audit)


def _git_clone(url: str, dest: str, timeout: float = 120.0) -> bool:
    """레지스트리가 선언한 공개 git 출처를 shallow clone(쉘 미경유, 리스트 인자). 성공 시 True."""
    try:
        r = subprocess.run(["git", "clone", "--depth", "1", url, dest],
                           capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _searchsploit_mirror(edb_id: str, cwd: str, timeout: float = 60.0) -> bool:
    """로컬 exploit-db 에서 PoC 를 현재 디렉터리로 복사(searchsploit -m, 로컬·무해). 성공 시 True."""
    try:
        r = subprocess.run(["searchsploit", "-m", edb_id],
                           capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def fetch_module_poc(module, dest_root: str, fetch_fn=None, audit=None) -> str:
    """내장 익스 모듈의 공개 PoC 를 레지스트리 선언 출처에서 조달한다(옵트인 호출).

    순서: 이미 받아진 로컬 PoC 가 있으면 재사용 → exploit-db ID 면 `searchsploit -m`(로컬 무해)
    → 아니면 레지스트리 git_source 를 shallow clone. 받은 뒤 module.find_local_poc 로 경로 반환.
    실패/미지원/네트워크 차단이면 ''. fetch_fn(module, cve_dir)->bool 주입 시 그걸 쓴다(테스트·대체).

    ⚠️ fetch_fn 미주입 + ASSASSIN_NO_NET 이면 실제 네트워크 조달을 하지 않는다(''). url/id 는
    항상 module(레지스트리)에서만 온다 — 임의 입력 clone 없음."""
    cve_dir = os.path.join(dest_root, getattr(module, "cve", "poc"))
    try:
        os.makedirs(cve_dir, exist_ok=True)
    except OSError:
        return ""
    existing = module.find_local_poc(extra_dirs=[cve_dir])
    if existing:
        return existing

    def _emit(ok: bool, how: str) -> None:
        if audit is not None:
            audit.event("poc_fetch", cve=getattr(module, "cve", ""), how=how, ok=ok)

    if fetch_fn is not None:
        ok = bool(fetch_fn(module, cve_dir))
        _emit(ok, "injected")
    elif os.environ.get("ASSASSIN_NO_NET"):
        _emit(False, "blocked_no_net")
        return ""
    elif getattr(module, "edb_id", ""):
        ok = _searchsploit_mirror(module.edb_id, cve_dir)
        _emit(ok, "searchsploit")
    elif getattr(module, "git_source", ""):
        ok = _git_clone(module.git_source, os.path.join(cve_dir, "src"))
        _emit(ok, "git")
    else:
        return ""
    if not ok:
        return ""
    return module.find_local_poc(extra_dirs=[cve_dir])


def default_cache_dir() -> str:
    """PoC 캐시 기본 위치. --poc-dir 미지정 시 여기로 받는다."""
    return os.path.expanduser("~/.assassin/pocs")
