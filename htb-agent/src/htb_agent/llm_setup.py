"""
LLM Setup — 초보자용 LLM 연결 마법사 + 키 보관 + 실제 호출 테스트
================================================================

`assassin --setup-llm` 한 번으로 Claude(API)·로컬 LLM(Ollama)을 연결한다.
  ① 무엇을 쓸지 고르기(하이브리드 권장)
  ② Claude: anthropic 패키지 확인(설치는 동의 시) → API 키 입력(화면 표시 안 함) → 실제 1회 호출 → 저장
  ③ Ollama: 설치·서버 확인 → 받아 둔 모델 표시 → PC 메모리에 맞는 모델 추천(받기는 동의 시) → 실제 1회 호출
  ④ 기본 설정 저장 → 이후 `assassin <타겟>` 만으로 연결된 LLM 사용

키 보관 원칙:
  · `~/.config/assassin/credentials` (디렉터리 700, 파일 600). 환경변수가 있으면 환경변수가 우선.
  · 화면에는 가린 값(`sk-ant-…abcd`)만 보이고, 상태 파일·감사 로그·리포트·라이트업에는 남기지 않는다
    (이 모듈은 키를 os.environ 에만 넣고, 다른 계층은 키를 읽거나 기록하지 않는다).
  · anthropic 설치는 먼저 묻는다(엔터=아니오). Ollama 는 미설치 시 [y/N] 확인 후 공식 스크립트로
    자동 설치(파이프→셸, 무확인 실행 아님)하고, 로컬을 '선택'했으면 추천 모델 다운로드는 기본
    진행한다(Enter=받기, 거부는 n) — 모델이 없으면 로컬 LLM 이 동작하지 않기 때문.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Callable

CRED_KEYS = ("ANTHROPIC_API_KEY",)
DEFAULT_OLLAMA_HOST = "http://localhost:11434"
OLLAMA_INSTALL_CMD = "curl -fsSL https://ollama.com/install.sh | sh"


# ── 경로 ─────────────────────────────────────────────────────────────
def config_dir(env=None) -> str:
    """설정 디렉터리. ASSASSIN_CONFIG_DIR > $XDG_CONFIG_HOME/assassin > ~/.config/assassin."""
    env = os.environ if env is None else env
    if env.get("ASSASSIN_CONFIG_DIR"):
        return env["ASSASSIN_CONFIG_DIR"]
    base = env.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "assassin")


def credentials_path(env=None) -> str:
    return os.path.join(config_dir(env), "credentials")


def user_config_path(env=None) -> str:
    return os.path.join(config_dir(env), "config.json")


# ── 키 보관 ──────────────────────────────────────────────────────────
def mask(secret: str) -> str:
    """키를 화면용으로 가린다. 앞 7자 + … + 끝 4자(짧으면 전부 가림)."""
    s = (secret or "").strip()
    if len(s) < 16:
        return "****"
    return f"{s[:7]}…{s[-4:]}"


def scrub(text: str, env=None) -> str:
    """오류 메시지 등에 키가 섞여 있으면 가린 값으로 바꾼다(방어적)."""
    env = os.environ if env is None else env
    out = str(text or "")
    for k in CRED_KEYS:
        v = env.get(k) or ""
        if len(v) >= 8 and v in out:
            out = out.replace(v, mask(v))
    return out


def read_credentials(path: str | None = None) -> tuple[dict[str, str], str]:
    """(키 값들, 경고). 허용된 키만 읽는다. 파일 권한이 넓으면 경고(로드는 함)."""
    path = path or credentials_path()
    vals: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return vals, ""
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k in CRED_KEYS and v:
            vals[k] = v
    warn = ""
    if os.name == "posix":
        try:
            mode = os.stat(path).st_mode & 0o777
            if mode & 0o077:
                warn = f"키 파일 권한이 넓습니다({oct(mode)}) — 'chmod 600 {path}' 로 본인만 읽게 하세요"
        except OSError:
            pass
    return vals, warn


def write_credentials(values: dict[str, str], path: str | None = None) -> str:
    """키를 저장(기존 값과 병합). 디렉터리 700·파일 600, 임시 파일 → 원자적 교체."""
    path = path or credentials_path()
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    cur, _ = read_credentials(path)
    cur.update({k: v for k, v in values.items() if k in CRED_KEYS and v})
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("# ASSASSIN LLM 자격증명 — 본인만 읽기(600). 공유·커밋 금지.\n")
        for k in CRED_KEYS:
            if cur.get(k):
                f.write(f"{k}={cur[k]}\n")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def apply_credentials(env=None, path: str | None = None) -> dict[str, str]:
    """저장된 키를 환경변수로 올린다(이미 있으면 환경변수 우선). 반환: 키 → 출처('env'/'file'/'')."""
    env = os.environ if env is None else env
    vals, _ = read_credentials(path)
    src: dict[str, str] = {}
    for k in CRED_KEYS:
        if env.get(k):
            src[k] = "env"
        elif vals.get(k):
            env[k] = vals[k]
            src[k] = "file"
        else:
            src[k] = ""
    return src


# ── 기본 설정 파일 ───────────────────────────────────────────────────
def write_user_config(llm: dict, extra: dict | None = None, path: str | None = None) -> str:
    """기본 설정(config.json)의 llm 항목을 갱신해 저장(다른 키는 보존)."""
    path = path or user_config_path()
    data: dict = {}
    try:
        with open(path, encoding="utf-8") as f:
            loaded = json.load(f)
            if isinstance(loaded, dict):
                data = loaded
    except (OSError, ValueError):
        pass
    cur: dict = data["llm"] if isinstance(data.get("llm"), dict) else {}
    cur = {**cur, **{k: v for k, v in llm.items() if v not in (None, "")}}
    for k in ("ollama_model", "ollama_host"):
        if llm.get(k) == "":
            cur.pop(k, None)
    data["llm"] = cur
    for k, v in (extra or {}).items():
        data[k] = v
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return path


# ── 로컬 모델 추천 ───────────────────────────────────────────────────
def total_memory_gb() -> float | None:
    """총 메모리(GB). Linux(/proc/meminfo)·macOS(sysctl) 지원, 그 외 None."""
    try:
        with open("/proc/meminfo", encoding="utf-8") as f:
            for ln in f:
                if ln.startswith("MemTotal:"):
                    return round(int(ln.split()[1]) / 1024 / 1024, 1)
    except (OSError, ValueError, IndexError):
        pass
    if sys.platform == "darwin":
        try:
            out = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True,
                                 text=True, timeout=3).stdout.strip()
            return round(int(out) / 1024 ** 3, 1)
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
    return None


# (최소 메모리 GB, 모델, 설명) — 위에서부터 첫 번째로 맞는 것. 수치는 대략치〔추정〕
_MODEL_TABLE = [
    (64, "llama3.3:70b", "대형(약 40GB) — 품질 최고, 매우 느릴 수 있음"),
    (32, "qwen2.5:32b", "중대형(약 20GB) — 품질·속도 균형"),
    (16, "qwen2.5:14b", "중형(약 9GB) — 16GB+ 메모리 권장"),
    (8, "qwen2.5:7b", "소형(약 5GB) — 일반 노트북 기본값"),
    (0, "llama3.2:3b", "초소형(약 2GB) — 메모리가 적을 때"),
]


def recommend_ollama_model(mem_gb: float | None) -> tuple[str, str]:
    """메모리에 맞는 로컬 모델 추천(모델, 이유). 모르면 8b."""
    if mem_gb is None:
        return "qwen2.5:7b", "메모리를 확인하지 못해 일반 기본값(약 5GB)을 추천"
    for need, model, desc in _MODEL_TABLE:
        if mem_gb >= need:
            return model, f"메모리 {mem_gb:g}GB → {desc}"
    return "llama3.2:3b", "메모리가 적어 초소형 모델 추천"


# ── 실제 호출 테스트 ─────────────────────────────────────────────────
def friendly_error(e: BaseException) -> str:
    """백엔드 오류를 초보자용 한 줄로. 키는 가린다."""
    name = type(e).__name__
    s = scrub(str(e))
    low = (name + " " + s).lower()
    if "authentication" in low or "401" in low or "invalid x-api-key" in low or "api key" in low:
        return "API 키가 올바르지 않습니다 — console.anthropic.com 에서 키를 다시 복사해 입력하세요"
    if "permission" in low or "403" in low or "credit" in low or "billing" in low:
        return "키는 맞지만 권한·결제 상태 때문에 거부됐습니다 — 콘솔에서 결제/한도를 확인하세요"
    if "notfound" in low or "404" in low or "not found" in low:
        return "모델을 찾을 수 없습니다 — 모델 이름 또는 'ollama pull <모델>' 을 확인하세요"
    if "ratelimit" in low or "429" in low or "overloaded" in low or "529" in low:
        return "요청이 많아 잠시 거부됐습니다 — 1~2분 뒤 다시 시도하세요"
    if ("connection" in low or "urlopen" in low or "timed out" in low or "timeout" in low
            or "refused" in low or "resolve" in low):
        return "연결 실패 — 인터넷·프록시, 로컬이면 'ollama serve' 실행과 주소(OLLAMA_HOST)를 확인하세요"
    return f"{name}: {s[:120]}"


def test_provider(provider, tier=None) -> tuple[bool, str]:
    """짧은 요청 1회로 실제 응답을 확인(공격 명령 아님). (성공?, 메시지)."""
    from .llm.base import Tier
    tier = tier or Tier.CHEAP
    ok, reason = provider.available()
    if not ok:
        return False, reason
    try:
        resp = provider.complete("연결 확인용 요청이다. 지시대로만 답하라.",
                                 "'OK' 한 단어로만 답하라.", tier, max_tokens=8)
    except Exception as e:   # noqa: BLE001 — 어떤 실패든 초보자용 문장으로
        return False, friendly_error(e)
    if resp.stop_reason == "refusal":
        return False, f"모델이 응답을 거절했습니다({resp.model})"
    if not (resp.text or "").strip():
        return False, f"빈 응답({resp.model}) — 모델 상태를 확인하세요"
    return True, f"응답 확인 · 모델 {resp.model}"


# ── 마법사 ───────────────────────────────────────────────────────────
@dataclass
class SetupIO:
    """입출력·외부 동작 주입(테스트용). 기본은 실제 터미널·서브프로세스."""
    ask: Callable[[str], str] = input
    secret: Any = None            # Callable[[str], str] — 기본 getpass.getpass(화면 표시 안 함)
    out: Callable[[str], None] = print
    run: Any = None               # Callable[[list[str]], int] — 기본 subprocess.run(...).returncode
    run_shell: Any = None         # Callable[[str], int] — 셸 경유(파이프 허용). Ollama 공식 설치용.
    sleep: Any = None             # Callable[[float], None] — 설치 직후 서버 기동 대기(폴링). 테스트 주입.
    which: Callable[[str], str | None] = shutil.which
    env: Any = None               # 기본 os.environ(키를 이 프로세스 환경변수로만 올림)
    claude_factory: Any = None    # 기본 ClaudeProvider
    ollama_factory: Any = None    # 기본 OllamaProvider(host=, models=)
    memory_gb: Callable[[], float | None] = total_memory_gb
    has_anthropic: Any = None     # Callable[[], bool] — anthropic 패키지 설치 여부

    def __post_init__(self):
        if self.secret is None:
            import getpass
            self.secret = getpass.getpass
        if self.run is None:
            self.run = lambda cmd: subprocess.run(cmd).returncode
        if self.run_shell is None:
            # 공식 Ollama 설치는 'curl … | sh'(파이프)라 셸이 필요하다. 사용자 [y/N] 확인
            # 뒤에만 호출된다(무확인 자동 실행 아님). 셸 인젝션 방지를 위해 고정 명령만 넘긴다.
            self.run_shell = lambda cmd: subprocess.run(cmd, shell=True).returncode
        if self.sleep is None:
            import time
            self.sleep = time.sleep
        if self.env is None:
            self.env = os.environ
        if self.claude_factory is None:
            from .llm.claude_provider import ClaudeProvider
            self.claude_factory = ClaudeProvider
        if self.ollama_factory is None:
            from .llm.ollama_provider import OllamaProvider
            self.ollama_factory = OllamaProvider
        if self.has_anthropic is None:
            def _has() -> bool:
                import importlib
                import importlib.util
                importlib.invalidate_caches()
                return importlib.util.find_spec("anthropic") is not None
            self.has_anthropic = _has


def _yes(ans: str) -> bool:
    return ans.strip().lower() in ("y", "yes", "예", "네", "ㅇ")


def _no(ans: str) -> bool:
    """명시적 거부만 True — '기본 자동 진행' 프롬프트에서 Enter/빈값은 거부가 아니다(진행)."""
    return ans.strip().lower() in ("n", "no", "아니", "아니오", "ㄴ")


def _await_ollama(io: "SetupIO", host: str, attempts: int, delay: float = 1.0):
    """Ollama 서버가 응답할 때까지 available() 를 재시도한다. (ok, reason, prov) 반환.
    서버 기동엔 시간이 걸리므로(특히 설치 직후 systemd 서비스가 올라오기 전) 폴링한다.
    '설치된 모델 없음' 은 서버가 떠 있다는 뜻이므로 '연결됨'으로 보고 멈춘다(모델 pull 로 이어감)."""
    prov = io.ollama_factory(host=host)
    ok, reason = prov.available()
    tries = 1
    while not (ok or "설치된 모델 없음" in reason) and tries < max(1, attempts):
        io.sleep(delay)
        prov = io.ollama_factory(host=host)
        ok, reason = prov.available()
        tries += 1
    return ok, reason, prov


def _ask(io: SetupIO, prompt: str) -> str:
    try:
        return io.ask(prompt)
    except EOFError:
        return ""


@dataclass
class SetupResult:
    backend: str = "none"            # 저장한 기본 백엔드
    claude_ok: bool = False
    ollama_ok: bool = False
    ollama_model: str = ""
    ollama_host: str = ""
    saved_key: bool = False
    config_path: str = ""
    cancelled: bool = False
    notes: list[str] = field(default_factory=list)


def _setup_claude(io: SetupIO, res: SetupResult) -> None:
    from . import ui
    from .llm.base import Tier
    io.out("\n" + ui.heading("Claude (API) 연결", "☁️"))
    if not io.has_anthropic():
        io.out(ui.mark_warn("anthropic 패키지가 없습니다 (Claude 호출용 라이브러리)"))
        cmd = [sys.executable, "-m", "pip", "install", "anthropic"]
        if _yes(_ask(io, ui.accent2("지금 설치할까요? ") + ui.dim(f"[{' '.join(cmd[2:])}] [y/N] "))):
            rc = io.run(cmd)
            if rc != 0 or not io.has_anthropic():
                io.out(ui.mark_err("설치 실패 — 직접 실행: pip install anthropic"))
                res.notes.append("Claude: anthropic 설치 필요(pip install anthropic)")
                return
            io.out(ui.mark_ok("anthropic 설치 완료"))
        else:
            io.out(ui.dim("  건너뜀 — 나중에: pip install anthropic 후 assassin --setup-llm"))
            res.notes.append("Claude: anthropic 설치 필요(pip install anthropic)")
            return
    stored, _ = read_credentials(credentials_path(io.env))
    cur = io.env.get("ANTHROPIC_API_KEY") or ""
    new_key = ""
    if cur:
        where = "저장된 키 파일" if stored.get("ANTHROPIC_API_KEY") == cur else "환경변수"
        io.out(ui.mark_ok(f"API 키 발견({where}): {mask(cur)}"))
        if _yes(_ask(io, ui.dim("  다른 키로 바꿀까요? [y/N] "))):
            cur = ""
    for attempt in range(2):
        if not cur:
            io.out(ui.dim("  키 발급: https://console.anthropic.com → API Keys → Create Key"))
            try:
                new_key = (io.secret("  API 키를 붙여넣고 엔터(화면에 표시되지 않음, 엔터만=건너뛰기): ")
                           or "").strip()
            except EOFError:
                new_key = ""
            if not new_key:
                io.out(ui.dim("  건너뜀 — Claude 없이 진행합니다"))
                res.notes.append("Claude: API 키 미입력")
                return
            if not new_key.startswith("sk-ant-"):
                io.out(ui.mark_warn("보통 'sk-ant-' 로 시작합니다 — 그대로 확인해 봅니다"))
            cur = new_key
        io.env["ANTHROPIC_API_KEY"] = cur
        io.out(ui.dim("  실제 호출로 확인 중… (아주 짧은 요청 1회)"))
        ok, msg = test_provider(io.claude_factory(), Tier.CHEAP)
        if ok:
            io.out(ui.mark_ok("Claude 연결 성공 — " + msg))
            res.claude_ok = True
            if new_key:
                path = write_credentials({"ANTHROPIC_API_KEY": new_key}, credentials_path(io.env))
                res.saved_key = True
                io.out(ui.mark_ok(f"키 저장: {path} (본인만 읽기 600 · 화면 표시 {mask(new_key)})"))
            return
        io.out(ui.mark_err("Claude 연결 실패 — " + scrub(msg, io.env)))
        # 틀린 키는 이 프로세스에서 내리고(저장하지 않음) 1회 재입력 기회를 준다
        io.env.pop("ANTHROPIC_API_KEY", None)
        cur = new_key = ""
        if attempt == 0 and not _yes(_ask(io, ui.dim("  키를 다시 입력할까요? [y/N] "))):
            break
    res.notes.append("Claude: 연결 실패(키·네트워크 확인 후 assassin --setup-llm)")


def _setup_ollama(io: SetupIO, res: SetupResult) -> None:
    from . import ui
    from .llm.base import Tier
    io.out("\n" + ui.heading("로컬 LLM (Ollama) 연결", "💻"))
    host = (io.env.get("OLLAMA_HOST") or DEFAULT_OLLAMA_HOST).rstrip("/")
    just_installed = False
    if io.which("ollama") is None and host == DEFAULT_OLLAMA_HOST:
        io.out(ui.mark_warn("Ollama 가 설치되어 있지 않습니다"))
        io.out("  " + ui.accent2("설치 명령: ") + ui.bold(OLLAMA_INSTALL_CMD))
        io.out(ui.dim("  공식 스크립트를 셸로 실행합니다(sudo·네트워크 필요) — "
                      "내용은 https://ollama.com/install.sh 에서 확인 가능"))
        # [확인 후 자동] 무확인 'curl|sh' 는 하지 않는다. 사용자가 승인([y/N])할 때만 실행한다
        # (§4 안전 경계·Zero-Guessing: 비가역·시스템 변경은 사람 확인 후). 비대화형이면 기본 No→건너뜀.
        if not _yes(_ask(io, ui.accent2("지금 자동 설치할까요? ") + ui.dim("[y/N] "))):
            io.out(ui.dim("  건너뜀 — 나중에 직접: " + OLLAMA_INSTALL_CMD + "  → 다시 assassin --setup-llm"))
            res.notes.append("Ollama: 설치 필요(https://ollama.com)")
            return
        io.out(ui.dim("  설치 중… (네트워크·sudo 암호 입력이 필요할 수 있고, 수 분 걸릴 수 있음)"))
        rc = io.run_shell(OLLAMA_INSTALL_CMD)
        if rc != 0 or io.which("ollama") is None:
            io.out(ui.mark_err("Ollama 설치 실패 — 직접 실행: " + OLLAMA_INSTALL_CMD))
            res.notes.append("Ollama: 설치 실패(직접 실행: " + OLLAMA_INSTALL_CMD + ")")
            return
        io.out(ui.mark_ok("Ollama 설치 완료 — 서버·모델 설정으로 이어집니다"))
        just_installed = True
        # 설치 성공 → 아래 서버 가용성 확인·모델 pull 흐름으로 그대로 진행(fall through).
    # 서버 기동 대기: 방금 설치했으면 systemd 서비스가 올라올 때까지 폴링(레이스 제거). 이미
    # 설치돼 있던 경우엔 1회만 확인(기존 동작 유지 — 서버 미기동이면 안내).
    if just_installed:
        io.out(ui.dim("  서버 기동 대기 중… (systemd 서비스가 올라올 때까지 최대 ~20초)"))
    ok, reason, prov = _await_ollama(io, host, attempts=20 if just_installed else 1, delay=1.0)
    if not ok and "설치된 모델 없음" not in reason:
        io.out(ui.mark_err(f"Ollama 서버에 연결하지 못했습니다 ({host})"))
        io.out("  " + ui.accent2("서버 켜기: ") + ui.bold("ollama serve") + ui.dim("   (다른 터미널에서 실행해 두기)"))
        io.out(ui.dim("  다른 PC 의 Ollama 면: export OLLAMA_HOST=http://<IP>:11434 후 다시 실행"))
        res.notes.append("Ollama: 서버 미실행(ollama serve)")
        return
    installed = list(getattr(prov, "installed", []) or [])
    mem = io.memory_gb()
    rec, why = recommend_ollama_model(mem)
    io.out(ui.mark_ok(f"Ollama 서버 연결됨 ({host})"))
    io.out(ui.kv("추천 모델", f"{rec} — {why}", 10))
    if installed:
        io.out(ui.kv("받아 둔 모델", ", ".join(installed), 10))
    choice = ""
    if installed:
        opts = installed[:9]
        for i, m in enumerate(opts, 1):
            io.out(f"    [{i}] {m}" + (ui.dim("  ← 추천") if m in (rec, rec + ":latest") else ""))
        io.out(f"    [p] 추천 모델 {rec} 새로 받기")
        ans = _ask(io, ui.accent2("사용할 모델 번호 ") + ui.dim("[엔터=1] ")).strip().lower()
        if ans == "p":
            choice = ""
        elif ans.isdigit() and 1 <= int(ans) <= len(opts):
            choice = opts[int(ans) - 1]
        else:
            choice = opts[0]
    if not choice:
        # [로컬 선택 시 자동] 이 지점에 왔다는 건 사용자가 이미 하이브리드/로컬을 '선택'했다는 뜻이다.
        # 모델이 없으면 로컬 LLM 이 안 도므로, 추천 모델 다운로드를 '기본 진행'으로 둔다(Enter·
        # 비대화형=받기). 수 GB 라 명시적 거부(n)면 건너뛴다 — 무확인 강제는 아니고 거부 경로를 남긴다.
        if _no(_ask(io, ui.accent2(f"'{rec}' 모델을 받을까요? ")
                    + ui.dim("(수 GB 다운로드 · 로컬 사용 선택 시 자동) [Y/n] "))):
            io.out(ui.dim(f"  건너뜀 — 나중에: ollama pull {rec}"))
            res.notes.append(f"Ollama: 모델 필요(ollama pull {rec})")
            return
        if io.run(["ollama", "pull", rec]) != 0:
            io.out(ui.mark_err(f"모델 받기 실패 — 직접 실행: ollama pull {rec}"))
            res.notes.append(f"Ollama: 모델 받기 실패(ollama pull {rec})")
            return
        choice = rec
    prov = io.ollama_factory(host=host, models={t: choice for t in Tier})
    io.out(ui.dim(f"  실제 호출로 확인 중… ({choice}, 처음엔 모델 로딩에 시간이 걸릴 수 있음)"))
    ok, msg = test_provider(prov, Tier.STANDARD)
    if ok:
        io.out(ui.mark_ok("로컬 LLM 연결 성공 — " + msg))
        res.ollama_ok = True
        res.ollama_model = choice
        res.ollama_host = "" if host == DEFAULT_OLLAMA_HOST else host
    else:
        io.out(ui.mark_err("로컬 LLM 연결 실패 — " + msg))
        res.notes.append("Ollama: 호출 실패(" + msg[:60] + ")")


def run_setup(io: SetupIO | None = None) -> SetupResult:
    """대화형 LLM 연결 마법사. 결과를 기본 설정에 저장하고 요약을 출력한다."""
    from . import ui
    io = io or SetupIO()
    res = SetupResult()
    io.out(ui.panel("LLM 연결 마법사", [
        "질문에 답하면 Claude(API)·로컬 LLM(Ollama)을 연결하고 실제로 한 번 호출해 확인합니다.",
        ui.dim("· 설치는 먼저 묻습니다. 로컬(Ollama) 선택 시 설치는 [y/N] 확인·모델 다운로드는 자동 진행(거부: n)."),
        ui.dim(f"· API 키는 {credentials_path(io.env)} 에 본인만 읽기(600)로 저장, 화면엔 가린 값만."),
        ui.dim("· LLM 없이도 규칙 기반으로 동작합니다 — 언제든 건너뛰어도 됩니다."),
    ], style="navy"))
    io.out("  [1] 하이브리드 — 로컬(무료)로 열거·명령, Claude 로 계획·어려운 단계 " + ui.ok("(권장)"))
    io.out("  [2] Claude 만  — 설치 간단, 사용량만큼 과금")
    io.out("  [3] 로컬만     — 무료·오프라인, PC 사양에 따라 품질 차이")
    io.out("  [q] 취소")
    ans = _ask(io, ui.accent2("무엇을 쓸까요? ") + ui.dim("[엔터=1] ")).strip().lower()
    if ans in ("q", "quit", "취소"):
        res.cancelled = True
        io.out(ui.dim("취소했습니다 — 아무것도 바꾸지 않았습니다."))
        return res
    mode = {"2": "claude", "3": "ollama"}.get(ans, "hybrid")
    if mode in ("hybrid", "claude"):
        _setup_claude(io, res)
    if mode in ("hybrid", "ollama"):
        _setup_ollama(io, res)

    if mode == "hybrid":
        backend = "hybrid" if (res.claude_ok or res.ollama_ok) else "none"
    elif mode == "claude":
        backend = "claude" if res.claude_ok else "none"
    else:
        backend = "ollama" if res.ollama_ok else "none"
    res.backend = backend
    extra: dict = {}
    if res.claude_ok:
        ans = _ask(io, ui.accent2("Claude 비용 상한(달러)을 기본으로 둘까요? ")
                   + ui.dim("[엔터=2 / 0=없음] ")).strip()
        try:
            cap = 2 if ans == "" else int(float(ans))
        except ValueError:
            cap = 2
        if cap > 0:
            extra["max_cost"] = cap
    if backend != "none":
        llm_cfg = {"backend": backend, "ollama_model": res.ollama_model if res.ollama_ok else None,
                   "ollama_host": res.ollama_host if res.ollama_ok else None}
        if res.ollama_ok and not res.ollama_host:
            llm_cfg["ollama_host"] = ""      # 기본 주소면 설정에서 제거
        res.config_path = write_user_config(llm_cfg, extra, user_config_path(io.env))

    # 요약
    lines = [
        (ui.mark_ok if res.claude_ok else ui.mark_warn)(
            "Claude      " + ("연결됨" if res.claude_ok else "미연결")),
        (ui.mark_ok if res.ollama_ok else ui.mark_warn)(
            "로컬(Ollama) " + (f"연결됨 · {res.ollama_model}" if res.ollama_ok else "미연결")),
    ]
    if res.config_path:
        lines.append(ui.kv("기본 설정", f"{res.config_path} (llm={backend}"
                           + (f", 비용 상한 ${extra['max_cost']}" if extra.get("max_cost") else "") + ")", 10))
        lines.append(ui.accent2("이제 이렇게만 실행: ") + ui.bold("assassin 10.129.x.x")
                     + ui.dim(f"   (자동으로 --llm {backend})"))
        lines.append(ui.dim("연결 재확인: assassin --llm-test   ·   일회성으로 끄기: --llm none"))
    else:
        lines.append(ui.info("연결된 LLM 이 없어 설정을 바꾸지 않았습니다 — 규칙 기반으로 그대로 동작합니다."))
    for n in res.notes:
        lines.append(ui.dim("· " + n))
    io.out(ui.panel("연결 결과", lines, style="accent" if backend != "none" else "warn"))
    return res
