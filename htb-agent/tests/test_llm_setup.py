# 실행: htb-agent 디렉토리에서  python3 tests/test_llm_setup.py
# LLM 연결 마법사(--setup-llm) · 키 보관(600) · 실제 호출 테스트 · 기본 설정 자동 로드 · 키 비노출.
import contextlib
import io
import json
import os
import stat
import sys
import tempfile

sys.path.insert(0, "src")
TMP = tempfile.mkdtemp()
os.environ["ASSASSIN_CONFIG_DIR"] = os.path.join(TMP, "cfg")   # 실제 홈 설정을 건드리지 않음
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("OLLAMA_HOST", None)
os.environ.pop("OLLAMA_MODEL", None)

from htb_agent import llm_setup as S
from htb_agent import main as M
from htb_agent.config import Config, ConfigError
from htb_agent.llm.base import LLMResponse, Tier
from htb_agent.tools.runner import FakeRunner, RunOutput

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

KEY = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-wxyz"

print("=== 경로 · 가리기 ===")
check("ASSASSIN_CONFIG_DIR 우선", S.config_dir() == os.path.join(TMP, "cfg"))
check("XDG_CONFIG_HOME", S.config_dir({"XDG_CONFIG_HOME": "/x"}) == "/x/assassin")
check("기본 ~/.config/assassin", S.config_dir({}).endswith(os.path.join(".config", "assassin")))
check("가리기: 앞 7 + 끝 4", S.mask(KEY) == "sk-ant-…wxyz" and KEY not in S.mask(KEY))
check("짧은 값은 전부 가림", S.mask("short") == "****")
check("scrub: 메시지 속 키 가림", KEY not in S.scrub(f"bad {KEY}", {"ANTHROPIC_API_KEY": KEY}))

print("\n=== 키 보관(디렉터리 700 · 파일 600 · 병합 · 허용 키만) ===")
cp = S.credentials_path()
S.write_credentials({"ANTHROPIC_API_KEY": KEY, "EVIL": "x"})
mode = stat.S_IMODE(os.stat(cp).st_mode)
dmode = stat.S_IMODE(os.stat(os.path.dirname(cp)).st_mode)
check("파일 권한 600", mode == 0o600)
check("디렉터리 권한 700", dmode == 0o700)
vals, warn = S.read_credentials()
check("읽기: 허용 키만", vals == {"ANTHROPIC_API_KEY": KEY} and not warn)
check("임시 파일 남지 않음", not os.path.exists(cp + ".tmp"))
os.chmod(cp, 0o644)
check("권한 넓으면 경고", "chmod 600" in S.read_credentials()[1])
os.chmod(cp, 0o600)
env = {}
src = S.apply_credentials(env)
check("환경변수 없으면 파일 값 적용", env.get("ANTHROPIC_API_KEY") == KEY and src["ANTHROPIC_API_KEY"] == "file")
env2 = {"ANTHROPIC_API_KEY": "sk-ant-from-env-000000000000"}
check("환경변수가 우선", S.apply_credentials(env2)["ANTHROPIC_API_KEY"] == "env"
      and env2["ANTHROPIC_API_KEY"].startswith("sk-ant-from-env"))
check("파일 없으면 빈 값", S.read_credentials(os.path.join(TMP, "none"))[0] == {})

print("\n=== 기본 설정 저장(다른 키 보존) ===")
up = S.user_config_path()
with open(up, "w") as f:
    json.dump({"max_enum": 9, "llm": {"tier": "strong"}}, f)
S.write_user_config({"backend": "hybrid", "ollama_model": "qwen2.5:14b", "ollama_host": ""}, {"max_cost": 2})
d = json.load(open(up))
check("llm 갱신 + 기존 tier 유지", d["llm"] == {"tier": "strong", "backend": "hybrid", "ollama_model": "qwen2.5:14b"})
check("다른 키 보존 + extra 반영", d["max_enum"] == 9 and d["max_cost"] == 2)
cfg = Config.from_dict(d)
check("Config 가 새 키를 읽음", cfg.llm_backend == "hybrid" and cfg.llm_ollama_model == "qwen2.5:14b")
try:
    Config.from_dict({"llm": {"ollama_host": "ftp://x"}})
    check("잘못된 ollama_host 거부", False)
except ConfigError:
    check("잘못된 ollama_host 거부", True)
check("알 수 없는 llm 키는 경고", any("llm.foo" in w for w in Config.from_dict({"llm": {"foo": 1}}).warnings))

print("\n=== 로컬 모델 추천 ===")
check("4GB → 3b", S.recommend_ollama_model(4)[0] == "llama3.2:3b")
check("8GB → 7b", S.recommend_ollama_model(8)[0] == "qwen2.5:7b")
check("16GB → 14b", S.recommend_ollama_model(16)[0] == "qwen2.5:14b")
check("64GB → 70b", S.recommend_ollama_model(64)[0] == "llama3.3:70b")
check("모르면 7b", S.recommend_ollama_model(None)[0] == "qwen2.5:7b")

print("\n=== 오류 메시지(초보자용 · 키 가림) ===")
class AuthenticationError(Exception): pass
class RateLimitError(Exception): pass
check("인증 실패", "API 키가 올바르지 않습니다" in S.friendly_error(AuthenticationError("401")))
check("한도", "잠시 거부" in S.friendly_error(RateLimitError("429")))
check("연결", "연결 실패" in S.friendly_error(OSError("Connection refused")))
check("모델 없음", "모델을 찾을 수 없습니다" in S.friendly_error(Exception("model not found 404")))
os.environ["ANTHROPIC_API_KEY"] = KEY
check("기타 오류도 키 가림", KEY not in S.friendly_error(ValueError(f"weird {KEY}")))
os.environ.pop("ANTHROPIC_API_KEY")

print("\n=== 실제 호출 테스트(가짜 백엔드) ===")
class FakeP:
    def __init__(self, text="OK", stop="", exc=None, avail=(True, "ok"), installed=None,
                 host="http://localhost:11434", models=None):
        self.text, self.stop, self.exc, self.avail = text, stop, exc, avail
        self.installed = installed or []
        self.host, self.models, self.calls = host, models or {}, 0
    def available(self): return self.avail
    def model_for(self, t): return self.models.get(t, "fake")
    def complete(self, system, user, tier=Tier.STANDARD, max_tokens=1024):
        self.calls += 1
        if self.exc: raise self.exc
        return LLMResponse(self.text, "fake-model", stop_reason=self.stop)
check("성공", S.test_provider(FakeP())[0] is True)
check("사용 불가 → 사유", S.test_provider(FakeP(avail=(False, "nope"))) == (False, "nope"))
check("빈 응답 실패", S.test_provider(FakeP(text=""))[0] is False)
check("거절 실패", "거절" in S.test_provider(FakeP(text="", stop="refusal"))[1])
check("예외 → 초보자 문장", "API 키" in S.test_provider(FakeP(exc=AuthenticationError("401")))[1])
fp = FakeP(); S.test_provider(fp)
check("요청은 1회(짧은 확인)", fp.calls == 1)

print("\n=== 마법사: 하이브리드 정상 흐름 ===")
def make_io(answers, secrets=(), which=lambda n: "/usr/bin/" + n, claude=None, ollama=None,
            has_anthropic=lambda: True, mem=16.0, env=None):
    outs, runs = [], []
    ans = list(answers); sec = list(secrets)
    io_ = S.SetupIO(ask=lambda p: ans.pop(0) if ans else "",
                    secret=lambda p: sec.pop(0) if sec else "",
                    out=outs.append, run=lambda c: (runs.append(c), 0)[1], which=which,
                    env=env if env is not None else {"ASSASSIN_CONFIG_DIR": os.environ["ASSASSIN_CONFIG_DIR"]},
                    claude_factory=claude or (lambda: FakeP()),
                    ollama_factory=ollama or (lambda host=None, models=None: FakeP(
                        installed=["llama3.1:8b"], host=host, models=models)),
                    memory_gb=lambda: mem, has_anthropic=has_anthropic)
    return io_, outs, runs
import shutil  # noqa: E402
shutil.rmtree(S.config_dir(), ignore_errors=True)
io1, outs, runs = make_io(["", "1", ""], secrets=[KEY])
r = S.run_setup(io1)
text = "\n".join(outs)
check("결과: 하이브리드 저장", r.backend == "hybrid" and r.claude_ok and r.ollama_ok)
check("키 저장(600)", r.saved_key and stat.S_IMODE(os.stat(S.credentials_path()).st_mode) == 0o600
      and S.read_credentials()[0]["ANTHROPIC_API_KEY"] == KEY)
cfgd = json.load(open(S.user_config_path()))
check("기본 설정: backend·모델·비용 상한 2", cfgd["llm"]["backend"] == "hybrid"
      and cfgd["llm"]["ollama_model"] == "llama3.1:8b" and cfgd["max_cost"] == 2)
check("기본 주소면 ollama_host 저장 안 함", "ollama_host" not in cfgd["llm"])
check("화면에 키 원문 없음(가린 값만)", KEY not in text and S.mask(KEY) in text)
check("설치·다운로드 실행 없음(필요 없었음)", runs == [])
check("다음 실행 안내", "assassin 10.129.x.x" in text and "--llm-test" in text)

print("\n=== 마법사: 틀린 키 → 저장 안 함 ===")
shutil.rmtree(S.config_dir(), ignore_errors=True)
io2, outs2, _ = make_io(["2", "n"], secrets=["sk-ant-wrong-key-0000000000000000"],
                        claude=lambda: FakeP(exc=AuthenticationError("401 invalid x-api-key")))
r2 = S.run_setup(io2)
check("연결 실패 · 저장 안 함", not r2.claude_ok and not r2.saved_key
      and not os.path.exists(S.credentials_path()))
check("설정도 바꾸지 않음", r2.backend == "none" and not os.path.exists(S.user_config_path()))
check("틀린 키는 환경에서 내림", "ANTHROPIC_API_KEY" not in io2.env)
check("초보자용 실패 이유", "API 키가 올바르지 않습니다" in "\n".join(outs2))

print("\n=== 마법사: 재입력으로 성공 ===")
shutil.rmtree(S.config_dir(), ignore_errors=True)
calls = {"n": 0}
def flaky():
    calls["n"] += 1
    return FakeP(exc=AuthenticationError("401")) if calls["n"] == 1 else FakeP()
io3, _, _ = make_io(["2", "y", ""], secrets=["sk-ant-wrong-000000000000000000", KEY], claude=flaky)
r3 = S.run_setup(io3)
check("두 번째 키로 성공 · 그 키 저장", r3.claude_ok and S.read_credentials()[0]["ANTHROPIC_API_KEY"] == KEY)

print("\n=== 마법사: 설치·다운로드는 동의할 때만 ===")
shutil.rmtree(S.config_dir(), ignore_errors=True)
io4, outs4, runs4 = make_io(["2", ""], has_anthropic=lambda: False)
r4 = S.run_setup(io4)
check("anthropic 설치 거절 → 실행 안 함", runs4 == [] and not r4.claude_ok)
state = {"inst": False}
def has():
    return state["inst"]
def run_pip(c):
    state["inst"] = True
    return 0
io5, _, _ = make_io(["2", "y", ""], secrets=[KEY], has_anthropic=has)
io5.run = lambda c: (runs5.append(c), run_pip(c))[1]
runs5 = []
r5 = S.run_setup(io5)
check("동의 → pip install anthropic 실행", runs5 and runs5[0][-3:] == ["pip", "install", "anthropic"][-3:]
      and r5.claude_ok)
io6, outs6, runs6 = make_io(["3", "n"], ollama=lambda host=None, models=None: FakeP(
    avail=(False, "Ollama 에 설치된 모델 없음"), host=host, models=models), mem=8)
r6 = S.run_setup(io6)
check("모델 받기 명시 거절(n) → 실행 안 함", runs6 == [] and not r6.ollama_ok)
io7, outs7, runs7 = make_io(["3", "y"], ollama=lambda host=None, models=None: FakeP(
    avail=(True, "ok") if models else (False, "Ollama 에 설치된 모델 없음"), host=host, models=models), mem=8)
r7 = S.run_setup(io7)
check("동의 → ollama pull <추천> 실행", runs7 == [["ollama", "pull", "qwen2.5:7b"]] and r7.ollama_ok)
io8, outs8, runs8 = make_io(["3"], which=lambda n: None)
r8 = S.run_setup(io8)
check("Ollama 미설치 → 설치 명령 안내만(자동 실행 안 함)", runs8 == [] and S.OLLAMA_INSTALL_CMD in "\n".join(outs8))
io9, outs9, _ = make_io(["3"], ollama=lambda host=None, models=None: FakeP(
    avail=(False, "Ollama 연결 실패"), host=host))
S.run_setup(io9)
check("서버 꺼짐 → 'ollama serve' 안내", "ollama serve" in "\n".join(outs9))

print("\n=== 마법사: 취소 ===")
shutil.rmtree(S.config_dir(), ignore_errors=True)
io10, _, _ = make_io(["q"])
r10 = S.run_setup(io10)
check("취소 → 아무것도 안 씀", r10.cancelled and not os.path.exists(S.config_dir()))

print("\n=== CLI: 단독 명령 · 기본 설정 자동 로드 ===")
def rc_of(argv):
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as e:
            return M.main(argv), e.getvalue()
    except SystemExit as ex:
        return ex.code, ""
p = M.build_parser()
check("파서: --setup-llm · --llm-test", p.parse_args(["--setup-llm"]).setup_llm
      and p.parse_args(["--llm-test"]).llm_test)
check("--setup-llm 은 타겟 없이", rc_of(["10.129.1.5", "--setup-llm"])[0] == 2)
check("--setup-llm 과 --bench 동시 거부", rc_of(["--setup-llm", "--bench"])[0] == 2)
check("--doctor --llm-test 함께 허용", rc_of(["--doctor", "--llm-test"])[0] in (0, 2))
os.makedirs(S.config_dir(), exist_ok=True)
with open(S.user_config_path(), "w") as f:
    json.dump({"llm": {"backend": "nope"}}, f)
rc, err = rc_of(["--doctor"])
check("기본 설정 자동 로드(잘못된 값이면 경로와 함께 오류)", rc == 2 and S.user_config_path() in err)
with open(S.user_config_path(), "w") as f:
    json.dump({"llm": {"backend": "none"}}, f)
rc, err = rc_of(["--doctor"])
check("자동 로드 안내(stderr)", "(자동" in err)

print("\n=== doctor: 키 출처(가림) · 마법사 안내 ===")
from htb_agent.doctor import _check_llm, run_doctor  # noqa: E402
txt, _ = run_doctor()
check("LLM 섹션에 --setup-llm 안내", "--setup-llm" in txt)
os.environ["ANTHROPIC_API_KEY"] = KEY
rows = _check_llm()
check("doctor 출력에 키 원문 없음", all(KEY not in r[2] and KEY not in r[3] for r in rows))
os.environ.pop("ANTHROPIC_API_KEY")

print("\n=== Ollama 설정 우선순위: 환경변수 > 설정 파일 ===")
pv = M._ollama_provider("qwen2.5:14b", "http://10.0.0.5:11434")
check("설정 파일 값 적용", pv.host == "http://10.0.0.5:11434" and pv.models[Tier.STRONG] == "qwen2.5:14b")
os.environ["OLLAMA_HOST"] = "http://127.0.0.9:11434"; os.environ["OLLAMA_MODEL"] = "mistral"
pv2 = M._ollama_provider("qwen2.5:14b", "http://10.0.0.5:11434")
check("환경변수가 우선", pv2.host == "http://127.0.0.9:11434" and pv2.models[Tier.CHEAP] == "mistral")
os.environ.pop("OLLAMA_HOST"); os.environ.pop("OLLAMA_MODEL")
check("설정 없으면 키워드 없음(기존 호출 호환)", M._ollama_opts(Config()) == {})

print("\n=== 키 비노출: 실행 산출물(상태·감사·리포트)에 키가 남지 않음 ===")
S.write_credentials({"ANTHROPIC_API_KEY": KEY})
with open(S.user_config_path(), "w") as f:
    json.dump({"llm": {"backend": "none"}}, f)
_XML = ('<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.129.1.5"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/>'
        '</port></ports></host></nmaprun>')
dd = os.path.join(TMP, "run")
buf = io.StringIO()
with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
    M.main(["10.129.1.5", "--auto", "--state-dir", dd, "--offline", "--json", "--html",
            "--writeup", os.path.join(dd, "w.md")],
           runner=FakeRunner(lambda c: RunOutput(c, stdout=_XML if c.startswith("nmap") else "ok")))
leak = []
for root, _, files in os.walk(dd):
    for fn in files:
        with open(os.path.join(root, fn), encoding="utf-8", errors="ignore") as f:
            if KEY in f.read():
                leak.append(fn)
check("파일 산출물에 키 없음", os.path.isdir(dd) and not leak)
check("화면 출력에 키 없음", KEY not in buf.getvalue())
check("저장된 키는 실행 중 환경변수로 사용 가능", os.environ.get("ANTHROPIC_API_KEY") == KEY)
os.environ.pop("ANTHROPIC_API_KEY", None)

print("\n=== Ollama 미설치: '확인 후 자동 설치' (y/N) ===")


def ollama_io(answers, which_ollama_after_install="/usr/bin/ollama", shell_rc=0):
    """ollama 미설치 상태의 SetupIO — 설치 승인 시 run_shell 로 설치, which 가 뒤집힌다."""
    outs, runs_shell = [], []
    state = {"installed": False}
    ans = list(answers)

    def which(n):
        if n == "ollama":
            return which_ollama_after_install if state["installed"] else None
        return "/usr/bin/" + n

    def run_shell(cmd):
        runs_shell.append(cmd)
        if shell_rc == 0:
            state["installed"] = True
        return shell_rc

    runs = []
    io_ = S.SetupIO(ask=lambda p: ans.pop(0) if ans else "",
                    out=outs.append, run=lambda c: (runs.append(c), 0)[1],
                    run_shell=run_shell, which=which, sleep=lambda s: None,
                    env={"ASSASSIN_CONFIG_DIR": os.environ["ASSASSIN_CONFIG_DIR"]},
                    ollama_factory=lambda host=None, models=None: FakeP(
                        installed=["llama3.1:8b"], host=host, models=models),
                    memory_gb=lambda: 16.0)
    return io_, outs, runs_shell, runs


# (1) 거부(N) → 설치 실행 안 함, 안내만
io_n, outs_n, shell_n, _ = ollama_io(["n"])
res_n = S.SetupResult()
S._setup_ollama(io_n, res_n)
check("거부 시 설치 셸 실행 없음", shell_n == [])
check("거부 시 '설치 필요' 노트", any("설치 필요" in n for n in res_n.notes))
check("거부해도 설치 명령 안내 출력", any("ollama.com/install.sh" in o for o in outs_n))

# (2) 승인(y) → 공식 설치 셸 실행 + 설치 후 서버·모델 흐름으로 진행
io_y, outs_y, shell_y, _ = ollama_io(["y", "1"])   # y=설치, 1=모델 선택(llama3.1:8b)
res_y = S.SetupResult()
S._setup_ollama(io_y, res_y)
check("승인 시 공식 설치 명령을 셸로 1회 실행", shell_y == [S.OLLAMA_INSTALL_CMD])
check("설치 성공 후 모델 흐름 진행 → ollama_ok", res_y.ollama_ok and res_y.ollama_model == "llama3.1:8b")

# (3) 승인했으나 설치 실패(rc!=0) → 실패 노트 + 중단(모델 흐름 미진입)
io_f, outs_f, shell_f, _ = ollama_io(["y"], shell_rc=1)
res_f = S.SetupResult()
S._setup_ollama(io_f, res_f)
check("설치 실패 시 셸은 호출됨", shell_f == [S.OLLAMA_INSTALL_CMD])
check("설치 실패 노트 + 미연결", any("설치 실패" in n for n in res_f.notes) and not res_f.ollama_ok)

# (4) 안전 경계: 무확인 자동 실행 아님 — 빈 입력(비대화형 기본)은 설치 안 함
io_e, outs_e, shell_e, _ = ollama_io([])   # 답 없음 → _ask "" → _yes False
res_e = S.SetupResult()
S._setup_ollama(io_e, res_e)
check("비대화형(빈 입력) 기본 No → 무확인 설치 안 함", shell_e == [])


print("\n=== 설치 직후 서버 기동 레이스: 준비될 때까지 폴링 → 모델 pull 로 이어짐 ===")
# 설치 직후 서버가 바로 안 뜨는(systemd 기동 전) 상황: available() 가 처음 N회는 '연결 실패',
# 이후 '설치된 모델 없음'(서버 기동·모델만 없음)으로 바뀐다. 폴링으로 레이스를 넘겨 pull 까지 가야 한다.
race = {"n": 0}


def race_factory(host=None, models=None):
    race["n"] += 1
    if models:                      # pull 후 모델 지정 재생성 → 실호출 성공
        return FakeP(avail=(True, "ok"), host=host, models=models)
    if race["n"] <= 2:              # 처음 2회(설치 직후): 서버 아직 안 뜸
        return FakeP(avail=(False, "Ollama 연결 실패"), host=host)
    return FakeP(avail=(False, "Ollama 에 설치된 모델 없음"), host=host)   # 서버 기동됨·모델만 없음


slept = []
state2 = {"installed": False}
io_r = S.SetupIO(
    ask=lambda p: "y",                        # 설치 승인 · 모델 pull 은 기본 진행(Y)
    out=lambda s: None, run=lambda c: 0,
    run_shell=lambda cmd: (state2.__setitem__("installed", True), 0)[1],
    which=lambda n: None if (n == "ollama" and not state2["installed"]) else "/usr/bin/" + n,
    sleep=lambda s: slept.append(s),
    env={"ASSASSIN_CONFIG_DIR": os.environ["ASSASSIN_CONFIG_DIR"]},
    ollama_factory=race_factory, memory_gb=lambda: 8.0)
res_r = S.SetupResult()
S._setup_ollama(io_r, res_r)
check("서버 기동까지 폴링함(sleep 호출됨)", len(slept) >= 1)
check("폴링 후 모델 흐름 도달 → pull 실행·연결 성공",
      res_r.ollama_ok and res_r.ollama_model == "qwen2.5:7b")


print("\n=== 로컬 선택 시 모델 pull '기본 자동 진행'(Enter=받기, n=거부) ===")
# 모델 미설치 + 빈 입력(Enter) → 자동으로 추천 모델 pull(로컬을 '선택'한 사용자 의도 반영).
io_auto, outs_auto, _, runs_auto = ollama_io(
    [""],   # 모델 받기 프롬프트에 Enter → 기본 진행
)
# 모델 없음→pull→모델 지정 시 성공으로 뒤집히는 팩토리로 교체
_state = {"pulled": False}
io_auto.ollama_factory = (lambda host=None, models=None:
                          FakeP(avail=(True, "ok"), host=host, models=models) if models
                          else FakeP(avail=(False, "Ollama 에 설치된 모델 없음"),
                                     installed=[], host=host))
io_auto.which = lambda n: "/usr/bin/" + n     # ollama 이미 설치됨(설치 분기 건너뜀)
io_auto.memory_gb = lambda: 8.0               # 8GB → 추천 qwen2.5:7b (결정적)
res_auto = S.SetupResult()
S._setup_ollama(io_auto, res_auto)
check("Enter(빈 입력) → 추천 모델 자동 pull 실행",
      runs_auto == [["ollama", "pull", "qwen2.5:7b"]] and res_auto.ollama_ok)

# 명시적 거부(n)는 여전히 건너뜀
io_no, outs_no, _, runs_no = ollama_io(["n"])
io_no.which = lambda nm: "/usr/bin/" + nm
io_no.ollama_factory = lambda host=None, models=None: FakeP(
    avail=(False, "Ollama 에 설치된 모델 없음"), installed=[], host=host)
res_no = S.SetupResult()
S._setup_ollama(io_no, res_no)
check("명시적 n → pull 건너뜀", runs_no == [] and not res_no.ollama_ok
      and any("모델 필요" in n for n in res_no.notes))


print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
