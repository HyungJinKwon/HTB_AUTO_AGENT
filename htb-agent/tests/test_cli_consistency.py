# 실행: htb-agent 디렉토리에서  python3 tests/test_cli_consistency.py
# CLI 일관성: 단독 명령 배타·설정 적용·오프라인·입력 오류·모드 표시·설정값 연결.
import contextlib
import io
import json
import os
import sys
import tempfile
sys.path.insert(0, "src")
from htb_agent import kb_sync  # noqa: E402
from htb_agent import main as M  # noqa: E402
from htb_agent.tools.runner import FakeRunner, RunOutput  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

def run(argv, runner=None):
    """(종료코드, stdout+stderr). argparse 오류는 SystemExit 코드로."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        try:
            rc = M.main(argv, runner=runner)
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue()

fake = lambda: FakeRunner(lambda c: RunOutput(c, stdout="ok"))  # noqa: E731
BASE = ["--no-save", "--no-audit", "--offline"]

print("=== 단독 명령: 하나만, 타겟 없이 ===")
rc, out = run(["--learn", "list", "--promote", "all"])
check("단독 명령 둘 → 오류(2)", rc == 2 and "함께 쓸 수 없는" in out)
rc, out = run(["--learn", "list", "10.129.1.5"])
check("단독 명령 + 타겟 → 오류(2)", rc == 2 and "타겟 없이" in out)
rc, out = run(["--learn", "list"])
check("단독 명령 하나 → 정상", rc == 0 and "kerberoasting" in out)

print("\n=== 단독 명령도 --config 의 knowledge_dir 를 따름 ===")
with tempfile.TemporaryDirectory() as d:
    kb = os.path.join(d, "cfgkb")
    cfg = os.path.join(d, "cfg.json")
    with open(cfg, "w", encoding="utf-8") as f:
        json.dump({"knowledge_dir": kb}, f)
    src = os.path.join(d, "src")
    os.makedirs(src)
    with open(os.path.join(src, "a.md"), "w", encoding="utf-8") as f:
        f.write("# 메모\n내 자료")
    rc, out = run(["--config", cfg, "--ingest", src])
    check("--ingest 결과가 설정의 knowledge_dir 아래에 저장", rc == 0
          and os.path.isdir(os.path.join(kb, "notes", "ingested"))
          and os.listdir(os.path.join(kb, "notes", "ingested")))
    rc, out = run(["--config", os.path.join(d, "missing.json"), "--learn", "list"])
    check("없는 설정 파일 → 단독 명령도 설정 오류(2)", rc == 2 and "설정 오류" in out)

print("\n=== --kb-sync --offline: 네트워크 접근 없음 ===")
calls = []
orig_fetch = kb_sync._default_fetch
kb_sync._default_fetch = lambda timeout=6: (lambda url: calls.append(url))
rc, out = run(["--kb-sync", "--offline", "--knowledge", tempfile.mkdtemp()])
kb_sync._default_fetch = orig_fetch
check("오류(2) + 조회 0건", rc == 2 and calls == [] and "--offline" in out)

print("\n=== 잘못된 허용 대역 → 깔끔한 오류 ===")
rc, out = run(["10.129.1.5", "--range", "10.129.0.0/33"] + BASE, runner=fake())
check("CIDR 오류 → 2 + 안내(트레이스백 없음)", rc == 2 and "허용 대역" in out and "Traceback" not in out)

print("\n=== 출력 옵션이 타겟을 삼킨 경우 안내 ===")
rc, out = run(["--auto", "--html", "10.129.1.5"])
check("'출력 경로로 읽혔습니다' 안내", rc == 2 and "출력 경로로 읽혔" in out)

print("\n=== 승인 모드 표시 = 실제 우선순위(manual 최우선) ===")
seen = []
orig_inter = M.interactive_approver
M.interactive_approver = lambda c, v, s: seen.append(c) or False
rc, out = run(["10.129.1.5", "--auto", "--manual"] + BASE, runner=fake())
M.interactive_approver = orig_inter
check("--auto --manual → 패널 '완전수동'", "완전수동" in out and "승인 │ 완전자동" not in out)

print("\n=== 설정값·플래그가 오케스트레이터에 연결 ===")
captured = {}
Orig = M.Orchestrator
class Spy(Orig):
    def __init__(self, *a, **kw):
        captured.update(kw)
        super().__init__(*a, **kw)
M.Orchestrator = Spy
with tempfile.TemporaryDirectory() as d:
    cfg = os.path.join(d, "cfg.json")
    with open(cfg, "w", encoding="utf-8") as f:
        json.dump({"max_llm": 7}, f)
    run(["10.129.1.5", "--auto", "--config", cfg] + BASE, runner=fake())
check("config max_llm → Orchestrator(max_llm=7)", captured.get("max_llm") == 7)
captured.clear()
run(["10.129.1.5", "--auto", "--web-learn"] + BASE, runner=fake())
check("--web-learn → 공백 탐지(learn_gaps) 함께 켬", captured.get("learn_gaps") is True)
captured.clear()
run(["10.129.1.5", "--auto", "--web-learn", "--no-learn-gaps"] + BASE, runner=fake())
check("--no-learn-gaps 가 우선", captured.get("learn_gaps") is False)
M.Orchestrator = Orig

print("\n=== --list-exploits (단독 도구, 타겟 불필요) ===")
rc, out = run(["--list-exploits"])
check("--list-exploits → rc 0", rc == 0)
check("내장 CVE-2025-57819 표시", "CVE-2025-57819" in out and "freepbx" in out)
check("자동 발사·확장 안내 포함", "--full-auto" in out and "--exploit-modules" in out)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
