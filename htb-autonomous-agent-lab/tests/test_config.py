# 실행: htb-agent 디렉토리에서  python3 tests/test_config.py
import sys, tempfile, os, json
sys.path.insert(0, "src")
from htb_agent.config import load_config, ConfigError, pick

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== JSON 로드 ===")
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "c.json")
    json.dump({"allowed_ranges": ["10.129.0.0/16"], "llm": {"backend": "claude", "tier": "strong"},
               "max_enum": 3, "unknown_key": 1}, open(p, "w"))
    c = load_config(p)
    check("allowed_ranges 파싱", c.allowed_ranges == ["10.129.0.0/16"])
    check("중첩 llm.backend", c.llm_backend == "claude")
    check("중첩 llm.tier", c.llm_tier == "strong")
    check("max_enum", c.max_enum == 3)
    check("미지정은 None", c.max_attempts is None)
    check("미지원 키 무시", not hasattr(c, "unknown_key"))

print("\n=== 우선순위 pick ===")
check("CLI 우선", pick("cli", "cfg", "def") == "cli")
check("CLI None → config", pick(None, "cfg", "def") == "cfg")
check("둘 다 None → 기본", pick(None, None, "def") == "def")
check("0/빈값도 유효(0 유지)", pick(0, 5, 9) == 0)

print("\n=== 오류 처리 ===")
try:
    load_config("/nonexistent/x.json"); check("없는 파일 에러", False)
except ConfigError: check("없는 파일 에러", True)
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "bad.json"); open(p, "w").write("{bad")
    try:
        load_config(p); check("깨진 JSON 에러", False)
    except ConfigError: check("깨진 JSON 에러", True)
    # 최상위 비매핑
    p2 = os.path.join(d, "arr.json"); json.dump([1,2], open(p2,"w"))
    try:
        load_config(p2); check("비매핑 최상위 에러", False)
    except ConfigError: check("비매핑 최상위 에러", True)

print("\n=== YAML (pyyaml 있을 때만) ===")
import importlib.util
if importlib.util.find_spec("yaml") is not None:
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "c.yaml"); open(p,"w").write("max_enum: 2\nllm:\n  backend: ollama\n")
        c = load_config(p)
        check("YAML 파싱", c.max_enum == 2 and c.llm_backend == "ollama")
else:
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "c.yaml"); open(p,"w").write("max_enum: 2\n")
        try:
            load_config(p); check("pyyaml 없음 안내", False)
        except ConfigError as e:
            check("pyyaml 없음 안내", "pyyaml" in str(e))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
