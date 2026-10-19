# 실행: htb-agent 디렉토리에서  python3 tests/test_tools.py
import sys
sys.path.insert(0, "src")
from htb_agent.tools import registry as R

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== Registry 구조 ===")
check("도구 목록 비어있지 않음", len(R.TOOLS) >= 20)
avail = R.check_available()
check("check_available 모든 키 포함", set(avail.keys()) == set(R.TOOLS_BY_KEY.keys()))

# 사용자가 예시로 든 도구들 포함 확인
check("BloodHound 수집기 등록", "bloodhound-python" in R.TOOLS_BY_KEY)
check("BloodHound GUI 등록", "bloodhound" in R.TOOLS_BY_KEY)
check("S3 스캐너 등록", "s3scanner" in R.TOOLS_BY_KEY)
check("AWS CLI 등록", "awscli" in R.TOOLS_BY_KEY)

print("\n=== 설치 힌트 ===")
check("netexec pipx 힌트", "pipx" in R.TOOLS_BY_KEY["netexec"].install_hint().lower())
check("nmap apt 힌트", "apt" in R.TOOLS_BY_KEY["nmap"].install_hint().lower())
check("kerbrute go 힌트", "go" in R.TOOLS_BY_KEY["kerbrute"].install_hint().lower())

print("\n=== ensure_tools (단계 전 확인, 무한재시도 금지) ===")
ok, msgs = R.ensure_tools(["bloodhound-python", "s3scanner"])
# 이 컨테이너엔 미설치일 것 → ok False + 안내문 존재
check("미설치 시 ok=False", ok is False)
check("안내문에 설치법 포함", any("설치:" in m for m in msgs))
ok2, _ = R.ensure_tools(["__nonexistent__"])
check("미등록 도구 처리", ok2 is False)

print("\n=== 카테고리 필터 ===")
ad_missing = R.missing_tools(categories=["ad"])
check("ad 카테고리 필터 동작", all(t.category == "ad" for t in ad_missing))

print("\n=== report 출력 ===")
rep = R.report(categories=["cloud"])
check("report 에 s3scanner 포함", "s3scanner" in rep)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
