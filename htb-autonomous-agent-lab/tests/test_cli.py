# 실행: htb-agent 디렉토리에서 python3 tests/test_cli.py
import sys

sys.path.insert(0, "src")

from htb_agent.main import build_parser, main

passed = failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


print("=== Kali launcher-facing CLI options ===")
args = build_parser().parse_args(["10.129.1.5"])
check("1-day 로컬 검색 기본 활성", not args.no_one_day and not args.online_cve)
args = build_parser().parse_args(["10.129.1.5", "--username", "alice", "--domain", "corp.local",
                                 "--online-cve"])
check("숨김 비밀번호 입력용 사용자/도메인 파싱",
      args.username == "alice" and args.domain == "corp.local" and args.online_cve)
check("상충하는 1-day 옵션 fail-closed",
      main(["10.129.1.5", "--no-one-day", "--online-cve"]) == 2)

print(f"\n결과: {passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
