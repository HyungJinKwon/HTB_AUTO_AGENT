#!/usr/bin/env python3
# 모든 테스트 스위트를 실행하고 집계. 실행: htb-agent 에서  python3 tests/run_all.py
import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)   # htb-agent


def main() -> int:
    suites = sorted(f for f in glob.glob(os.path.join(HERE, "test_*.py")))
    total_pass = total_fail = failed_suites = 0
    for path in suites:
        name = os.path.basename(path)
        r = subprocess.run([sys.executable, path], capture_output=True, text=True, cwd=ROOT)
        last = ""
        for line in reversed(r.stdout.strip().splitlines()):
            if "passed" in line:
                last = line.strip()
                break
        print(f"  {'✅' if r.returncode == 0 else '❌'} {name:24} {last}")
        if r.returncode != 0:
            failed_suites += 1
            print(r.stdout[-800:]); print(r.stderr[-400:])
        # passed/failed 합산
        import re
        m = re.search(r"(\d+) passed, (\d+) failed", r.stdout)
        if m:
            total_pass += int(m.group(1)); total_fail += int(m.group(2))
    print(f"\n총 {len(suites)} 스위트 | {total_pass} passed, {total_fail} failed | "
          f"실패 스위트 {failed_suites}")
    return 1 if failed_suites else 0


if __name__ == "__main__":
    raise SystemExit(main())
