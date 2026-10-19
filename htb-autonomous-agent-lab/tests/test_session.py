# 실행: htb-agent 디렉토리에서  python3 tests/test_session.py
# ShellSession 은 실제 pty 가 필요 → Linux(Kali/WSL)에서만 의미있음.
import sys

sys.path.insert(0, "src")

passed = failed = 0


def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


# pty·pexpect 없는 환경(Windows 등)에서는 스위트를 건너뛴다 — run_all 을 깨지 않게
try:
    import pexpect  # noqa: F401
    import pty      # noqa: F401
except ImportError as e:
    print(f"=== ShellSession: 건너뜀 ({e}) ===")
    print("\n결과: 0 passed, 0 failed")
    sys.exit(0)

from htb_agent.tools.session import BgJob, ShellSession  # noqa: E402

print("=== 세션 생성 ===")
s = ShellSession(default_timeout=30)
check("세션 살아있음", s.alive is True)
check("Runner 프로토콜(run 보유)", callable(getattr(s, "run", None)))

print("\n=== 상태 유지 (one-shot 러너로는 불가능한 것) ===")
s.run("cd /tmp")
check("cd 가 다음 명령까지 유지", s.run("pwd").stdout.strip() == "/tmp")
s.run("export HTBA_TEST=zxcv")
check("환경변수 유지", s.run("echo $HTBA_TEST").stdout.strip() == "zxcv")

print("\n=== 셸 연산자 (shell=False 로는 불가능한 것) ===")
check("파이프", s.run("echo abc | tr a-z A-Z").stdout.strip() == "ABC")
check("리다이렉트 + 재독", (s.run("echo hi > /tmp/htba_t.txt"),
                           s.run("cat /tmp/htba_t.txt").stdout.strip())[1] == "hi")
check("&& 연쇄", s.run("true && echo chained").stdout.strip() == "chained")
check("명령치환", s.run("echo $(echo nested)").stdout.strip() == "nested")

print("\n=== 종료코드 ===")
check("성공 rc=0", s.run("true").returncode == 0)
check("실패 rc!=0", s.run("false").returncode != 0)
check("특정 rc 회수", s.run("(exit 7)").returncode == 7)   # 서브셸 — 세션을 죽이지 않음

print("\n=== 셸 사망 시 자동 복구 (무개입 운용의 전제) ===")
s.run("cd /tmp; export HTBA_GONE=1")
r = s.run("exit 3")                                  # 지속 셸을 실제로 죽인다
check("EOF 를 오류로 보고", "EOF" in r.error)
check("상태 초기화를 명시", "초기화" in r.error)
check("복구 후 재사용 가능", s.run("echo revived").stdout.strip() == "revived")
check("respawn 카운트 증가", s.respawns == 1)
check("잃어버린 env 를 숨기지 않음", s.run("echo [$HTBA_GONE]").stdout.strip() == "[]")

print("\n=== 타임아웃 → Ctrl-C → 세션 재사용 ===")
r = s.run("sleep 10", timeout=2)
check("타임아웃 표시", r.timed_out is True)
check("복구 실패 아님", r.error == "")
check("세션 계속 사용 가능", s.run("echo alive").stdout.strip() == "alive")

print("\n=== 백그라운드 (긴 스캔 중 다른 단계 진행) ===")
job = s.start_background("echo started; sleep 3; echo finished", name="t1")
check("BgJob 반환", isinstance(job, BgJob) and job.pid > 0)
check("실행중 판정", s.bg_running(job) is True)
check("즉시 다른 명령 가능", s.run("echo concurrent").stdout.strip() == "concurrent")
s.run("sleep 4")
check("완료 후 종료 판정", s.bg_running(job) is False)
out = s.bg_output(job)
check("로그에 전체 출력", "started" in out and "finished" in out)
check("bg_jobs 등록", [j.name for j in s.bg_jobs()] == ["t1"])

print("\n=== 대화형 (stdin 소비 명령) ===")
s.send_line("read x; echo got=$x")
s.send_line("hello")
idx = s.expect(["got=hello", "got="], timeout=10)
check("프롬프트에 입력 전달", idx == 0)

print("\n=== 정리 ===")
s.run("rm -f /tmp/htba_t.txt")
s.close()
check("close 후 alive=False", s.alive is False)
check("종료 세션은 run 거부", s.run("echo x").error != "")

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
