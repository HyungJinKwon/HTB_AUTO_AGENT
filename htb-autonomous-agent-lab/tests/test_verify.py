# 실행: htb-agent 디렉토리에서  python3 tests/test_verify.py
import sys
sys.path.insert(0, "src")
from htb_agent.verify import shell, confirms, flag, Evidence
from htb_agent.attempt import Attempt
from htb_agent.tools.runner import FakeRunner, RunOutput

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


print("=== shell: 토큰 왕복 ===")
# 정상 셸 — echo 가 토큰을 돌려준다
r = FakeRunner(lambda c: c.split()[-1] if c.startswith("echo ") else "")
ev = shell(r)
check("토큰 반환 → confirmed", ev.verdict == "confirmed" and ev.foothold == "shell")
check("확인에 쓴 명령 기록", ev.probe_command.startswith("echo "))

# 매 호출 다른 토큰 (재생공격·캐시된 출력 방지)
t1 = shell(r).probe_command
t2 = shell(r).probe_command
check("토큰은 매번 새로 생성", t1 != t2)

# 명령을 그대로 에코만 하는 채널 — 토큰이 '출력'이 아니라 '명령'에 있을 뿐
echo_only = FakeRunner(lambda c: c)
check("명령 에코만 하는 채널 → refuted", shell(echo_only).verdict == "refuted")

# 프롬프트처럼 보이는 배너 — 모양으로 속지 않는다
banner = FakeRunner(lambda c: "root@target:~# ")
ev = shell(banner)
check("프롬프트 배너 → refuted", ev.verdict == "refuted")
check("refuted 에 근거 있음", bool(ev.because.strip()))

print("=== shell: 모르면 inconclusive ===")
check("미설치/실행실패 → inconclusive",
      shell(FakeRunner(lambda c: RunOutput(c, error="'sh' 미설치"))).verdict == "inconclusive")
check("타임아웃 → inconclusive",
      shell(FakeRunner(lambda c: RunOutput(c, timed_out=True))).verdict == "inconclusive")

print("=== confirms: 일반 증거 ===")
# 내용을 아는 파일을 읽어 일치 확인
fr = FakeRunner(lambda c: "root:x:0:0:root:/root:/bin/bash" if "passwd" in c else "")
ev = confirms(fr, "cat /etc/passwd", "root:x:0:0")
check("파일 내용 일치 → confirmed", ev.verdict == "confirmed")
check("foothold 기본값 채워짐", bool(ev.foothold))
check("표식 없음 → refuted", confirms(fr, "cat /etc/shadow", "root:$6$").verdict == "refuted")
check("must_contain 미지정 → inconclusive",
      confirms(fr, "whoami", "").verdict == "inconclusive")
check("probe 실패 → inconclusive",
      confirms(FakeRunner(lambda c: RunOutput(c, error="boom")),
               "id", "uid=0").verdict == "inconclusive")

# 명령줄에만 표식이 있는 경우를 성공으로 오인하지 않는다
check("명령 에코는 증거가 아님",
      confirms(FakeRunner(lambda c: c), "echo uid=0", "uid=0").verdict == "refuted")

print("=== flag: 형식 + 출처 ===")
ev = flag("cat /home/bob/user.txt", "a" * 32)
check("user 플래그 → confirmed", ev.verdict == "confirmed" and ev.foothold == "flag:user")
check("출처 경로를 근거에 기록", "user.txt" in ev.because)
check("TAG{} 형식 포착", flag("echo x", "HTB{p0wn3d}").verdict == "confirmed")
# 못 찾은 것은 반증이 아니다
check("플래그 없음 → inconclusive(= not refuted)",
      flag("cat /etc/hostname", "target").verdict == "inconclusive")
# 플래그 맥락이 아닌 해시는 플래그가 아니다
check("비플래그 맥락의 hex 무시",
      flag("hashid 5f4dcc3b5aa765d61d8327deb882cf99",
           "5f4dcc3b5aa765d61d8327deb882cf99").verdict == "inconclusive")

print("=== 짧은 명령이 출력을 파괴하지 않는다 (거짓 refuted 회귀) ===")
# 에코 제거를 단순 치환으로 하면 'id' 가 'uid='/'gid=' 안에서 뜯겨나가
# 성공한 루트 셸이 refuted 로 판정되고, 그 refuted 가 접근면 소진에 쌓인다.
def out_runner(text):
    return FakeRunner(lambda c, timeout=120, t=text: RunOutput(c, stdout=t))
check("probe:id::uid= 가 루트 셸을 인정",
      confirms(out_runner("uid=0(root) gid=0(root) groups=0(root)"), "id", "uid=").verdict
      == "confirmed")
check("관측이 원형 보존",
      confirms(out_runner("uid=0(root)"), "id", "uid=").observed.startswith("uid=0"))
check("probe:ls::id_rsa", confirms(out_runner("total 8\nid_rsa"), "ls", "id_rsa").verdict
      == "confirmed")
check("probe:ps::systemd", confirms(out_runner("PID CMD\n1 systemd"), "ps", "systemd").verdict
      == "confirmed")
check("복합 명령도 보존",
      confirms(out_runner("uid=1000(bob)"), "cd /tmp && id", "uid=").verdict == "confirmed")

print("=== 에코는 여전히 증거가 아니다 (거짓 confirmed 방지) ===")
check("순수 에코 줄 → refuted",
      shell(FakeRunner(lambda c, timeout=120: RunOutput(c, stdout=c))).verdict == "refuted")
# 프롬프트가 붙어 에코된 줄에만 토큰이 있으면 '돌아온 것'이 아니다
check("프롬프트+에코 → refuted",
      shell(FakeRunner(lambda c, timeout=120:
                       RunOutput(c, stdout=f"root@htb:~# {c}"))).verdict == "refuted")
check("에코 뒤 실제 출력 → confirmed",
      shell(FakeRunner(lambda c, timeout=120:
                       RunOutput(c, stdout=f"{c}\n{c.split()[-1]}"))).verdict == "confirmed")

print("=== is_capability: 능력 vs 확인된 사실 ===")
from htb_agent.verify import is_capability
check("셸은 능력", is_capability("www"))
check("플래그는 능력 아님", not is_capability("flag:user"))
check("verified: 는 능력 아님", not is_capability("verified:http:80: uid="))
check("빈 값/None 은 능력 아님", not is_capability("") and not is_capability(None))

print("=== flag provenance (ctf-abacus) ===")
from htb_agent.verify import FLAG_GENUINE, FLAG_UNDEMONSTRATED
ev_u = flag("cat /home/bob/user.txt", "a" * 32, earned=False)
check("선행 익스플로잇 없음 → undemonstrated", ev_u.provenance == FLAG_UNDEMONSTRATED)
check("undemonstrated 근거 명시", "undemonstrated" in ev_u.because or "미증명" in ev_u.because)
ev_g = flag("cat /home/bob/user.txt", "a" * 32, earned=True)
check("선행 Foothold 있음 → genuine", ev_g.provenance == FLAG_GENUINE)
check("genuine 도 confirmed", ev_g.verdict == "confirmed")
check("기본값은 undemonstrated(보수적)", flag("x user.txt", "b" * 32).provenance == FLAG_UNDEMONSTRATED)

print("=== attempt.py 와의 접합 ===")
# confirmed 는 foothold 를 들고 와야 Attempt 가 강등하지 않는다
ev = shell(r)
a = Attempt(hid="h1", surface="http:80", commands=["x"], expected="shell",
            observed=ev.observed, verdict=ev.verdict, because=ev.because,
            foothold=ev.foothold)
check("confirmed 가 강등되지 않음", a.verdict == "confirmed" and not a.coerced)

# refuted 는 근거를 들고 와야 강등되지 않는다
ev = shell(banner)
a = Attempt(hid="h2", surface="http:80", commands=["x"], expected="shell",
            observed=ev.observed, verdict=ev.verdict, because=ev.because)
check("refuted 가 강등되지 않음", a.verdict == "refuted" and not a.coerced)

# inconclusive 는 그대로
ev = flag("cat /etc/hostname", "target")
a = Attempt(hid="h3", surface="http:80", commands=["x"], expected="flag",
            observed=ev.observed, verdict=ev.verdict, because=ev.because)
check("inconclusive 유지", a.verdict == "inconclusive")

print(f"\n{passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
