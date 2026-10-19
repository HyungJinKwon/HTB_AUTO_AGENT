# 실행: htb-agent 디렉토리에서  python3 tests/test_attempt.py
import sys

sys.path.insert(0, "src")
from htb_agent.attempt import Attempt, Candidate, CandidateError, Ledger  # noqa: E402

passed = failed = 0


def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")


def raises(fn, exc=CandidateError):
    try:
        fn(); return False
    except exc:
        return True


print("=== 후보: 검증 불가하면 생성 거부 ===")
ok = Candidate(surface="http:8080", summary="업로드 우회", commands=["echo x"],
               expected="업로드된 파일이 /uploads 에서 200 으로 응답")
check("정상 후보 생성", ok.hid.startswith("h") and len(ok.hid) == 9)
check("expected 없으면 거부", raises(lambda: Candidate(
    surface="http:80", summary="s", commands=["x"], expected="   ")))
check("commands 없으면 거부", raises(lambda: Candidate(
    surface="http:80", summary="s", commands=[], expected="뭔가")))
check("surface 없으면 거부", raises(lambda: Candidate(
    surface=" ", summary="s", commands=["x"], expected="뭔가")))
check("hid 지정 시 유지", Candidate(surface="s:1", summary="s", commands=["x"],
                                  expected="e", hid="fixed").hid == "fixed")

print("\n=== 판정 규율: 근거 없는 refuted 는 인정 안 함 ===")
a = Attempt(hid="h1", surface="smb:445", commands=["c"], expected="e",
            verdict="refuted", because="")
check("근거 없으면 inconclusive 강등", a.verdict == "inconclusive")
check("강등 사유를 기록", "근거" in a.coerced)
b = Attempt(hid="h1", surface="smb:445", commands=["c"], expected="e",
            verdict="refuted", because="해당 버전엔 그 파이프가 없음")
check("근거 있으면 refuted 유지", b.verdict == "refuted" and b.coerced == "")

print("\n=== 판정 규율: 전제조건 미충족은 가설 반증이 아님 ===")
c = Attempt(hid="h2", surface="http:80", commands=["c"], expected="e",
            verdict="refuted", because="도구가 안 깔려 있었음", precond_ok=False)
check("전제조건 실패 → inconclusive", c.verdict == "inconclusive")
check("전제조건 사유 명시", "전제조건" in c.coerced)

print("\n=== 판정 규율: 증거 없는 성공 주장 금지 ===")
d = Attempt(hid="h3", surface="http:80", commands=["c"], expected="e",
            verdict="confirmed", foothold="")
check("foothold 없는 confirmed 강등", d.verdict == "inconclusive")
e = Attempt(hid="h3", surface="http:80", commands=["c"], expected="e",
            verdict="confirmed", foothold="www-data 셸")
check("foothold 있으면 confirmed 유지", e.verdict == "confirmed")
check("알 수 없는 판정은 예외", raises(lambda: Attempt(
    hid="x", surface="s:1", commands=["c"], expected="e", verdict="maybe"), ValueError))

print("\n=== 원장: 접근면 소진 ===")
led = Ledger(max_retries=2, refute_cap=3)
for i in range(3):
    led.record(Attempt(hid=f"r{i}", surface="smb:445", commands=[f"c{i}"],
                       expected="e", verdict="refuted", because=f"근거{i}", seconds=5),
               summary=f"가설{i}")
check("refuted 3건 → 소진", led.surface_exhausted("smb:445") is True)
check("다른 접근면은 멀쩡", led.surface_exhausted("http:80") is False)
led.record(Attempt(hid="w", surface="smb:445", commands=["win"], expected="e",
                   verdict="confirmed", foothold="SMB 쓰기"))
check("성과 있으면 소진 아님", led.surface_exhausted("smb:445") is False)

print("\n=== 원장: inconclusive 재시도 상한 ===")
led2 = Ledger(max_retries=2)
led2.record(Attempt(hid="q", surface="http:80", commands=["c1"], expected="e"))
check("1회 후 재시도 가능", led2.retryable("q") is True)
led2.record(Attempt(hid="q", surface="http:80", commands=["c2"], expected="e"))
check("상한 도달 시 재시도 불가", led2.retryable("q") is False)
check("재시도 큐에서 제외", "q" not in led2.retry_queue())
led2.record(Attempt(hid="z", surface="http:80", commands=["c3"], expected="e"))
check("여력 있는 가설은 큐에 남음", led2.retry_queue() == ["z"])
led2.record(Attempt(hid="z", surface="http:80", commands=["c4"], expected="e",
                    verdict="refuted", because="경로 자체가 없음"))
check("반증되면 재시도 안 함", led2.retryable("z") is False)

print("\n=== 원장: 중복 명령 / 집계 / 미탐색 ===")
check("같은 명령 재실행 감지", led2.already_ran("c1") is True)
check("안 돌린 명령은 False", led2.already_ran("c999") is False)
check("footholds 수집", led.footholds() == ["SMB 쓰기"])
check("접근면 목록", led.surfaces() == ["smb:445"])
check("미탐색 접근면", led.untouched(["smb:445", "http:80", "ldap:389"])
      == ["http:80", "ldap:389"])
check("요약에 획득 표기", "SMB 쓰기" in led.summary())
check("요약에 소요시간", "15s" in led.summary())

print("\n=== 원장: 죽은 가설을 근거와 함께 (L4→L1) ===")
dead = led.dead_hypotheses()
check("반증 3건 반환", len(dead) == 3)
check("설명+근거 쌍", dead[0] == ("가설0", "근거0"))

print("\n=== 영속: 왕복 ===")
rt = Ledger.from_dict(led.to_dict())
check("시도 수 보존", len(rt.attempts()) == len(led.attempts()))
check("판정 보존", rt.count("refuted") == led.count("refuted"))
check("foothold 보존", rt.footholds() == led.footholds())
check("summary 매핑 보존", rt.dead_hypotheses() == led.dead_hypotheses())
check("상한 설정 보존", (rt.max_retries, rt.refute_cap) == (2, 3))
# 저장된 기록을 되살릴 때도 규율이 다시 적용돼야 한다
tampered = led.to_dict()
tampered["attempts"].append({"hid": "bad", "surface": "x:1", "commands": ["c"],
                             "expected": "e", "verdict": "refuted", "because": ""})
check("복원 시 규율 재적용", Ledger.from_dict(tampered).attempts()[-1].verdict
      == "inconclusive")

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
