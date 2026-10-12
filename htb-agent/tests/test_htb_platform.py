# 실행: htb-agent 디렉토리에서  python3 tests/test_htb_platform.py
#
# [G1] HTB 통합 — 플래그 제출/스폰 요청 구성·토큰 안전·VPN 프리플라이트. 네트워크 없이 http 주입.
import json
import sys

sys.path.insert(0, "src")
from htb_agent import htb_platform as H  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


class Stub:
    """주입 http — 요청을 포착하고 고정 응답 반환."""
    def __init__(self, code=200, text='{"message":"ok"}'):
        self.code, self.text = code, text
        self.calls = []
    def __call__(self, url, headers, body):
        self.calls.append((url, headers, json.loads(body.decode())))
        return self.code, self.text


print("=== clamp_difficulty(10~100, 10단위) ===")
check("30→30", H.clamp_difficulty(30) == 30)
check("5→10(하한)", H.clamp_difficulty(5) == 10)
check("200→100(상한)", H.clamp_difficulty(200) == 100)
check("47→40(10단위 내림)", H.clamp_difficulty(47) == 40)
check("비정수→30(기본)", H.clamp_difficulty("x") == 30)

print("\n=== submit_flag: POST machine/own {flag,id,difficulty} + Bearer ===")
s = Stub()
c = H.HtbClient(token="SECRET", http=s)
c.submit_flag(705, "HTB{flag}", difficulty=47)
url, headers, body = s.calls[0]
check("경로 machine/own", url.endswith("/machine/own"))
check("바디 flag/id/difficulty", body == {"flag": "HTB{flag}", "id": 705, "difficulty": 40})
check("Authorization Bearer 헤더", headers.get("Authorization") == "Bearer SECRET")

print("\n=== spawn_machine: POST vm/spawn {machine_id} ===")
s2 = Stub()
H.HtbClient(token="T", http=s2).spawn_machine(705)
check("경로 vm/spawn", s2.calls[0][0].endswith("/vm/spawn"))
check("바디 machine_id", s2.calls[0][2] == {"machine_id": 705})

print("\n=== 토큰 없으면 호출 안 하고 HtbError ===")
s3 = Stub()
c3 = H.HtbClient(token="", http=s3)
err = False
try:
    c3.submit_flag(1, "x")
except H.HtbError:
    err = True
check("토큰 없음 → HtbError", err)
check("http 호출 안 됨(토큰 없음)", s3.calls == [])
check("has_token False", c3.has_token is False)

print("\n=== 비2xx → HtbError, 토큰은 메시지에 노출 안 됨 ===")
s4 = Stub(code=403, text="forbidden")
c4 = H.HtbClient(token="SUPERSECRET", http=s4)
msg = ""
try:
    c4.submit_flag(1, "x")
except H.HtbError as e:
    msg = str(e)
check("403 → HtbError", "403" in msg)
check("토큰이 오류 메시지에 없음", "SUPERSECRET" not in msg)

print("\n=== 빈 플래그는 제출 안 함 ===")
s5 = Stub()
empty = False
try:
    H.HtbClient(token="T", http=s5).submit_flag(1, "   ")
except H.HtbError:
    empty = True
check("빈 플래그 → HtbError·미호출", empty and s5.calls == [])

print("\n=== VPN 프리플라이트(로컬·조언) ===")
ok, m = H.vpn_preflight("10.129.1.5", detect=lambda: [])
check("HTB 대역 + VPN 없음 → 경고", ok is False and "VPN" in m)
ok2, m2 = H.vpn_preflight("10.129.1.5", detect=lambda: ["10.10.14.9"])
check("HTB 대역 + VPN 있음 → 통과", ok2 is True)
ok3, m3 = H.vpn_preflight("192.168.1.5", detect=lambda: [])
check("HTB 대역 아님 → 판단 보류(통과·무경고)", ok3 is True and m3 == "")

print("\n=== 네트워크 장애(URLError) → HtbError(run 크래시 방지·감사 H4) ===")
import urllib.error  # noqa: E402


def _boom(*a, **k):
    raise urllib.error.URLError("Connection refused")


_orig = H.urllib.request.urlopen
H.urllib.request.urlopen = _boom
try:
    c_net = H.HtbClient(token="SUPERSECRET")   # 실제 _urllib_post 경로(http 미주입)
    net_raised = False
    net_msg = ""
    try:
        c_net.submit_flag(1, "HTB{x}")
    except H.HtbError as e:
        net_raised, net_msg = True, str(e)
    except urllib.error.URLError:
        net_raised = False   # URLError 가 새어나오면 실패(크래시 경로)
    check("URLError → HtbError 로 승격(uncaught 아님)", net_raised)
    check("네트워크 오류 메시지에도 토큰 미노출", "SUPERSECRET" not in net_msg)
finally:
    H.urllib.request.urlopen = _orig

print("\n=== submit-flags 안전 필터: exploit-derived 만 신뢰(감사 T1) ===")
from types import SimpleNamespace  # noqa: E402


def _prov(kind, value, verdict):
    return SimpleNamespace(kind=kind, value=value, verdict=verdict)


_report = SimpleNamespace(flag_provenance=[
    _prov("user", "HTB{exploit1}", "exploit-derived"),
    _prov("root", "HTB{exploit2}", "exploit-derived"),
    _prov("user", "HTB{local}", "local-derived"),
    _prov("user", "HTB{reason}", "reasoning-only"),
    _prov("root", "HTB{looked}", "looked-up"),
    _prov("user", "HTB{unver}", "unverified"),
])
_trusted = H.trusted_exploit_flags(_report)
check("exploit-derived 2건만 신뢰 집합에",
      _trusted == {("user", "HTB{exploit1}"), ("root", "HTB{exploit2}")})
check("local/reasoning/looked-up/unverified 전부 제외",
      all(v not in {x[1] for x in _trusted}
          for v in ["HTB{local}", "HTB{reason}", "HTB{looked}", "HTB{unver}"]))
check("flag_provenance 없는 report → 빈 집합(안전)",
      H.trusted_exploit_flags(SimpleNamespace()) == set())

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
