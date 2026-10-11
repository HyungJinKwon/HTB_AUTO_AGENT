# 실행: htb-agent 디렉토리에서  python3 tests/test_cve_discovery.py
#
# 제품→CVE 자동발견 (enrich.discover_by_product) — 네트워크는 주입 fetcher 로 모사.
# 기존 enrich 는 '이미 아는 CVE ID' 만 조회했다 → KB 룰 없는 신종 취약점은 버전을 정확히
# 탐지하고도 묻혔다(connected.htb / FreePBX 16.0.40.7 실사례). 이 스위트는 역질의가 그 갭을
# 닫는지(제품→CVE), 버전필터가 과매칭을 배제하는지, CVSS 랭킹이 맞는지 고정한다.
import json
import sys

sys.path.insert(0, "src")
from htb_agent.enrich import Enricher, _version_applies  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


def _cpe(product, end_excl=None, end_incl=None, start_incl=None, ver="*", vulnerable=True):
    m = {"criteria": f"cpe:2.3:a:vendor:{product}:{ver}:*:*:*:*:*:*:*", "vulnerable": vulnerable}
    if end_excl:
        m["versionEndExcluding"] = end_excl
    if end_incl:
        m["versionEndIncluding"] = end_incl
    if start_incl:
        m["versionStartIncluding"] = start_incl
    return {"nodes": [{"cpeMatch": [m]}]}


# NVD keywordSearch 모사 페이로드 — FreePBX 3건:
#  · CRITICAL(9.8) endpoint <16.0.89  → 16.0.40.7 적용(발견돼야 함)
#  · HIGH(7.5)     <13.0.0            → 16.0.40.7 미적용(버전필터로 배제돼야 함)
#  · MEDIUM(5.3)   범위 미기재        → 보수적 포함(단 CVSS 낮아 후순위)
_NVD_FREEPBX = json.dumps({"vulnerabilities": [
    {"cve": {
        "id": "CVE-2025-57819",
        "descriptions": [{"lang": "en", "value": "FreePBX endpoint unauth SQLi to RCE"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}, "baseSeverity": "CRITICAL"}]},
        "weaknesses": [{"description": [{"value": "CWE-89"}, {"value": "CWE-288"}]}],
        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2025-57819"}],
        "published": "2025-08-28T00:00:00",
        "configurations": [_cpe("freepbx", end_excl="16.0.89")]}},
    {"cve": {
        "id": "CVE-2016-99999",
        "descriptions": [{"lang": "en", "value": "Old FreePBX issue"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}, "baseSeverity": "HIGH"}]},
        "weaknesses": [], "references": [], "published": "2016-01-01T00:00:00",
        "configurations": [_cpe("freepbx", end_excl="13.0.0")]}},
    {"cve": {
        "id": "CVE-2020-12345",
        "descriptions": [{"lang": "en", "value": "FreePBX info leak"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.3}, "baseSeverity": "MEDIUM"}]},
        "weaknesses": [], "references": [], "published": "2020-01-01T00:00:00",
        "configurations": []}},   # 범위 미기재 → 보수적 포함
]})


def fetcher(url):
    if "keywordSearch" in url:
        return _NVD_FREEPBX
    if "api.github.com" in url:
        return json.dumps({"items": [{"html_url": "https://github.com/x/CVE-2025-57819-poc"}]})
    return None


E = Enricher(cache_dir="/tmp/assassin_cve_disco_test", fetch_fn=fetcher, enabled=True, want_poc=True)

print("=== 제품→CVE 역탐색: FreePBX 16.0.40.7 ===")
found = E.discover_by_product("FreePBX", "16.0.40.7")
ids = [c.id for c in found]
check("CVE-2025-57819 자동발견됨(KB 룰 없이도)", "CVE-2025-57819" in ids)
check("버전 밖(<13.0.0) CVE-2016-99999 배제", "CVE-2016-99999" not in ids)
check("범위 미기재 CVE-2020-12345 보수적 포함", "CVE-2020-12345" in ids)
check("CVSS 내림차순 랭킹 — 1위가 9.8 critical", ids and ids[0] == "CVE-2025-57819")
top = found[0] if found else None
check("발견 CVE 에 PoC 레포 자동 수집", bool(top and top.poc_repos))
check("severity/cwe 파싱", bool(top and top.severity == "CRITICAL" and "CWE-288" in top.cwe))

print("\n=== 버전 적용범위 판정(_version_applies) 단위 ===")
cve_end_excl = {"configurations": [_cpe("freepbx", end_excl="16.0.89")]}
check("16.0.40.7 < 16.0.89(excluding) → 적용", _version_applies(cve_end_excl, "freepbx", "16.0.40.7"))
check("16.0.89 == endExcluding → 미적용", not _version_applies(cve_end_excl, "freepbx", "16.0.89"))
check("16.0.90 > 16.0.89 → 미적용", not _version_applies(cve_end_excl, "freepbx", "16.0.90"))
rng = {"configurations": [_cpe("freepbx", start_incl="16.0.0", end_incl="16.0.88")]}
check("범위 [16.0.0,16.0.88] 안의 16.0.40.7 → 적용", _version_applies(rng, "freepbx", "16.0.40.7"))
check("범위 밖 15.0.1 → 미적용", not _version_applies(rng, "freepbx", "15.0.1"))
noconf = {"configurations": []}
check("CPE 미기재 → 보수적 포함(True)", _version_applies(noconf, "freepbx", "16.0.40.7"))
other = {"configurations": [_cpe("apache", end_excl="2.5")]}
check("무관 제품 CPE 만 있으면 포함(제품 불일치→판단불가)", _version_applies(other, "freepbx", "16.0.40.7"))

print("\n=== 가드: 비활성/빈 제품 ===")
check("enabled=False → 빈 목록", Enricher(fetch_fn=fetcher, enabled=False).discover_by_product("FreePBX", "16.0") == [])
check("빈 제품명 → 빈 목록", E.discover_by_product("", "16.0") == [])

print("\n=== 음성: 버전 미지정이면 과매칭(범위필터 없음) ===")
# 버전 없으면 버전필터를 건너뛰어 전부 반환 — 그래서 상위 호출부는 '버전 있는 제품'만 질의함.
found_nov = E.discover_by_product("FreePBX", "")
check("버전 없으면 저버전 CVE 도 반환(필터 없음 입증)", "CVE-2016-99999" in [c.id for c in found_nov])

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
