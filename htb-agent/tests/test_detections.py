# 실행: htb-agent 디렉토리에서  python3 tests/test_detections.py
#
# [T1-c] 배포형 탐지 산출물 — Sigma/Suricata/ATT&CK Navigator/MISP/triage 를 '돌려볼 수 있는'
# 형태로 생성(생성 전용·방어용). 근거(탐지 CWE/CVE·대상) 있을 때만, 없으면 정직하게 생략.
import json
import sys
from types import SimpleNamespace

sys.path.insert(0, "src")
from htb_agent import detections  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


def rep(**kw):
    base = dict(target="10.129.1.5", detected_cwe=[], detected_cve=[],
                discovered_cve=[], vuln_matches=[], world=None)
    base.update(kw)
    return SimpleNamespace(**base)


print("=== Sigma: 탐지 CWE 에서 생성 ===")
r = rep(detected_cwe=["CWE-89", "CWE-78"])
sig = detections.sigma_rules(r)
check("CWE 2건 → Sigma 2건", len(sig) == 2)
check("SQLi Sigma 에 union select 포함", any("union select" in s for s in sig))
check("Sigma 에 attack 태그", any("attack.t1190" in s for s in sig))

print("\n=== Suricata: 네트워크 의미 CWE 만 ===")
sur = detections.suricata_rules(rep(detected_cwe=["CWE-89", "CWE-79"]))  # 79 는 네트워크 규칙 없음
check("CWE-89 만 Suricata(1건)", len(sur) == 1 and "sid:1000001" in sur[0])
check("Suricata 룰에 union select content", "union select" in sur[0].lower())

print("\n=== ATT&CK 매핑·Navigator layer ===")
techs = detections.attack_techniques(rep(detected_cwe=["CWE-89", "CWE-78", "CWE-434"]))
ids = {t[0] for t in techs}
check("CWE-89→T1190·78→T1059·434→T1505.003", ids == {"T1190", "T1059", "T1505.003"})
layer = detections.navigator_layer(rep(detected_cwe=["CWE-89"]))
check("Navigator layer JSON 직렬화 가능", isinstance(json.dumps(layer), str))
check("layer.techniques 에 T1190", any(t["techniqueID"] == "T1190" for t in layer["techniques"]))

print("\n=== MISP: 대상·CVE 를 IoC 로 ===")
ev = detections.misp_event(rep(detected_cve=["CVE-2025-57819"]))
attrs = ev["Event"]["Attribute"]
check("대상 IP ip-dst 포함", any(a["type"] == "ip-dst" and a["value"] == "10.129.1.5" for a in attrs))
check("CVE vulnerability 포함", any(a["value"] == "CVE-2025-57819" for a in attrs))
check("to_ids=False(방어 지표)", all(a["to_ids"] is False for a in attrs))
check("MISP JSON 직렬화 가능", isinstance(json.dumps(ev), str))

print("\n=== host-triage: 읽기 전용(파괴 명령 없음) ===")
ts = detections.host_triage_script(rep())
check("조회 명령 포함(실제 라인 id·uname·ss)",
      "id; uname -a" in ts and "ss -tlnp" in ts)
# 명령 위치 기준(앞 공백) — 'perm -4000' 의 'rm' 같은 부분문자열 오탐 방지
destructive = [" rm ", " chmod ", " chown ", " mkfs", " dd if=", "curl http",
               "wget http", "nc -e", " kill "]
check("파괴·공격 명령 없음(읽기 전용)", not any(d in ts for d in destructive))

print("\n=== Sigma 맵에 없는 CWE 는 조용히 생략(KeyError 금지) ===")
check("CWE-200(Sigma 맵 없음) → sigma 0건·무예외",
      detections.sigma_rules(rep(detected_cwe=["CWE-200"])) == [])
check("CWE-200 은 ATT&CK 매핑은 됨(T1595)",
      detections.attack_techniques(rep(detected_cwe=["CWE-200"]))[0][0] == "T1595")

print("\n=== vuln_matches 의 CWE 도 반영 ===")
vm = SimpleNamespace(name="FreePBX RCE", cwe=["CWE-89"], suggest=[])
check("vuln_matches.cwe 에서 Sigma 생성",
      len(detections.sigma_rules(rep(vuln_matches=[vm]))) == 1)

print("\n=== 근거 없으면 정직하게 생략 ===")
empty = rep(target="")
check("CWE·CVE·대상 모두 없음 → has_content False", detections.has_content(empty) is False)
md = detections.render_markdown(rep(target=""))
check("빈 근거 → 생략 안내(지어내지 않음)", "생략" in md)

print("\n=== render_markdown: 펜스 블록 포함 ===")
full = detections.render_markdown(rep(detected_cwe=["CWE-89"], detected_cve=["CVE-2025-57819"]))
check("Sigma yaml 블록", "```yaml" in full)
check("MISP json 블록", "```json" in full)
check("triage bash 블록", "```bash" in full)

print("\n=== Sigma YAML 이스케이프(감사 H2) — 작은따옴표 미이스케이프 시 파싱 불가 ===")
s89 = detections.sigma_rules(rep(detected_cwe=["CWE-89"]))[0]
# CWE-89 키워드 `' or '1'='1` 은 작은따옴표가 두 개로('') 이스케이프돼야 유효 YAML.
check("SQLi 키워드 작은따옴표 doubling('' )", "'' or ''1''=''1'" in s89)
# 모든 키워드 라인('      - '...'')의 작은따옴표 수가 짝수(여는/닫는 + 내부 doubling)여야 함.
_kw_lines = [ln for ln in s89.splitlines() if ln.strip().startswith("- '")]
check("모든 키워드 라인 작은따옴표 짝수(균형)", all(ln.count("'") % 2 == 0 for ln in _kw_lines))
check("원형 미이스케이프(' or '1'='1')가 그대로 남지 않음", "- '' or '1'='1'" not in s89)

print("\n=== Suricata content 이스케이프(감사 H3) — | ; 미이스케이프 시 적재 불가 ===")
s78 = detections.suricata_rules(rep(detected_cwe=["CWE-78"]))[0]
check("세미콜론은 |3B| 로 hex-escape(;id → |3B|id)", "|3B|id" in s78)
check("파이프는 |7C| 로 hex-escape(|nc → |7C|nc)", "|7C|nc" in s78)
check("원형 ';id' content 가 그대로 남지 않음", '"' + ";id" not in s78 and ';id"' not in s78)
# 원형 파이프로 시작하는 content 가 없어야 함(|7C| 이스케이프는 content:"|7C|..., 원형은 content:"|nc)
check("원형 '|nc' content 가 그대로 남지 않음", 'content:"|nc' not in s78)
# content 안의 모든 파이프는 |HH| 쌍 — 규칙 전체 파이프 개수가 짝수여야 적재 가능.
check("Suricata 룰 파이프 개수 짝수(hex 구분자 균형)", s78.count("|") % 2 == 0)
# `$(` 같은 비특수 출력가능 문자는 그대로 유지(과도한 이스케이프 아님)
check("$( 는 그대로 유지(비특수 문자)", "$(" in s78)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
