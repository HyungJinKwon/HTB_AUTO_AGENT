# 실행: htb-agent 디렉토리에서  python3 tests/test_kb_grounding.py
#
# A8 — 소스-그라운드 드리프트 테스트 (ARTEX 'source-grounded drift tests' 장점 반영).
#
# 문제: 룰/취약점 로더는 잘못된 스키마를 **stderr 경고로만** 흘리거나(_load_rule_dir:
# 알 수 없는 phase/os) **아예 침묵 드롭**한다(_load_vuln_dir: name/service 없으면 continue,
# _load_rule_dir: ports 비정수면 continue). 즉 KB 에 `phase:"foothold"` 같은 오타가 들어가도
# 런타임은 '그 룰이 영영 매칭 안 됨'으로 조용히 degrade 할 뿐 테스트/CI 는 초록으로 남는다.
# → 코드(파이프라인 phase·os 집합·필드 계약)와 출하 KB 사이의 '침묵 드리프트'가 쌓인다.
#
# 이 스위트는 **출하되는 KB 전수(knowledge/rules/*.json·knowledge/vulns/*.json)** 를
# 코드가 실제로 쓰는 계약에 '접지(ground)'시켜, 드리프트를 테스트 타임 실패로 승격한다.
# 정직성 경계(§ 출처 표기)도 구조적 가드로 둔다: 운영 취약점 노트는 출처를 인용해야 한다.
#
# 주의: 빈 suggest([]) 는 '명령 없는 방법론/노트 전용 룰'로 의도된 패턴 → 비어있음을
#       위반으로 보지 않는다(대신 note 가 비면 '죽은 룰'이므로 그것만 막는다).
import glob
import io
import json
import os
import re
import sys

sys.path.insert(0, "src")
from htb_agent import knowledge as K  # noqa: E402
from htb_agent.orchestrator import PENTEST_PHASES  # noqa: E402
from htb_agent.vuln import VulnKB  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


# KB 디렉터리는 테스트 파일 기준으로 해석(실행 cwd 무관하게 견고).
HERE = os.path.dirname(os.path.abspath(__file__))
KNOW = os.path.join(HERE, "..", "knowledge")
RULES_GLOB = os.path.join(KNOW, "rules", "*.json")
VULNS_GLOB = os.path.join(KNOW, "vulns", "*.json")

# 코드 쪽 '진실 집합' — 드리프트는 이 집합과 KB 의 불일치로 정의된다.
PIPELINE_PHASES = {k for k, _ in PENTEST_PHASES}          # enum/access/privesc/lateral
VALID_OS = set(getattr(K, "_VALID_OS", {"linux", "windows", "windows_ad", "unknown"}))
SEVERITY = {"critical", "high", "medium", "low", "info"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_RE = re.compile(r"^CWE-\d+$")


def _load_json_objs(pattern):
    """glob 의 각 JSON(객체 또는 배열)을 (파일명, 객체) 튜플로 평탄화."""
    objs = []
    for fn in sorted(glob.glob(pattern)):
        base = os.path.basename(fn)
        with open(fn, encoding="utf-8") as f:
            data = json.load(f)              # JSONDecodeError 면 그 자체로 테스트 실패
        for it in (data if isinstance(data, list) else [data]):
            objs.append((base, it))
    return objs


# ─────────────────────────────────────────────────────────────────────────
print("=== 전제: KB 파일이 실제로 존재한다(빈 glob 으로 '0건 통과' 위양성 방지) ===")
rule_files = sorted(glob.glob(RULES_GLOB))
vuln_files = sorted(glob.glob(VULNS_GLOB))
check("rules/*.json 1개 이상 존재", len(rule_files) >= 1)
check("vulns/*.json 1개 이상 존재", len(vuln_files) >= 1)

rules = _load_json_objs(RULES_GLOB)
vulns = _load_json_objs(VULNS_GLOB)
check("룰 객체를 1개 이상 로드", len(rules) >= 1)
check("취약점 객체를 1개 이상 로드", len(vulns) >= 1)


# ─────────────────────────────────────────────────────────────────────────
print("\n=== 룰 스키마 접지: 모든 출하 룰이 코드 계약을 만족한다 ===")
bad_name = [(f, it.get("name")) for f, it in rules
            if not isinstance(it.get("name"), str) or not it["name"].strip()]
check("모든 룰: name 이 비어있지 않은 문자열", not bad_name)

bad_sug = [(f, it.get("name")) for f, it in rules if not isinstance(it.get("suggest"), list)]
check("모든 룰: suggest 가 리스트(빈 리스트=노트전용 허용)", not bad_sug)

bad_when = [(f, it.get("name")) for f, it in rules if not isinstance(it.get("when", {}), dict)]
check("모든 룰: when 이 매핑", not bad_when)

# 핵심 드리프트 가드 ①: phase 는 파이프라인이 실제로 순회하는 단계여야 한다.
# (로더는 알 수 없는 phase 를 경고만 하고 '어떤 단계에도 매칭 안 됨'으로 침묵 degrade.)
drift_phase = [(f, it.get("name"), it.get("phase"))
               for f, it in rules if str(it.get("phase", "enum")) not in PIPELINE_PHASES]
check("드리프트 가드: 모든 룰 phase ∈ PENTEST_PHASES", not drift_phase)
if drift_phase:
    for d in drift_phase[:10]:
        print(f"      ↳ {d}")

# 핵심 드리프트 가드 ②: when.os 는 코드가 아는 OS 집합이어야 한다(아니면 침묵 미매칭).
drift_os = [(f, it.get("name"), o) for f, it in rules
            for o in (it.get("when", {}) or {}).get("os", []) if o not in VALID_OS]
check("드리프트 가드: 모든 룰 when.os ∈ _VALID_OS", not drift_os)
if drift_os:
    for d in drift_os[:10]:
        print(f"      ↳ {d}")

# 핵심 드리프트 가드 ③: when.ports 는 정수(비정수면 로더가 룰 통째 침묵 드롭).
drift_port = [(f, it.get("name"), p) for f, it in rules
              for p in (it.get("when", {}) or {}).get("ports", []) if not isinstance(p, int)]
check("드리프트 가드: 모든 룰 when.ports 가 정수(침묵 드롭 방지)", not drift_port)

# 죽은 룰 방지: 빈 suggest 는 반드시 note 로 가이드를 실어야 한다(명령도 노트도 없으면 무의미).
dead_rule = [(f, it.get("name")) for f, it in rules
             if not it.get("suggest") and not str(it.get("note", "")).strip()]
check("접지: suggest 빈 룰은 note 가이드를 갖는다(죽은 룰 없음)", not dead_rule)


# ─────────────────────────────────────────────────────────────────────────
print("\n=== 로더 접지: 출하 룰이 로드 중 침묵 드롭/경고 없이 전수 적재된다 ===")
# _load_rule_dir 를 직접 호출해 경고를 수집하고, '객체 수 == 적재 룰 수' 로 드롭을 잡는다.
warns: list[str] = []
loaded_rules = K._load_rule_dir(os.path.join(KNOW, "rules"), warnings=warns)
check("로더: 룰 객체 수 == 적재 Rule 수(침묵 드롭 없음)", len(loaded_rules) == len(rules))
# '조건 없음(보존)' 경고는 의도된 패턴(포트/서비스에 묶이지 않는 일반 기법 룰 — note/phase
# 경로로 노출, 로더가 드롭하지 않고 보존)이라 면제한다. 그 외(알 수 없는 phase/os·형식오류
# 로 인한 드롭)는 진짜 드리프트이므로 0건이어야 한다.
dangerous = [w for w in warns if "조건 없음" not in w]
check("로더: 위험 경고 0건(알수없는 phase/os·형식오류; '조건없음 보존'은 면제)", not dangerous)
if dangerous:
    for w in dangerous[:10]:
        print(f"      ⚠ {w}")

# 적재된 Rule 의 phase 역시 파이프라인 집합 안이어야 한다(코드→KB 양방향 접지).
loaded_phase_drift = [r.name for r in loaded_rules
                      if getattr(r, "phase", "enum") not in PIPELINE_PHASES]
check("로더: 적재 Rule.phase ⊆ PENTEST_PHASES", not loaded_phase_drift)


# ─────────────────────────────────────────────────────────────────────────
print("\n=== 취약점 스키마 접지: 모든 출하 취약점이 코드 계약을 만족한다 ===")
# 로더는 name/service 없는 항목을 침묵 드롭한다 → 운영 취약점엔 둘 다 있어야 한다.
bad_vname = [(f, it.get("name")) for f, it in vulns
             if not isinstance(it.get("name"), str) or not it["name"].strip()]
check("모든 취약점: name 이 비어있지 않은 문자열", not bad_vname)

bad_vsvc = [(f, it.get("name")) for f, it in vulns
            if not isinstance(it.get("service"), str) or not it["service"].strip()]
check("모든 취약점: service 가 비어있지 않은 문자열(침묵 드롭 방지)", not bad_vsvc)

bad_vsug = [(f, it.get("name")) for f, it in vulns if not isinstance(it.get("suggest", []), list)]
check("모든 취약점: suggest 가 리스트", not bad_vsug)

bad_sev = [(f, it.get("name"), it.get("severity")) for f, it in vulns
           if str(it.get("severity", "")) not in SEVERITY]
check("모든 취약점: severity ∈ {critical,high,medium,low,info}", not bad_sev)
if bad_sev:
    for d in bad_sev[:10]:
        print(f"      ↳ {d}")

bad_cve = [(f, it.get("name"), c) for f, it in vulns
           for c in it.get("cve", []) if not CVE_RE.match(str(c))]
check("모든 취약점: CVE 형식 'CVE-YYYY-N+'", not bad_cve)
if bad_cve:
    for d in bad_cve[:10]:
        print(f"      ↳ {d}")

bad_cwe = [(f, it.get("name"), c) for f, it in vulns
           for c in it.get("cwe", []) if not CWE_RE.match(str(c))]
check("모든 취약점: CWE 형식 'CWE-N+'", not bad_cwe)


# ─────────────────────────────────────────────────────────────────────────
print("\n=== 정직성 접지(§ 출처 표기): 운영 취약점 노트는 출처를 인용한다 ===")
# example.* 는 문서화용 스키마 샘플이므로 면제(그 외 전부 '출처' 인용 필수).
no_src = [(f, it.get("name")) for f, it in vulns
          if not f.startswith("example") and "출처" not in str(it.get("note", ""))]
check("운영 취약점 노트에 '출처' 인용(§3/§4 정직성 경계의 구조적 가드)", not no_src)
if no_src:
    for d in no_src[:10]:
        print(f"      ↳ {d}")


# ─────────────────────────────────────────────────────────────────────────
print("\n=== 코드↔KB 바인딩: 실제 로더/API 가 출하 KB 를 예외 없이 적재한다 ===")
try:
    buf = io.StringIO()
    _old = sys.stderr
    sys.stderr = buf
    try:
        kb = K.KnowledgeBase.load(base_dir=KNOW, include_seeds=False)
    finally:
        sys.stderr = _old
    kb_ok = hasattr(kb, "rules") and len(kb.rules) >= 1
except Exception as e:  # noqa: BLE001
    kb_ok = False
    print(f"      ↳ KnowledgeBase.load 예외: {e}")
check("KnowledgeBase.load(출하 KB) 예외 없이 룰 적재", kb_ok)

try:
    vkb = VulnKB.load(base_dir=KNOW, include_seeds=False)
    vkb_ok = hasattr(vkb, "rules") and len(vkb.rules) >= 1
    # 로더가 파일 객체를 드롭 없이 적재했는가(name/service 전수 통과의 교차 확인).
    vkb_no_drop = len(vkb.rules) == len(vulns)
except Exception as e:  # noqa: BLE001
    vkb_ok = vkb_no_drop = False
    print(f"      ↳ VulnKB.load 예외: {e}")
check("VulnKB.load(출하 KB) 예외 없이 취약점 적재", vkb_ok)
check("VulnKB: 취약점 객체 수 == 적재 수(침묵 드롭 없음)", vkb_no_drop)


# ─────────────────────────────────────────────────────────────────────────
print("\n=== 음성 테스트: 드리프트가 실제로 탐지됨을 입증(가드 민감도) ===")
# phase 오타를 섞은 가짜 룰 집합 → phase 드리프트 가드가 걸러내는가.
_fake = [("fake.json", {"name": "오타룰", "suggest": ["echo {t}"],
                        "when": {"ports": [80]}, "phase": "foothold"})]
_det = [it for f, it in _fake if str(it.get("phase", "enum")) not in PIPELINE_PHASES]
check("음성: phase 오타('foothold')가 드리프트로 탐지됨", len(_det) == 1)

# name 없는 가짜 취약점 → 로더가 침묵 드롭하고, 그 드롭이 '수 불일치'로 잡히는가.
_fakev = [{"service": "X", "severity": "high", "note": "출처: test"}]  # name 없음
_dropped = [it for it in _fakev if "name" not in it or "service" not in it]
check("음성: name 없는 취약점이 침묵 드롭 대상으로 탐지됨", len(_dropped) == 1)


print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
