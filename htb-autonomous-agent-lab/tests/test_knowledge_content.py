# 실행: htb-agent 디렉토리에서  python3 tests/test_knowledge_content.py
# knowledge/ 디렉토리의 사용자 KB 콘텐츠를 회귀 보호한다(G3: 빈 KB 채움).
import glob
import json
import os
import sys
sys.path.insert(0, "src")
from htb_agent.knowledge import KnowledgeBase

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KDIR = os.path.join(ROOT, "knowledge")

print("=== 룰 파일 JSON 유효성 + 스키마 ===")
rule_files = sorted(glob.glob(os.path.join(KDIR, "rules", "*.json")))
check("룰 파일 다수 존재", len(rule_files) >= 5)
all_rules = []
bad = []
for f in rule_files:
    try:
        data = json.load(open(f, encoding="utf-8"))
    except json.JSONDecodeError:
        bad.append(f); continue
    items = data if isinstance(data, list) else [data]
    for it in items:
        if "name" not in it or "suggest" not in it or not it["suggest"]:
            bad.append(f"{f}:{it.get('name','?')}")
        all_rules.append(it)
check("모든 룰 파일 JSON 유효 + name/suggest 보유", not bad)

VALID_PHASES = {"enum", "access", "privesc", "lateral"}
VALID_OS = {"linux", "windows", "windows_ad"}
phase_bad = [it["name"] for it in all_rules if it.get("phase", "enum") not in VALID_PHASES]
check("phase 값 유효", not phase_bad)
os_bad = [it["name"] for it in all_rules
          for o in (it.get("when", {}) or {}).get("os", []) if o not in VALID_OS]
check("when.os 값 유효", not os_bad)

print("=== 로딩 후 커버리지 (시드+사용자) ===")
kb = KnowledgeBase.load(base_dir=KDIR)
WIN_PORTS = [88, 135, 139, 389, 445, 3389, 5985]
NIX_PORTS = [21, 22, 80, 443, 3306, 5432]
def names(osc, ports, svcs, phase):
    return [r.rule_name for r in kb.query(osc, ports, svcs, phase=phase)]

# G3 의 핵심 공백이던 privesc/lateral 이 실제로 채워졌는가
pl = names("linux", NIX_PORTS, ["ssh", "http"], "privesc")
pw = names("windows_ad", WIN_PORTS, ["smb", "ldap"], "privesc")
check("privesc(linux) 다수", len(pl) >= 4)
check("privesc(windows) 다수", len(pw) >= 4)
check("sudo 점검 포함", any("sudo" in n for n in pl))
check("토큰/Potato 포함", any("Potato" in n or "토큰" in n for n in pw))

lw = names("windows_ad", WIN_PORTS, ["smb"], "lateral")
check("lateral(windows) 존재", len(lw) >= 3)
check("Pass-the-Hash 포함", any("Pass-the-Hash" in n for n in lw))

# 서비스 열거 확장
check("MSSQL 열거 매칭", "MSSQL 열거" in names("windows", [1433], [], "enum"))
check("SNMP 열거 매칭", "SNMP 열거" in names("linux", [161], [], "enum"))
check("AD RID 브루트 매칭", "AD RID 브루트(널/게스트)" in names("windows_ad", [445], ["smb"], "enum"))

# G4 겹침 — privesc 열거 도구가 KB 에 등장(linpeas/winpeas/pspy)
allsug = " ".join(s for it in all_rules for s in it["suggest"])
check("linpeas 참조", "linpeas" in allsug.lower())
check("winPEAS 참조", "winpeas" in allsug.lower())
check("pspy 참조", "pspy" in allsug.lower())

print("=== 노트 로딩 ===")
kb_notes = KnowledgeBase.load(base_dir=KDIR).notes
check("방법론 노트 로드", any("방법론" in n or "privesc 순서" in n for n in kb_notes))

print(f"\n{passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
