# 실행: htb-agent 디렉토리에서  python3 tests/test_knowledge.py
import sys, os, tempfile, json
sys.path.insert(0, "src")
from htb_agent.knowledge import KnowledgeBase

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== 시드 규칙 질의 ===")
kb = KnowledgeBase.load()
# 웹 포트 → 웹 열거 제안
recs = kb.query("linux", [22, 80], ["ssh", "http"])
names = [r.rule_name for r in recs]
check("웹 열거 규칙 매칭", "웹 기초 열거" in names)
check("관련없는 AD 규칙 제외", "AD BloodHound 수집" not in names)

# Windows AD → AD 규칙
recs = kb.query("windows_ad", [88, 389, 445], ["kerberos", "ldap", "microsoft-ds"])
names = [r.rule_name for r in recs]
check("SMB 열거 매칭", "SMB 열거(인증없음)" in names)
check("AD BloodHound 매칭", "AD BloodHound 수집" in names)
check("점수 정렬(OS+포트 우선)", recs[0].score >= recs[-1].score)

print("\n=== 플레이스홀더 치환/수동분류 ===")
cmd, auto = kb.format_suggestion("netexec smb {t}", "10.129.1.5")
check("{t} 치환 + 자동실행 가능", cmd == "netexec smb 10.129.1.5" and auto)
cmd, auto = kb.format_suggestion("evil-winrm -i {t} -u {user} -p {pass}", "10.129.1.5")
check("크리덴셜 플레이스홀더 → 수동", (not auto) and "{user}" in cmd)

print("\n=== 사용자 학습데이터로 성장 ===")
with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "rules"))
    os.makedirs(os.path.join(d, "notes"))
    rule = {"name": "내 커스텀 웹규칙",
            "when": {"ports": [80], "services": ["http"]},
            "suggest": ["feroxbuster -u http://{t}"],
            "note": "내 노하우", "tags": ["web"]}
    with open(os.path.join(d, "rules", "my.json"), "w", encoding="utf-8") as f:
        json.dump(rule, f, ensure_ascii=False)
    with open(os.path.join(d, "notes", "tips.md"), "w", encoding="utf-8") as f:
        f.write("# 내 노트\nvhost 꼭 확인")
    kb2 = KnowledgeBase.load(base_dir=d)
    recs = kb2.query("linux", [80], ["http"])
    names = [r.rule_name for r in recs]
    check("사용자 규칙 로드(성장)", "내 커스텀 웹규칙" in names)
    check("사용자 규칙 source 표기", any(r.source.startswith("user:") for r in recs))
    check("사용자 노트 로드", any("내 노트" in n for n in kb2.notes))
    check("시드+사용자 병합", len(kb2.rules) > len(KnowledgeBase.load(include_seeds=False, base_dir=d).rules))

print("\n=== 잘못된 규칙 파일 내성 ===")
with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "rules"))
    with open(os.path.join(d, "rules", "bad.json"), "w") as f:
        f.write("{ this is not json ")
    with open(os.path.join(d, "rules", "incomplete.json"), "w") as f:
        json.dump({"name": "불완전"}, f)  # suggest 없음
    kb3 = KnowledgeBase.load(base_dir=d)   # 깨지지 않아야
    check("깨진/불완전 규칙 무시하고 로드", len(kb3.rules) >= 1)

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
