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

print("\n=== B5 관련도 기반 노트 랭킹(경량 RAG) ===")
kb_n = KnowledgeBase(rules=[], notes=[
    "SMB 널세션과 공유 열거: smbclient -N -L 로 익명 접근 점검",
    "Kerberoasting: SPN 계정 TGS 해시 획득 후 오프라인 크랙",
    "웹 디렉토리 퍼징과 LFI/SSRF 점검 노트",
])
# 'smb' 질의 → SMB 노트가 1순위
top = kb_n.relevant_notes(["smb", "kerberoasting"], limit=2)
check("관련 노트 우선(SMB 1순위)", "SMB 널세션" in top[0])
check("상한 준수(매칭 2개)", len(top) == 2)
# 매칭 1개면 1개만 반환(패딩 안 함)
one = kb_n.relevant_notes(["smb"], limit=3)
check("매칭 1개 → 1개만", len(one) == 1 and "SMB 널세션" in one[0])
# 'kerberos' 질의 → Kerberoasting 노트 포함
k = kb_n.relevant_notes(["kerberos", "spn"], limit=1)
check("kerberos 질의 → Kerberoast 노트", "Kerberoasting" in k[0])
# 매칭 없으면 앞 N개 폴백
fb = kb_n.relevant_notes(["무관단어xyz"], limit=2)
check("매칭 없음 → 앞 N개 폴백", len(fb) == 2 and fb[0] == kb_n.notes[0])
# 빈 용어 → 폴백
check("빈 용어 → 앞 N개", kb_n.relevant_notes([], limit=1) == kb_n.notes[:1])
# 노트 없으면 빈 리스트
check("노트 없음 → 빈 리스트", KnowledgeBase(rules=[], notes=[]).relevant_notes(["smb"]) == [])

print("\n=== 비UTF-8 파일(예: cp949 메모)도 로드 실패 없이 처리 ===")
with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "notes")); os.makedirs(os.path.join(d, "rules"))
    with open(os.path.join(d, "notes", "my-notes.md"), "wb") as f:
        f.write("한글 메모 smb".encode("cp949"))
    with open(os.path.join(d, "notes", "ok.md"), "w", encoding="utf-8") as f:
        f.write("정상 노트")
    with open(os.path.join(d, "rules", "r.json"), "wb") as f:
        f.write('{"name": "한글", "when": {}, "suggest": []}'.encode("cp949"))
    kb = KnowledgeBase.load(d)
    check("cp949 노트 → 예외 없이 로드(대체 문자)", any("my-notes.md" in n for n in kb.notes)
          and any("정상 노트" in n for n in kb.notes))
    check("cp949 규칙 파일 → 경고 후 건너뜀", any("r.json" in w for w in kb.warnings))

print("\n=== 서비스 열거 일반 규칙(service-enum.json) 로드·질의 ===")
# 라이트업 역량 공백 분석으로 신설한 머신 비의존 정석 규칙(NFS·SNMP·WordPress).
if os.path.isdir("knowledge"):
    rkb = KnowledgeBase.load(base_dir="knowledge")
    nfs = rkb.query("linux", [2049], ["nfs"], phase="enum")
    snmp = rkb.query("linux", [161], ["snmp"], phase="enum")
    check("NFS export 열거 규칙 질의됨", any("showmount" in r.rule_name or "NFS" in r.rule_name for r in nfs))
    check("SNMP 커뮤니티 열거 규칙 질의됨", any("SNMP" in r.rule_name for r in snmp))
    check("WordPress 규칙 존재", any("WordPress" in r.name for r in rkb.rules))
    # 틈새 기법 규칙(AD CS/NoSQLi/JWT) + 모든 규칙 phase 명시(위생)
    check("AD CS(certipy) 규칙 존재", any("AD CS" in r.name for r in rkb.rules))
    check("NoSQLi·JWT 규칙 존재",
          any("NoSQL" in r.name for r in rkb.rules) and any("JWT" in r.name for r in rkb.rules))
    check("모든 규칙 phase 명시(결측 0)", all(r.phase for r in rkb.rules))
else:
    check("knowledge 디렉터리 없음 — 스킵(비레포 실행)", True)

print("\n=== _lowered_notes 캐시: 중간 원소 교체도 감지(감사 A-LOW8) ===")
kb2 = KnowledgeBase(rules=[], notes=["alpha sqlinjection tips", "beta ssh notes"])
_ = kb2.relevant_notes(["sqlinjection"])          # 캐시 워밍(두 노트 lower 캐시)
kb2.notes[0] = "gamma kerberoasting steps"        # 마지막이 아닌 원소를 in-place 교체(길이 불변)
r = kb2.relevant_notes(["kerberoasting"])
check("교체된 노트 내용이 관련도 검색에 반영(stale 캐시 아님)",
      any("kerberoasting" in n for n in r))
check("교체로 사라진 내용은 노트에 없음", not any("sqlinjection" in n for n in kb2.notes))

print("\n=== TF-IDF 색인 캐시: 동일 노트 재사용·변경 시 재구성 ===")
kb3 = KnowledgeBase(rules=[], notes=["alpha sqli tips", "beta ssh notes"])
idx_a = kb3._tfidf_index()
idx_b = kb3._tfidf_index()
check("동일 노트 → 색인 객체 재사용(재구성 안 함)", idx_a is idx_b)
kb3.notes.append("gamma kerberoasting")           # 노트 추가 → 시그니처 변화 → 재구성
idx_c = kb3._tfidf_index()
check("노트 변경 → 색인 재구성(stale 아님)", idx_c is not idx_a)
check("재구성된 색인이 새 노트 반영",
      any("kerberoasting" in kb3.notes[i] for i, _ in idx_c.rank(["kerberoasting"], limit=1)))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
