# 실행: htb-agent 디렉토리에서  python3 tests/test_lineage.py
#
# A5 — 타입드 리니지 그래프: 평면 evidence(사실→출처문자열)를 승격한 타입드 노드(종류·출처·
# 부모·콘텐츠해시)와 다중 홉 유래(chain)를 고정한다. 평면 evidence 하위호환도 함께 검증.
import sys
sys.path.insert(0, "src")
from htb_agent.world import WorldModel, LineageNode   # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

print("=== add_* 가 타입드 리니지 노드를 남긴다 ===")
w = WorldModel(target="10.129.1.5")
w.add_loot("config.php(노출)", source="curl .../config.php")
w.add_cred("admin:S3cret", source="cat config.php", parent="config.php(노출)",
           content_hash="deadbeef")
w.add_vuln("CVE-2021-1", source="searchsploit")
w.add_flag("user", "HTB{u}", source="ssh id")

check("cred 노드 종류/출처", w.lineage["admin:S3cret"].kind == "cred"
      and w.lineage["admin:S3cret"].source == "cat config.php")
check("cred 노드 부모 엣지(설정파일 loot)", w.lineage["admin:S3cret"].parent == "config.php(노출)")
check("cred 노드 콘텐츠해시(A7)", w.lineage["admin:S3cret"].content_hash == "deadbeef")
check("loot 노드 종류", w.lineage["config.php(노출)"].kind == "loot")
check("vuln 노드 종류", w.lineage["CVE-2021-1"].kind == "vuln")
check("flag 노드 종류/출처", w.lineage["HTB{u}"].kind == "flag"
      and w.lineage["HTB{u}"].source == "ssh id")

print("\n=== 평면 evidence 하위호환(문자열 출처) ===")
check("evidence 문자열 유지", w.evidence.get("admin:S3cret") == "cat config.php")
check("_with_src 부모 사슬 표시", "← config.php(노출)" in w._with_src("admin:S3cret"))

print("\n=== chain(): 다중 홉 유래 재구성 ===")
# config.php(노출) ← (parent 없음), admin:S3cret ← config.php(노출)
ch = w.chain("admin:S3cret")
check("chain 길이 2(자식→부모)", len(ch) == 2)
check("chain[0] 자식", ch[0].value == "admin:S3cret")
check("chain[1] 부모", ch[1].value == "config.php(노출)")

print("\n=== 사이클 방어 ===")
w2 = WorldModel(target="t")
w2.record_lineage("loot", "A", source="x", parent="B")
w2.record_lineage("loot", "B", source="y", parent="A")   # A↔B 사이클
cyc = w2.chain("A")
check("사이클이어도 유한 종료", len(cyc) <= 2)

print("\n=== to_dict 에 lineage 포함(리포트 내보내기) ===")
d = w.to_dict()
check("to_dict lineage 키", "lineage" in d and "admin:S3cret" in d["lineage"])
check("to_dict lineage 노드 직렬화", d["lineage"]["admin:S3cret"]["kind"] == "cred"
      and d["lineage"]["admin:S3cret"]["parent"] == "config.php(노출)")

print("\n=== 최초 출처 보존 + 부모/해시 보강 ===")
w3 = WorldModel(target="t")
w3.add_cred("u:p", source="first")
w3.add_cred("u:p", source="second", parent="loot1", content_hash="h1")  # 중복 — 출처 고정, 보강만
check("최초 출처 고정", w3.lineage["u:p"].source == "first")
check("부모 보강됨", w3.lineage["u:p"].parent == "loot1")
check("해시 보강됨", w3.lineage["u:p"].content_hash == "h1")

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
