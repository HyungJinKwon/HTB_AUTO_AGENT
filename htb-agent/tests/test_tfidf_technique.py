# 실행: htb-agent 디렉토리에서  python3 tests/test_tfidf_technique.py
#
# [T2-c] TF-IDF 코사인 관련도(knowledge.relevant_notes 보강) + [T2-b] 명령→ATT&CK 기법 라벨링.
import sys
from types import SimpleNamespace

sys.path.insert(0, "src")
from htb_agent import technique  # noqa: E402
from htb_agent.knowledge import KnowledgeBase  # noqa: E402
from htb_agent.tfidf import TfidfIndex, tokenize  # noqa: E402

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


print("=== TF-IDF: 토크나이즈·랭킹 ===")
check("tokenize 소문자 영숫자 2+(1글자 제외)",
      tokenize("FreePBX 16.0 RCE!") == ["freepbx", "16", "rce"])
docs = [
    "freepbx endpoint sqli rce unauth",     # 0
    "apache http server default page",      # 1
    "ssh openssh user enumeration cve",     # 2
]
idx = TfidfIndex(docs)
r = idx.rank(["freepbx", "rce"], limit=3)
check("freepbx rce 질의 → 문서0 최상위", r and r[0][0] == 0)
check("무관 질의는 결과 없음", idx.rank(["nonexistent", "zzz"]) == [])
check("점수 내림차순·동점 index 오름차순", all(
    r[i][1] >= r[i + 1][1] for i in range(len(r) - 1)))

print("\n=== 희귀 용어 가중(흔한 단어 지배 방지) ===")
docs2 = ["the server the the the", "rareword here"]
idx2 = TfidfIndex(docs2)
# 'rareword'(희귀)로 질의하면 문서1
rr = idx2.rank(["rareword"], limit=2)
check("희귀 용어 질의 → 해당 문서", rr and rr[0][0] == 1)

print("\n=== knowledge.relevant_notes 가 TF-IDF 사용 ===")
kb = KnowledgeBase(rules=[], notes=[
    "[seed-web] freepbx endpoint ajax unauth sqli to rce",
    "[seed-ssh] openssh username enumeration timing",
    "[seed-smb] samba usermap script rce",
])
top = kb.relevant_notes(["freepbx", "sqli"], limit=1)
check("freepbx sqli → freepbx 노트", "freepbx" in top[0].lower())
top2 = kb.relevant_notes(["openssh", "enumeration"], limit=1)
check("openssh → ssh 노트", "openssh" in top2[0].lower())
check("무관 질의는 앞 N개 폴백", len(kb.relevant_notes(["zzzznomatch"], limit=2)) == 2)
check("노트 없으면 빈 리스트", KnowledgeBase(rules=[], notes=[]).relevant_notes(["x"]) == [])

print("\n=== [T2-b] 명령 → ATT&CK 기법 ===")
check("nmap → T1046", technique.technique_of("nmap -sV 10.0.0.1") == ("T1046", "Network Service Discovery"))
check("ffuf → T1595.003", technique.technique_of("ffuf -w list -u http://x/FUZZ")[0] == "T1595.003")
check("hydra → T1110", technique.technique_of("hydra -l u -P p ssh://x")[0] == "T1110")
check("searchsploit → T1588.005", technique.technique_of("searchsploit freepbx")[0] == "T1588.005")
check("모르는 명령 → None", technique.technique_of("echo hello") is None)
check("빈 명령 → None", technique.technique_of("") is None)

print("\n=== coverage: ran 된 명령만·중복 제거 ===")
fs = [
    SimpleNamespace(command="nmap -sV x", ran=True),
    SimpleNamespace(command="nmap -p- x", ran=True),      # 같은 기법(중복)
    SimpleNamespace(command="ffuf -u x", ran=True),
    SimpleNamespace(command="hydra ...", ran=False),      # 미실행 제외
]
cov = technique.coverage(fs)
ids = [t[0] for t in cov]
check("nmap 1회(중복 제거)·ffuf 포함", ids == ["T1046", "T1595.003"])
check("미실행 hydra 제외(T1110 없음)", "T1110" not in ids)
md = technique.render_markdown(fs)
check("render 에 T1046 줄", "T1046" in md)
check("커버리지 없으면 안내", "없음" in technique.render_markdown([]))

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
