# 실행: htb-agent 디렉토리에서  python3 tests/test_plan.py
# 하이브리드 방향성: 가설 기록(계획 원장) · 분석가 갱신 모드 · 의미 있는 변화 때만 재계획 ·
# '지금 할 일 1개' · 기대 신호 대조 · 막힘 2회 → 재계획 · 재개 시 계획 이어가기.
import contextlib
import io
import json
import os
import sys
import tempfile

sys.path.insert(0, "src")
from htb_agent import hypotheses as HY
from htb_agent.hypotheses import HypothesisLedger
from htb_agent.knowledge import KnowledgeBase, Rule
from htb_agent.llm.fake_provider import FakeProvider
from htb_agent.llm.router import LLMRouter
from htb_agent.orchestrator import Orchestrator
from htb_agent.scope_guard import ScopeGuard
from htb_agent.state import StateStore
from htb_agent.tools.recon import auto_approve_in_scope
from htb_agent.tools.runner import FakeRunner, RunOutput

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ✅ {name}")
    else:    failed += 1; print(f"  ❌ {name}")

T = "10.129.1.5"

print("=== 가설 기록: 병합(처음부터 다시 쓰지 않음) ===")
L = HypothesisLedger()
n = L.apply_update({"hypotheses": [
    {"id": "H1", "text": "숨은 관리자 경로", "priority": "상", "check": "ffuf", "expected": "/admin 200"},
    {"id": "H2", "text": "기본 자격증명", "priority": "중"}]})
check("새 가설 2개 반영", n == 2 and [h.id for h in L.items] == ["H1", "H2"])
L.get("H1").tried.append("curl x"); L.get("H1").misses = 2
L.apply_update({"hypotheses": [{"id": "H1", "text": "숨은 관리자 경로(갱신)", "status": "testing"}]})
h1 = L.get("H1")
check("기존 ID 갱신 시 시도 이력 유지", h1.tried == ["curl x"] and h1.text.endswith("(갱신)"))
check("상태만 바꾸고 확인 방법 그대로면 연속 불일치 유지", h1.misses == 2)
L.apply_update({"hypotheses": [{"id": "H1", "check": "gobuster 다른 워드리스트"}]})
check("확인 방법을 바꾸면 연속 불일치 0(새 기회)", L.get("H1").misses == 0)
check("언급하지 않은 가설은 삭제 안 함", L.get("H2") is not None)
check("갱신 횟수(revision) 증가", L.revision == 3)
for i in range(3, 12):
    L.apply_update({"hypotheses": [{"id": f"H{i}", "text": f"가설 {i}"}]})
check(f"활성 가설 상한 {HY.MAX_ACTIVE}", len([h for h in L.items if h.status != "rejected"]) == HY.MAX_ACTIVE)
check("텍스트 없는 새 ID 는 무시", HypothesisLedger().apply_update([{"id": "H1"}]) == 0)
check("ID 없는 항목 무시", HypothesisLedger().apply_update([{"text": "x"}]) == 0)
check("이상한 입력 무시", HypothesisLedger().apply_update("nope") == 0)
check("parse_id", HY.parse_id("가설 h3: x") == "H3" and HY.parse_id("none") == "")

print("\n=== 분석가 응답 해석: JSON 줄 우선, 텍스트 줄 폴백 ===")
txt = ('가설:\n  H1 [우선:상] SMB 익명 — 근거 〔추정〕 · 확인: smbclient -L · 기각 시: RPC\n'
       '가설기록: {"hypotheses":[{"id":"H1","text":"SMB 익명 접근","priority":"상",'
       '"expected":"Sharename"}]}\n확신도: 중')
L2 = HypothesisLedger()
check("JSON 줄 해석", L2.apply_text(txt) == 1 and L2.get("H1").expected == "Sharename")
check("표시용 텍스트에서 기계용 줄 제거", "가설기록" not in HY.strip_ledger_json(txt)
      and "확신도: 중" in HY.strip_ledger_json(txt))
L3 = HypothesisLedger()
L3.apply_text("가설:\n  H1 [우선:상] (SMB 익명) — 근거 〔추정〕 · 확인: smbclient -L · 기각 시: RPC\n"
              "  H2 [우선:하] 웹 LFI — 근거 약함\n확신도: 하")
check("텍스트 폴백: 가설 2개", [h.id for h in L3.items] == ["H1", "H2"])
check("텍스트 폴백: 우선·확인·대안", L3.get("H1").priority == "상" and L3.get("H1").check == "smbclient -L"
      and L3.get("H1").fallback == "RPC" and L3.get("H2").priority == "하")
check("깨진 JSON 이면 텍스트 폴백", HypothesisLedger().apply_text(
    '가설기록: {"hypotheses": [오류\n  H1 [우선:중] 대체 가설') == 1)

print("\n=== 기대 신호 대조(규칙 기반) ===")
check("경로 단서 일치", HY.match_signal("/admin 페이지 200", "HTTP/1.1 200 OK /admin") is True)
check("상태코드 단서", HY.match_signal("응답 403", "HTTP/1.1 403 Forbidden") is True)
check("따옴표 문자열", HY.match_signal("'Anonymous access allowed' 문구", "230 Anonymous access allowed") is True)
check("강한 단서 불일치", HY.match_signal("/backup.zip 존재", "404 not here") is False)
check("약한 단서 2개 일치", HY.match_signal("Sharename and Comment columns", "Sharename  Type  Comment") is True)
check("부정어 있으면 약한 단서 일치 무효", HY.match_signal("anonymous login allowed", "Anonymous login denied") is False)
check("단서 없으면 판단 보류(None)", HY.match_signal("확인", "anything") is None)

print("\n=== 결과 기록 → 상태·막힘·초점 ===")
L4 = HypothesisLedger(replan_after=2)
L4.apply_update([{"id": "H1", "text": "관리자 경로", "priority": "상", "expected": "/admin"},
                 {"id": "H2", "text": "백업 파일", "priority": "중", "expected": "/backup.zip"}])
sig0 = L4.signature()
check("초점은 우선순위 상", L4.focus().id == "H1")
check("실행 안 됨 → neutral(근거 아님)", L4.record("H1", "c0", "", ran=False) == "neutral" and L4.get("H1").misses == 0)
check("시도 명령은 기록", "c0" in L4.get("H1").tried)
check("불일치 → miss", L4.record("H1", "c1", "HTTP/1.1 404", ran=True, target_rejected=True) == "miss")
check("대기→검증중은 재계획 신호 아님(signature 동일)", L4.get("H1").status == "testing" and L4.signature() == sig0)
L4.record("H1", "c2", "nothing", ran=True)
check("2회 연속 불일치 → 막힘", [h.id for h in L4.stuck()] == ["H1"])
check("막히면 signature 변화(재계획 신호)", L4.signature() != sig0)
check("막힌 가설은 초점에서 제외 → H2", L4.focus().id == "H2")
check("일치 → hit · 확인", L4.record("H2", "c3", "200 /backup.zip", ran=True) == "hit"
      and L4.get("H2").status == "confirmed" and L4.get("H2").misses == 0)
check("근거 한 줄 기록(〔추정〕 표기)", any("〔추정〕" in e for e in L4.get("H2").evidence))
check("모두 막힘/확인 → 확인된 가설로 심화", L4.focus().id == "H2")
check("없는 가설 → neutral", L4.record("H9", "c", "x", ran=True) == "neutral")
check("보드에 막힘 표시", any("막힘" in ln and "H1" in ln for ln in L4.board_lines()))
check("초점 줄: 이미 시도·기대 신호", any(ln.startswith("이미 시도") for ln in L4.focus_lines(L4.get("H1")))
      and any(ln.startswith("기대 신호") for ln in L4.focus_lines(L4.get("H1"))))
R = HypothesisLedger.from_dict(json.loads(json.dumps(L4.to_dict())))
check("저장·복원 왕복", R.to_dict() == L4.to_dict())
check("복원: 깨진 값 무시", HypothesisLedger.from_dict({"items": [{"id": "x"}, "y"]}).items == [])

print("\n=== 오케스트레이터: 갱신 모드 · 지금 할 일 · 막힘 2회 → 재계획 ===")
XMLw = (f'<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="{T}"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http"/></port></ports></host></nmaprun>')
def runweb(c):
    if c.startswith("nmap"):
        return RunOutput(c, stdout=XMLw)
    if "backup" in c:
        return RunOutput(c, stdout="HTTP/1.1 200 OK\n\nPK.. /backup.zip archive")
    return RunOutput(c, stdout="HTTP/1.1 404 Not Found\n\nnope")

calls = {"analyst": [], "gen": []}
def llm(system, user, tier):
    if "분석가" in system:
        calls["analyst"].append(user)
        if "막힌 가설" in user and "H1" in user:   # 2차: H1 기각, H2 로
            return ('가설:\n  H2 [우선:상] 백업 파일 노출\n'
                    '가설기록: {"hypotheses":[{"id":"H1","status":"rejected"},'
                    '{"id":"H2","text":"백업 파일 노출","priority":"상","expected":"/backup.zip"}]}\n확신도: 중')
        return ('가설:\n  H1 [우선:상] 숨은 관리자 경로\n'
                '가설기록: {"hypotheses":[{"id":"H1","text":"숨은 관리자 경로","priority":"상",'
                '"expected":"/admin"},{"id":"H2","text":"백업 파일 노출","priority":"하",'
                '"expected":"/backup.zip"}]}\n확신도: 중')
    calls["gen"].append(user)
    n = len(calls["gen"])
    if "지금 할 일: H2" in user:
        return json.dumps([{"command": "curl -i http://{t}/backup.zip", "hypothesis": "H2"}])
    return json.dumps([{"command": f"curl -i http://{{t}}/admin{n}", "hypothesis": "H1"},
                       {"command": f"curl -i http://{{t}}/manage{n}", "hypothesis": "H1"}])

g = ScopeGuard.from_cidr_strings(); g.bind_target(T)
kb = KnowledgeBase(rules=[Rule(name="w", phase="enum", ports=[80],
                               suggest=["curl -I http://{t}/"])], notes=[])
tmp = tempfile.mkdtemp()
store = StateStore(os.path.join(tmp, "state"))
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rep = Orchestrator(g, FakeRunner(runweb), kb, auto_approve_in_scope,
                       llm_router=LLMRouter(FakeProvider(llm)), state_store=store,
                       is_tool_available=lambda b: True, max_sweeps=2, max_rounds=4,
                       max_llm=10).run()
out = buf.getvalue()
check("실행자 프롬프트에 '지금 할 일'", calls["gen"] and "지금 할 일: H1" in calls["gen"][0])
check("실행자에게 분석 전문 대신 과제(분석가 판단 섹션 없음)",
      all("분석가 판단(" not in u for u in calls["gen"]))
check("H1 막힘 → 분석가 재호출 시 '막힌 가설' 전달", any("막힌 가설" in u for u in calls["analyst"]))
check("재호출은 갱신 모드(이전 가설 기록 전달)", any("이전 가설 기록" in u for u in calls["analyst"][1:]))
check("재계획 후 실행자 초점이 H2", any("지금 할 일: H2" in u for u in calls["gen"]))
check("H1 기각 · H2 확인", rep.plan.get("H1").status == "rejected" and rep.plan.get("H2").status == "confirmed")
check("분석가 호출이 실행 건수만큼 늘지 않음(의미 있는 변화 때만)",
      len(calls["analyst"]) <= 3 < len(rep.llm_findings) + len(rep.enum_findings))
check("비고에 신호 대조 표시", any("H1 신호 불일치" in (f.note or "") for f in rep.llm_findings)
      and any("H2 신호 일치" in (f.note or "") for f in rep.llm_findings))
check("화면: 지금 집중·재계획 요청 안내", "지금 집중" in out and "재계획 요청" in out)
check("표시용 분석에 기계용 JSON 없음", "가설기록" not in rep.analysis)
check("가설 확인은 목표 판정에 쓰이지 않음", rep.goal_reached is False and not rep.flags)
check("요약에 PLAN(가설 보드)", "PLAN" in rep.summary() and "H2" in rep.summary())

print("\n=== 산출물: JSON·HTML·라이트업·재생·벤치 ===")
from htb_agent import bench as B  # noqa: E402
from htb_agent import replay as RP  # noqa: E402
from htb_agent import report_export as RX  # noqa: E402
from htb_agent import writeup as WU  # noqa: E402
d = RX.to_dict(rep)
check("JSON schema 1.7 + plan", d["schema_version"] == "1.7" and d["plan"]["items"][0]["id"] == "H1")
check("JSON 직렬화 가능", json.loads(RX.to_json(rep))["plan"]["revision"] >= 2)
html = RX.to_html(rep, "Box")
check("HTML 가설 보드(표·지금 표시)", "<th>기대 신호</th>" in html and "← 지금" in html)
check("HTML 가설 문구 이스케이프", "<script>" not in RX._html_plan(type("R", (), {"plan": HypothesisLedger(
    items=[HY.Hypothesis(id="H1", text="<script>x</script>")])})()))
check("라이트업 분석 블록에 가설 보드", "가설 보드" in WU._analysis_block(rep))
evs = []
class _A:
    def event(self, ev, **kw): evs.append({"event": ev, **kw})
g5 = ScopeGuard.from_cidr_strings(); g5.bind_target(T)
calls["analyst"].clear(); calls["gen"].clear()
with contextlib.redirect_stdout(io.StringIO()):
    Orchestrator(g5, FakeRunner(runweb), kb, auto_approve_in_scope,
                 llm_router=LLMRouter(FakeProvider(llm)), audit=_A(),
                 is_tool_available=lambda b: True, max_sweeps=2, max_rounds=4, max_llm=10).run()
kinds = {e["event"] for e in evs}
check("감사 로그: plan_update·hypothesis_signal·hypothesis_stuck",
      {"plan_update", "hypothesis_signal", "hypothesis_stuck"} <= kinds)
steps = RP.build_steps([{"ts": "t", **e} for e in evs])
labels = {s["label"] for s in steps}
check("재생: 계획 갱신·가설 막힘 단계", "계획(가설 기록) 갱신" in labels and "가설 막힘 → 재계획 요청" in labels)
check("재생: 계획 갱신 단계에 보드 상세", any(s["label"].startswith("계획") and "H1" in s["detail"] for s in steps))
ch = [c for c in B.load_suite(B.default_suite_dir()) if c.name == "web-header"]
res = B.run_bench(ch, attempts=1, kb=KnowledgeBase.load("knowledge"),
                  router=LLMRouter(FakeProvider("가설:\n  H1 [우선:상] 헤더\n확신도: 중")))
st = B.summarize(ch, res)
t = B.totals(st)
check("벤치: 시도당 LLM 호출 수 집계", st[0].avg_llm_calls >= 1 and t["llm_calls"] >= 1)
check("벤치: 풀이 1건당 LLM 호출", t["llm_calls_per_solve"] > 0 and "풀이 1건당" in B.render(st, 1, "fake"))
t0 = B.totals(B.summarize(ch, B.run_bench(ch, attempts=1, kb=KnowledgeBase.load("knowledge"))))
check("벤치: LLM 없으면 호출 0·표시 생략", t0["llm_calls"] == 0 and t0["llm_calls_per_solve"] == 0.0)

print("\n=== 재개: 계획 이어가기 ===")
saved = store.load(T)
check("상태 파일에 가설 기록·분석 저장", saved.plan and saved.plan["items"] and saved.analysis)
seen_first = []
def llm2(system, user, tier):
    if "분석가" in system:
        seen_first.append(user)
        return "가설:\n  (변화 없음)\n확신도: 중"
    return "curl -I http://{t}/robots.txt"
g2 = ScopeGuard.from_cidr_strings(); g2.bind_target(T)
with contextlib.redirect_stdout(io.StringIO()):
    rep2 = Orchestrator(g2, FakeRunner(runweb), kb, auto_approve_in_scope,
                        llm_router=LLMRouter(FakeProvider(llm2)), state_store=store, resume=True,
                        is_tool_available=lambda b: True, max_sweeps=1, max_rounds=1).run()
check("재개 시 가설 기록 복원", rep2.plan.get("H2") is not None and rep2.plan.get("H2").status == "confirmed")
check("재개 후 첫 분석은 갱신 모드(이전 기록 전달)", seen_first and "이전 가설 기록" in seen_first[0])
check("분석가가 가설을 안 줘도 기존 기록 유지", rep2.plan.get("H1").status == "rejected")

print("\n=== LLM 이 가설을 못 주면 기존 동작(분석 전문 전달) ===")
gen_users = []
def llm3(system, user, tier):
    if "분석가" in system:
        return "계획: 웹부터\n확신도: 중"
    gen_users.append(user)
    return "curl -I http://{t}/x"
g3 = ScopeGuard.from_cidr_strings(); g3.bind_target(T)
with contextlib.redirect_stdout(io.StringIO()):
    rep3 = Orchestrator(g3, FakeRunner(runweb), kb, auto_approve_in_scope,
                        llm_router=LLMRouter(FakeProvider(llm3)),
                        is_tool_available=lambda b: True, max_sweeps=1, max_rounds=1).run()
check("가설 없음 → 보드 없음", not rep3.plan)
check("가설 없음 → 분석 전문을 실행자에게(폴백)", gen_users and "분석가 판단(" in gen_users[0])

print(f"\n결과: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
