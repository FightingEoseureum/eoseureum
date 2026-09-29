"""test_attack_surface_planner.py — Attack Surface Planner / Semantic / Scoring / KB / Levels."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attack_surface_planner as asp
import technique_kb as kb
import evidence_levels as evl


# ── Semantic Classification ──────────────────────────────────────────────────
def test_semantic_search():
    assert asp.classify_semantic({"param": "q", "context": "search"}) == kb.ROLE_SEARCH
    assert asp.classify_semantic({"param": "keyword"}) == kb.ROLE_SEARCH


def test_semantic_object_reference():
    for p in ["userId", "accountId", "fileId", "id", "seq", "orderId"]:
        assert asp.classify_semantic({"param": p}) == kb.ROLE_OBJECT_REF


def test_semantic_business_logic():
    for p in ["role", "price", "discount", "amount", "point"]:
        assert asp.classify_semantic({"param": p}) == kb.ROLE_BUSINESS


def test_semantic_auth_and_others():
    assert asp.classify_semantic({"param": "pw", "input_type": "password"}) == kb.ROLE_AUTH
    assert asp.classify_semantic({"param": "next"}) == kb.ROLE_REDIRECT
    assert asp.classify_semantic({"param": "webhook"}) == kb.ROLE_URL_FETCH
    assert asp.classify_semantic({"param": "filename"}) == kb.ROLE_FILE
    assert asp.classify_semantic({"param": "xyz"}) == kb.ROLE_GENERIC


# ── Recommended techniques from KB ───────────────────────────────────────────
def test_recommended_techniques_from_kb():
    r = asp.analyze_input_point({"param": "q", "context": "search"})
    assert set(["xss", "sqli", "ssti"]) <= set(r["recommended_techniques"])
    r2 = asp.analyze_input_point({"param": "userId"})
    assert "idor" in r2["recommended_techniques"]
    r3 = asp.analyze_input_point({"param": "price"})
    assert "business_logic" in r3["recommended_techniques"]


# ── Attack Surface Scoring / levels ──────────────────────────────────────────
def test_scoring_auth_object_ref_is_high():
    r = asp.analyze_input_point({"param": "userId", "url": "https://t/api/admin/user",
                                 "method": "POST", "authenticated": True})
    assert r["priority_level"] in ("Critical", "High")
    assert r["priority_score"] >= 8


def test_scoring_generic_is_low():
    r = asp.analyze_input_point({"param": "color", "url": "https://t/p", "method": "GET"})
    assert r["priority_level"] in ("Low", "Medium")


# ── Probe Budget Optimization (top-N selection) ──────────────────────────────
def test_budget_selects_top_scored():
    pts = [
        {"param": "color", "url": "http://t/a", "method": "GET"},
        {"param": "userId", "url": "http://t/api/user", "method": "POST", "authenticated": True},
        {"param": "q", "url": "http://t/s", "context": "search"},
    ]
    plan = asp.plan_attack_surface(pts, budget=1)
    assert plan["summary"]["total_surfaces"] == 3
    assert plan["summary"]["selected_surfaces"] == 1
    # 가장 높은 점수(인증 후 객체참조)가 선택
    assert plan["selected"][0]["param"] == "userId"
    assert plan["reasoning_trace"][0]["input"] == "userId"


def test_raw_point_score_orders_points():
    high = {"method": "POST", "url": "http://t/api/user", "params": {"userId": "1"}, "authenticated": True}
    low = {"method": "GET", "url": "http://t/p", "params": {"color": "red"}}
    assert asp.raw_point_score(high) > asp.raw_point_score(low)


# ── Technique KB extensibility ───────────────────────────────────────────────
def test_kb_register_new_technique():
    kb.register_technique("graphql_abuse", {"category": "API", "roles": [kb.ROLE_OBJECT_REF],
                                            "risk": "HIGH", "expected_signal": "introspection"})
    assert "graphql_abuse" in kb.all_techniques()
    assert "graphql_abuse" in kb.techniques_for_role(kb.ROLE_OBJECT_REF)


# ── Evidence levels ──────────────────────────────────────────────────────────
def test_level_mapping():
    assert evl.level_of({"confidence": "CONFIRMED_BROWSER"}) == 3
    assert evl.level_of({"confidence": "CONFIRMED_RESPONSE"}) == 3
    assert evl.level_of({"confidence": "POSSIBLE"}) == 2
    assert evl.level_of({"confidence": "MANUAL_REVIEW"}) == 1
    assert evl.level_of({}, finding_type="attack_surface") == 1
    assert evl.level_of({}, finding_type="discovery") == 0


def test_observed_view_structure():
    f = {"title": "IDOR 실증", "confidence": "CONFIRMED_RESPONSE",
         "evidence_detail": "교차 계정 노출", "business_impact": "타 사용자 정보 접근",
         "recommendation": "권한 검증"}
    v = evl.observed_view(f, finding_type="vulnerability")
    assert v["verification_level"] == 3
    assert v["observed_phenomenon"] == "IDOR 실증"
    assert v["evidence"] == "교차 계정 노출"
    assert "Level 3" in v["verification_label"]


def test_summarize_levels_counts():
    findings = [{"confidence": "CONFIRMED_RESPONSE"}, {"confidence": "POSSIBLE"}]
    surface = [{"confidence": "MANUAL_REVIEW"}]
    disc = [{"title": "info"}]
    s = evl.summarize_levels(findings, surface, disc)
    assert s["level3_proven"] == 1
    assert s["level2_evidence"] == 1
    assert s["level1_observed"] == 1
    assert s["level0_info"] == 1
    assert s["priority_actions"] == 2
