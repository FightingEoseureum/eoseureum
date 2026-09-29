"""⑤ AI 비즈니스 로직 가설 — 구조추출·파싱·finding 변환·안전성 회귀."""
import business_logic_ai as bla


def _analysis():
    return {
        "technologies": [{"name": "Node/Express"}],
        "host_results": [{"host": "t", "services": [{"port": 3000,
            "discovered_urls": ["http://t:3000/rest/basket/1?coupon=X", "http://t:3000/api/order"],
            "active_probes": {"swagger_openapi": {"api_summary": {
                "payment_endpoints": ["POST /rest/checkout"], "admin_endpoints": ["GET /api/admin"]}}}}]}],
        "findings": [{"title": "Swagger 노출"}],
    }


def test_build_app_context_extracts_endpoints_and_payment():
    ctx = bla.build_app_context(_analysis())
    paths = {e["path"] for e in ctx["endpoints"]}
    assert "/rest/basket/1" in paths and "/rest/checkout" in paths and "/api/admin" in paths
    assert ctx["has_payment"] is True   # basket/order/checkout 존재


def test_parse_hypotheses_robust():
    raw = ('설명 문장 무시\n[{"title":"쿠폰 중복적용","category":"coupon_discount_abuse",'
           '"endpoint":"/rest/basket","rationale":"coupon 파라미터","test_steps":"쿠폰 2회 적용"}]')
    hyps = bla._parse_hypotheses(raw)
    assert len(hyps) == 1 and hyps[0]["category"] == "coupon_discount_abuse"


def test_invalid_category_defaults():
    raw = '[{"title":"x","category":"nonsense","endpoint":"/a","rationale":"r","test_steps":"t"}]'
    assert bla._parse_hypotheses(raw)[0]["category"] == "workflow_bypass"


def test_hypotheses_to_findings_are_advisory():
    hyps = [{"title": "가격 조작", "category": "price_manipulation", "endpoint": "/checkout",
             "rationale": "amount 파라미터", "test_steps": "음수 전송"}]
    fs = bla.hypotheses_to_findings(hyps)
    f = fs[0]
    assert f["confidence"] == "MANUAL_REVIEW" and f["is_vulnerable"] is False
    assert f["ai_hypothesis"] is True and f["family"] == "business_logic"
    assert "[AI 가설]" in f["title"]


def test_analyze_with_fake_ai_fn():
    def fake_ai(prompt):
        return '[{"title":"수량 음수","category":"negative_value","endpoint":"/api/order",' \
               '"rationale":"qty 검증 없음","test_steps":"qty=-1"}]'
    fs = bla.analyze(_analysis(), fake_ai)
    assert fs and fs[0]["biz_category"] == "negative_value"


def test_analyze_none_ai_fn_returns_empty():
    assert bla.analyze(_analysis(), None) == []


def test_analyze_with_host_results_param():
    import business_logic_ai as bla
    analysis_no_hr = {"technologies": [{"name": "Node"}], "findings": []}  # host_results 없음
    hr = [{"host": "t", "services": [{"port": 3000,
        "discovered_urls": ["http://t:3000/api/order?id=1"]}]}]
    def fake_ai(p):
        return '[{"title":"x","category":"parameter_tampering","endpoint":"/api/order","rationale":"r","test_steps":"t"}]'
    fs = bla.analyze(analysis_no_hr, fake_ai, host_results=hr)
    assert fs and fs[0]["biz_category"] == "parameter_tampering"
