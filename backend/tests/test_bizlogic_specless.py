"""비즈니스 로직 안티패턴 — 스펙 없는 추론(P1-#2 Part A) 회귀 테스트.

operations_from_points 로 크롤 입력점을 operation 스키마로 변환하고,
business_logic_candidates 가 Swagger 스펙 없이도 BOLA/MASS_ASSIGN/PRICE_TAMPER/
REPLAY/STEP_SKIP 후보를 생성하는지 확인.
"""
import api_audit as aa


def test_operations_from_points_schema():
    points = [
        {"method": "GET", "url": "http://t/api/users/123", "params": {}},
        {"method": "POST", "url": "http://t/api/checkout", "params": {"price": "100", "qty": "1"}},
    ]
    ops = aa.operations_from_points(points)
    assert {o["method"] for o in ops} == {"GET", "POST"}
    users_op = [o for o in ops if o["path"] == "/api/users/123"][0]
    assert "id" in users_op["path_params"]            # 숫자 세그먼트 → 객체식별자(합성 'id')
    checkout_op = [o for o in ops if o["path"] == "/api/checkout"][0]
    assert set(checkout_op["body_props"]) == {"price", "qty"}


def test_specless_price_tamper_candidate():
    points = [{"method": "POST", "url": "http://t/api/order",
               "params": {"amount": "50", "coupon": "X"}}]
    ops = aa.operations_from_points(points)
    cands = aa.business_logic_candidates(ops)
    pats = {c["pattern"] for c in cands}
    assert "PRICE_TAMPER" in pats
    assert "REPLAY" in pats               # coupon → 재사용 후보
    # safe_test 레시피가 실려있어야 함(후보 표기 계약)
    pt = [c for c in cands if c["pattern"] == "PRICE_TAMPER"][0]
    assert pt["safe_test"]


def test_specless_bola_and_stepskip():
    points = [
        {"method": "GET", "url": "http://t/api/invoices/8842", "params": {}},
        {"method": "POST", "url": "http://t/api/payment/confirm", "params": {"ok": "1"}},
    ]
    cands = aa.business_logic_candidates(aa.operations_from_points(points))
    pats = {c["pattern"] for c in cands}
    assert "BOLA" in pats          # /invoices/8842 숫자 세그먼트
    assert "STEP_SKIP" in pats     # /payment/confirm 흐름경로


def test_empty_points_no_crash():
    assert aa.operations_from_points([]) == []
    assert aa.business_logic_candidates([]) == []
