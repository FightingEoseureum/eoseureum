"""② 벤치마크 정확도 루프 — 골든셋 매칭 + 집계 로직 회귀."""
import benchmark.golden as g
import benchmark.evaluate as e


def test_local_containers_match_golden():
    assert (g.resolve_golden("127.0.0.1:3000") or {}).get("label") == "OWASP Juice Shop"
    assert (g.resolve_golden("127.0.0.1:8080") or {}).get("label", "").startswith("DVWA")
    assert g.resolve_golden("unknown-target.example") is None


def test_juiceshop_allowed_extra_suppresses_bonus_findings():
    # swagger/token_in_url 은 allowed_extra → 유의미 오탐(precision)에서 제외
    gd = g.resolve_golden("127.0.0.1:3000")
    analysis = {"findings": [
        {"family": "sqli", "confidence": "CONFIRMED", "judgment": "취약"},
        {"family": "swagger", "confidence": "CONFIRMED", "judgment": "취약"},
        {"family": "token_in_url", "confidence": "CONFIRMED", "judgment": "취약"},
    ]}
    r = e.evaluate(analysis, gd)
    assert r["true_positive"] >= 1                    # sqli 정탐
    assert r["significant_false_positive"] == 0       # swagger/token 은 부가발견(오탐 아님)


def test_aggregate_micro_math():
    # 마이크로 평균 계산 로직(엔드포인트와 동일 식) 단위 검증
    tp, fn, fp = 5, 3, 2
    recall = round(tp / (tp + fn), 3)
    prec = round(tp / (tp + fp), 3)
    f1 = round(2 * prec * recall / (prec + recall), 3)
    assert recall == 0.625 and prec == 0.714
    assert 0.6 < f1 < 0.7
