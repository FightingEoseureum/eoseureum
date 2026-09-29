"""벤치마크 하네스 강화(고도화 #4) 회귀 테스트.

- discovery_items/attack_surface_items 도 채점 대상에 포함(예전엔 findings 만 봐서 IDOR/Swagger 가 FN)
- allowed_extra 로 정상 부가발견을 제외해 precision 을 의미있게 측정
- 스캔 미실행(no-self-run): 합성 analysis dict 로만 검증
"""
from benchmark.evaluate import evaluate, _all_scored_items
from benchmark.golden import resolve_golden


def test_discovery_and_attack_surface_items_scored():
    """IDOR 이 discovery_items 에 있어도 TP 로 잡혀야 한다(예전엔 findings 만 봐서 FN)."""
    analysis = {
        "findings": [{"title": "SQL 인젝션", "family": "sqli", "judgment": "취약",
                      "confidence": "CONFIRMED"}],
        "discovery_items": [{"title": "IDOR 후보", "family": "idor", "judgment": "참고",
                             "confidence": "MANUAL_REVIEW"}],
        "attack_surface_items": [{"title": "Swagger 노출", "family": "swagger",
                                  "judgment": "취약"}],
        "good_items": [{"title": "무언가 양호", "family": "xss", "judgment": "양호"}],
    }
    items = _all_scored_items(analysis)
    fams = {(__import__("proof_evidence")._family(f)) for f in items}
    assert "sqli" in fams and "idor" in fams and "swagger" in fams
    # good_items(양호)는 제외
    assert len(items) == 3


def test_idor_in_discovery_counts_as_tp():
    golden = {"label": "t", "exhaustive": False,
              "expected": [{"family": "idor", "note": "BOLA"}]}
    analysis = {"findings": [],
                "discovery_items": [{"title": "IDOR 가능성", "family": "idor",
                                     "judgment": "참고"}]}
    r = evaluate(analysis, golden)
    assert r["true_positive"] == 1 and r["false_negative"] == 0
    assert r["recall"] == 1.0


def test_allowed_extra_excludes_benign_from_fp():
    golden = {"label": "t", "exhaustive": False,
              "allowed_extra": ["clickjacking", "tls"],
              "expected": [{"family": "sqli", "note": ""}]}
    analysis = {"findings": [
        {"title": "SQLi", "family": "sqli", "judgment": "취약", "confidence": "CONFIRMED"},
        {"title": "Clickjacking", "family": "clickjacking", "judgment": "취약"},   # allowed_extra
        {"title": "SSL/TLS", "family": "tls", "judgment": "취약"},                 # allowed_extra
        {"title": "이상한거", "family": "weirdvuln", "judgment": "취약"},           # 유의미 FP
    ]}
    r = evaluate(analysis, golden)
    assert r["true_positive"] == 1
    assert r["significant_false_positive"] == 1     # weirdvuln 만
    assert r["potential_false_positive"] == 3       # 전체 unexpected
    assert r["precision"] == 0.5                    # tp1 / (tp1 + fp1)


def test_no_significant_fp_perfect_precision():
    golden = resolve_golden("demo.testfire.net")
    assert golden is not None
    analysis = {"findings": [
        {"title": "SQLi", "family": "sqli", "judgment": "취약", "confidence": "CONFIRMED"},
        {"title": "XSS", "family": "xss", "judgment": "취약", "confidence": "CONFIRMED"},
        {"title": "Server 노출", "family": "server", "judgment": "취약"},
        {"title": "Clickjacking", "family": "clickjacking", "judgment": "취약"},   # allowed_extra
        {"title": "Swagger", "family": "swagger", "judgment": "취약"},             # allowed_extra
    ]}
    r = evaluate(analysis, golden)
    assert r["recall"] == 1.0
    assert r["significant_false_positive"] == 0
    assert r["precision"] == 1.0
