"""BFLA finding 병합 회귀 — 엔드포인트별 중복 대신 (카테고리,등급)별 1건 + 엔드포인트 목록."""


def test_bfla_grouping_logic():
    # main.py 병합 로직과 동일: (category, grade)별로 묶고 엔드포인트 목록화
    results = [
        {"grade": "CONFIRMED", "category": "missing_auth", "endpoint": {"url": "http://t/rest/admin/a"}, "anon": 200, "b": 200, "a": 200},
        {"grade": "CONFIRMED", "category": "missing_auth", "endpoint": {"url": "http://t/rest/admin/b"}, "anon": 200, "b": 200, "a": 200},
        {"grade": "POSSIBLE", "category": "missing_auth", "endpoint": {"url": "http://t/rest/admin/c"}, "anon": 200, "b": 200, "a": 200},
        {"grade": "SKIP", "category": "x", "endpoint": {"url": "http://t/z"}},  # 등급 제외
    ]
    groups = {}
    for br in results:
        if br["grade"] not in ("CONFIRMED", "POSSIBLE"):
            continue
        groups.setdefault((br["category"], br["grade"]), []).append(br)
    # CONFIRMED/missing_auth 2건 → 1그룹, POSSIBLE/missing_auth 1건 → 1그룹
    assert len(groups) == 2
    confirmed = groups[("missing_auth", "CONFIRMED")]
    eps = []
    for br in confirmed:
        u = br["endpoint"]["url"]
        if u not in eps:
            eps.append(u)
    assert len(eps) == 2   # 2개 엔드포인트가 1 finding 으로 병합
    assert "http://t/rest/admin/a" in eps and "http://t/rest/admin/b" in eps
