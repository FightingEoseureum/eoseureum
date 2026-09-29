"""tests/test_deep_input_discovery.py — 입력점 발굴 확대 검증 (네트워크 없음).

- gather_all_points: injection_points + discovered_urls(쿼리 파라미터) + authenticated_forms 합치고 dedup.
- detect_search_points: 검색 입력점(q/search/keyword/.. 또는 action 에 search 포함)을 "is_search":True 로 표시.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from probes.base import ProbeContext
from probes.utils.injection_points import (
    detect_search_points,
    gather_all_points,
)


def _ctx(**kw):
    base = dict(target_url="http://t.example/")
    base.update(kw)
    return ProbeContext(**base)


def test_gather_merges_forms_urls_and_authenticated_forms():
    form_point = {"url": "http://t.example/login", "method": "POST",
                  "source": "form", "params": {"username": "a", "password": "b"}}
    ctx = _ctx(
        injection_points=[form_point],
        discovered_urls=["http://t.example/list?id=5&cat=2"],
        authenticated_forms=[{"url": "http://t.example/profile", "method": "POST",
                              "source": "form", "params": {"bio": "x"}}],
    )
    points = gather_all_points(ctx)

    urls = {p["url"] for p in points}
    assert "http://t.example/login" in urls          # form
    assert "http://t.example/list" in urls            # query parameter URL
    assert "http://t.example/profile" in urls         # authenticated form

    # query parameter URL 이 주입 지점 params 로 추출됨
    list_pt = next(p for p in points if p["url"] == "http://t.example/list")
    assert set(list_pt["params"]) == {"id", "cat"}


def test_gather_dedup():
    dup = {"url": "http://t.example/p", "method": "GET",
           "source": "url", "params": {"id": "1"}}
    ctx = _ctx(
        injection_points=[dict(dup), dict(dup)],
        discovered_urls=["http://t.example/p?id=1"],
    )
    points = gather_all_points(ctx)
    matches = [p for p in points if p["url"] == "http://t.example/p"]
    assert len(matches) == 1, "동일 (method,url,파라미터키) 지점은 dedup 되어야 한다"


def test_gather_ignores_urls_without_query():
    ctx = _ctx(
        injection_points=[],
        discovered_urls=["http://t.example/static/page.html"],
    )
    assert gather_all_points(ctx) == []


def test_detect_search_points_by_param_name():
    points = [
        {"url": "http://t.example/find", "method": "GET", "params": {"q": "x"}},
        {"url": "http://t.example/find", "method": "GET", "params": {"keyword": "x"}},
        {"url": "http://t.example/p", "method": "GET", "params": {"id": "1"}},
    ]
    out = detect_search_points(points)
    by_param = {tuple(sorted(p.get("params", {}))): p for p in out}
    assert by_param[("q",)].get("is_search") is True
    assert by_param[("keyword",)].get("is_search") is True
    assert by_param[("id",)].get("is_search") is not True


def test_detect_search_points_by_action_url():
    points = [{"url": "http://t.example/search", "method": "GET", "params": {"x": "1"}}]
    out = detect_search_points(points)
    assert out[0].get("is_search") is True
