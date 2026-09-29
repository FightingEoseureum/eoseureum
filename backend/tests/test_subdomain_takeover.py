"""test_subdomain_takeover.py — 서브도메인 탈취 탐지(고정밀 지문) 검증."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import subdomain_takeover as st


def test_confirmed_when_cname_and_fingerprint_match():
    f = st.detect("blog.t.com", "t-com.github.io",
                  body="<html>There isn't a GitHub Pages site here.</html>", status=404)
    assert f and f["confidence"] == "CONFIRMED_RESPONSE"
    assert f["family"] == "subdomain_takeover" and f["service"] == "github_pages"
    assert f["severity"] == "HIGH"


def test_manual_review_when_cname_only():
    # CNAME 은 heroku dangling 이나 미클레임 지문 없음 → 검토 권고(오탐 회피)
    f = st.detect("api.t.com", "myapp.herokuapp.com", body="<html>Welcome</html>", status=200)
    assert f and f["confidence"] == "MANUAL_REVIEW" and f["severity"] == "MEDIUM"


def test_none_when_cname_not_a_known_service():
    assert st.detect("www.t.com", "t.com.edgekey.net", body="whatever") is None
    assert st.detect("www.t.com", "", body="x") is None


def test_analyze_list_and_dedup_fields():
    infos = [
        {"subdomain": "a.t.com", "cname": "x.s3.amazonaws.com",
         "body": "<Error><Code>NoSuchBucket</Code></Error>"},
        {"subdomain": "b.t.com", "cname": "internal.t.com", "body": "ok"},  # 서비스 아님
        {"subdomain": "c.t.com", "cname": ""},                             # cname 없음
    ]
    out = st.analyze(infos)
    assert len(out) == 1 and out[0]["service"] == "aws_s3"
    assert out[0]["confidence"] == "CONFIRMED_RESPONSE"
