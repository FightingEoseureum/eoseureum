"""test_sqli_candidate_priority.py — SQLi 후보 입력점 우선순위."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import external_tools as et

def _names(ordered):
    return [c[0].split("?", 1)[1] if "?" in c[0] else c[0] for c in ordered]

def test_login_beats_search_and_content():
    cands = [
        ("http://t/index.jsp?content=security.htm", "t", 80),
        ("http://t/s?q=x", "t", 80),
        ("http://t/login?username=a&password=b", "t", 80),
    ]
    ordered = et.prioritize_sqli_candidates(cands)
    names = _names(ordered)
    assert names[0].startswith("username")        # 로그인 최우선
    assert names.index("q=x") < names.index("content=security.htm")  # 검색 > content

def test_content_navigation_lowest():
    cands = [("http://t/a?uid=1", "t", 80), ("http://t/b?content=home", "t", 80)]
    ordered = et.prioritize_sqli_candidates(cands)
    assert _names(ordered)[-1] == "content=home"

def test_priority_scores():
    assert et._candidate_priority("http://t/login?u=1&password=2") == 0
    assert et._candidate_priority("http://t/s?q=1") == 1
    assert et._candidate_priority("http://t/p?uid=1") <= 3
    assert et._candidate_priority("http://t/i?content=x") == 9
