"""딥페이지 폼 입력점 확대(P1-#1) 회귀 테스트.

_forms_from_html 이 발견된 페이지의 <form> 을 active_probing 스키마 입력점으로 뽑고,
_FORM_SOURCES 가 form/discovered_form/browser_discovery 를 모두 포함하는지 확인.
"""
import active_probing as ap


def test_forms_from_html_extracts_post_form():
    html = """
    <html><body>
      <form action="/comment" method="POST">
        <input type="text" name="title" value="">
        <textarea name="body"></textarea>
        <input type="hidden" name="csrf_token" value="abc">
        <input type="submit" value="Send">
      </form>
    </body></html>
    """
    pts = ap._forms_from_html("http://t.example/page", html, source="discovered_form")
    assert len(pts) == 1
    p = pts[0]
    assert p["method"] == "POST"
    assert p["url"].endswith("/comment")
    assert p["source"] == "discovered_form"
    # submit 은 제외. csrf 토큰은 폼 유효제출 위해 params 에도 유지되며 csrf_fields 로도 표기
    # (주입 로직이 csrf/token 이름 파라미터를 별도로 건너뜀).
    assert {"title", "body"} <= set(p["params"])
    assert "csrf_token" in p["csrf_fields"]


def test_forms_from_html_relative_action_resolved():
    html = '<form action="submit.php" method="post"><input name="q"></form>'
    pts = ap._forms_from_html("http://t.example/dir/page.html", html)
    assert pts[0]["url"] == "http://t.example/dir/submit.php"
    assert pts[0]["source"] == "form"


def test_forms_from_html_empty_and_no_params():
    assert ap._forms_from_html("http://t.example", "") == []
    # 파라미터 없는 폼(버튼만)은 입력점 아님
    assert ap._forms_from_html("http://t.example",
                               '<form method="post"><input type="submit"></form>') == []


def test_form_sources_includes_deep_and_browser():
    assert "form" in ap._FORM_SOURCES
    assert "discovered_form" in ap._FORM_SOURCES
    assert "browser_discovery" in ap._FORM_SOURCES
