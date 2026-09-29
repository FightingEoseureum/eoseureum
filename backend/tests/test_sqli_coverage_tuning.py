"""SQLi 미검출(FN) 튜닝 회귀 — 유망 지점 우선정렬 + .NET/MSSQL 에러 시그니처.

캡(points[:N])에 잘려 취약 파라미터를 놓치던 문제를, '전형적 SQLi 표면을 앞으로'로 방지.
"""
import active_probing as ap


def _pt(url, params):
    return {"url": url, "method": "GET", "params": params}


def test_sqli_point_prioritization_puts_likely_first():
    points = [
        _pt("https://t.com/static/style", {}),                       # 표면 아님
        _pt("https://t.com/about", {"lang": "ko"}),                  # 약한 표면
        _pt("https://t.com/ReadNews.aspx", {"id": "5"}),            # 강한 표면(id + 숫자 + news 경로)
        _pt("https://t.com/product.aspx", {"pid": "12"}),          # 강한 표면
    ]
    ordered = ap._prioritize_sqli_points(points)
    # id/숫자/news·product 지점이 앞으로
    assert ordered[0]["url"].endswith(("ReadNews.aspx", "product.aspx"))
    assert ordered[-1]["params"] == {}                              # 표면 아닌 것 뒤로
    # 점수: id+숫자+news경로 > lang
    assert ap._sqli_point_score(points[2]) > ap._sqli_point_score(points[1])


def test_sqli_cap_scales_with_env(monkeypatch):
    monkeypatch.setenv("SQLI_COVERAGE_MULT", "3")
    assert ap._sqli_cap(12) == 36
    monkeypatch.setenv("SQLI_COVERAGE_MULT", "1")
    assert ap._sqli_cap(12) == 12          # 최소 base 보장


def test_sql_error_signatures_cover_dotnet_mssql():
    for msg in [
        "System.Data.SqlClient.SqlException: Incorrect syntax near ''",
        "Conversion failed when converting the varchar value 'x' to data type int.",
        "[Microsoft][ODBC SQL Server Driver][SQL Server]Unclosed quotation mark",
        "OLE DB provider error '80040e14'",
    ]:
        assert ap._SQL_ERR.search(msg), f"미매칭: {msg}"
    # 무관한 에러는 매칭 안 됨(오탐 방지)
    assert not ap._SQL_ERR.search("404 Not Found — page missing")
