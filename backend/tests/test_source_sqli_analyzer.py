"""
test_source_sqli_analyzer.py — 화이트박스 SQLi 소스 분석기 검증.

모듈: backend/source_sqli_analyzer.py
  analyze_source_file / analyze_source_tree -> list[SourceFinding]

핵심 불변식:
  - 사용자 입력이 변환(md5.digest 등)을 거쳐 SQL f-string 에 삽입 + 필터가 원본에만 적용되면
    'filter_transform_mismatch' 를 CONFIRMED/High 로 탐지(블랙박스로는 트리거 불가한 클래스).
  - bytes/.digest() 가 따옴표 SQL 문자열에 보간되면 bytes repr 위험을 증거에 남긴다.
  - 파라미터라이즈드 쿼리(execute(sql, params))는 탐지하지 않는다(오탐 없음).
  - 정적 상수 SQL(execute("SELECT 1"))도 탐지하지 않는다.

실행:
  cd backend && venv_linux/bin/python -m pytest tests/test_source_sqli_analyzer.py -q
"""
import os
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from source_sqli_analyzer import SqliSourceAnalyzer, analyze_source_file  # noqa: E402


def _run(src: str):
    return SqliSourceAnalyzer("t.py", textwrap.dedent(src)).run()


def test_filter_transform_mismatch_detected():
    """핵심: 입력이 md5 digest 로 변환된 뒤 삽입, 필터는 원본에만 → CONFIRMED mismatch."""
    src = """
        import hashlib
        def encoder(p): return hashlib.md5(p.encode()).digest()
        def login():
            password = request.form.get("password", "").strip()
            if sql_filter(password):
                return "blocked"
            row = db.execute(f"SELECT username FROM t WHERE password='{encoder(password)}'")
            return row
    """
    findings = _run(src)
    mism = [f for f in findings if f.kind == "filter_transform_mismatch"]
    assert mism, f"변환 불일치 미탐지: {[f.kind for f in findings]}"
    f = mism[0]
    assert f.confidence == "CONFIRMED"
    assert f.severity == "High"
    assert f.cwe == "CWE-89"
    assert f.filter_applied and "filter" in f.filter_applied.lower()
    assert f.transform  # 변환 흔적 기록


def test_bytes_digest_repr_flagged():
    """.digest() 를 따옴표 SQL 에 직접 보간 → bytes repr 위험 증거 포함."""
    src = """
        import hashlib
        def login():
            pw = request.form.get("pw")
            db.execute("SELECT * FROM u WHERE p='" + str(hashlib.md5(pw.encode()).digest()) + "'")
    """
    findings = _run(src)
    assert any("bytes" in f.evidence.lower() or "digest" in f.evidence.lower()
               for f in findings), "bytes/digest 위험 증거 누락"


def test_plain_tainted_dynamic_sql_high():
    """변환/필터 없이 요청 입력 직접 보간도 High 로 탐지."""
    src = """
        def q():
            name = request.args.get("name")
            db.execute("SELECT * FROM users WHERE name='%s'" % name)
    """
    findings = _run(src)
    assert findings and findings[0].severity == "High"
    assert findings[0].taint_source


def test_parameterized_query_not_flagged():
    """파라미터라이즈드 쿼리는 탐지하지 않는다(오탐 방지)."""
    src = """
        def q():
            name = request.args.get("name")
            db.execute("SELECT * FROM users WHERE name=?", (name,))
    """
    findings = _run(src)
    assert findings == [], f"파라미터라이즈드 쿼리 오탐: {[f.snippet for f in findings]}"


def test_constant_sql_not_flagged():
    """상수 SQL 은 동적 아님 → 무시."""
    src = """
        def q():
            db.execute("SELECT 1 FROM dual")
    """
    assert _run(src) == []


def test_wrapper_sink_detected():
    """def w(sql): conn.execute(sql) 처럼 인자를 싱크로 넘기는 래퍼도 싱크로 인식."""
    src = """
        def dbq(sql):
            return conn.execute(sql)
        def q():
            name = request.form.get("name")
            dbq(f"SELECT * FROM u WHERE n='{name}'")
    """
    findings = _run(src)
    assert any(f.sink.endswith("dbq") or "dbq" in f.sink for f in findings), \
        f"래퍼 싱크 미인식: {[f.sink for f in findings]}"


def test_challenge_app_auth_line_confirmed():
    """실제 챌린지 app.py 의 /auth(71행) 가 CONFIRMED mismatch 로 잡히는지(있을 때만)."""
    app_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "app.py")
    if not os.path.exists(app_path):
        return  # 챌린지 소스 없으면 skip
    findings = analyze_source_file(app_path)
    auth = [f for f in findings if f.line == 71]
    assert auth and auth[0].kind == "filter_transform_mismatch", \
        f"/auth 변환 불일치 미탐지: {[(f.line, f.kind) for f in findings]}"
