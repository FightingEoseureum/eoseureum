"""화이트박스 소스 SQLi 기본 파이프라인 연결(P2-#3) 회귀 테스트.

main._run_source_sqli 가 EOSEUREUM_SOURCE_ROOT 소스트리를 정적 분석해 analysis findings
스키마의 취약점 목록을 반환하는지(orchestrator 경로 없이) 확인.
"""
import os
import textwrap

import main


def test_run_source_sqli_detects_dynamic_sql(tmp_path):
    src = tmp_path / "vuln.py"
    src.write_text(textwrap.dedent('''
        def login(request, db):
            name = request.form.get("name")
            db.execute("SELECT * FROM users WHERE name='%s'" % name)
    '''), encoding="utf-8")

    findings = main._run_source_sqli(str(tmp_path))
    assert findings, "취약 동적 SQL 을 탐지해야 함"
    f = findings[0]
    assert f["judgment"] == "취약"
    assert f["finding_type"] == "vulnerability"
    assert f["cwe"] == "CWE-89"
    assert f["scan_category"] == "source"
    assert "whitebox" in f["tags"]
    assert "vuln.py" in f["affected_endpoint"]


def test_run_source_sqli_empty_for_safe_code(tmp_path):
    src = tmp_path / "safe.py"
    src.write_text('def q(db, name): db.execute("SELECT * FROM u WHERE n=?", (name,))\n',
                   encoding="utf-8")
    assert main._run_source_sqli(str(tmp_path)) == []


def test_run_source_sqli_missing_root():
    assert main._run_source_sqli("") == []
    assert main._run_source_sqli("/nonexistent/path/xyz") == []
