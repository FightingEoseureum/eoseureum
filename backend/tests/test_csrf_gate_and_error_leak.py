"""CSRF 실제수행 게이팅 + 에러페이지 정보노출 서술 강화 회귀 테스트.

사용자 지침:
- CSRF: 토큰 '부재'만으로는 어떤 행위가 가능한지 실증되지 않아 취약점으로 올리지 않는다.
  위조 상태변경을 서버가 실제 수락함(csrf_executed)을 실증한 경우만 finding.
- 에러페이지 정보노출: '무슨 정보가 새고, 공격자가 그걸로 무엇을 할 수 있는지'가 서술돼야 한다.
"""
import active_probing as apc
import rule_engine as re_mod


# ── CSRF: csrf_executed 게이팅 ──
def test_csrf_form_dropped_when_not_executed():
    pd = {"type": "csrf_no_token", "confirmed": True, "csrf_executed": False,
          "url": "http://t/csrf/", "evidence": "토큰 부재"}
    assert re_mod._has_concrete_evidence("csrf_form", pd) is False


def test_csrf_form_surfaced_when_executed():
    pd = {"type": "csrf_no_token", "confirmed": True, "csrf_executed": True,
          "url": "http://t/csrf/", "evidence": "위조 수락"}
    assert re_mod._has_concrete_evidence("csrf_form", pd) is True


# ── 에러페이지 정보노출: 노출정보/악용가능성 분류 ──
def test_classify_leak_mariadb_with_syntax():
    snip = ("You have an error in your SQL syntax; check the manual that corresponds "
            "to your MariaDB server version for the right syntax to use near ''' at line 1")
    lk = apc._classify_error_leak(snip)
    assert lk["dbms"] == "MariaDB"
    assert "DBMS 종류=MariaDB" in lk["label"]
    assert "실행된 SQL 구문 일부" in lk["label"]
    # 악용 가능성 서술이 DBMS 특정을 언급해야 함
    assert "MariaDB" in lk["utility"]


def test_classify_leak_path_and_stack():
    snip = "Fatal error in /var/www/html/app.php on line 42\nSystem.Data.SqlClient.SqlException at Foo.Bar()"
    lk = apc._classify_error_leak(snip)
    assert "서버 내부 파일 경로/라인번호" in lk["label"]
    assert lk["dbms"] == "Microsoft SQL Server"


def test_classify_leak_short_mysql_signature():
    # 스니펫이 짧게 잘려 'syntax/MariaDB' 문맥이 없어도 MySQL/MariaDB 계열은 특정돼야 한다
    # (에러정보노출 finding 이 일반 폴백으로 떨어지지 않도록).
    lk = apc._classify_error_leak("You have an error in your SQL")
    assert lk["dbms"] == "MySQL/MariaDB"
    assert "실행된 SQL 구문 일부" in lk["label"]
    assert "MySQL/MariaDB" in lk["utility"]


def test_classify_leak_generic_fallback():
    lk = apc._classify_error_leak("some opaque db error")
    assert lk["label"]        # 최소 하나의 분류
    assert lk["utility"]      # 최소 하나의 악용 서술


# ── 블라인드 SQLi: '문자단위 추출' 실증한 경우만 확정 ──
def test_blind_sqli_needs_extracted_value():
    # 오라클만 성립(추출 없음) → 확정 아님
    assert re_mod._has_concrete_evidence(
        "sql_injection_blind", {"confirmed": True, "extracted_data": {}}) is False
    # 문자단위로 DB명 추출 성공 → 확정
    assert re_mod._has_concrete_evidence(
        "sql_injection_blind",
        {"confirmed": True, "extracted_data": {"db_name": "dvwa", "requests": 32}}) is True


def test_blind_sqli_bool_pairs_have_and_variants():
    # 블라인드 판별에 필요한 AND 기반 쌍(따옴표/숫자)이 페이로드에 포함돼야 한다.
    import inspect
    src = inspect.getsource(apc._probe_sqli_bool)
    assert "AND '1'='1" in src   # 따옴표 컨텍스트
    assert "1 AND 1=1" in src    # 숫자형 컨텍스트


# ── 브루트포스 방어 부재 ──
def test_bruteforce_gate_requires_attempts_and_url():
    assert re_mod._has_concrete_evidence(
        "no_bruteforce_protection", {"confirmed": True, "url": "http://t/login", "attempts": 6}) is True
    # 시도 수 부족(임계치 부재 결론 근거 약함) → 미확정
    assert re_mod._has_concrete_evidence(
        "no_bruteforce_protection", {"confirmed": True, "url": "http://t/login", "attempts": 2}) is False
    # url 없음 → 미확정
    assert re_mod._has_concrete_evidence(
        "no_bruteforce_protection", {"confirmed": True, "attempts": 6}) is False


def test_bruteforce_protect_regex_ignores_nav_captcha_word():
    # DVWA 등 좌측 메뉴의 'CAPTCHA'·'Brute Force' 같은 '단어'가 보호 신호로 오인되면 안 된다
    # (그러면 미탐). 보호 문구 정규식은 잠금/rate-limit '문구'에만 반응해야 한다.
    nav = "Home Instructions Brute Force Command Injection CSRF Insecure CAPTCHA File Inclusion"
    assert apc._BRUTE_PROTECT_RE.search(nav) is None
    # 실제 잠금/rate-limit 문구는 잡아야 한다
    assert apc._BRUTE_PROTECT_RE.search("Your account is locked. Try again later.") is not None
    assert apc._BRUTE_PROTECT_RE.search("Too many login attempts") is not None
    # CAPTCHA 마커는 nav 단어가 아니라 실제 위젯 마커에만 반응
    assert apc._CAPTCHA_RE.search("Insecure CAPTCHA menu link") is None
    assert apc._CAPTCHA_RE.search('<div class="g-recaptcha" data-sitekey="x">') is not None
