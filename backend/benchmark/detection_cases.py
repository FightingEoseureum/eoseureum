"""
detection_cases.py — 탐지 로직 회귀 벤치마크 '라벨 데이터셋'(오프라인·네트워크 없음).

두 종류의 케이스:
  - kind="active_probe": 합성 active_probes({probe_key: probe_data})를 rule_engine 의
    _build_active_probe_findings 에 통과 → finding 생성 여부/판정을 기대치와 대조.
  - kind="judge": 순수 판정 함수(judge_*/classify_* 등)를 직접 호출해 결과를 기대치와 대조.

각 케이스는 '취약(should_report=True)' 또는 '양성/오탐가드(should_report=False)'로 라벨된다.
이 데이터셋으로 payload/판정 로직 변경 전후의 탐지율·오탐율을 정량 비교한다.
"""
from __future__ import annotations

# ── active_probe 케이스: (id, probe_key, probe_data, should_report, expect_judgment|None, note) ──
ACTIVE_PROBE_CASES = [
    # ── 양성(취약) — 실증 근거 있음 → 보고되어야 함 ─────────────────────────────
    ("xss_reflected_confirmed", "xss_reflected",
     {"confirmed": True, "alert_message": "EOSEUREUM_XSS_x", "param": "q", "url": "http://t/s"},
     True, "취약", "반사형 XSS: alert 실증"),
    ("xss_stored_confirmed", "xss_stored",
     {"confirmed": True, "alert_message": "EOSEUREUM_XSS_STORED_x", "param": "content", "url": "http://t/c"},
     True, "취약", "저장형 XSS: alert 실증"),
    ("sqli_error_snippet", "sql_injection",
     {"type": "error_based", "error_snippet": "SQL syntax; MySQL server", "param": "id", "url": "http://t/p"},
     True, "취약", "SQLi 에러 원문 추출"),
    ("sqli_union_version", "sql_injection",
     {"type": "union_based", "extracted_version": "5.7.31-log", "param": "id", "url": "http://t/p"},
     True, "취약", "SQLi UNION 버전 추출"),
    ("ssti_confirmed", "ssti",
     {"confirmed": True, "expected_result": "49", "engine": "Jinja2", "param": "name", "url": "http://t/g"},
     True, "취약", "SSTI 수식 평가 출력"),
    ("xxe_confirmed", "xxe",
     {"confirmed": True, "url": "http://t/api", "evidence": "root:x:0:0:"},
     True, "취약", "XXE 파일 노출"),
    ("lfi_content", "lfi",
     {"file_content_preview": "root:x:0:0:root:/root", "param": "file", "url": "http://t/d"},
     True, "취약", "LFI 파일 내용 노출"),
    ("cmdi_output", "cmd_injection",
     {"type": "output_based", "param": "host", "url": "http://t/ping", "evidence": "EOSEUREUM_CMD_TEST"},
     True, "취약", "CMDi echo 출력"),
    # ── NoSQL: $ne/$eq 불린 차등·Mongo 오류로 '연산자 실제 해석' 확증 시 실증(취약) ───────────
    ("nosql_diff", "nosql_injection",
     {"confirmed": True, "nosql_confirmed": True, "response_diff_bytes": 320,
      "param": "username", "url": "http://t/login", "type": "mongodb_ne_operator"},
     True, "취약", "NoSQL 연산자 실증(불린 차등) → 취약"),
    # 확증 실패(응답차만, nosql_confirmed 없음)는 프로브가 폐기 → 판정 대상 아님(양호).
    ("deserialization_surface", "deserialization",
     {"confirmed": False, "url": "http://t/",
      "locations": [{"location": "cookie", "format": "Java 직렬화 객체(base64)", "sample": "rO0ABX"}]},
     True, "취약", "역직렬화 대상 노출(직렬화 서명 관측) → 취약(노출 실증)"),
    ("api_audit_exposure", "api_audit",
     {"confirmed": False, "excessive_data_exposure": [{"url": "http://t/api/users/1", "sensitive_fields": ["password_hash"]}],
      "mass_assignment_candidates": [], "bola_candidates": []},
     True, "취약", "API 과다노출(민감필드 관측) → 취약(실증)"),

    # ── 음성(양성/오탐가드) — 근거 부족 → 보고되면 안 됨 ─────────────────────────
    ("xss_reflected_no_alert", "xss_reflected",
     {"confirmed": True, "alert_message": "", "param": "q", "url": "http://t/s"},
     False, None, "반사형 XSS: alert 없음 → 보고 금지"),
    ("sqli_boolean_only", "sql_injection",
     {"type": "boolean_based", "param": "id", "url": "http://t/p"},
     False, None, "불린 기반(추출 없음) → 보고 금지"),
    ("sqli_time_only", "sql_injection",
     {"type": "time_based", "delay": 3, "param": "id", "url": "http://t/p"},
     False, None, "시간 기반(추출 없음) → 보고 금지"),
    ("ssti_no_result", "ssti",
     {"confirmed": True, "expected_result": "", "param": "n", "url": "http://t/g"},
     False, None, "SSTI 결과 미출력 → 보고 금지"),
    ("cors_wildcard", "cors",
     {"confirmed": True, "type": "wildcard", "cors_level": "INFO", "url": "http://t/api"},
     False, None, "CORS 와일드카드(공개 API 가능) → 보고 금지"),
    ("nosql_no_diff", "nosql_injection",
     {"confirmed": True, "param": "username", "url": "http://t/login"},
     False, None, "NoSQL 응답차 없음 → 보고 금지"),
    ("deserialization_no_locations", "deserialization",
     {"confirmed": False, "url": "http://t/", "locations": []},
     False, None, "직렬화 서명 없음 → 보고 금지"),
    ("csrf_plain", "csrf",
     {"confirmed": True, "url": "http://t/save"},
     False, None, "CSRF(텍스트 기반) → 보고 금지"),
    ("auth_bypass_unconfirmed", "auth_bypass",
     {"confirmed": False, "url": "http://t/admin"},
     False, None, "auth_bypass 미실증 → 보고 금지"),
    ("api_audit_empty", "api_audit",
     {"confirmed": False, "excessive_data_exposure": [], "mass_assignment_candidates": [], "bola_candidates": []},
     False, None, "API 후보 없음 → 보고 금지"),
]


# ── judge 케이스: (id, module, func, args(kwargs), expected, note) ────────────────
JUDGE_CASES = [
    # BFLA
    ("bfla_missing_auth", "authz_matrix", "judge_bfla",
     {"anon": "allowed", "b": "denied", "a": "allowed"}, "CONFIRMED", "익명 접근 → 확정"),
    ("bfla_lowpriv", "authz_matrix", "judge_bfla",
     {"anon": "denied", "b": "allowed", "a": "allowed", "role_a": "admin", "role_b": "user"},
     "CONFIRMED", "저권한 B 접근 → 확정"),
    ("bfla_b_denied", "authz_matrix", "judge_bfla",
     {"anon": "denied", "b": "denied", "a": "allowed"}, None, "B 차단 → 정상"),
    ("bfla_roles_unknown", "authz_matrix", "judge_bfla",
     {"anon": "denied", "b": "allowed", "a": "allowed"}, "POSSIBLE", "역할 미상 → 가능성"),
    # write authz
    ("writeauthz_confirmed", "authz_write", "judge_write_authz",
     {"b_status": 200, "readback_has_marker": True, "a_owns": True}, "CONFIRMED_WRITE", "B 수정+반영 → 확정"),
    ("writeauthz_blocked", "authz_write", "judge_write_authz",
     {"b_status": 403, "readback_has_marker": None, "a_owns": True}, None, "B 차단 → 정상"),
    ("writeauthz_possible", "authz_write", "judge_write_authz",
     {"b_status": 200, "readback_has_marker": False, "a_owns": True}, "POSSIBLE", "수락+미확정 → 가능성"),
]


def judge_expected(case_id: str):
    for c in JUDGE_CASES:
        if c[0] == case_id:
            return c[4]
    return None
