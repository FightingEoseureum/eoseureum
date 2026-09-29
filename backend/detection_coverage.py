"""
detection_coverage.py — Detection Coverage / Result Matrix.

"무엇을 검사했고 무엇을 검사하지 않았는지"를 기법별로 명확히 집계한다(고객 이해 핵심).
신규 탐지/판정 없음 — 이미 산출된 findings/coverage/proof_validation 으로 '집계'만 한다.

Technique 별: Tested / Confirmed / Possible / Blocked by Policy / Not Applicable(Not Injectable).
"""
from __future__ import annotations

import proof_evidence as pe

_TECHNIQUES = ["sqli", "xss", "ssti", "idor", "csrf", "open_redirect", "path_traversal",
               "clickjacking", "http_method", "server", "file_upload", "ssrf",
               # 확장: active_probing 이 실제 수행하는 기법을 모두 표기(정직성/범위 가시화)
               "lfi", "xxe", "cmdi", "cors", "crlf", "nosqli", "auth_bypass",
               "user_enumeration", "graphql", "swagger", "actuator", "source_map",
               "backup_file", "admin_exposure", "js_secrets", "email_header_injection",
               "jwt", "subdomain_takeover"]
_LABEL = {"sqli": "SQL Injection", "xss": "XSS", "ssti": "SSTI", "idor": "IDOR/AuthZ",
          "csrf": "CSRF", "open_redirect": "Open Redirect", "path_traversal": "Path Traversal",
          "clickjacking": "Clickjacking", "http_method": "HTTP Method", "server": "Server/Header",
          "file_upload": "File Upload", "ssrf": "SSRF",
          "lfi": "LFI/Path Traversal", "xxe": "XXE", "cmdi": "Command Injection",
          "cors": "CORS Misconfig", "crlf": "CRLF Injection", "nosqli": "NoSQL Injection",
          "auth_bypass": "Auth Bypass", "user_enumeration": "User Enumeration",
          "graphql": "GraphQL Introspection", "swagger": "Swagger/OpenAPI Exposure",
          "actuator": "Spring Actuator", "source_map": "Source Map Exposure",
          "backup_file": "Backup/Config File", "admin_exposure": "Admin Exposure",
          "js_secrets": "JS Secrets", "email_header_injection": "Email Header Injection",
          "jwt": "JWT Weakness", "subdomain_takeover": "Subdomain Takeover"}

# active_probing._probe_one 이 입력점마다 항상 시도하는 코어 기법(능동 점검 실행 시 '검사됨')
_CORE_ALWAYS = {"sqli", "xss", "ssti", "lfi", "xxe", "cmdi", "cors", "crlf",
                "nosqli", "open_redirect", "ssrf", "csrf", "http_method", "clickjacking",
                "server"}


def _confirmed(f) -> bool:
    return (f.get("confidence") or "").upper().startswith("CONFIRMED") or f.get("probe_confirmed") is True


def build_coverage(analysis: dict) -> dict:
    """기법별 Detection Result Matrix + Detection Coverage 요약."""
    findings = [f for f in (analysis.get("findings") or []) if f.get("judgment") != "양호"]
    cov = analysis.get("coverage") or {}
    # 기법별 시도 대상 수(coverage 우선, 없으면 발견 수로 하한).
    # 실제 기록 키는 '*_attempts'(active_probing _COVERAGE) — 과거 '*_tested' 키를 읽어 항상 None 이
    # 되던 버그를 교정. 구키(*_tested 등)는 호환을 위해 폴백으로 남긴다.
    tested_hint = {
        "sqli": cov.get("sqli_attempts") or cov.get("sqli_tested"),
        "xss": cov.get("xss_attempts") or cov.get("xss_tested"),
        "cmdi": cov.get("cmdi_attempts"),
        "ssti": cov.get("ssti_attempts") or cov.get("ssti_tested"),
        "idor": cov.get("idor_candidates"),
        "server": cov.get("header_config_checks"),
        "file_upload": cov.get("upload_attempts") or cov.get("upload_tested"),
    }
    # blocked(정책 차단) 카운트 — proof_validation 기반
    blocked_by_fam: dict = {}
    for r in (analysis.get("proof_validation") or []):
        fam = pe._family({"title": r.get("finding_title", ""),
                          "family": r.get("family", "")})
        blocked_by_fam[fam] = blocked_by_fam.get(fam, 0) + len(r.get("blocked_actions", []))

    by_fam: dict = {t: {"technique": _LABEL[t], "tested": 0, "confirmed": 0, "possible": 0,
                        "blocked_by_policy": blocked_by_fam.get(t, 0), "not_applicable": 0,
                        "manual_review": 0, "reason": ""} for t in _TECHNIQUES}
    for f in findings:
        fam = pe._family(f)
        row = by_fam.get(fam)
        if not row:
            continue
        if _confirmed(f):
            row["confirmed"] += 1
        elif (f.get("confidence") or "").upper() == "MANUAL_REVIEW":
            row["manual_review"] += 1
            row["possible"] += 1
        else:
            row["possible"] += 1

    # 공격표면·참고 항목도 '도달·발견'으로 반영(정직성): 해당 기법이 표면을 실제 발견했으면
    # not_reached(미도달)로 표기되면 안 된다. → 그 기법을 'possible(검토)'로 최소 반영.
    for f in ((analysis.get("attack_surface_items") or []) + (analysis.get("discovery_items") or [])):
        row = by_fam.get(pe._family(f))
        if not row:
            continue
        row["possible"] += 1
        if (f.get("confidence") or "").upper() == "MANUAL_REVIEW":
            row["manual_review"] += 1

    # 능동 점검이 실제 실행됐는지 신호(입력점/폼/발견 중 하나라도 있으면 실행된 것).
    # 과거엔 coverage 하위에 없는 web_candidates/validation_candidates 를 읽어 항상 0 → 코어 기법이
    # 입력점 수십 개를 점검하고도 'Tested=1' 로 과소보고. 실제 기록 키(inputs_found/params/forms)로 교정.
    def _as_count(v):
        # web_candidates/validation_candidates 등은 '리스트'라 int() 시 터졌다(Detection Coverage 오류).
        # 리스트/튜플/딕트/셋은 길이로, 그 외는 int 로 강건 변환(변환 불가는 0).
        if isinstance(v, (list, tuple, dict, set)):
            return len(v)
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0
    _probed_points = (_as_count(cov.get("inputs_found")) or _as_count(cov.get("params"))
                      or _as_count(cov.get("forms_found")) or _as_count(cov.get("discovered_forms"))
                      or _as_count(cov.get("login_forms_tested"))
                      or _as_count(analysis.get("web_candidates"))
                      or _as_count(analysis.get("validation_candidates")) or 0)
    probing_ran = bool(findings) or bool(_probed_points)

    matrix = []
    for t in _TECHNIQUES:
        row = by_fam[t]
        hint = tested_hint.get(t)
        found = row["confirmed"] + row["possible"]
        row["tested"] = int(hint) if isinstance(hint, int) and hint >= found else max(found, hint or found)
        # 코어 기법: 능동 점검이 실행됐다면 입력점마다 항상 시도됨 → '검사됨'으로 정직 표기
        if probing_ran and t in _CORE_ALWAYS and row["tested"] < max(1, int(_probed_points or 1)):
            row["tested"] = max(row["tested"], int(_probed_points) if _probed_points else 1)
        row["not_applicable"] = max(0, row["tested"] - found - row["blocked_by_policy"])

        # ── 상태 판정(정직성): confirmed / tested_clean / blocked / not_reached ──
        if row["confirmed"]:
            row["status"] = "confirmed"
            row["status_label"] = "취약 확인"
        elif row["possible"]:
            row["status"] = "possible"
            row["status_label"] = "취약 가능(검토)"
        elif row["blocked_by_policy"] and not row["tested"]:
            row["status"] = "blocked"
            row["status_label"] = "정책 차단"
        elif row["tested"]:
            row["status"] = "tested_clean"
            row["status_label"] = "검사함 · 안전"
        else:
            row["status"] = "not_reached"
            row["status_label"] = "미도달(표면 없음)"

        # 사유
        if t == "idor" and row["manual_review"]:
            row["reason"] = "second account required (cross-account 미수행)"
        elif row["status"] == "tested_clean":
            row["reason"] = "검사 수행 · 취약점 미발견"
        elif row["status"] == "not_reached":
            row["reason"] = "해당 입력 표면 미발견(도달 못 함)"
        matrix.append(row)

    summary = {
        "total_confirmed": sum(r["confirmed"] for r in matrix),
        "total_possible": sum(r["possible"] for r in matrix),
        "total_blocked": sum(r["blocked_by_policy"] for r in matrix),
        "techniques_with_findings": sum(1 for r in matrix if r["confirmed"] or r["possible"]),
        "techniques_tested_clean": sum(1 for r in matrix if r["status"] == "tested_clean"),
        "techniques_not_reached": sum(1 for r in matrix if r["status"] == "not_reached"),
        "techniques_total": len(matrix),
        "sqli": _fmt(by_fam["sqli"]), "ssti": _fmt(by_fam["ssti"]),
        "xss": _fmt(by_fam["xss"]), "idor": _fmt(by_fam["idor"]),
    }
    # 외부도구 실행 상태(정직성): ran/available/missing/disabled/not_applicable 를 리포트에 노출.
    ext_status = analysis.get("external_tools_status") or {}
    ext_rows = []
    for _name, _st in ext_status.items():
        if isinstance(_st, dict):
            ext_rows.append({"tool": _name, "status": _st.get("status", ""),
                             "label": _st.get("label", "")})

    return {"detection_coverage": {"matrix": matrix, "summary": summary,
                                   "external_tools": ext_rows}}


def _fmt(row) -> str:
    return (f"Tested {row['tested']} · Confirmed {row['confirmed']} · Possible {row['possible']}"
            + (f" · Blocked {row['blocked_by_policy']}" if row["blocked_by_policy"] else ""))
