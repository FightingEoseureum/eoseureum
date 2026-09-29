"""
report_qa.py — Report Quality Checker v1 (보고서 생성 직전 자동 QA).

보고서 데이터(analysis)를 점검해 누락/깨짐/중복/placeholder 를 찾아내고, 안전하게 자동
수정 가능한 항목은 수정한다. 판정/데이터 값은 바꾸지 않으며 표현 결함만 정리한다.
"""
from __future__ import annotations

import re as _re

_PLACEHOLDER = _re.compile(r"(lorem ipsum|todo|tbd|placeholder|xxxx+|채워주세요|여기에)", _re.I)
# 리소스성 URL(폰트/이미지 등) — 취약 URL 로 오인 표시 방지
_RESOURCE_URL = _re.compile(r"(fontawesome|\.woff2?|\.ttf|\.eot|\.png|\.jpg|\.gif|\.svg|\.css|"
                            r"\.ico|glyphicon)", _re.I)


def _dedup_sentences(text: str) -> str:
    """연속 중복 문장 제거(마침표 기준)."""
    if not text:
        return text
    parts = _re.split(r"(?<=[.。])\s+", text)
    out, prev = [], None
    for p in parts:
        if p and p.strip() != (prev or "").strip():
            out.append(p)
        prev = p
    return " ".join(out)


def is_resource_url(url: str) -> bool:
    return bool(_RESOURCE_URL.search(url or ""))


def _check_score_distribution(analysis: dict, findings: list) -> list:
    """수치 무결성: High 존재 시 Score 100 금지, Finding Level 과 분포 불일치 검출."""
    issues = []
    try:
        import report as _r
        sev = _r._eff_severity_counts(analysis)
        score = _r._v3_security_score(analysis)
        if (sev.get("Critical", 0) or sev.get("High", 0)) and score >= 100:
            issues.append(f"Security Score 무결성 오류: High 이상 취약점 존재하나 Score {score}")
        # Finding 이 L3 인데 '저장된' 분포 집계가 0 이면 불일치(렌더 fallback 전 원본 기준)
        import evidence_levels as _evl
        raw = analysis.get("evidence_levels")
        l3 = sum(1 for f in findings if _evl.level_of(f) >= 3)
        if isinstance(raw, dict) and raw and l3 and not raw.get("level3_proven"):
            issues.append("Validation Distribution 불일치: L3 Finding 존재하나 저장 분포 0")
    except Exception:
        pass
    return issues


def check_html_pdf(analysis: dict) -> list:
    """HTML/PDF Finding↔Evidence 정합성 검사. 유형별 증거 키워드 + 카드 교차오염 검출."""
    issues = []
    cards = analysis.get("proof_evidence_cards") or []
    _needs = {  # family → 증거에 반드시 포함돼야 할 키워드(하나 이상)
        "ssti": ["49", "7*7", "template", "jinja", "twig"],
        "clickjacking": ["iframe", "x-frame", "frame-ancestors", "csp"],
        "http_method": ["allow", "trace"],
        "server": ["server:", "server ", "nginx", "apache", "iis", "framework", "language"],
    }
    seen_observed = {}
    for c in cards:
        fam = c.get("vulnerability_type", "")
        blob = " ".join(str(c.get(k, "")) for k in
                        ("observed_result", "response_evidence_snippet", "payload",
                         "expected_result", "technical_basis")).lower()
        kws = _needs.get(fam)
        if kws and not any(k in blob for k in kws):
            issues.append(f"[{fam}] 유형 증거 키워드 부재({'/'.join(kws[:3])}) — 매핑 오류 의심")
        if c.get("business_function", "미상") == "미상":
            issues.append(f"[{fam}] Business 미상")
        if not (c.get("remediation_summary") or "").strip() or c.get("remediation_summary") == "-":
            issues.append(f"[{fam}] Recommendation 누락")
        # 카드 교차 오염: 서로 다른 유형인데 동일 Observed
        obs = (c.get("observed_result") or "").strip()
        if obs and obs != "-":
            if obs in seen_observed and seen_observed[obs] != fam:
                issues.append(f"[{fam}] Observed 값이 다른 유형({seen_observed[obs]})과 동일 — 카드 교차 오염")
            seen_observed[obs] = fam
    return issues


def check(analysis: dict) -> dict:
    """analysis 를 점검하고 QA 리포트 + 자동수정 개수를 반환(원본은 표현 필드만 정리)."""
    issues, fixed = [], 0
    findings = [f for f in (analysis.get("findings") or []) if f.get("judgment") != "양호"]

    for f in findings:
        title = f.get("title", "(제목 없음)")
        # URL 누락 / 리소스 URL 우선표시
        url = f.get("evidence_url") or f.get("url") or ""
        if url and is_resource_url(url):
            # 실제 취약 URL 후보(affected_endpoints)로 교체 시도
            alt = next((u for u in (f.get("affected_endpoints") or [])
                        if u and not is_resource_url(u)), "")
            if alt:
                f["evidence_url"] = alt
                fixed += 1
            else:
                issues.append(f"[{title}] 리소스성 URL 표시({url[:40]}) — 취약 URL 불명확")
        # placeholder
        for k in ("recommendation", "evidence_detail"):
            v = f.get(k) or ""
            if _PLACEHOLDER.search(v):
                issues.append(f"[{title}] {k} 에 placeholder 문구")
            # 중복 문장 자동 정리
            dd = _dedup_sentences(v)
            if dd != v:
                f[k] = dd
                fixed += 1
        # 권고 누락
        if not (f.get("recommendation") or "").strip():
            issues.append(f"[{title}] 권장 조치 누락")

    # Proof 카드 무결성 2.0(있을 때만)
    for c in (analysis.get("proof_evidence_cards") or []):
        vt = c.get("vulnerability_type")
        if not c.get("observed_result") or c.get("observed_result") == "-":
            issues.append(f"[{vt}] Proof Observed 값 없음")
        if not c.get("affected_endpoint") or c.get("affected_endpoint") in (":", ""):
            issues.append(f"[{vt}] Proof endpoint 불명확")
        if (c.get("fingerprint") or {}).get("fingerprint_name", "미상") == "미상":
            issues.append(f"[{vt}] Fingerprint 미상")
        if c.get("business_function", "미상") == "미상":
            issues.append(f"[{vt}] Business 미상")

    # Knowledge Graph / Attack Story 무결성(있을 때만)
    kg = (analysis.get("security_knowledge_graph") or {}).get("summary") or {}
    if analysis.get("security_knowledge_graph") is not None and not kg.get("node_count"):
        issues.append("Knowledge Graph 노드 없음")
    ap = analysis.get("attack_path_graph")
    if ap is not None and not (ap.get("paths")):
        if findings:
            issues.append("Attack Story(공격 경로) 비어 있음")

    # ── HTML/PDF 콘텐츠 정합성 QA (Finding↔Evidence 매핑 검증) ──
    html_pdf_issues = check_html_pdf(analysis)
    html_pdf_issues += _check_score_distribution(analysis, findings)
    # 오탐 위험 자문(참고): 실증 확인인데 soft-404/WAF 신호와 충돌하는 항목
    for _t in (analysis.get("fp_risk_summary") or {}).get("inconsistent_confirmed", []):
        html_pdf_issues.append(f"[{_t}] 실증 확인이나 soft-404/WAF 반사 신호 — 재검토 권고")

    summary = {
        "checked_findings": len(findings),
        "issues_found": len(issues),
        "auto_fixed": fixed,
        "html_pdf_issues": html_pdf_issues,
        "checks": ["중복 문장", "깨진 시간 표현", "리소스 URL 우선표시", "실제 입력점/URL 누락",
                   "Payload/Observed/Fingerprint 누락", "Business 미상", "Recommendation 누락",
                   "Screenshot 누락", "Knowledge Graph 노드", "Attack Story 비어있음",
                   "Proof 카드 무결성"],
        "passed": len(issues) == 0,
        "issues": issues[:60],
    }
    return summary
