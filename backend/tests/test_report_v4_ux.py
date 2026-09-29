"""test_report_v4_ux.py — Report UX/UI Framework v4 (고객 전달용 컨설팅 보고서)."""
import os, sys, io
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import report
from docx import Document


def _txt(doc):
    parts = [p.text for p in doc.paragraphs]
    for t in doc.tables:
        for r in t.rows:
            for c in r.cells:
                parts.append(c.text)
    return "\n".join(parts)


def _rich():
    return {
        "domain": "t.example.com", "overall_risk": "HIGH",
        "summary": {"vulnerability_count": 3, "confirmed_count": 2,
                    "by_severity": {"Critical": 1, "High": 1, "Medium": 1, "Low": 0}},
        "evidence_levels": {"level3_proven": 2, "level2_evidence": 1, "level1_observed": 2,
                            "level0_info": 4, "priority_actions": 3},
        "business_impact_summary": {"critical": 1, "high": 1, "medium": 1, "low": 0},
        "attack_surface_plan": {"summary": {"total_surfaces": 20, "auth_after_surfaces": 5,
                                            "by_type": {"Object Reference": 5}}},
        "ai_payload_plan": {"summary": {"total_input_points": 31, "ai_selected_input_points": 12,
                                        "executed": 9}},
        "attack_path_summary": {"total_paths": 3, "confirmed_paths": 2},
        "path_priority_summary": {"prioritized_paths": 2},
        "attack_paths": [
            {"path_id": "AP-001", "title": "인증 후 객체 접근(IDOR) 경로",
             "path_confidence": "Confirmed Path", "risk_score": 22,
             "steps": ["Entry Point: 인터넷", "Login Page: 로그인", "Object Reference: accountId",
                       "Evidence: Level 3", "Report Impact: 정보 노출"],
             "possible_impact": "타 사용자 정보 노출 가능"},
            {"path_id": "AP-002", "title": "반사형 XSS 경로", "path_confidence": "Confirmed Path",
             "risk_score": 14, "steps": ["Entry Point: 인터넷", "Parameter: q", "Evidence: alert"]},
        ],
        "prioritized_paths": [{"path_id": "AP-001", "score": 22, "priority": "Critical"}],
        "priority_action_plan": [
            {"rank": "P1", "title": "객체 단위 접근 제어 검증 추가", "priority": "Critical",
             "team": "Backend", "effort": "1~3일", "benefit": "교차 계정 접근 차단"},
            {"rank": "P2", "title": "출력 인코딩 적용", "priority": "Medium",
             "team": "Frontend", "effort": "1일", "benefit": "스크립트 실행 차단"},
        ],
        "business_impact": [
            {"title": "관리자 IDOR 실증 — 객체 참조", "family": "idor",
             "business_risk": "고객 정보 노출 가능", "impact_category": ["Access Control"],
             "potential_consequence": ["고객 정보 노출"], "regulatory_risk": []},
        ],
        "remediation_items": [
            {"finding_title": "관리자 IDOR 실증 — 객체 참조", "family": "idor",
             "remediation_title": "객체 단위 접근 제어 검증 추가", "estimated_effort": "1~3일",
             "responsible_team": "Backend", "expected_benefit": "교차 계정 접근 차단"},
        ],
        "asset_inventory": [{"ip": "10.0.0.5", "asset_type": "Database Server",
                             "open_ports": [3306], "detected_services": [{"family": "mysql"}],
                             "risk_tags": ["exposed_database"], "priority": "High", "os_guess": "linux",
                             "web_endpoints": []}],
        "asset_summary": {"total_assets": 1, "high_priority": 1, "internet_exposed": 0},
        "network_exposure_summary": {"input_targets": ["10.0.0.0/24"], "target_type": "cidr",
                                     "live_hosts": 1, "open_ports": 1, "services": 1,
                                     "web_candidates": 0, "high_priority_assets": 1},
        "service_surface_summary": {"total_service_surfaces": 1, "authentication_surfaces": 0,
                                    "database_surfaces": 1, "data_exposure_surfaces": 0,
                                    "file_sharing_surfaces": 0, "container_surfaces": 0},
        "good_items": [{"title": "TLS 1.2 적용"}],
        "solver_summary": {"solver_runs": 3, "by_solver": {"idor_solver": 1}},
        "agent_results": [{"path_id": "AP-001", "family": "idor", "agents": [
            {"agent_name": "object_reference_agent", "agent_role": "객체 참조 분석",
             "observation": "객체 식별자 존재", "limitation": "읽기 전용", "recommended_next_step": "검증"}]}],
        "agent_summary": {"agent_runs": 3},
        "evidence_graph_summary": {"total_nodes": 40, "total_edges": 55, "evidence_nodes": 8,
                                   "agent_observations": 3},
        "service_surfaces": [{"port": 3306, "service": "mysql", "family": "mysql",
                              "attack_surface_type": "Database Surface", "priority": "High",
                              "recommended_solver": "mysql_solver", "evidence_level": 1,
                              "evidence": {}}],
        "validation_candidates": [{"family": "idor", "validation_candidate": "IDOR",
                                   "current_level": 1, "target_level": 3,
                                   "validation_priority": "High", "recommended_validation": "A/B 비교",
                                   "required_evidence": "교차 계정", "promotable_to_level3": True}],
        "validation_summary": {"validation_candidates": 1},
        "findings": [
            {"title": "관리자 IDOR 실증 — 객체 참조", "confidence": "CONFIRMED_RESPONSE",
             "severity": "HIGH", "evidence_detail": "타 계정 노출", "judgment": "취약"},
            {"title": "반사형 XSS", "confidence": "CONFIRMED_BROWSER", "severity": "MEDIUM",
             "evidence_detail": "alert", "judgment": "취약"},
            {"title": "정보 노출", "confidence": "MANUAL_REVIEW", "severity": "LOW", "judgment": "취약"},
        ],
    }


# ── Key Findings (Top 5) ─────────────────────────────────────────────────────

# ── Attack Story (한 줄 Flow, 엔진 용어 없음) ────────────────────────────────

# ── Risk Matrix (4x4) ────────────────────────────────────────────────────────

# ── Roadmap (Priority 1/2/3) ─────────────────────────────────────────────────
def test_roadmap_priorities():
    doc = Document(); a = _rich()
    report._add_v4_roadmap(doc, a)
    txt = _txt(doc)
    assert "개선 로드맵" in txt
    assert "Priority 1" in txt and "Priority 2" in txt
    assert "객체 단위 접근 제어" in txt
    assert "담당 Backend" in txt and "1~3일" in txt


# ── Finding Card (엔진 내부 없음, 핵심 필드 유지) ───────────────────────────
def test_finding_card_layout():
    a = _rich()
    doc = Document()
    report._add_observed_view_block(doc, a["findings"][0], a)
    txt = _txt(doc)
    assert "관찰 내용" in txt and "확보 증거" in txt
    assert "비즈니스 영향" in txt and "권장 조치" in txt
    assert "관련 Solver" not in txt and "Evidence Chain" not in txt


# ── 본문 엔진 용어 제거 검증 ─────────────────────────────────────────────────

def test_engine_terms_in_appendix():
    doc = Document(); a = _rich()
    report._add_developer_appendix(doc, a)
    txt = _txt(doc)
    assert "Developer Appendix" in txt
    assert ("Solver" in txt) or ("Multi-Agent" in txt) or ("Evidence Graph" in txt)


# ── Executive Summary: 큰 KPI + Business Impact ──────────────────────────────
def test_executive_summary_kpis():
    a = _rich()
    buf = report.generate_report({"domain": "t.example.com", "analysis": a,
                                  "created_at": "2026-07-01", "results": []})
    doc = Document(io.BytesIO(buf.getvalue()))
    txt = _txt(doc)
    assert "종합 위험도" in txt and "실증 확인" in txt and "핵심 자산" in txt
    assert "비즈니스 영향" in txt and "우선 조치" in txt and "보안 점수" in txt


# ── 전체 보고서 회귀(v4 IA 전 구성) ──────────────────────────────────────────
def test_full_report_v4_intact(monkeypatch):
    monkeypatch.setenv("REPORT_SHOW_ENGINE_INTERNAL", "true")   # 풀 리포트(엔진내부 포함) 검증
    a = _rich()
    buf = report.generate_report({"domain": "t.example.com", "analysis": a,
                                  "created_at": "2026-07-01", "results": []})
    doc = Document(io.BytesIO(buf.getvalue()))
    txt = _txt(doc)
    for sect in ("Security Assessment Report", "Executive Summary", "보안 진단 대시보드",
                 "점검 목적", "점검 항목 및 위험도", "발견된 취약점", "개선 로드맵",
                 "취약점 상세", "대응방안", "부록", "Developer Appendix"):
        assert sect in txt, f"섹션 누락: {sect}"
