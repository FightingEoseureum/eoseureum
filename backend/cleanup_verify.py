"""
cleanup_verify.py — 스캔이 생성한 테스트 아티팩트의 '정리 검증' 집계(순수 로직).

여러 정리 소스(finding 기반 cleanup / 저장형 XSS 주입 전체 / 쓰기권한 원복 실패)를 모아
"이 스캔이 남긴 흔적이 모두 정리·원복됐는가"를 정직하게 판정한다. 네트워크 없음·예외 미발생.

원칙: 삭제/원복이 항상 가능한 것은 아니므로(앱마다 다름), 목표는 '보장된 삭제'가 아니라
'검증된 정직성' — 남은 잔여물(residue)을 숨기지 않고 명확히 보고한다.
"""
from __future__ import annotations


def build_cleanup_report(findings_cleanup: dict | None = None,
                         stored_xss: dict | None = None,
                         write_authz_revert_failures: list | None = None) -> dict:
    """정리 소스들을 모아 통합 리포트를 만든다.

    findings_cleanup: cleanup_manager.CleanupResult.to_dict() (finding 기반 정리) 또는 None
    stored_xss: active_probing.cleanup_stored_xss_injections() 결과 또는 None
    write_authz_revert_failures: 원복 실패한 쓰기검증 항목 리스트({url,field,...}) 또는 None
    """
    residue: list[dict] = []
    attempted = 0
    cleaned = 0

    fc = findings_cleanup or {}
    attempted += int(fc.get("cleanup_attempted", 0) or 0)
    cleaned += int(fc.get("cleanup_success", 0) or 0)
    for f in (fc.get("cleanup_failed") or []):
        residue.append({"type": "finding_artifact", "detail": f})

    sx = stored_xss or {}
    attempted += int(sx.get("injected", 0) or 0)
    cleaned += int(sx.get("verified_gone", 0) or 0)
    for r in (sx.get("residue") or []):
        residue.append({"type": "stored_xss_marker", "detail": r})

    for w in (write_authz_revert_failures or []):
        residue.append({"type": "write_authz_revert_failed", "detail": w})

    verified_clean = len(residue) == 0
    return {
        "verified_clean": verified_clean,
        "attempted": attempted,
        "cleaned": cleaned,
        "residue_count": len(residue),
        "residue": residue[:50],
        "sources": {
            "findings": fc or None,
            "stored_xss": sx or None,
            "write_authz_revert_failed": len(write_authz_revert_failures or []),
        },
    }


def build_deletion_requests(report: dict | None) -> list[dict]:
    """정리 리포트의 잔여물(residue)을 '삭제 요청' 항목으로 정규화한다.

    상태변경형 실증(저장형 XSS·파일 업로드·쓰기검증)이 남긴, 자동 원복에 실패한 산출물을
    사용자가 대상에서 직접 삭제할 수 있도록 {경로, 작성내용, 방법}으로 정리한다.
    보고서 하단·프론트 '삭제요청' 패널이 공통으로 사용한다. 네트워크 없음·순수 로직.

    반환 각 항목: {kind, path, content, method, marker, note}
    """
    out: list[dict] = []
    for r in (report or {}).get("residue", []) or []:
        rtype = r.get("type", "")
        d = r.get("detail") or {}
        if rtype == "stored_xss_marker":
            marker = d.get("marker", "")
            param = d.get("param", "") or "content"
            out.append({
                "kind": "저장형 XSS 테스트 데이터",
                "path": d.get("submit_url", "") or "",
                "content": f"파라미터 '{param}' 에 저장한 무해 마커 문자열 '{marker}'",
                "method": "POST",
                "marker": marker,
                "note": "게시글/댓글 등으로 저장됨 — 해당 항목 삭제 필요",
            })
        elif rtype == "write_authz_revert_failed":
            field = d.get("field", "") or d.get("param", "")
            out.append({
                "kind": "쓰기검증 생성/변경 데이터",
                "path": d.get("url", "") or d.get("submit_url", "") or "",
                "content": (f"쓰기 접근통제 검증 중 생성/변경한 항목"
                            + (f" (필드 '{field}')" if field else "")),
                "method": (d.get("method", "") or "POST").upper(),
                "marker": d.get("marker", ""),
                "note": "자동 원복 실패 — 생성/변경된 항목 확인·삭제 필요",
            })
        else:  # finding_artifact (파일 업로드 등)
            eps = d.get("endpoints") or []
            marker = d.get("marker", "")
            out.append({
                "kind": "테스트 아티팩트",
                "path": (eps[0] if eps else ""),
                "content": (f"{d.get('title','')} 실증으로 생성된 테스트 파일/데이터"
                            + (f" (마커 {marker})" if marker else "")),
                "method": "",
                "marker": marker,
                "note": "자동 삭제 실패 — 업로드/생성물 확인·삭제 필요",
            })
    return out[:50]


def has_residue(report: dict | None) -> bool:
    return bool(report and report.get("residue_count", 0) > 0)


def residue_message(report: dict | None) -> str:
    """잔여물이 있을 때 사용자에게 보여줄 경고 문구(수동 정리 안내)."""
    if not has_residue(report):
        return ""
    n = report.get("residue_count", 0)
    kinds = {}
    for r in report.get("residue", []):
        kinds[r.get("type", "")] = kinds.get(r.get("type", ""), 0) + 1
    parts = []
    if kinds.get("stored_xss_marker"):
        parts.append(f"저장형 XSS 마커 {kinds['stored_xss_marker']}건")
    if kinds.get("write_authz_revert_failed"):
        parts.append(f"쓰기검증 원복실패 {kinds['write_authz_revert_failed']}건")
    if kinds.get("finding_artifact"):
        parts.append(f"기타 아티팩트 {kinds['finding_artifact']}건")
    return (f"테스트 데이터 {n}건이 정리되지 않았습니다({', '.join(parts)}). "
            "대상에서 수동 확인·제거가 필요합니다.")
