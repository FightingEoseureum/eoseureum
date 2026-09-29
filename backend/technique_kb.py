"""
technique_kb.py — Technique Knowledge Base (데이터 주도 레지스트리).

각 technique 의 메타데이터(카테고리/의미역할/기대신호/위험도/안전메모)를 한곳에 모은다.
신규 technique 는 TECHNIQUES 에 항목을 추가하거나 techniques/*.json 을 두기만 하면
Attack Surface Planner / Technique Planner 가 자동으로 활용한다(코드 변경 불필요).

기존 payload_planner(Technique Planner) 와 proof_mode 의 등급 체계를 '참조'만 하고
중복 구현하지 않는다. payload 자체는 payload_planner 가 생성한다.
"""
from __future__ import annotations

import json
import pathlib

# semantic_role 표준값
ROLE_SEARCH = "search_function"
ROLE_OBJECT_REF = "object_reference"
ROLE_BUSINESS = "business_logic"
ROLE_AUTH = "authentication"
ROLE_REDIRECT = "redirect"
ROLE_URL_FETCH = "url_fetch"
ROLE_FILE = "file_handling"
ROLE_GENERIC = "generic_input"

# technique 메타데이터. roles: 이 technique 을 추천하는 semantic_role 목록.
TECHNIQUES: dict[str, dict] = {
    "xss": {
        "category": "Injection", "roles": [ROLE_SEARCH, ROLE_GENERIC],
        "expected_signal": "Playwright 브라우저 alert 발생(미발생 시 반사→관찰)",
        "risk": "HIGH", "safe_note": "marker 기반 비파괴 페이로드만.",
    },
    "sqli": {
        "category": "Injection", "roles": [ROLE_SEARCH, ROLE_AUTH, ROLE_GENERIC],
        "expected_signal": "SQLMap injectable 또는 DB 에러 원문 반사",
        "risk": "HIGH", "safe_note": "Time-based/DML/덤프/파일 I/O 금지.",
    },
    "ssti": {
        "category": "Injection", "roles": [ROLE_SEARCH],
        "expected_signal": "응답에 수식 평가 결과 출력(예: 49)",
        "risk": "HIGH", "safe_note": "산술식 평가 확인만(코드 실행 금지).",
    },
    "idor": {
        "category": "Access Control", "roles": [ROLE_OBJECT_REF, ROLE_FILE],
        "expected_signal": "교차 계정 응답에 타 사용자 식별정보 노출",
        "risk": "HIGH", "safe_note": "읽기 전용 교차계정 검증, 상태변경 금지.",
    },
    "access_control": {
        "category": "Access Control", "roles": [ROLE_OBJECT_REF],
        "expected_signal": "권한 없는 접근 허용(인증/인가 우회)",
        "risk": "HIGH", "safe_note": "비파괴 접근 확인만.",
    },
    "auth_bypass": {
        "category": "Authentication", "roles": [ROLE_AUTH],
        "expected_signal": "로그인 폼 우회 신호(안전 응답 비교, 잠금 금지)",
        "risk": "HIGH", "safe_note": "폼당 시도 제한, 계정 잠금 금지.",
    },
    "csrf": {
        "category": "Access Control", "roles": [ROLE_GENERIC],
        "expected_signal": "토큰/SameSite/상태변경성 위험도(자동 확정 없음)",
        "risk": "MEDIUM", "safe_note": "상태 변경 요청 미수행 — 위험도 평가만.",
    },
    "business_logic": {
        "category": "Insecure Design", "roles": [ROLE_BUSINESS],
        "expected_signal": "서버측 재검증 부재(값 변조는 수동 검토)",
        "risk": "MEDIUM", "safe_note": "값 변조 자동 수행 안 함.",
    },
    "open_redirect": {
        "category": "Access Control", "roles": [ROLE_REDIRECT],
        "expected_signal": "Location 헤더에 외부 도메인 반환",
        "risk": "MEDIUM", "safe_note": "비파괴 리다이렉트 확인만.",
    },
    "ssrf": {
        "category": "SSRF", "roles": [ROLE_URL_FETCH],
        "expected_signal": "내부망/메타데이터 응답(자동 전송 없음 — 후보)",
        "risk": "HIGH", "safe_note": "자동 외부/내부 요청 전송 금지 — 후보 분류.",
    },
    "path_traversal": {
        "category": "Path Traversal", "roles": [ROLE_FILE],
        "expected_signal": "응답에 파일 내용 노출(무해 파일만)",
        "risk": "MEDIUM", "safe_note": "무해 파일 경로만 — 민감 파일 덤프 금지.",
    },
    "file_upload": {
        "category": "Insecure Design", "roles": [ROLE_FILE],
        "expected_signal": "서버측 확장자/콘텐츠 검증 부재(업로드는 승인 시)",
        "risk": "MEDIUM", "safe_note": "웹쉘/실행파일 업로드 금지.",
    },
    "command_injection": {
        "category": "Injection", "roles": [],   # 기본 미추천(고위험) — RCE proof mode 승인 시
        "expected_signal": "RCE Proof Mode 고정 echo marker 반사만",
        "risk": "HIGH", "safe_note": "OS 명령 기본 금지 — 승인 시 echo marker 한정.",
    },
}

_EXTRA_DIR = pathlib.Path(__file__).resolve().parent / "techniques"


def _load_extra() -> None:
    """techniques/*.json 이 있으면 추가 로드(신규 technique 디렉터리 모델 지원)."""
    try:
        if not _EXTRA_DIR.is_dir():
            return
        for fp in _EXTRA_DIR.glob("*.json"):
            try:
                data = json.loads(fp.read_text(encoding="utf-8"))
            except Exception:
                continue
            name = data.get("name") or fp.stem
            if name and isinstance(data, dict):
                register_technique(name, data)
    except Exception:
        pass


def register_technique(name: str, meta: dict) -> None:
    """신규 technique 등록(런타임). roles/expected_signal/risk/safe_note/category."""
    if not name:
        return
    TECHNIQUES[name.lower()] = {
        "category": meta.get("category", "Other"),
        "roles": list(meta.get("roles", [])),
        "expected_signal": meta.get("expected_signal", ""),
        "risk": (meta.get("risk", "MEDIUM") or "MEDIUM").upper(),
        "safe_note": meta.get("safe_note", "비파괴 안전 점검만."),
    }


def get_technique(name: str) -> dict | None:
    return TECHNIQUES.get((name or "").lower())


def techniques_for_role(role: str) -> list[str]:
    """semantic_role 에 매핑된 technique 목록(KB 데이터 주도)."""
    return [t for t, m in TECHNIQUES.items() if role in (m.get("roles") or [])]


def all_techniques() -> list[str]:
    return list(TECHNIQUES.keys())


# 모듈 로드 시 외부 technique 디렉터리 병합(있으면)
_load_extra()
