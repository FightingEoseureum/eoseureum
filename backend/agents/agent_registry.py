"""
agents/agent_registry.py — Agent 등록/선택 레지스트리.

Attack Path 유형(family/technique/solver)에 따라 적절한 Agent Group 을 선택한다.
신규 Agent(GraphQL/JWT/OAuth/SAML/WebSocket/Mobile API/LLM/Agent Security)는
register_agent() 로 코드 수정 없이 추가 가능하다.
"""
from __future__ import annotations

import agents as _agents

# family → [agent 인스턴스]
_GROUPS: dict[str, list] = {}
# agent_name → 인스턴스
_BY_NAME: dict[str, object] = {}


def register_agent(agent_cls, family: str | None = None) -> None:
    """Agent 클래스 등록. family 미지정 시 클래스의 family 속성 사용."""
    inst = agent_cls() if isinstance(agent_cls, type) else agent_cls
    fam = (family or getattr(inst, "family", "") or "generic").lower()
    _GROUPS.setdefault(fam, [])
    if all(a.name != inst.name for a in _GROUPS[fam]):
        _GROUPS[fam].append(inst)
    _BY_NAME[inst.name] = inst


def select_agents(*keys: str) -> list:
    """family/technique/solver 키들로 Agent Group 선택(첫 매칭 family 의 전체 Agent)."""
    for k in keys:
        if not k:
            continue
        fam = _norm_family(str(k).lower())
        if fam in _GROUPS:
            return list(_GROUPS[fam])
    return []


def list_agents() -> list[str]:
    return list(_BY_NAME.keys())


def list_groups() -> dict[str, int]:
    return {f: len(a) for f, a in _GROUPS.items()}


_FAMILY_ALIAS = {
    "object_reference": "idor", "access_control": "idor",
    "search_function": "xss", "sql_injection": "sqli",
    "state_change": "redirect", "url_fetch": "ssrf",
    "external_fetch": "ssrf", "authentication": "auth", "login": "auth",
    "file_handling": "upload", "file_upload": "upload",
    "business_logic": "logic", "open_redirect": "redirect",
    # solver name → family
    "idor_solver": "idor", "xss_solver": "xss", "sqli_solver": "sqli",
    "logic_solver": "logic", "upload_solver": "upload",
    "redirect_solver": "redirect", "ssrf_solver": "ssrf", "auth_solver": "auth",
    # CSRF 는 전용 Agent Group 미정의 → 별도 매핑하지 않음(미할당)
}


def _norm_family(key: str) -> str:
    if key in _GROUPS:
        return key
    return _FAMILY_ALIAS.get(key, key)


def _bootstrap() -> None:
    for fam, classes in _agents.FAMILY_AGENTS.items():
        for cls in classes:
            register_agent(cls, family=fam)


_bootstrap()
