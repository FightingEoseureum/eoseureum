"""
solver_registry.py — Solver 레지스트리(코드 수정 없이 신규 Solver 추가 가능하도록 설계).

내장 9종(IDOR/XSS/SQLi/CSRF/Logic/Upload/Redirect/SSRF/Auth)을 등록하고,
향후 GraphQL/JWT/OAuth/SAML/WebSocket/Mobile API/LLM/Agent Solver 를
register_solver() 로 추가하면 Orchestrator 가 자동 활용한다.
"""
from __future__ import annotations

import solvers as _solvers

# name → solver 인스턴스
_REGISTRY: dict[str, object] = {}
# handles 키워드(technique/semantic_role/node_type) → solver name
_HANDLER_INDEX: dict[str, str] = {}


def register_solver(solver_cls) -> None:
    """Solver 클래스 등록(런타임). handles 키워드로 자동 라우팅에 편입된다."""
    inst = solver_cls() if isinstance(solver_cls, type) else solver_cls
    _REGISTRY[inst.name] = inst
    for kw in getattr(inst, "handles", ()) or ():
        _HANDLER_INDEX.setdefault(str(kw).lower(), inst.name)


def get_solver(name: str):
    return _REGISTRY.get(name)


def select_solver(*keys: str):
    """technique/semantic_role/node_type 키들로 적합한 solver 를 선택(없으면 None)."""
    for k in keys:
        if not k:
            continue
        kl = str(k).lower()
        if kl in _REGISTRY:
            return _REGISTRY[kl]
        if kl in _HANDLER_INDEX:
            return _REGISTRY[_HANDLER_INDEX[kl]]
    return None


def all_solvers() -> list[str]:
    return list(_REGISTRY.keys())


def _bootstrap() -> None:
    for cls in _solvers.BUILTIN_SOLVERS:
        register_solver(cls)


_bootstrap()
