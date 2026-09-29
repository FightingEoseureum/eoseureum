"""
discovery_worker — Browser-based Attack Surface Discovery 2.0 + Worker Ready Architecture.

기본 비활성화(ENABLE_BROWSER_DISCOVERY=false). 활성 시 브라우저에서 실제 오가는 Request 를
안전하게 수집해 API/XHR/JSON/Header/Cookie/SPA Route 입력점을 확보하고, 기존 Attack Surface
Planner 로 넘긴다. 향후 Redis Queue 기반 별도 Worker 서버로 분리 가능하도록 설계.
"""
from __future__ import annotations

from .discovery_models import (DiscoveryJob, DiscoveryResult, DiscoveryTaskStatus,
                               DiscoveryWorkerInterface)
from .browser_discovery import (LocalDiscoveryWorker, run_browser_job, assemble_result,
                                normalize_requests_to_inputs, collect_graphql_ws,
                                to_planner_points, to_injection_points, merge_results, SOURCE)
from . import discovery_policy as policy

__all__ = [
    "DiscoveryJob", "DiscoveryResult", "DiscoveryTaskStatus", "DiscoveryWorkerInterface",
    "LocalDiscoveryWorker", "run_browser_job", "assemble_result",
    "normalize_requests_to_inputs", "collect_graphql_ws", "to_planner_points",
    "to_injection_points", "merge_results",
    "policy", "SOURCE", "apply_to_analysis", "enabled",
]


def enabled() -> bool:
    """브라우저 발견 활성 여부(기본 False → 기존 동작 보존)."""
    return policy.enabled()


# analysis 저장 키(원문/응답 body 는 저장하지 않음 — 마스킹된 메타만).
_ANALYSIS_KEYS = {
    "summary": "browser_discovery_summary",
    "requests": "browser_discovery_requests",
    "endpoints": "browser_discovery_endpoints",
    "inputs": "browser_discovery_inputs",
    "blocked_actions": "browser_discovery_blocked_actions",
    "errors": "browser_discovery_errors",
}


def apply_to_analysis(analysis: dict, result: DiscoveryResult) -> list:
    """DiscoveryResult 를 analysis 에 반영하고, Planner 로 넘길 입력점 목록을 반환.

    저장 원칙: 응답 원문 미저장, 민감정보 마스킹(수집 단계에서 이미 적용됨), Body 길이 제한.
    """
    if analysis is None or result is None:
        return []
    d = result.to_dict()
    analysis[_ANALYSIS_KEYS["summary"]] = d.get("summary", {})
    analysis[_ANALYSIS_KEYS["requests"]] = d.get("requests", [])
    analysis[_ANALYSIS_KEYS["endpoints"]] = d.get("endpoints", [])
    analysis[_ANALYSIS_KEYS["inputs"]] = d.get("inputs", [])
    analysis["browser_discovery_routes"] = d.get("routes", [])
    analysis[_ANALYSIS_KEYS["blocked_actions"]] = d.get("blocked_actions", [])
    analysis[_ANALYSIS_KEYS["errors"]] = d.get("errors", [])
    # v3 확장 데이터(값 미저장 원칙 유지 — 스토리지는 키/존재만)
    analysis["browser_discovery_storage"] = d.get("storage", {})
    analysis["browser_discovery_interaction_points"] = d.get("interaction_points", [])
    analysis["browser_discovery_api_graph"] = d.get("api_graph", {})
    analysis["browser_discovery_replay_candidates"] = d.get("replay_candidates", [])
    analysis["browser_dom_snapshots"] = d.get("dom_snapshots", [])
    analysis["browser_request_dom_links"] = d.get("request_dom_links", [])
    return to_planner_points(d.get("inputs", []))
