"""
discovery_models.py — Browser Discovery 2.0 데이터 모델 + Worker 추상 인터페이스.

Worker Ready 구조: 지금은 Eoseureum Main Process 내부에서 호출하지만, 향후 Redis Queue 를 통해
별도 Discovery Worker 서버로 분리 가능하도록 Job/Result/Status/Interface 를 순수 dataclass +
JSON 직렬화로 정의한다(외부 의존 없음).
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict


# ── Task 상태 ────────────────────────────────────────────────────────────────
class DiscoveryTaskStatus:
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    DONE = "DONE"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"

    ALL = {PENDING, RUNNING, DONE, FAILED, TIMEOUT, CANCELLED}
    TERMINAL = {DONE, FAILED, TIMEOUT, CANCELLED}


@dataclass
class DiscoveryJob:
    """브라우저 발견 작업 명세(직렬화 가능). v3: capabilities 로 수집 범위 확장."""
    job_id: str
    base_url: str
    scope: list = field(default_factory=list)          # 허용 host/도메인
    auth: dict | None = None                           # {login_url, username, password, ...} (선택)
    options: dict = field(default_factory=dict)         # 정책 override(없으면 env 정책)
    # v3 Worker 인터페이스 확장 — 수집 능력 플래그(향후 원격 Worker 분리 대비)
    capabilities: dict = field(default_factory=lambda: {
        "runtime_hook": True, "storage": True, "relationship_graph": True,
        "replay_candidate": True, "hidden_api": True, "interaction": True})
    status: str = DiscoveryTaskStatus.PENDING

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "DiscoveryJob":
        d = dict(d or {})
        job = DiscoveryJob(
            job_id=str(d.get("job_id", "job")),
            base_url=str(d.get("base_url", "")),
            scope=list(d.get("scope") or []),
            auth=d.get("auth"),
            options=dict(d.get("options") or {}),
            status=d.get("status", DiscoveryTaskStatus.PENDING),
        )
        if d.get("capabilities"):
            job.capabilities = dict(d["capabilities"])
        return job


@dataclass
class DiscoveryResult:
    """브라우저 발견 결과(요약 + 상세, 원문 미저장)."""
    job_id: str
    status: str = DiscoveryTaskStatus.DONE
    summary: dict = field(default_factory=dict)
    requests: list = field(default_factory=list)        # 마스킹된 요청 메타
    endpoints: list = field(default_factory=list)       # JS/네트워크 endpoint 후보
    inputs: list = field(default_factory=list)          # 정규화된 입력점
    routes: list = field(default_factory=list)          # SPA route
    blocked_actions: list = field(default_factory=list)  # 차단된 위험 클릭
    errors: list = field(default_factory=list)
    # v3 확장 필드
    storage: dict = field(default_factory=dict)          # 스토리지 키/JWT 존재(값 미수집)
    interaction_points: list = field(default_factory=list)  # 이벤트 핸들러 후보
    api_graph: dict = field(default_factory=dict)        # API 관계 그래프
    replay_candidates: list = field(default_factory=list)  # 재현 후보(수행 안 함)
    dom_snapshots: list = field(default_factory=list)    # 구조화 DOM 스냅샷(전체 HTML 미저장)
    request_dom_links: list = field(default_factory=list)  # Request↔DOM 상관

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "DiscoveryResult":
        d = dict(d or {})
        return DiscoveryResult(
            job_id=str(d.get("job_id", "job")),
            status=d.get("status", DiscoveryTaskStatus.DONE),
            summary=dict(d.get("summary") or {}),
            requests=list(d.get("requests") or []),
            endpoints=list(d.get("endpoints") or []),
            inputs=list(d.get("inputs") or []),
            routes=list(d.get("routes") or []),
            blocked_actions=list(d.get("blocked_actions") or []),
            errors=list(d.get("errors") or []),
            storage=dict(d.get("storage") or {}),
            interaction_points=list(d.get("interaction_points") or []),
            api_graph=dict(d.get("api_graph") or {}),
            replay_candidates=list(d.get("replay_candidates") or []),
            dom_snapshots=list(d.get("dom_snapshots") or []),
            request_dom_links=list(d.get("request_dom_links") or []),
        )


class DiscoveryWorkerInterface:
    """Discovery Worker 추상 인터페이스 — 로컬/원격(향후 Redis) 구현이 공통으로 따른다."""

    def run(self, job: DiscoveryJob) -> DiscoveryResult:  # pragma: no cover - 추상
        raise NotImplementedError

    async def run_async(self, job: DiscoveryJob) -> DiscoveryResult:  # pragma: no cover
        raise NotImplementedError
