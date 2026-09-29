"""
workers.py — Worker-ready Architecture (분리 준비). 실제 Redis Queue 는 아직 미구현.

Discovery/Validation/Proof/Graph/Report/Renderer/QA 를 동일한 WorkerJob 모델로 다룰 수 있게
공통 인터페이스를 정의한다. 현재는 LocalWorker 로 in-process 동작. 향후 원격 Worker(큐)로
교체 가능하도록 순수 dict/dataclass + 공통 run() 시그니처만 맞춘다.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict


class WorkerStatus:
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    DONE = "DONE"
    FAILED = "FAILED"
    ALL = {PENDING, RUNNING, DONE, FAILED}


@dataclass
class WorkerJob:
    job_id: str
    scan_id: str = ""
    target: str = ""
    kind: str = ""                       # discovery|validation|proof|graph|report|renderer|qa
    input: dict = field(default_factory=dict)
    output: dict = field(default_factory=dict)
    status: str = WorkerStatus.PENDING
    started_at: str = ""
    finished_at: str = ""
    errors: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_dict(d):
        d = dict(d or {})
        return WorkerJob(job_id=str(d.get("job_id", "job")), scan_id=str(d.get("scan_id", "")),
                         target=str(d.get("target", "")), kind=str(d.get("kind", "")),
                         input=dict(d.get("input") or {}), output=dict(d.get("output") or {}),
                         status=d.get("status", WorkerStatus.PENDING),
                         started_at=d.get("started_at", ""), finished_at=d.get("finished_at", ""),
                         errors=list(d.get("errors") or []))


class BaseWorker:
    """모든 Worker 공통 인터페이스. run(job)->job (output/status 채움)."""
    kind = "base"

    def run(self, job: WorkerJob) -> WorkerJob:  # pragma: no cover - 추상
        raise NotImplementedError


class _AnalysisFnWorker(BaseWorker):
    """analysis dict 를 입력받아 build 함수를 실행하는 LocalWorker 공통 구현."""

    def __init__(self, kind, fn):
        self.kind = kind
        self._fn = fn

    def run(self, job: WorkerJob) -> WorkerJob:
        job.status = WorkerStatus.RUNNING
        try:
            job.output = self._fn(job.input.get("analysis") or {}) or {}
            job.status = WorkerStatus.DONE
        except Exception as e:  # 안전: 실패해도 파이프라인 중단 없이 기록
            job.errors.append(str(e))
            job.status = WorkerStatus.FAILED
        return job


def _lazy(modname, fnname):
    def _call(analysis):
        mod = __import__(modname)
        return getattr(mod, fnname)(analysis)
    return _call


def local_workers() -> dict:
    """현재 사용 가능한 LocalWorker 레지스트리(분리 준비 — 동일 인터페이스)."""
    reg = {
        "proof": _AnalysisFnWorker("proof", _lazy("proof_evidence", "build_all")),
        "graph": _AnalysisFnWorker("graph", _lazy("security_knowledge_graph", "build_all")),
        "qa": _AnalysisFnWorker("qa", lambda a: {"report_qa": __import__("report_qa").check(a)}),
    }
    try:
        import proof_validation  # noqa: F401
        reg["validation"] = _AnalysisFnWorker(
            "validation", _lazy("proof_validation", "run_proof_validation"))
    except Exception:
        pass
    return reg


WORKER_KINDS = ["discovery", "validation", "proof", "graph", "report", "renderer", "qa"]
