"""worker.py — 어스름 Scanner Worker (i7, hands). 경량 external_tools 오프로드 전용(B2).

실행(i7 WSL Ubuntu):
  EOSEUREUM_ROLE=worker .venv/bin/uvicorn worker:app --host 0.0.0.0 --port 8100

하이브리드(B2): 맥은 능동점검(engine, 로컬), i7 은 외부도구(sqlmap/nuclei/testssl/ffuf/…)를
네이티브로 실행한다. 외부도구가 i7 에서 대상으로 나가므로 egress 도 i7 단일출구가 된다
(B1 의 외부도구 프록시 공백을 네이티브 실행으로 완결).

폴링 방식(콜백 불필요): 맥이 POST /worker/scan 으로 잡을 넘기고 GET /worker/scan/{id} 를
폴링해 진행률과, 완료 시 external_findings 를 회수한다. 워커는 상태 비저장(메모리 잡 레지스트리만,
DB 없음). 보안: LAN 한정 + Bearer(WORKER_TOKEN, fail-close).
"""
import asyncio

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

# 잡별 env 격리(probe_env: ENABLE_SQLMAP 등)를 위해 os.environ 을 컨텍스트 오버레이로 교체.
import scan_context
scan_context.install()

import worker_config as wc
import worker_tasks

app = FastAPI(title="Eoseureum Scanner Worker", version="2.0-lean")

# 메모리 잡 레지스트리(스캔별 상태/결과). DB 없음.
_JOBS: dict = {}
_TASKS: dict = {}


class ScanJob(BaseModel):
    scan_id: str
    target: str = ""
    phase: str = "external_tools"     # 경량 워커는 external_tools 만 지원
    host_results: list = Field(default_factory=list)
    config: dict = Field(default_factory=dict)
    callback_url: str = ""            # 호환용(미사용 — 폴링 방식)


def _auth(authorization: str | None) -> None:
    if not wc.check_token(authorization):
        raise HTTPException(status_code=401, detail="invalid or missing worker token")


@app.get("/worker/health")
async def health():
    return {"status": "ok", "role": wc.role(), "active_jobs": len(_TASKS)}


@app.post("/worker/scan", status_code=202)
async def start_scan(job: ScanJob, authorization: str | None = Header(default=None)):
    _auth(authorization)
    scan_id = job.scan_id
    if not scan_id:
        raise HTTPException(status_code=400, detail="scan_id required")
    if scan_id in _TASKS and not _TASKS[scan_id].done():
        raise HTTPException(status_code=409, detail="scan already running")
    _JOBS[scan_id] = {"status": "accepted", "stage": "queued", "percent": 0}
    task = asyncio.create_task(worker_tasks.run_external_tools_job(job.model_dump(), _JOBS))
    _TASKS[scan_id] = task
    return {"scan_id": scan_id, "status": "accepted"}


@app.get("/worker/scan/{scan_id}")
async def scan_status(scan_id: str, authorization: str | None = Header(default=None)):
    _auth(authorization)
    st = _JOBS.get(scan_id)
    if st is None:
        raise HTTPException(status_code=404, detail="unknown scan_id")
    resp = {"scan_id": scan_id,
            "status": st.get("status", "unknown"),
            "progress": {"stage": st.get("stage", ""), "percent": st.get("percent", 0),
                         "message": st.get("last_message", "")},
            "error": st.get("error")}
    # 완료 시에만 결과(external_findings)를 실어 폴링 회수(콜백 불필요).
    if st.get("status") == "complete":
        resp["external_findings"] = st.get("external_findings", [])
    return resp


@app.post("/worker/scan/{scan_id}/stop")
async def stop_scan(scan_id: str, authorization: str | None = Header(default=None)):
    _auth(authorization)
    task = _TASKS.get(scan_id)
    if task is None:
        raise HTTPException(status_code=404, detail="unknown scan_id")
    if not task.done():
        task.cancel()
    _JOBS.setdefault(scan_id, {})["status"] = "stopping"
    return {"scan_id": scan_id, "status": "stopping"}
