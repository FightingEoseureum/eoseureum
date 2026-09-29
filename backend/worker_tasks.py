"""worker_tasks.py — 경량 external_tools 오프로드 실행부(B2, 폴링 방식·콜백 없음).

맥이 넘긴 host_results 에 대해 external_tools(sqlmap/nuclei/testssl/ffuf/…)를 i7 에서 실행하고
결과를 jobs[scan_id]['external_findings'] 에 저장한다. 맥은 GET /worker/scan/{id} 폴링으로 회수.

원칙: 워커는 상태 비저장. allow/disallow_scopes 를 방어적으로 강제(out-of-scope 대상 차단).
probe_env(ENABLE_SQLMAP 등)는 이 잡 컨텍스트에만 적용(동시 잡 env 오염 방지).
"""
import asyncio

import scan_scope
import scan_context


async def run_external_tools_job(job: dict, jobs: dict) -> None:
    """external_tools 오프로드 잡 1건 실행. jobs[scan_id] 상태/결과를 갱신한다."""
    scan_id = job["scan_id"]
    host_results = job.get("host_results") or []
    config = job.get("config") or {}

    st = jobs.setdefault(scan_id, {})
    st.update(status="running", stage="external_tools", percent=0)

    # 스코프 강제(워커가 out-of-scope 대상으로 나가지 않도록) — 방어적. 맥이 이미 스코프했지만 이중 안전.
    try:
        scan_scope.register_scope(
            scan_id,
            allow=config.get("allow_scopes"),
            disallow=config.get("disallow_scopes"),
            deny=config.get("category_deny_list"))
    except Exception:
        pass

    async def _prog(msg):
        # 폴링 status 에 최근 진행 메시지/증가 퍼센트만 반영(B3 2칸 UX 가 소비).
        try:
            st.update(percent=min(99, int(st.get("percent", 0)) + 1))
        except Exception:
            pass
        st["last_message"] = str(msg)

    _probe_env = config.get("probe_env") if isinstance(config.get("probe_env"), dict) else {}
    try:
        with scan_context.scope(_probe_env):
            import external_tools
            findings = await external_tools.run_all_external_tools(
                host_results, scan_id=scan_id, progress_cb=_prog)
        st.update(status="complete", percent=100, stage="complete",
                  external_findings=findings or [])
    except asyncio.CancelledError:
        st.update(status="stopped", stage="stopped")
        raise
    except Exception as e:
        # 부분 실패라도 빈 결과로 완료 처리하지 않고 error 로 남긴다(맥이 로컬 폴백 판단).
        st.update(status="error", error=str(e), external_findings=[])
    finally:
        try:
            scan_scope.clear_scope(scan_id)
        except Exception:
            pass
