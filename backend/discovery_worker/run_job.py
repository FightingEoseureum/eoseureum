"""
run_job.py — Discovery Worker CLI 진입점 (Worker 분리 대비).

사용:
  python -m discovery_worker.run_job --job-file <job.json> --out <result.json>
  (또는 backend 를 패키지 루트로: python -m backend.discovery_worker.run_job ...)

입력: DiscoveryJob JSON, 출력: DiscoveryResult JSON.
현재는 내부 호출만 사용해도 되지만, CLI 단독 실행/테스트가 가능해야 한다.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

try:
    from .discovery_models import DiscoveryJob, DiscoveryResult, DiscoveryTaskStatus
    from .browser_discovery import run_browser_job
    from . import discovery_policy as policy
except ImportError:  # 직접 실행 대비
    from discovery_worker.discovery_models import (DiscoveryJob, DiscoveryResult,
                                                   DiscoveryTaskStatus)
    from discovery_worker.browser_discovery import run_browser_job
    from discovery_worker import discovery_policy as policy


async def _run(job: DiscoveryJob) -> DiscoveryResult:
    if not policy.enabled():
        return DiscoveryResult(job_id=job.job_id, status=DiscoveryTaskStatus.DONE,
                               summary={"enabled": False, "status": "SKIPPED",
                                        "note": "ENABLE_BROWSER_DISCOVERY=false"})
    return await run_browser_job(job)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Eoseureum Discovery Worker")
    ap.add_argument("--job-file", required=True, help="DiscoveryJob JSON 파일 경로")
    ap.add_argument("--out", required=True, help="DiscoveryResult JSON 출력 경로")
    args = ap.parse_args(argv)

    with open(args.job_file, "r", encoding="utf-8") as f:
        job = DiscoveryJob.from_dict(json.load(f))

    result = asyncio.run(_run(job))

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)
    print(f"[discovery_worker] job={job.job_id} status={result.status} "
          f"requests={len(result.requests)} inputs={len(result.inputs)} -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
