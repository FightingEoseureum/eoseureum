"""worker_config.py — STEP5 Mac↔i7 분할 공통 설정/헬퍼.

역할(EOSEUREUM_ROLE):
  backend(기본) — Orchestrator(Mac, brain): recon 지시·결과수신·룰엔진판정·리포트·프론트·AI.
  worker         — Scanner Worker(i7, hands): 타겟에 요청/도구/브라우저/OOB. 상태 비저장(DB 없음).

배포 env:
  EOSEUREUM_ROLE = backend | worker
  WORKER_URL     = http://<worker-LAN-IP>:8100   (backend 가 워커로 작업을 넘길 주소)
  WORKER_TOKEN   = <공유 Bearer 토큰>             (backend·worker 동일해야 함, LAN 한정 인증)
  WORKER_PORT    = 8100                            (worker uvicorn 포트)

worker 실행: EOSEUREUM_ROLE=worker uvicorn worker:app --host 0.0.0.0 --port 8100
"""
import hmac
import os


def role() -> str:
    return (os.getenv("EOSEUREUM_ROLE") or "backend").strip().lower()


def is_worker() -> bool:
    return role() == "worker"


def worker_url() -> str:
    """backend 가 작업을 넘길 워커 base URL(끝 슬래시 제거). 미설정이면 빈 문자열."""
    return (os.getenv("WORKER_URL") or "").strip().rstrip("/")


def worker_token() -> str:
    return (os.getenv("WORKER_TOKEN") or "").strip()


def worker_port() -> int:
    try:
        return int(os.getenv("WORKER_PORT", "8100"))
    except (TypeError, ValueError):
        return 8100


def worker_enabled() -> bool:
    """backend 관점: 원격 워커로 능동 점검을 넘길 수 있는 설정이 갖춰졌는가.
    (WORKER_URL + WORKER_TOKEN 둘 다 있어야 함 — 토큰 없는 원격 호출은 금지.)"""
    return bool(worker_url() and worker_token())


def callback_base() -> str:
    """워커가 진행/결과를 되돌릴 백엔드(Mac) base URL. 예: http://192.168.45.5:8000
    미설정이면 빈 문자열 — 이 경우 오프로드는 결과를 회수할 수 없어 로컬 실행으로 폴백한다."""
    return (os.getenv("WORKER_CALLBACK_BASE") or "").strip().rstrip("/")


def check_token(authorization: str | None) -> bool:
    """'Authorization: Bearer <token>' 헤더가 WORKER_TOKEN 과 일치하는지(상수시간 비교).

    **fail-close**: WORKER_TOKEN 미설정이면 거부한다. 오프로드는 WORKER_TOKEN 이 반드시 있어야
    성립하므로(worker_enabled 이 강제) 정상 호출자(워커·백엔드 콜백)는 항상 토큰을 갖는다.
    토큰이 없는 순수 로컬 실행에서는 워커/콜백 엔드포인트를 애초에 호출하지 않는다.
    """
    expected = worker_token()
    if not expected:
        return False
    if not authorization:
        return False
    parts = authorization.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return hmac.compare_digest(parts[1], expected)
    return False
