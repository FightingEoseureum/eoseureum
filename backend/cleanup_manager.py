"""
cleanup_manager.py

스캔 중 생성된 테스트 데이터를 정리합니다.
안전 원칙:
  - Eoseureum_vulntest_{scan_id}_{timestamp} 마커가 있는 항목만 삭제
  - 삭제 시도·성공 여부를 cleanup_attempted/cleanup_success로 추적
  - 삭제 실패 시 경고 로그만 남기고 계속 진행
"""

import contextlib
import time
import ssl

import aiohttp

import adaptive_throttle as _gov   # rate 거버너(미설치/PROOF 시 no-op)


_SCANNER_UA = "Mozilla/5.0 (compatible; SecurityScanner/2.0)"
_SCANNER_HEADERS = {"User-Agent": _SCANNER_UA}


@contextlib.asynccontextmanager
async def _gov_gate():
    """정리 요청을 rate 거버너에 태운다(SAFE: 전역 5rps 합산에 포함). box['status']에 응답코드 기록."""
    _g = _gov.stage("cleanup")
    if _g is not None:
        await _g.before()
    _t0 = time.monotonic()
    box = {"status": 0}
    try:
        yield box
    finally:
        if _g is not None:
            _g.after(time.monotonic() - _t0, box.get("status", 0), None)


def _ssl_connector() -> aiohttp.TCPConnector:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return aiohttp.TCPConnector(ssl=ctx)


async def _delete_resource(session: aiohttp.ClientSession, url: str) -> bool:
    """DELETE 요청으로 리소스 삭제를 시도합니다."""
    try:
        async with _gov_gate() as _gb:
            async with session.delete(
                url,
                headers=_SCANNER_HEADERS,
                timeout=aiohttp.ClientTimeout(total=8),
                allow_redirects=False,
                ssl=False,
            ) as resp:
                _gb["status"] = resp.status
                return resp.status in (200, 204, 202)
    except Exception:
        return False


async def _check_marker_gone(session: aiohttp.ClientSession, url: str, marker: str) -> bool:
    """URL에서 마커가 더 이상 나타나지 않으면 True."""
    try:
        async with _gov_gate() as _gb:
            async with session.get(
                url,
                headers=_SCANNER_HEADERS,
                timeout=aiohttp.ClientTimeout(total=8),
                ssl=False,
            ) as resp:
                _gb["status"] = resp.status
                body = await resp.text(errors="ignore")
                return marker not in body
    except Exception:
        # 접근 실패(타임아웃/연결오류)는 '제거 확인 불가' — 성공으로 오보고하지 않는다.
        # (기존엔 True 로 처리해, 흔적이 남아도 '정리 완료'로 보고되던 문제)
        return False


class CleanupResult:
    def __init__(self):
        self.attempted: int = 0
        self.success: int = 0
        self.failed: list[dict] = []
        self.skipped: int = 0

    def to_dict(self) -> dict:
        return {
            "cleanup_attempted": self.attempted,
            "cleanup_success": self.success,
            "cleanup_failed": self.failed,
            "cleanup_skipped": self.skipped,
        }


async def cleanup_scan_artifacts(
    findings: list[dict],
    scan_id: str,
) -> CleanupResult:
    """
    findings 목록에서 cleanup_status가 required=True인 항목을 찾아 정리합니다.
    각 finding의 cleanup_status를 업데이트합니다.
    """
    result = CleanupResult()

    connector = _ssl_connector()
    async with aiohttp.ClientSession(connector=connector) as session:
        for finding in findings:
            cleanup = finding.get("cleanup_status")
            if not cleanup or not cleanup.get("required"):
                result.skipped += 1
                continue

            marker = cleanup.get("marker", "")
            probe_detail = finding.get("probe_detail", {})
            affected = finding.get("affected_endpoints", [])

            result.attempted += 1
            cleanup["cleanup_attempted"] = True

            probe_key = _infer_probe_key(finding)
            cleaned = False

            if probe_key == "xss_stored":
                cleaned = await _cleanup_stored_xss(session, marker, affected, scan_id)
            elif probe_key == "file_upload":
                cleaned = await _cleanup_uploaded_file(session, probe_detail, affected)
            else:
                # 범용: 마커가 사라졌는지 확인
                for endpoint in affected:
                    if await _check_marker_gone(session, endpoint, marker):
                        cleaned = True
                        break

            cleanup["cleanup_success"] = cleaned
            if cleaned:
                result.success += 1
            else:
                result.failed.append({
                    "title": finding.get("title", ""),
                    "marker": marker,
                    "endpoints": affected[:3],
                })

    return result


def _infer_probe_key(finding: dict) -> str:
    """finding에서 probe_key를 추론합니다."""
    probe_detail = finding.get("probe_detail", {})
    title = finding.get("title", "").lower()
    if "stored xss" in title or "저장형" in title:
        return "xss_stored"
    if "파일 업로드" in title or "file upload" in title:
        return "file_upload"
    return ""


async def _cleanup_stored_xss(
    session: aiohttp.ClientSession,
    marker: str,
    affected_endpoints: list[str],
    scan_id: str,
) -> bool:
    """
    저장형 XSS 테스트 데이터 정리.
    마커 문자열이 포함된 POST 제출 페이지에서 데이터 제거를 시도합니다.
    전략: 마커가 없는 데이터로 재제출하거나 DELETE 요청을 시도합니다.
    """
    if not marker or not affected_endpoints:
        return False

    # 먼저 마커가 이미 사라졌는지 확인
    for endpoint in affected_endpoints:
        if await _check_marker_gone(session, endpoint, marker):
            return True

    # 마커가 아직 있으면 빈 값으로 재제출 시도
    submit_url = next((e for e in affected_endpoints if "?" not in e), affected_endpoints[0])
    try:
        # 빈 폼 데이터로 재제출 (덮어쓰기 시도)
        async with _gov_gate() as _gb:
            async with session.post(
                submit_url,
                data={"content": "", "message": "", "comment": "", "text": ""},
                headers=_SCANNER_HEADERS,
                timeout=aiohttp.ClientTimeout(total=8),
                ssl=False,
            ) as resp:
                _gb["status"] = resp.status
    except Exception:
        pass

    # 재확인
    for endpoint in affected_endpoints:
        if await _check_marker_gone(session, endpoint, marker):
            return True

    return False


async def _cleanup_uploaded_file(
    session: aiohttp.ClientSession,
    probe_detail: dict,
    affected_endpoints: list[str],
) -> bool:
    """업로드된 테스트 파일 삭제 시도."""
    uploaded_url = probe_detail.get("uploaded_url", "")
    if not uploaded_url:
        # affected_endpoints에서 업로드 파일 URL 추론
        for ep in affected_endpoints:
            if "scanner_probe_test" in ep or ".php" in ep:
                uploaded_url = ep
                break

    if not uploaded_url:
        return False

    # DELETE 요청
    deleted = await _delete_resource(session, uploaded_url)
    if deleted:
        return True

    # 파일이 이미 없으면 성공으로 처리
    try:
        async with _gov_gate() as _gb:
            async with session.get(
                uploaded_url,
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False,
            ) as resp:
                _gb["status"] = resp.status
                return resp.status == 404
    except Exception:
        # 접근 실패는 '삭제 확인 불가' — 성공 오보고 금지(404 확인만 성공으로 인정)
        return False


def annotate_findings_cleanup_requirement(findings: list[dict]) -> None:
    """
    findings를 순회하며 cleanup이 필요한 항목에 cleanup_status를 설정합니다.
    이미 cleanup_status가 설정된 경우 건너뜁니다.
    """
    CLEANUP_REQUIRED_PROBES = {"xss_stored", "file_upload"}
    for finding in findings:
        if finding.get("cleanup_status") is not None:
            continue
        title = finding.get("title", "").lower()
        needs = (
            "저장형 xss" in title
            or "stored xss" in title
            or "파일 업로드" in title
            or "file upload" in title
        )
        if needs:
            finding["cleanup_status"] = {
                "required": True,
                "marker": "",
                "cleanup_attempted": False,
                "cleanup_success": False,
            }
