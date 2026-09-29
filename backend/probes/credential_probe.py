"""
probes/credential_probe.py — Known/기본 자격증명 검증 probe (기본 비활성).

안전 정책:
  - enable_known_credential_check=True 일 때만 동작.
  - 자격증명은 credential_loader.load_credentials(config) 로만 로드(대량 하드코딩 금지).
  - 로그인 폼당 최대 max_auth_attempts_per_form 회까지만 시도.
  - 각 시도 전 ctx.auth_rate_limiter.acquire()(초당 ≤2 + 전역 ≤10) 적용.
  - STOP_ON_ACCOUNT_LOCK_HINT=True 면 잠금 문구 감지 즉시 중단.
  - 비밀번호는 evidence/로그에 평문 저장 금지(mask_value/mask_secrets).
  - 브루트포스/대량 로그인 금지(자격증명 개수·시도 횟수 상한으로 강제).

네트워크부는 테스트 monkeypatch 가능하게 모듈 함수 _http_post 로 분리.
"""
from __future__ import annotations

from probes.base import BaseProbe, ProbeContext, ProbeResult
from probes.utils import form_parser
from probes.utils.credential_loader import load_credentials
from probes.utils.sanitization import mask_value, mask_secrets

# 계정 잠금 징후 문구
_LOCK_HINTS = (
    "account locked", "계정 잠금", "계정이 잠", "too many attempts",
    "too many login", "locked out", "account is locked", "account has been locked",
)
_SUCCESS_KEYWORDS = (
    "logout", "log out", "sign out", "signout", "dashboard", "profile",
    "admin", "my account", "로그아웃", "마이페이지",
)
_FAILURE_KEYWORDS = (
    "invalid", "incorrect", "failed", "wrong password", "login failed",
    "authentication failed", "아이디 또는 비밀번호", "잘못된", "로그인 실패",
)
_USER_FIELD_HINTS = ("user", "username", "email", "login", "id", "userid", "uid", "account")
_PASS_FIELD_HINTS = ("password", "pass", "passwd", "pwd")

# 잘 알려진 기본 계정(기본계정 성공 → High 분류용)
_DEFAULT_ACCOUNTS = {
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("administrator", "administrator"), ("root", "root"), ("root", "toor"),
    ("test", "test"), ("guest", "guest"), ("user", "user"), ("admin", "1234"),
}


async def _http_post(session, url: str, data: dict, timeout: float = 8.0):
    """로그인 POST. 반환: (status, body, headers_dict). monkeypatch 대상."""
    try:
        import aiohttp
        async with session.post(url, data=data, allow_redirects=False,
                                timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            return r.status, await r.text(errors="ignore"), dict(r.headers)
    except Exception:
        return 0, "", {}


def _has_lock_hint(text: str) -> bool:
    if not text:
        return False
    low = text.lower()
    return any(h.lower() in low for h in _LOCK_HINTS)


def _field_for(params: dict, hints) -> str | None:
    for k in params:
        kl = k.lower()
        if any(h in kl for h in hints):
            return k
    return None


def _judge_success(status: int, body: str, headers: dict, baseline_fail: bool) -> tuple[bool, bool]:
    """로그인 성공 판정. 반환: (success, response_diff_only).
    success=True 면 강한 성공 신호, 아니면 response_diff_only 여부 보고."""
    low = (body or "").lower()

    set_cookie = "".join(str(v) for k, v in (headers or {}).items() if k.lower() == "set-cookie")
    if any(t in set_cookie.lower() for t in ("session", "sessid", "sid=", "jwt", "token", "auth")):
        return True, False

    if status in (301, 302, 303, 307, 308):
        loc = "".join(str(v) for k, v in (headers or {}).items() if k.lower() == "location")
        if loc and "login" not in loc.lower() and "signin" not in loc.lower():
            return True, False

    if any(kw in low for kw in _SUCCESS_KEYWORDS):
        return True, False

    now_fail = any(f in low for f in _FAILURE_KEYWORDS)
    # 실패 메시지 소실 (baseline 엔 실패 문구가 있었음)
    if status == 200 and body and not now_fail and baseline_fail:
        return True, False

    # 응답 차이만(실패 문구는 없지만 강한 성공 신호도 없음) → MANUAL_REVIEW 후보
    if status == 200 and body and not now_fail:
        return False, True
    return False, False


class CredentialProbe(BaseProbe):
    name = "credential"
    category = "credential"
    enabled_by_default = False

    async def run(self, ctx: ProbeContext) -> list[ProbeResult]:
        results: list[ProbeResult] = []
        cfg = ctx.scan_config

        # enable_known_credential_check=True 일 때만 동작.
        if cfg is None or not getattr(cfg, "enable_known_credential_check", False):
            return results

        credentials = load_credentials(cfg)
        if not credentials:
            return results

        # 로그인 폼 지점 수집 (injection_points + authenticated_forms)
        points = list(ctx.injection_points or []) + list(ctx.authenticated_forms or [])
        login_points = form_parser.find_login_points(points)
        if not login_points:
            return results

        timeout = float(getattr(cfg, "request_timeout", 8.0) or 8.0)
        max_attempts = int(getattr(cfg, "max_auth_attempts_per_form", 1000) or 0)
        if max_attempts <= 0:
            return results
        stop_on_lock = bool(getattr(cfg, "stop_on_account_lock_hint", True))
        session = ctx.authenticated_session or ctx.session

        for point in login_points:
            params = point.get("params") or {}
            user_field = _field_for(params, _USER_FIELD_HINTS)
            pass_field = _field_for(params, _PASS_FIELD_HINTS)
            if not user_field or not pass_field:
                continue
            url = point.get("url") or ctx.target_url
            base_params = dict(params)

            attempts = 0
            stopped = False
            for (user, pw) in credentials:
                if attempts >= max_attempts:
                    break
                attempts += 1

                # 각 시도 전 인증 rate limiter(초당 ≤2 + 전역 ≤10).
                if ctx.auth_rate_limiter is not None:
                    try:
                        await ctx.auth_rate_limiter.acquire()
                    except Exception:
                        pass

                data = dict(base_params)
                data[user_field] = user
                data[pass_field] = pw
                status, body, headers = await _http_post(session, url, data, timeout=timeout)

                if stop_on_lock and _has_lock_hint(body):
                    results.append(self._lock_result(url, user))
                    stopped = True
                    break

                baseline_fail = any(f in (body or "").lower() for f in _FAILURE_KEYWORDS)
                # baseline_fail 은 현재 응답 기준이라 항상 False 처리(보수적): 강한 신호만 성공.
                success, diff_only = _judge_success(status, body, headers, baseline_fail=False)

                if success:
                    is_default = (user, pw) in _DEFAULT_ACCOUNTS
                    results.append(self._success_result(url, user, pw, is_default, status))
                    # 한 폼에서 성공하면 추가 시도 중단(불필요한 로그인 금지).
                    stopped = True
                    break
                elif diff_only:
                    results.append(self._manual_review_result(url, user, status))

            if not stopped and not any(
                r.affected_url == (point.get("url") or ctx.target_url)
                and r.finding_type == "vulnerability" for r in results
            ):
                # 모두 실패 → good/noise (폼당 1개만)
                results.append(self._good_result(url, attempts))

        return results

    # ── ProbeResult 빌더 (비밀번호 mask) ─────────────────────────────────────

    def _success_result(self, url, user, pw, is_default, status) -> ProbeResult:
        masked = mask_value(pw)
        if is_default:
            sev = "High"
            title = "기본 자격증명 로그인 성공 (Default Credentials)"
        else:
            sev = "High"
            title = "알려진 자격증명 로그인 성공 (Known Credentials)"
        return ProbeResult(
            title=title,
            category=self.category,
            finding_type="vulnerability",
            severity=sev,
            confidence="CONFIRMED",
            confidence_score=90,
            affected_url=url,
            evidence=[mask_secrets(
                f"로그인 성공: user={user} password={masked} (status={status})"
            )],
            reproduction=mask_secrets(f"POST {url} with user={user} password={masked}"),
            recommendation="기본/알려진 자격증명을 즉시 변경하고 강력한 비밀번호 정책을 적용하세요.",
            cwe="CWE-798",
            owasp="A07:2021 - 식별 및 인증 실패",
            probe_key="known_credential",
            tags=["credential", "default" if is_default else "known"],
            raw={"url": url, "username": user, "password_masked": masked,
                 "default": is_default, "status": status},
        )

    def _manual_review_result(self, url, user, status) -> ProbeResult:
        return ProbeResult(
            title="자격증명 검증 — 응답 차이 (수동 확인 필요)",
            category=self.category,
            finding_type="vulnerability",
            severity="Low",
            confidence="MANUAL_REVIEW",
            confidence_score=30,
            affected_url=url,
            evidence=[mask_secrets(
                f"명확한 성공 신호는 없으나 실패 문구 없음: user={user} (status={status})"
            )],
            recommendation="응답을 수동 확인하여 로그인 성공 여부를 판별하세요.",
            cwe="CWE-798",
            owasp="A07:2021 - 식별 및 인증 실패",
            probe_key="known_credential_manual",
            tags=["credential", "manual_review"],
            raw={"url": url, "username": user, "status": status},
        )

    def _lock_result(self, url, user) -> ProbeResult:
        return ProbeResult(
            title="계정 잠금 징후 감지 — 검증 즉시 중단",
            category=self.category,
            finding_type="noise",
            severity="Info",
            confidence="MANUAL_REVIEW",
            confidence_score=0,
            affected_url=url,
            evidence=[mask_secrets(f"계정 잠금 징후 감지로 검증 중단 (user={user})")],
            recommendation="계정 잠금 정책이 동작 중입니다. 추가 시도를 중단했습니다.",
            probe_key="account_lock_hint",
            tags=["credential", "account_lock", "stopped"],
            safe_check=True,
            raw={"url": url, "stopped": True},
        )

    def _good_result(self, url, attempts) -> ProbeResult:
        return ProbeResult(
            title="기본/알려진 자격증명 로그인 실패 (양호)",
            category=self.category,
            finding_type="good",
            severity="Info",
            confidence="CONFIRMED",
            confidence_score=0,
            affected_url=url,
            evidence=[f"{attempts}개 자격증명 시도 모두 실패 — 기본/알려진 자격증명 없음"],
            recommendation="현재 기본/알려진 자격증명으로는 로그인되지 않습니다.",
            probe_key="known_credential_good",
            tags=["credential", "good"],
            safe_check=True,
            raw={"url": url, "attempts": attempts},
        )


PROBE = CredentialProbe()
