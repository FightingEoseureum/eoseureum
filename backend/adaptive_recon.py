"""
adaptive_recon.py — 추가 점검 후보 생성 모듈.

기술스택 인식 결과(technologies), 발견 항목(findings), 공격 표면(attack_surface_items)을
입력받아 "추가로 점검해 볼 만한" 후보(suggested_checks)를 *생성*만 한다.
네트워크 호출은 하지 않으며, 실제 실행은 호출 측의 책임이다.

안전 원칙:
  - GET/HEAD 로 안전하게 접근 가능한 경로만 후보에 포함한다.
  - 인증 우회 / 브루트포스 / 대량요청 / 파괴적(쓰기/삭제) 경로는 후보에서 제외한다.
  - auto_run_allowed 는 위험이 낮고(low) 안전한 GET/HEAD 대상일 때만 True 이며,
    is_enabled() 가 False 이면(자동 실행 기본 비활성화) 모든 항목을 False 로 강제한다.

공개 인터페이스:
  is_enabled() -> bool
  suggest_checks(technologies, findings, attack_surface_items) -> dict
"""

import os

# 환경변수에서 "활성" 으로 인정하는 값(대소문자 무시).
_TRUTHY = {"true", "1", "yes"}

# 파괴적/위험 경로 또는 인증우회·브루트포스성 후보를 걸러내기 위한 키워드.
# paths 에 이런 토큰이 들어가면 안전 GET/HEAD 후보로 보지 않는다.
_UNSAFE_PATH_TOKENS = (
    "delete",
    "remove",
    "drop",
    "shutdown",
    "halt",
    "reboot",
    "format",
    "wipe",
    "purge",
    "destroy",
    "kill",
    "logout",
    "signout",
    "reset",
    "brute",
    "bypass",
    "..",  # 경로 탐색 시도
)

# 후보 생성에 사용하는 안전 GET/HEAD 메서드.
_SAFE_METHODS = ("GET", "HEAD")


def is_enabled() -> bool:
    """ENABLE_ADAPTIVE_RECON 환경변수가 truthy 일 때만 True. 기본 False."""
    val = os.environ.get("ENABLE_ADAPTIVE_RECON")
    if val is None:
        return False
    return val.strip().lower() in _TRUTHY


def _is_safe_path(path) -> bool:
    """GET/HEAD 로 안전하게 접근 가능한 경로인지 검사한다."""
    if not isinstance(path, str):
        return False
    p = path.strip()
    if not p:
        return False
    # 절대 경로만 허용(스킴/도메인 없는 path).
    if not p.startswith("/"):
        return False
    lowered = p.lower()
    return not any(tok in lowered for tok in _UNSAFE_PATH_TOKENS)


def _normalize_paths(paths) -> list:
    """안전한 경로만 남기고 순서 유지 중복 제거한다."""
    out = []
    seen = set()
    if not paths:
        return out
    for path in paths:
        if not _is_safe_path(path):
            continue
        if path in seen:
            continue
        seen.add(path)
        out.append(path)
    return out


def _builtin_probes_for(tech_name: str):
    """알려진 기술스택에 대한 기본 안전 점검 경로 매핑.

    각 항목: (reason, [paths], risk)
    여기에 정의된 경로는 모두 GET/HEAD 안전 경로여야 한다.
    """
    if not tech_name:
        return []
    name = tech_name.lower()
    suggestions = []

    # Tomcat / Apache-Coyote
    if "tomcat" in name or "coyote" in name:
        suggestions.append(
            (
                "Apache-Coyote 헤더로 Tomcat 가능성",
                ["/manager/html", "/host-manager/html"],
                "low",
            )
        )

    # JBoss / WildFly
    if "jboss" in name or "wildfly" in name:
        suggestions.append(
            (
                "JBoss/WildFly 관리 콘솔 노출 점검",
                ["/console", "/management"],
                "low",
            )
        )

    # Jenkins
    if "jenkins" in name:
        suggestions.append(
            (
                "Jenkins 대시보드/로그인 페이지 노출 점검",
                ["/login", "/api/json"],
                "low",
            )
        )

    # Apache HTTP Server
    if "apache" in name and "coyote" not in name and "tomcat" not in name:
        suggestions.append(
            (
                "Apache 서버 상태/정보 페이지 노출 점검",
                ["/server-status", "/server-info"],
                "low",
            )
        )

    # nginx
    if "nginx" in name:
        suggestions.append(
            (
                "nginx 상태 페이지 노출 점검",
                ["/nginx_status", "/status"],
                "low",
            )
        )

    # PHP
    if "php" in name:
        suggestions.append(
            (
                "PHP 정보 노출 페이지 점검",
                ["/phpinfo.php", "/info.php"],
                "low",
            )
        )

    # WordPress
    if "wordpress" in name:
        suggestions.append(
            (
                "WordPress 로그인/REST API 노출 점검",
                ["/wp-login.php", "/wp-json"],
                "low",
            )
        )

    # Spring Boot Actuator
    if "spring" in name:
        suggestions.append(
            (
                "Spring Boot Actuator 엔드포인트 노출 점검",
                ["/actuator", "/actuator/health"],
                "low",
            )
        )

    return suggestions


def _candidate(reason: str, paths, risk: str) -> dict:
    """안전 경로만 추린 후보 dict 생성. 유효 경로 없으면 None."""
    safe_paths = _normalize_paths(paths)
    if not safe_paths:
        return None
    if risk not in ("low", "medium"):
        risk = "medium"
    # auto_run_allowed: 안전 GET/HEAD 대상이고 위험이 낮을 때만 후보로 허용.
    base_auto = risk == "low"
    return {
        "reason": reason,
        "paths": safe_paths,
        "risk": risk,
        "auto_run_allowed": base_auto,
    }


def _collect(technologies, findings, attack_surface_items):
    """입력을 순회하며 (reason, paths, risk) 후보 튜플을 모은다."""
    raw = []

    for tech in technologies or []:
        if not isinstance(tech, dict):
            continue
        name = tech.get("name") or ""

        # 내장 매핑 기반 후보.
        raw.extend(_builtin_probes_for(name))

        # technology 가 직접 추천한 probe 들(recommended_probes).
        for probe in tech.get("recommended_probes") or []:
            if isinstance(probe, str):
                raw.append(
                    (
                        "%s 권장 점검 경로" % (name or "기술스택"),
                        [probe],
                        "low",
                    )
                )
            elif isinstance(probe, dict):
                reason = probe.get("reason") or (
                    "%s 권장 점검 경로" % (name or "기술스택")
                )
                paths = probe.get("paths")
                if paths is None and probe.get("path"):
                    paths = [probe.get("path")]
                raw.append((reason, paths or [], probe.get("risk") or "low"))

    return raw


def _merge(raw_candidates) -> list:
    """동일 reason 의 후보를 병합하고 paths 중복을 제거한다."""
    merged = {}
    order = []
    for reason, paths, risk in raw_candidates:
        cand = _candidate(reason, paths, risk)
        if cand is None:
            continue
        key = cand["reason"]
        if key not in merged:
            merged[key] = cand
            order.append(key)
        else:
            existing = merged[key]
            # paths 병합(순서 유지 중복 제거).
            seen = set(existing["paths"])
            for p in cand["paths"]:
                if p not in seen:
                    seen.add(p)
                    existing["paths"].append(p)
            # 위험도는 더 높은 쪽(medium)으로, auto_run 도 그에 맞춰 보수적으로.
            if existing["risk"] == "low" and cand["risk"] == "medium":
                existing["risk"] = "medium"
                existing["auto_run_allowed"] = False

    return [merged[k] for k in order]


def suggest_checks(
    technologies: list = None,
    findings: list = None,
    attack_surface_items: list = None,
) -> dict:
    """추가 점검 후보를 생성한다.

    반환: {"suggested_checks": [ {reason, paths, risk, auto_run_allowed} ]}
    네트워크 호출 없음 — 후보 '생성'만 한다.
    """
    raw = _collect(technologies, findings, attack_surface_items)
    checks = _merge(raw)

    # is_enabled() 가 False 면 자동 실행을 전면 비활성화.
    enabled = is_enabled()
    if not enabled:
        for c in checks:
            c["auto_run_allowed"] = False

    return {"suggested_checks": checks}
