"""cve_intel.py — 알려진 취약점(CVE) 상관 지식베이스.

목적: 스택 지문(프레임워크/서버/버전)을 '알려진 CVE'와 연결해, 단순 정보 노출을
      '점검해야 할 CVE 노출'로 승격한다. 순수 데이터/로직(네트워크 없음) — 프로브가 참조.

원칙(SAFE): CVE 해당 '가능성/노출'을 판정·상관할 뿐, 익스플로잇은 수행하지 않는다.
표현 전용이 아니라 판정 근거(매칭 조건)를 함께 담아 재현·감사 가능하게 한다.
"""
from __future__ import annotations

import re

# 각 항목: 프레임워크 지문 → 해당 CVE 메타.
#   match: 지문 텍스트(프레임워크명/헤더/본문 마커)를 검사하는 정규식
#   surface_hint: 취약 표면(엔드포인트) 확인 방법(프로브가 참조)
_CVE_DB = [
    {
        "cve": "CVE-2025-55182",
        "alias": "React2Shell",
        "title": "React/Next.js Server Components 역직렬화 무인증 RCE (React2Shell)",
        "cvss": "10.0",
        "severity": "Critical",
        "cwe": "CWE-502",
        "match": re.compile(r"next\.?js|__NEXT_DATA__|react-server-dom|x-nextjs|text/x-component|"
                            r"react\s*server\s*components|/_next/", re.IGNORECASE),
        "affected": ("React 19 생태계 · Next.js(App Router, React Server Components) · "
                     "react-server-dom-webpack/turbopack/parcel"),
        "surface_hint": ("Server Functions/Actions 엔드포인트에 Flight 페이로드가 무인증 역직렬화됨. "
                         "POST + 'Next-Action'/'text/x-component' 처리 여부로 취약 표면 확인."),
        "description": ("React Server Components의 Flight 페이로드 디코딩 과정에서 공격자 제어 입력이 "
                        "안전하지 않게 역직렬화됩니다. 내부 가젯을 연쇄해 '.then' 속성을 가진 Promise 유사 "
                        "객체를 만들면 역직렬화 중 자동 resolve 되어 서버에서 원격 코드 실행(RCE)으로 이어집니다. "
                        "무인증으로 임의의 Server Function 엔드포인트에 악성 HTTP 요청을 보내 트리거할 수 있습니다."),
        "recommendation": ("즉시 패치 적용 — react-server-dom-* 및 Next.js를 보안 권고에서 명시한 고정 버전으로 "
                           "업그레이드하세요(2025-12-03 React 보안 권고). 임시로 미검증 Server Action/RSC 요청을 "
                           "WAF/프록시에서 차단하고, Server Functions 노출을 최소화하십시오."),
        "references": [
            "https://checkmarx.com/zero-post/react2shell-cve-2025-55182-deserialization-to-remote-code-execution-in-react-and-next-js/",
            "https://www.akamai.com/blog/security-research/cve-2025-55182-react-nextjs-server-functions-deserialization-rce",
        ],
        "actively_exploited": True,
        "dedicated_probe": True,       # 전용 능동 프로브(_probe_react2shell)가 표면 확증 담당
    },
    {
        "cve": "CVE-2025-29927",
        "alias": "Next.js Middleware Authorization Bypass",
        "title": "Next.js 미들웨어 인가 우회 (CVE-2025-29927)",
        "cvss": "9.1",
        "severity": "Critical",
        "cwe": "CWE-285",
        "match": re.compile(r"next\.?js|__NEXT_DATA__|x-nextjs|/_next/|x-middleware", re.IGNORECASE),
        "affected": "Next.js(미들웨어 기반 인증·인가 사용) 특정 버전 범위",
        "surface_hint": ("'x-middleware-subrequest' 헤더를 이용해 미들웨어(인증·인가 검사)를 우회. "
                         "미들웨어로 보호되는 경로가 무인증 접근되는지 확인."),
        "description": ("Next.js 미들웨어가 인증·인가를 수행하는 경우, 특수 헤더로 미들웨어 실행을 "
                        "건너뛰어 보호된 경로에 무인증 접근할 수 있습니다. 스택 지문상 해당 가능성이 있어 "
                        "버전·패치 여부 확인이 필요합니다(단순 지문 상관 — 능동 실증 아님)."),
        "recommendation": ("Next.js를 보안 패치 버전으로 업그레이드하고, 인가 검사를 미들웨어에만 의존하지 말고 "
                           "각 라우트/서버 단에서도 강제하세요. 'x-middleware-subrequest' 헤더를 엣지에서 차단."),
        "references": [
            "https://nextjs.org/blog/cve-2025-29927",
        ],
        "actively_exploited": True,
        "dedicated_probe": False,      # 지문 상관 → '확인 필요'로 surface
    },
]


# ── ③ 로컬 CVE 피드(오프라인) 흡수 — 코드 수정 없이 CVE DB 최신화 ─────────────────
import json as _json
import os as _os
import pathlib as _pathlib

_FEED_CACHE: dict = {"mtime": 0.0, "data": None}


def _feed_path() -> str:
    return (_os.getenv("CVE_FEED_PATH", "").strip()
            or str(_pathlib.Path(__file__).parent / "security_knowledge" / "cve_feed.json"))


def _compile_entry(e: dict) -> dict | None:
    """피드 항목(JSON)을 내부 CVE 엔트리로 변환. match 는 정규식 문자열 또는 match_keywords 리스트."""
    if not isinstance(e, dict) or not e.get("cve"):
        return None
    pat = e.get("match")
    if not pat:
        kws = [str(k).strip() for k in (e.get("match_keywords") or []) if str(k).strip()]
        if not kws:
            return None
        pat = "|".join(re.escape(k) for k in kws)
    try:
        rx = re.compile(pat, re.IGNORECASE) if isinstance(pat, str) else pat
    except re.error:
        return None
    out = {k: v for k, v in e.items() if k not in ("match", "match_keywords")}
    out["match"] = rx
    out.setdefault("dedicated_probe", False)
    out.setdefault("severity", "Medium")
    out["source"] = e.get("source", "feed")
    return out


def _load_feed() -> list[dict]:
    """로컬 CVE 피드 파일 로드(mtime 캐시). 없으면 빈 리스트."""
    p = _feed_path()
    try:
        mt = _os.path.getmtime(p)
    except OSError:
        return []
    if _FEED_CACHE["data"] is not None and mt == _FEED_CACHE["mtime"]:
        return _FEED_CACHE["data"]
    try:
        raw = _json.loads(_pathlib.Path(p).read_text("utf-8"))
        items = raw if isinstance(raw, list) else (raw.get("cves") or [])
        compiled = [c for c in (_compile_entry(e) for e in items) if c]
    except Exception:
        compiled = []
    _FEED_CACHE.update(mtime=mt, data=compiled)
    return compiled


def _all_cves() -> list[dict]:
    """큐레이션 DB + 로컬 피드(중복 cve 는 큐레이션 우선)."""
    seen = {e["cve"] for e in _CVE_DB}
    return list(_CVE_DB) + [e for e in _load_feed() if e.get("cve") not in seen]


def correlate(fingerprint_text: str) -> list[dict]:
    """스택 지문 텍스트에서 해당 가능성이 있는 CVE 목록을 반환(매칭 근거 포함)."""
    text = fingerprint_text or ""
    hits = []
    for e in _all_cves():
        m = e["match"].search(text)
        if m:
            hit = {k: v for k, v in e.items() if k != "match"}
            hit["matched_on"] = m.group(0)
            hits.append(hit)
    return hits


def get(cve_id: str) -> dict | None:
    for e in _all_cves():
        if e["cve"] == cve_id:
            return {k: v for k, v in e.items() if k != "match"}
    return None


# ── NVD 덤프(오프라인) → CVE 피드 인제스터 ───────────────────────────────────────
_WEB_TECH_HINT = re.compile(
    r"(apache|nginx|tomcat|spring|struts|php|wordpress|drupal|joomla|node|express|"
    r"django|flask|laravel|rails|jquery|angular|react|vue|next\.?js|nuxt|jenkins|"
    r"grafana|kibana|elasticsearch|graphql|swagger|openapi|iis|asp\.net|jboss|weblogic|"
    r"struts2|log4j|spring boot|fastapi|gitlab|confluence|jira|http)", re.IGNORECASE)


def ingest_nvd(nvd_items: list, min_cvss: float = 7.0, cap: int = 5000) -> list[dict]:
    """NVD 2.0 형식 CVE 아이템 리스트에서 '웹 기술 관련' 고위험 CVE 만 추려 피드 항목으로 변환.

    완전 오프라인(네트워크 없음): 호출측이 NVD JSON 덤프를 읽어 vulnerabilities 배열을 넘긴다.
    반환 항목은 cve_feed.json 스키마(match_keywords 로 지문 매칭).
    """
    out: list[dict] = []
    for it in (nvd_items or []):
        cve = (it.get("cve") if isinstance(it.get("cve"), dict) else it) or {}
        cid = cve.get("id") or cve.get("CVE_data_meta", {}).get("ID")
        if not cid:
            continue
        # 설명
        descs = cve.get("descriptions") or []
        desc = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
        if not desc:
            continue
        # CVSS (v3.1 우선)
        metrics = cve.get("metrics") or {}
        score = 0.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key) or []
            if arr:
                score = float((arr[0].get("cvssData") or {}).get("baseScore") or 0.0)
                break
        if score < min_cvss:
            continue
        # 웹 기술 키워드(제품명) 추출 — CPE configurations + 설명
        kws: set = set()
        for cfg in (cve.get("configurations") or []):
            for node in (cfg.get("nodes") or []):
                for cpe in (node.get("cpeMatch") or []):
                    crit = cpe.get("criteria", "")  # cpe:2.3:a:vendor:product:...
                    parts = crit.split(":")
                    if len(parts) > 4 and parts[4] and parts[4] not in ("*", "-"):
                        prod = parts[4].replace("_", " ")
                        if _WEB_TECH_HINT.search(prod) or _WEB_TECH_HINT.search(crit):
                            kws.add(prod)
        for m in _WEB_TECH_HINT.finditer(desc):
            kws.add(m.group(0).lower())
        if not kws:
            continue
        # CWE
        cwe = ""
        for w in (cve.get("weaknesses") or []):
            for d in (w.get("description") or []):
                if str(d.get("value", "")).startswith("CWE-"):
                    cwe = d["value"]; break
            if cwe:
                break
        sev = ("Critical" if score >= 9 else "High" if score >= 7 else "Medium")
        out.append({
            "cve": cid, "title": f"{cid} ({', '.join(sorted(kws))[:60]})",
            "cvss": str(score), "severity": sev, "cwe": cwe,
            "match_keywords": sorted(kws)[:8],
            "affected": ", ".join(sorted(kws))[:120],
            "description": desc[:500],
            "recommendation": "해당 컴포넌트를 벤더 보안 권고의 고정 버전으로 즉시 업데이트하세요.",
            "dedicated_probe": False, "source": "nvd_feed",
        })
        if len(out) >= cap:
            break
    return out
