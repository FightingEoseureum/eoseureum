"""
subdomain_takeover.py — 서브도메인 탈취(Subdomain Takeover) 탐지 v1.

기존 서브도메인 열거 결과에 대해, 서브도메인의 CNAME 이 외부 서비스(GitHub Pages/Heroku/S3
등)를 가리키지만 그 리소스가 '미클레임' 상태(서비스별 특유 응답)인 경우를 탐지한다. 공격자가
그 리소스를 선점하면 해당 서브도메인을 장악할 수 있다.

고정밀 원칙: CNAME 이 서비스 패턴과 일치하고 + 응답 본문이 서비스별 '미클레임 지문'과 일치할
때만 CONFIRMED(실증). CNAME 만 dangling 이고 지문 불일치면 MANUAL_REVIEW(검토 권고).
SAFE: DNS 조회 + GET 만 사용, 리소스 선점(등록) 등 상태 변경은 하지 않는다.
"""
from __future__ import annotations

# service -> {"cname": [substr...], "fingerprint": [body substr...], "severity": ...}
_FINGERPRINTS = {
    "github_pages": {"cname": ["github.io", "githubusercontent"],
                     "fingerprint": ["There isn't a GitHub Pages site here",
                                     "For root URLs (like http://example.com/) you must provide an index.html"],
                     "severity": "HIGH"},
    "heroku": {"cname": ["herokuapp.com", "herokudns.com", "herokussl"],
               "fingerprint": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
               "severity": "HIGH"},
    "aws_s3": {"cname": ["s3.amazonaws.com", "s3-website", "amazonaws.com"],
               "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"],
               "severity": "HIGH"},
    "azure": {"cname": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net",
                        "blob.core.windows.net", "azureedge.net"],
              "fingerprint": ["404 Web Site not found", "The resource you are looking for has been removed"],
              "severity": "HIGH"},
    "shopify": {"cname": ["myshopify.com"],
                "fingerprint": ["Sorry, this shop is currently unavailable"],
                "severity": "HIGH"},
    "fastly": {"cname": ["fastly.net"],
               "fingerprint": ["Fastly error: unknown domain"],
               "severity": "HIGH"},
    "zendesk": {"cname": ["zendesk.com"],
                "fingerprint": ["Help Center Closed", "this help center no longer exists"],
                "severity": "MEDIUM"},
    "unbounce": {"cname": ["unbounce.com"],
                 "fingerprint": ["The requested URL was not found on this server"],
                 "severity": "MEDIUM"},
    "wordpress": {"cname": ["wordpress.com"],
                  "fingerprint": ["Do you want to register"],
                  "severity": "MEDIUM"},
    "bitbucket": {"cname": ["bitbucket.io"],
                  "fingerprint": ["Repository not found"],
                  "severity": "HIGH"},
    "ghost": {"cname": ["ghost.io"],
              "fingerprint": ["The thing you were looking for is no longer here"],
              "severity": "MEDIUM"},
    "surge": {"cname": ["surge.sh"],
              "fingerprint": ["project not found"],
              "severity": "MEDIUM"},
    "tumblr": {"cname": ["domains.tumblr.com"],
               "fingerprint": ["Whatever you were looking for doesn't currently exist"],
               "severity": "MEDIUM"},
    "pantheon": {"cname": ["pantheonsite.io"],
                 "fingerprint": ["The gods are wise", "404 error unknown site"],
                 "severity": "MEDIUM"},
}


def _match_service(cname: str) -> str | None:
    cl = (cname or "").lower()
    for svc, spec in _FINGERPRINTS.items():
        if any(sub in cl for sub in spec["cname"]):
            return svc
    return None


def detect(subdomain: str, cname: str, body: str = "", status: int | None = None) -> dict | None:
    """단일 서브도메인 탈취 판정. 반환: finding dict 또는 None."""
    svc = _match_service(cname)
    if not svc:
        return None
    spec = _FINGERPRINTS[svc]
    body = body or ""
    matched_fp = any(fp in body for fp in spec["fingerprint"])
    if matched_fp:
        return _f(subdomain, svc, cname, spec["severity"], "CONFIRMED_RESPONSE",
                  f"CNAME 이 {svc}({cname}) 를 가리키나 리소스가 미클레임 상태(서비스 미클레임 지문 확인) "
                  f"— 공격자가 리소스를 선점하면 {subdomain} 장악 가능.")
    # CNAME 은 외부 서비스로 dangling 이나 지문 불일치 → 검토 권고(오탐 회피)
    return _f(subdomain, svc, cname, "MEDIUM", "MANUAL_REVIEW",
              f"CNAME 이 외부 서비스 {svc}({cname}) 를 가리킴 — 리소스 소유/활성 여부 수동 확인 권고"
              f"(미클레임 시 서브도메인 탈취 가능).")


def _f(subdomain, svc, cname, severity, confidence, evidence) -> dict:
    return {
        "title": f"서브도메인 탈취 가능 — {subdomain}",
        "family": "subdomain_takeover", "vuln_type": "subdomain_takeover",
        "severity": severity, "confidence": confidence, "judgment": "취약",
        "url": f"http://{subdomain}", "host": subdomain,
        "evidence_detail": evidence,
        "recommendation": (f"미사용 서브도메인의 DNS 레코드(CNAME→{svc})를 제거하거나, 해당 외부 "
                           "리소스를 정식으로 소유·활성화하십시오."),
        "source": "subdomain_takeover", "service": svc, "cname": cname,
    }


def analyze(subdomains_info: list[dict]) -> list[dict]:
    """서브도메인 정보 목록 분석.
    각 항목: {"subdomain","cname","body"(선택),"status"(선택)}. → finding dict 목록."""
    out = []
    for info in subdomains_info or []:
        sub = info.get("subdomain") or info.get("host") or ""
        cname = info.get("cname") or ""
        if not sub or not cname:
            continue
        f = detect(sub, cname, info.get("body", ""), info.get("status"))
        if f:
            out.append(f)
    return out
