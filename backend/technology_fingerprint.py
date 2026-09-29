"""
technology_fingerprint.py — Eoseureum 기술 스택 인식 엔진.

수동 수집한 HTTP 신호(헤더/본문/쿠키/경로 상태코드 등)를 받아
구동 중인 기술 스택을 추정하고, 각 기술별로 다음 단계에서 시도할
안전한(비파괴적) GET/HEAD 프로브 경로를 추천한다.

순수 함수 모듈 — 네트워크 호출이 전혀 없다.

공개 인터페이스:
  fingerprint(signals: dict) -> dict
  from_host_result(host_result: dict) -> dict

signals 키 (모두 optional):
  server (str)              : Server 응답 헤더
  x_powered_by (str)        : X-Powered-By 응답 헤더
  headers (dict[str,str])   : 임의의 응답 헤더 모음 (대소문자 무관)
  html (str)                : 응답 본문 일부 (title/meta generator 등)
  cookies (list[str])       : Set-Cookie 로 관측된 쿠키 이름들
  known_paths (dict[str,int]): 경로 -> HTTP 상태코드
  favicon_hash (str)        : favicon 해시 (mmh3 등)

반환:
  {"technologies": [
      {"name": str, "confidence": int(0~100),
       "evidence": list[str], "recommended_probes": list[str]}
  ]}
  - confidence 내림차순 정렬, 동일 name 은 병합.
"""
from __future__ import annotations

import re

# 신뢰도 가중치 (시그니처 한 건이 기여하는 점수)
_W_STRONG = 70   # 거의 확정적인 단서 (전용 헤더, 고유 쿠키 등)
_W_MEDIUM = 40   # 강한 정황 (Server 헤더의 제품명 등)
_W_WEAK = 20     # 보조 정황 (경로 존재, 본문 키워드 등)


def _norm_headers(signals: dict) -> dict:
    """모든 헤더를 소문자 키로 평탄화한 dict 반환."""
    out: dict[str, str] = {}
    headers = signals.get("headers") or {}
    if isinstance(headers, dict):
        for k, v in headers.items():
            if k is None:
                continue
            out[str(k).lower()] = "" if v is None else str(v)
    server = signals.get("server")
    if server:
        out.setdefault("server", str(server))
    xpb = signals.get("x_powered_by")
    if xpb:
        out.setdefault("x-powered-by", str(xpb))
    return out


def _paths(signals: dict) -> dict:
    kp = signals.get("known_paths") or {}
    if not isinstance(kp, dict):
        return {}
    return {str(k): v for k, v in kp.items()}


def _cookie_names(signals: dict) -> list[str]:
    cookies = signals.get("cookies") or []
    if not isinstance(cookies, (list, tuple, set)):
        return []
    return [str(c) for c in cookies if c]


def _add(tech_map: dict, name: str, score: int, evidence: str, probes: list[str]) -> None:
    """기술 추정 결과를 누적 병합한다."""
    entry = tech_map.setdefault(
        name, {"score": 0, "evidence": [], "probes": []}
    )
    entry["score"] += score
    if evidence and evidence not in entry["evidence"]:
        entry["evidence"].append(evidence)
    for p in probes:
        if p not in entry["probes"]:
            entry["probes"].append(p)


def fingerprint(signals: dict) -> dict:
    """수집된 신호로부터 기술 스택을 추정한다."""
    if not isinstance(signals, dict):
        signals = {}

    headers = _norm_headers(signals)
    server = headers.get("server", "")
    xpb = headers.get("x-powered-by", "")
    html = signals.get("html") or ""
    if not isinstance(html, str):
        html = str(html)
    paths = _paths(signals)
    cookies = _cookie_names(signals)

    server_l = server.lower()
    xpb_l = xpb.lower()
    html_l = html.lower()
    cookies_l = [c.lower() for c in cookies]

    def path_status(p: str):
        return paths.get(p)

    def has_path_active(p: str) -> bool:
        """경로가 404/410 이 아닌, 즉 존재/접근제어됨을 의미하는 상태코드인지."""
        st = paths.get(p)
        return st is not None and st not in (404, 410)

    tech: dict = {}

    # ---- Apache Tomcat ----
    tomcat_probes = ["/manager/html", "/host-manager/html", "/docs", "/examples"]
    if "apache-coyote" in server_l:
        _add(tech, "Apache Tomcat", _W_STRONG,
             f"Server 헤더에 Apache-Coyote 포함: '{server}'", tomcat_probes)
    if "tomcat" in server_l:
        _add(tech, "Apache Tomcat", _W_MEDIUM,
             f"Server 헤더에 Tomcat 포함: '{server}'", tomcat_probes)
    for mgr in ("/manager", "/manager/html", "/host-manager/html"):
        st = path_status(mgr)
        if st in (401, 403):
            _add(tech, "Apache Tomcat", _W_MEDIUM,
                 f"{mgr} 가 {st} 응답 (관리 콘솔 접근제어)", tomcat_probes)
    if "tomcat" in html_l:
        _add(tech, "Apache Tomcat", _W_WEAK, "본문에 Tomcat 문자열 존재", tomcat_probes)

    # ---- Spring Boot ----
    spring_probes = ["/actuator", "/actuator/health", "/actuator/env", "/actuator/heapdump"]
    if "x-application-context" in headers:
        _add(tech, "Spring Boot", _W_STRONG,
             "X-Application-Context 헤더 존재", spring_probes)
    for ap in ("/actuator", "/actuator/health"):
        if has_path_active(ap):
            _add(tech, "Spring Boot", _W_STRONG,
                 f"{ap} 가 {path_status(ap)} 응답 (Actuator 엔드포인트)", spring_probes)
    if "whitelabel error page" in html_l:
        _add(tech, "Spring Boot", _W_MEDIUM,
             "Whitelabel Error Page 본문 감지", spring_probes)

    # ---- WordPress ----
    wp_probes = ["/wp-login.php", "/wp-json/", "/xmlrpc.php", "/wp-content/debug.log"]
    if re.search(r'<meta[^>]+name=["\']generator["\'][^>]*wordpress', html_l):
        _add(tech, "WordPress", _W_STRONG,
             "meta generator 에 WordPress 표기", wp_probes)
    elif "wordpress" in html_l:
        _add(tech, "WordPress", _W_WEAK, "본문에 WordPress 문자열 존재", wp_probes)
    if "wp-content" in html_l or "wp-includes" in html_l:
        _add(tech, "WordPress", _W_MEDIUM,
             "본문에 wp-content/wp-includes 경로 참조", wp_probes)
    if has_path_active("/wp-login.php"):
        _add(tech, "WordPress", _W_STRONG,
             f"/wp-login.php 가 {path_status('/wp-login.php')} 응답", wp_probes)
    if any(c.startswith("wordpress_") or c.startswith("wp-") for c in cookies_l):
        _add(tech, "WordPress", _W_MEDIUM, "WordPress 관련 쿠키 관측", wp_probes)

    # ---- PHP ----
    php_probes = ["/.env", "/phpinfo.php", "/composer.json"]
    if "php" in xpb_l:
        _add(tech, "PHP", _W_STRONG,
             f"X-Powered-By 헤더에 PHP 표기: '{xpb}'", php_probes)
    if "phpsessid" in cookies_l:
        _add(tech, "PHP", _W_STRONG, "PHPSESSID 쿠키 관측", php_probes)
    if any(p.lower().endswith(".php") and has_path_active(p) for p in paths):
        _add(tech, "PHP", _W_MEDIUM, ".php 경로가 응답함", php_probes)

    # ---- Nginx ----
    if "nginx" in server_l:
        _add(tech, "Nginx", _W_MEDIUM,
             f"Server 헤더에 nginx 표기: '{server}'", ["/nginx_status"])

    # ---- Apache HTTPD ----
    if re.search(r"\bapache\b", server_l) and "coyote" not in server_l and "tomcat" not in server_l:
        _add(tech, "Apache HTTPD", _W_MEDIUM,
             f"Server 헤더에 Apache 표기: '{server}'", ["/server-status", "/server-info"])

    # ---- IIS ----
    iis_probes = ["/web.config", "/trace.axd"]
    if "microsoft-iis" in server_l:
        _add(tech, "IIS", _W_STRONG,
             f"Server 헤더에 Microsoft-IIS 표기: '{server}'", iis_probes)
    if "x-aspnet-version" in headers or "x-aspnetmvc-version" in headers:
        _add(tech, "IIS", _W_MEDIUM, "ASP.NET 버전 헤더 존재", iis_probes)

    # ---- Node / Express ----
    if "express" in xpb_l:
        _add(tech, "Node/Express", _W_STRONG,
             f"X-Powered-By 헤더에 Express 표기: '{xpb}'", ["/.env", "/package.json"])

    # ---- Jenkins ----
    jenkins_probes = ["/script", "/api/json"]
    if "x-jenkins" in headers:
        _add(tech, "Jenkins", _W_STRONG, "X-Jenkins 헤더 존재", jenkins_probes)
    if "jenkins" in html_l and (has_path_active("/login") or "x-jenkins" in headers):
        _add(tech, "Jenkins", _W_MEDIUM, "로그인 페이지 본문에 Jenkins 표기", jenkins_probes)

    # ---- Grafana ----
    grafana_probes = ["/api/health", "/login"]
    if "grafana" in server_l:
        _add(tech, "Grafana", _W_STRONG,
             f"Server 헤더에 Grafana 표기: '{server}'", grafana_probes)
    if any("grafana" in c for c in cookies_l):
        _add(tech, "Grafana", _W_MEDIUM, "Grafana 관련 쿠키 관측", grafana_probes)

    # ---- Kibana ----
    if "kbn-name" in headers or "kbn-version" in headers:
        _add(tech, "Kibana", _W_STRONG, "kbn-name/kbn-version 헤더 존재",
             ["/api/status", "/app/kibana"])

    # ---- phpMyAdmin ----
    pma_probes = ["/phpmyadmin/", "/pma/"]
    if any(c.startswith("phpmyadmin") or c == "pma_lang" or c.startswith("pma") for c in cookies_l):
        _add(tech, "phpMyAdmin", _W_STRONG, "phpMyAdmin 관련 쿠키 관측", pma_probes)
    if "phpmyadmin" in html_l:
        _add(tech, "phpMyAdmin", _W_MEDIUM, "본문 title/내용에 phpMyAdmin 표기", pma_probes)

    # ---- 프론트엔드 프레임워크 (클라이언트 사이드) ----
    # 보안 관점 추천 점검은 소스맵(.map)/번들 노출 위주.
    # Next.js (React 기반 메타 프레임워크)
    if "__next_data__" in html_l or 'id="__next"' in html_l or "/_next/static" in html_l:
        _add(tech, "Next.js", _W_STRONG, "Next.js 마커(__NEXT_DATA__ / _next/static) 감지",
             ["/_next/static/", "/_next/static/chunks/"])
        _add(tech, "React", _W_MEDIUM, "Next.js 기반(React) 추정", ["/static/js/"])
    # Nuxt (Vue 기반 메타 프레임워크)
    if "__nuxt__" in html_l or 'id="__nuxt"' in html_l or "/_nuxt/" in html_l:
        _add(tech, "Nuxt", _W_STRONG, "Nuxt 마커(__NUXT__ / _nuxt/) 감지", ["/_nuxt/"])
        _add(tech, "Vue.js", _W_MEDIUM, "Nuxt 기반(Vue) 추정", [])
    # React
    if any(m in html_l for m in ("data-reactroot", "react-dom", "__reactcontainer", "_reactlisteners", "__react_devtools")):
        _add(tech, "React", _W_STRONG, "React 마커(data-reactroot / react-dom) 감지",
             ["/static/js/", "/asset-manifest.json"])
    elif re.search(r'react(?:\.production|\.development|\.min)?\.js', html_l):
        _add(tech, "React", _W_MEDIUM, "react.js 스크립트 참조", ["/static/js/"])
    # Vue.js
    if "__vue__" in html_l or "vue@" in html_l or re.search(r'vue(?:\.runtime)?(?:\.global)?(?:\.esm)?(?:\.min)?\.js', html_l):
        _add(tech, "Vue.js", _W_STRONG, "Vue 마커(__VUE__ / vue.js) 감지", [])
    elif "data-v-" in html_l and ("vue" in html_l or 'id="app"' in html_l):
        _add(tech, "Vue.js", _W_WEAK, "data-v- scoped 속성 + Vue 정황", [])
    # Angular
    if re.search(r'ng-version="', html_l) or "_nghost" in html_l or "_ngcontent" in html_l:
        _add(tech, "Angular", _W_STRONG, "Angular 마커(ng-version / _nghost) 감지",
             ["/main.js.map", "/ngsw.json"])
    elif "ng-app" in html_l or re.search(r'angular(?:\.min)?\.js', html_l):
        _add(tech, "Angular", _W_MEDIUM, "AngularJS 마커(ng-app / angular.js)", [])
    # Svelte
    if re.search(r'class="[^"]*svelte-[0-9a-z]+', html_l) or "__svelte" in html_l:
        _add(tech, "Svelte", _W_MEDIUM, "Svelte 마커(svelte- 클래스) 감지", [])
    # jQuery (보조 정보)
    if re.search(r'jquery(?:-[\d.]+)?(?:\.slim)?(?:\.min)?\.js', html_l):
        _add(tech, "jQuery", _W_WEAK, "jQuery 스크립트 참조", [])

    # 런타임 추론: Tomcat/Spring → Java (httpx wappalyzer 수준의 파생 태그 보강)
    if ("Apache Tomcat" in tech or "Spring Boot" in tech) and "Java" not in tech:
        _add(tech, "Java", _W_WEAK, "Tomcat/Spring 기반 → Java 런타임 추론", [])

    technologies = []
    for name, entry in tech.items():
        confidence = min(100, entry["score"])
        if confidence <= 0:
            continue
        technologies.append({
            "name": name,
            "confidence": confidence,
            "evidence": entry["evidence"],
            "recommended_probes": entry["probes"],
        })

    technologies.sort(key=lambda t: (-t["confidence"], t["name"]))
    return {"technologies": technologies}


def _extract_signals_from_service(svc: dict) -> dict:
    """단일 서비스 dict 에서 signals 를 추출한다 (KeyError 금지)."""
    if not isinstance(svc, dict):
        return {}

    http_info = svc.get("http_info") or {}
    if not isinstance(http_info, dict):
        http_info = {}

    headers = http_info.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}

    # 쿠키: scanner 는 dict(name 키) 또는 str 형태로 보관할 수 있음.
    cookies_raw = http_info.get("cookies") or []
    cookie_names: list[str] = []
    if isinstance(cookies_raw, (list, tuple)):
        for c in cookies_raw:
            if isinstance(c, dict):
                n = c.get("name")
                if n:
                    cookie_names.append(str(n))
            elif c:
                # "NAME=value; ..." 형태면 이름만 분리
                cookie_names.append(str(c).split("=", 1)[0].strip())

    # known_paths: sensitive_paths 리스트 -> {path: status}
    known_paths: dict[str, int] = {}
    sp = svc.get("sensitive_paths") or []
    if isinstance(sp, (list, tuple)):
        for item in sp:
            if isinstance(item, dict):
                p = item.get("path")
                st = item.get("status")
                if p is not None and st is not None:
                    known_paths[str(p)] = st

    # html: title + (가능하면) 본문 미리보기 모음
    html_parts: list[str] = []
    title = http_info.get("title")
    if title:
        html_parts.append(str(title))
    if isinstance(sp, (list, tuple)):
        for item in sp:
            if isinstance(item, dict) and item.get("body_preview"):
                html_parts.append(str(item["body_preview"]))
    banner = svc.get("banner")
    if banner:
        html_parts.append(str(banner))

    return {
        "server": http_info.get("server") or "",
        "x_powered_by": http_info.get("x_powered_by") or "",
        "headers": headers,
        "html": "\n".join(html_parts),
        "cookies": cookie_names,
        "known_paths": known_paths,
        "favicon_hash": http_info.get("favicon_hash") or "",
    }


def _merge_signals(a: dict, b: dict) -> dict:
    """여러 서비스의 signals 를 하나로 병합한다."""
    out = {
        "server": a.get("server") or b.get("server") or "",
        "x_powered_by": a.get("x_powered_by") or b.get("x_powered_by") or "",
        "favicon_hash": a.get("favicon_hash") or b.get("favicon_hash") or "",
    }
    headers = dict(a.get("headers") or {})
    headers.update(b.get("headers") or {})
    out["headers"] = headers

    html = "\n".join(x for x in (a.get("html"), b.get("html")) if x)
    out["html"] = html

    cookies = list(a.get("cookies") or [])
    for c in (b.get("cookies") or []):
        if c not in cookies:
            cookies.append(c)
    out["cookies"] = cookies

    known = dict(a.get("known_paths") or {})
    known.update(b.get("known_paths") or {})
    out["known_paths"] = known
    return out


def from_host_result(host_result: dict) -> dict:
    """scanner 의 host_result 에서 signals 를 추출해 fingerprint() 결과를 반환한다."""
    if not isinstance(host_result, dict):
        return {"technologies": []}

    services = host_result.get("services") or []
    if not isinstance(services, (list, tuple)):
        return {"technologies": []}

    merged: dict = {}
    for svc in services:
        sig = _extract_signals_from_service(svc)
        merged = _merge_signals(merged, sig) if merged else sig

    if not merged:
        return {"technologies": []}

    return fingerprint(merged)
