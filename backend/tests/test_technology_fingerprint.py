"""
test_technology_fingerprint.py — technology_fingerprint 엔진 검증.

모듈: backend/technology_fingerprint.py
  fingerprint(signals: dict) -> {"technologies": [...]}
  from_host_result(host_result: dict) -> {"technologies": [...]}

실행:
  cd backend && venv_linux/bin/python -m pytest tests/test_technology_fingerprint.py -q
"""
import os
import sys

import pytest

# backend 디렉터리를 import 경로에 추가 (tests/ 의 부모)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import technology_fingerprint as tf


def _by_name(result: dict, name: str):
    for t in result["technologies"]:
        if t["name"] == name:
            return t
    return None


def test_apache_coyote_detects_tomcat():
    result = tf.fingerprint({"server": "Apache-Coyote/1.1"})
    tomcat = _by_name(result, "Apache Tomcat")
    assert tomcat is not None
    assert tomcat["confidence"] > 0


def test_tomcat_recommended_probes():
    result = tf.fingerprint({"server": "Apache-Coyote/1.1"})
    tomcat = _by_name(result, "Apache Tomcat")
    assert tomcat is not None
    assert "/manager/html" in tomcat["recommended_probes"]
    assert "/host-manager/html" in tomcat["recommended_probes"]


def test_php_via_x_powered_by():
    result = tf.fingerprint({"x_powered_by": "PHP/7.4"})
    php = _by_name(result, "PHP")
    assert php is not None
    assert php["confidence"] > 0
    assert "/.env" in php["recommended_probes"]


def test_empty_signals_returns_empty():
    assert tf.fingerprint({}) == {"technologies": []}


def test_from_host_result_without_services_is_safe():
    # services 키가 아예 없는 dict
    assert tf.from_host_result({}) == {"technologies": []}
    # services 가 None 이거나 빈 리스트
    assert tf.from_host_result({"services": None}) == {"technologies": []}
    assert tf.from_host_result({"services": []}) == {"technologies": []}
    # dict 가 아닌 입력
    assert tf.from_host_result(None) == {"technologies": []}


# ---- 추가 신뢰성 검증 ----

def test_results_sorted_by_confidence_desc():
    result = tf.fingerprint({
        "server": "Apache-Coyote/1.1",       # Tomcat strong
        "x_powered_by": "PHP/7.4",           # PHP strong
        "cookies": ["PHPSESSID"],            # PHP strong (병합으로 더 높음)
    })
    confidences = [t["confidence"] for t in result["technologies"]]
    assert confidences == sorted(confidences, reverse=True)


def test_confidence_capped_at_100():
    result = tf.fingerprint({
        "x_powered_by": "PHP/7.4",
        "cookies": ["PHPSESSID"],
        "known_paths": {"/index.php": 200},
    })
    php = _by_name(result, "PHP")
    assert php is not None
    assert php["confidence"] <= 100


def test_duplicate_tech_merged():
    # Tomcat 단서가 여러 개여도 항목은 하나로 병합
    result = tf.fingerprint({
        "server": "Apache-Coyote/1.1",
        "known_paths": {"/manager": 403},
        "html": "Apache Tomcat/9.0",
    })
    tomcats = [t for t in result["technologies"] if t["name"] == "Apache Tomcat"]
    assert len(tomcats) == 1
    assert tomcats[0]["confidence"] > 70  # 병합으로 단일 단서보다 높음


def test_spring_boot_actuator():
    result = tf.fingerprint({"known_paths": {"/actuator/health": 200}})
    spring = _by_name(result, "Spring Boot")
    assert spring is not None
    assert "/actuator/heapdump" in spring["recommended_probes"]


def test_from_host_result_extracts_signals():
    host_result = {
        "host": "example.com",
        "services": [
            {
                "port": 8080,
                "http_info": {
                    "server": "Apache-Coyote/1.1",
                    "x_powered_by": "",
                    "headers": {"server": "Apache-Coyote/1.1"},
                    "title": "Apache Tomcat",
                    "cookies": [{"name": "JSESSIONID"}],
                },
                "sensitive_paths": [
                    {"path": "/manager", "status": 403},
                ],
            },
        ],
    }
    result = tf.from_host_result(host_result)
    tomcat = _by_name(result, "Apache Tomcat")
    assert tomcat is not None
    assert tomcat["confidence"] > 0
    assert "/manager/html" in tomcat["recommended_probes"]


def test_recommended_probes_are_non_destructive():
    # 모든 추천 프로브는 안전한 경로여야 한다 (파괴 동사 미포함)
    result = tf.fingerprint({
        "server": "Apache-Coyote/1.1",
        "x_powered_by": "PHP/7.4",
        "cookies": ["PHPSESSID", "grafana_session"],
    })
    bad = ("delete", "drop", "shutdown", "remove")
    for t in result["technologies"]:
        for p in t["recommended_probes"]:
            assert not any(b in p.lower() for b in bad)


# ── 프론트엔드 프레임워크 탐지 ──────────────────────────────────────────────────
def _names(html):
    r = tf.fingerprint({"headers": {}, "html": html, "cookies": [], "known_paths": {}})
    return {t["name"] for t in r["technologies"]}


def test_detect_react():
    assert "React" in _names('<div data-reactroot><script src="react-dom.production.min.js"></script></div>')


def test_detect_vue():
    assert "Vue.js" in _names('<div id="app"></div><script>window.__VUE__=1</script>')


def test_detect_angular():
    assert "Angular" in _names('<app-root ng-version="16.2.0"></app-root>')


def test_detect_nextjs_implies_react():
    names = _names('<div id="__next"></div><script id="__NEXT_DATA__">{}</script>')
    assert "Next.js" in names and "React" in names


def test_detect_nuxt_implies_vue():
    names = _names('<div id="__nuxt"></div><script>window.__NUXT__={}</script>')
    assert "Nuxt" in names and "Vue.js" in names


def test_detect_svelte_and_jquery():
    assert "Svelte" in _names('<div class="app svelte-1x2y3z"></div>')
    assert "jQuery" in _names('<script src="/js/jquery-3.6.0.min.js"></script>')


def test_plain_html_no_frontend_framework():
    names = _names("<html><body><h1>hello</h1></body></html>")
    assert not ({"React", "Vue.js", "Angular", "Next.js", "Nuxt", "Svelte"} & names)
