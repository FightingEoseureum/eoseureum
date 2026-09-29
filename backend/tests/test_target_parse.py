"""test_target_parse.py — 명시 포트 타깃 파싱(비표준 포트 스캔 지원)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scanner as s


def test_host_port():
    r = s.parse_target("host3.dreamhack.games:13006")
    assert r["host"] == "host3.dreamhack.games" and r["port"] == 13006 and r["scheme"] == "http"


def test_full_url_with_port_and_path():
    r = s.parse_target("http://host3.dreamhack.games:13006/")
    assert r["host"] == "host3.dreamhack.games" and r["port"] == 13006 and r["scheme"] == "http"


def test_https_port_infers_scheme():
    assert s.parse_target("x.com:8443")["scheme"] == "https"
    assert s.parse_target("https://x.com:8443")["scheme"] == "https"


def test_plain_host_no_port():
    r = s.parse_target("example.com")
    assert r["host"] == "example.com" and r["port"] is None and r["scheme"] is None


def test_url_without_port_keeps_host_only():
    r = s.parse_target("http://a.b/c/d")
    assert r["host"] == "a.b" and r["port"] is None
