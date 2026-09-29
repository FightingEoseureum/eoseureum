"""
report_theme.py — Report Theme System 로더. DOCX/HTML 공용.

config/report_theme.yaml 에서 테마를 읽고, env REPORT_THEME 로 활성 테마를 선택한다.
PyYAML 미설치/파일 없음 시 내장 기본 테마로 폴백(항상 동작).
"""
from __future__ import annotations

import os
import pathlib

_YAML_PATH = pathlib.Path(__file__).parent / "config" / "report_theme.yaml"

_BUILTIN = {
    "themes": {
        "corporate_blue": {
            "primary_color": "1E3A5F", "secondary_color": "2563EB", "accent_color": "0E9488",
            "background_color": "0F2A43", "font_family": "맑은 고딕",
            "cover_style": "dark_gradient", "card_style": "shadow_rounded",
            "severity_colors": {"Critical": "DC2626", "High": "EA580C", "Medium": "CA8A04",
                                "Low": "2563EB", "Info": "6B7280"}},
    },
    "default": "corporate_blue",
}

_cache = None


def _load() -> dict:
    global _cache
    if _cache is not None:
        return _cache
    data = None
    try:
        import yaml
        if _YAML_PATH.exists():
            data = yaml.safe_load(_YAML_PATH.read_text(encoding="utf-8"))
    except Exception:
        data = None
    _cache = data if (isinstance(data, dict) and data.get("themes")) else _BUILTIN
    return _cache


def available_themes() -> list:
    return list(_load().get("themes", {}).keys())


def active_theme_name() -> str:
    data = _load()
    req = (os.getenv("REPORT_THEME") or data.get("default") or "corporate_blue").strip()
    return req if req in data.get("themes", {}) else data.get("default", "corporate_blue")


def get_theme(name: str | None = None) -> dict:
    """활성(또는 지정) 테마 dict 반환. 없으면 기본 테마."""
    data = _load()
    themes = data.get("themes", {})
    key = name or active_theme_name()
    if key not in themes:                       # 미상 테마 → 기본으로 폴백(이름도 기본으로)
        key = data.get("default", "corporate_blue")
        if key not in themes:
            key = next(iter(themes), "corporate_blue")
    theme = dict(themes.get(key) or _BUILTIN["themes"]["corporate_blue"])
    theme["name"] = key
    return theme
