"""
report_html_renderer.py — HTML Report Renderer v2 (카드형 상용 리포트 디자인).

목업 승인 디자인 적용: 표지 → 경영 요약(심각도 도넛·우선조치) → 발견 개요표 →
취약점 상세 카드(심각도 스트라이프·3줄 요약·기술 근거·증거 스크린샷·재현 방법) → 탐지 커버리지.
판정/데이터는 변경하지 않고 analysis 를 '표현'만 한다. HTML→PDF(report_html_pdf) 공용 소스.
"""
from __future__ import annotations

import html as _html
import os

_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
_SEV_KO = {"critical": ("치명적", "crit"), "high": ("높음", "high"),
           "medium": ("보통", "med"), "low": ("낮음", "low"), "info": ("정보", "info")}
_SEV_RANK = {"crit": 0, "high": 1, "med": 2, "low": 3, "info": 4}


import re as _re
# 외부/내부 점검 도구명은 보고서에 노출하지 않는다(브랜드 일관성) — 렌더 시 일괄 치환.
_TOOL_RE = _re.compile(
    r'\b(sqlmap|nuclei|ffuf|katana|nikto|testssl(?:\.sh)?|ghauri|wpscan|nmap|masscan|'
    r'amass|gobuster|dirb|arjun|playwright|puppeteer|selenium|wafw00f)\b', _re.I)


def _scrub_tools(s: str) -> str:
    return _TOOL_RE.sub("자체 점검 엔진", s)


def _e(x) -> str:
    return _html.escape(_scrub_tools(str(x if x is not None else "")))


def _sev(f) -> tuple:
    s = (f.get("report_severity") or f.get("severity") or "").strip().lower()
    if s.startswith("crit"):
        s = "critical"
    return _SEV_KO.get(s, ("정보", "info"))


def _org_name() -> str:
    return os.getenv("REPORT_ORG_NAME", "Eoseureum Security")


def _endpoint(f) -> str:
    return (f.get("evidence_url") or f.get("url")
            or (f.get("affected_endpoints") or [""])[0] or "")


def _first_sentence(txt: str, limit: int = 160) -> str:
    t = " ".join(str(txt or "").split())
    if not t:
        return ""
    for sep in (". ", "다. ", "요. "):
        i = t.find(sep)
        if 0 < i < limit:
            return t[:i + len(sep)].strip()
    return t[:limit].strip() + ("…" if len(t) > limit else "")


def _clean_evidence(f) -> str:
    """도구 원문 덤프([testssl.sh]/항목 ID:.../심각도:... 등)를 걷어내고 핵심 근거 한 줄만."""
    raw = str(f.get("evidence_detail") or f.get("evidence") or "")
    keep = []
    for ln in raw.splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.startswith("[") and s.endswith("]"):        # [testssl.sh 점검 결과] 류 헤더
            continue
        # "키 : 값" 형태의 도구 메타 라인 — '결과/근거'만 취하고 나머지 버림
        if " : " in s[:14] or s[:6] in ("항목 ID", "심각도  ", "CVE   "):
            k = s.split(":", 1)
            if len(k) == 2 and any(w in k[0] for w in ("결과", "근거", "위험")):
                keep.append(k[1].strip())
            continue
        keep.append(s)
    return _first_sentence(" ".join(keep) or raw, 200)


def _essence(f) -> tuple:
    """(한 줄 요약, 왜 위험한가, 조치)."""
    try:
        import report as _r
        one = _r._finding_at_a_glance(f) if hasattr(_r, "_finding_at_a_glance") else ""
    except Exception:
        one = ""
    # at-a-glance 가 여러 줄(• 무엇이 문제 / • 왜 위험 / • 어떻게 조치)이면 첫 항목만 → 진짜 한 줄
    if one and ("\n" in one or "•" in one):
        parts = [ln.strip(" •\t") for ln in one.replace("•", "\n").splitlines() if ln.strip(" •\t")]
        first = parts[0] if parts else one
        one = first.split("—", 1)[-1].strip() if "—" in first else first
    one = _first_sentence(one or f.get("description") or f.get("title") or "", 120)
    why = (f.get("business_impact") or f.get("impact")
           or _first_sentence(f.get("attack_vector") or "", 140)
           or "공격자가 악용 시 데이터·계정·세션에 영향을 줄 수 있습니다.")
    fix = _first_sentence(f.get("recommendation") or "", 160) or "권고 조치를 적용하십시오."
    return one, why, fix


def _screenshot_data_uri(f: dict):
    """Finding 의 증거 스크린샷을 base64 data URI 로 임베드(자기 자신 것만, 비율 유지).
    파일 없거나 과대(>2MB)면 None → 표시 생략."""
    import base64
    import pathlib
    names = []
    if f.get("evidence_screenshot"):
        names.append(f["evidence_screenshot"])
    for s in (f.get("evidence_screenshots") or [])[:1]:   # 최상위 복수 필드(능동 프로브 캡처)
        names.append(s)
    pd = f.get("probe_detail") or {}
    for s in (pd.get("evidence_screenshots") or [])[:1]:
        names.append(s)
    for name in names:
        try:
            base = pathlib.Path(__file__).parent / "screenshots"
            p = (base / pathlib.Path(str(name)).name)
            if p.exists() and p.stat().st_size <= 2_000_000:
                mime = "image/png" if p.suffix.lower() == ".png" else "image/jpeg"
                return f"data:{mime};base64," + base64.b64encode(p.read_bytes()).decode("ascii")
        except Exception:
            continue
    return None


def _poc_for(f) -> str:
    try:
        import poc_generator
        return poc_generator.generate_poc(f) or ""
    except Exception:
        return f.get("poc") or ""




def _eff_levels(analysis):
    ev = analysis.get("evidence_levels") or {}
    if any(ev.get(k) for k in ("level3_proven", "level2_evidence", "level1_observed", "level0_info")):
        return ev
    try:
        import report
        return report._eff_levels(analysis)
    except Exception:
        return ev


def _donut_bg(crit, high, med, low) -> str:
    segs = [("var(--sev-crit)", crit), ("var(--sev-high)", high),
            ("var(--sev-med)", med), ("var(--sev-low)", low)]
    total = crit + high + med + low
    if total <= 0:
        return "conic-gradient(var(--sev-info) 0 100%)"
    acc, stops = 0, []
    for color, cnt in segs:
        if cnt <= 0:
            continue
        start = acc / total * 100
        acc += cnt
        end = acc / total * 100
        stops.append(f"{color} {start:.1f}% {end:.1f}%")
    return "conic-gradient(" + ",".join(stops) + ")"


_CSS = """
:root{--canvas:#e9edf2;--paper:#fff;--ink:#0f172a;--ink-2:#475569;--ink-3:#94a3b8;
 --line:#e2e8f0;--line-2:#eef2f6;--brand:#1e3a8a;--brand-2:#2563eb;--brand-wash:#eff4ff;
 --sev-crit:#dc2626;--sev-high:#ea580c;--sev-med:#d97706;--sev-low:#2563eb;--sev-info:#64748b;--ok:#16a34a;
 --mono:"SFMono-Regular","Consolas","D2Coding",monospace;
 --sans:"맑은 고딕","Malgun Gothic","Pretendard","Noto Sans CJK KR","Noto Sans KR","NanumGothic",system-ui,sans-serif;}
@page{size:A4;margin:16mm 14mm;}
*{box-sizing:border-box}
body{margin:0;background:var(--canvas);color:var(--ink);font-family:var(--sans);line-height:1.6;
 -webkit-print-color-adjust:exact;print-color-adjust:exact;}
.watermark{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;pointer-events:none;
 z-index:0;opacity:.05;font-size:120px;font-weight:800;color:#dc2626;transform:rotate(-30deg);letter-spacing:.1em;}
.doc{max-width:900px;margin:0 auto;padding:28px 16px 56px;display:flex;flex-direction:column;gap:24px;position:relative;z-index:1;}
.page{background:var(--paper);border:1px solid var(--line);border-radius:6px;
 box-shadow:0 1px 2px rgba(15,23,42,.06),0 12px 32px rgba(15,23,42,.10);padding:44px 48px;}
h1,h2,h3{margin:0;text-wrap:balance;letter-spacing:-.01em}
p{margin:0}
.mono{font-family:var(--mono)}
.muted{color:var(--ink-2)}
.eyebrow{font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--ink-3);font-weight:700}
.tnum{font-variant-numeric:tabular-nums}
.cover{padding:52px 48px;position:relative;overflow:hidden}
.cover::before{content:"";position:absolute;inset:0 0 auto 0;height:6px;background:linear-gradient(90deg,var(--brand),var(--brand-2))}
.brand{display:flex;align-items:center;gap:10px}
.brand-mark{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;color:#fff;font-weight:800;
 background:linear-gradient(135deg,var(--brand),var(--brand-2))}
.brand-name{font-weight:800;letter-spacing:.02em}.brand-sub{font-size:11px;color:var(--ink-3);letter-spacing:.06em}
.cover-title{font-size:34px;font-weight:800;line-height:1.15;margin-top:40px}
.cover-meta{margin-top:26px;display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--line);border:1px solid var(--line);border-radius:8px;overflow:hidden}
.cover-meta>div{background:var(--paper);padding:13px 16px}
.cover-meta .k{font-size:11px;color:var(--ink-3)}.cover-meta .v{font-weight:700;margin-top:2px}
.risk-strip{margin-top:22px;display:flex;align-items:center;gap:16px;padding:16px 20px;border-radius:10px;background:var(--brand-wash);border:1px solid #dbe4ff}
.risk-badge{font-weight:800;font-size:13px;padding:8px 14px;border-radius:999px;color:#fff;white-space:nowrap}
.cover-stats{margin-top:24px;display:grid;grid-template-columns:repeat(5,1fr);gap:10px}
.stat{border:1px solid var(--line);border-radius:10px;padding:13px 10px;text-align:center}
.stat .n{font-size:24px;font-weight:800;line-height:1;font-variant-numeric:tabular-nums}
.stat .l{font-size:11px;color:var(--ink-2);margin-top:5px}
.sec-head{display:flex;align-items:baseline;gap:12px;padding-bottom:11px;border-bottom:2px solid var(--ink);margin-bottom:22px}
.sec-no{font-family:var(--mono);font-size:13px;font-weight:700;color:var(--brand-2)}
.sec-title{font-size:19px;font-weight:800}.sec-en{font-size:12px;color:var(--ink-3);margin-left:auto;letter-spacing:.04em}
.exec{display:grid;grid-template-columns:190px 1fr;gap:26px;align-items:center}
.donut{width:158px;height:158px;border-radius:50%;display:grid;place-items:center;position:relative;margin:0 auto}
.donut::after{content:"";position:absolute;inset:25px;background:var(--paper);border-radius:50%}
.donut-c{position:relative;z-index:1;text-align:center}.donut-c .n{font-size:32px;font-weight:800;line-height:1}.donut-c .l{font-size:11px;color:var(--ink-2)}
.legend{display:grid;grid-template-columns:1fr 1fr;gap:5px 14px;font-size:12px;margin-top:10px;max-width:158px;margin-left:auto;margin-right:auto}
.legend .r{display:flex;align-items:center;gap:6px}.dot{width:10px;height:10px;border-radius:3px;flex:none}
.priority{margin-top:14px;display:flex;flex-direction:column;gap:7px}
.priority .pill{display:flex;align-items:center;gap:10px;padding:9px 13px;border:1px solid var(--line);border-radius:10px;font-size:13px}
.priority .rank{font-family:var(--mono);font-weight:800;color:var(--brand-2)}
table.ov{width:100%;border-collapse:collapse;font-size:13.5px}
table.ov th{text-align:left;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-3);padding:0 10px 9px;border-bottom:1px solid var(--line)}
table.ov td{padding:11px 10px;border-bottom:1px solid var(--line-2);vertical-align:middle}
table.scan-tbl td{padding:8px 10px}table.scan-tbl .tcell{text-align:right}table.scan-tbl .num{color:var(--ink-3);font-variant-numeric:tabular-nums}
.num{font-family:var(--mono);color:var(--ink-3);font-weight:700}.cwe{font-family:var(--mono);font-size:12px;color:var(--ink-2)}
.chip{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;font-weight:700;padding:3px 10px;border-radius:999px;white-space:nowrap}
.chip::before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor}
.chip.crit{color:var(--sev-crit);background:#fef2f2}.chip.high{color:var(--sev-high);background:#fff7ed}
.chip.med{color:var(--sev-med);background:#fffbeb}.chip.low{color:var(--sev-low);background:#eff6ff}.chip.info{color:var(--sev-info);background:#f1f5f9}
.status-ok{font-size:12px;color:var(--ok);font-weight:700}
.cards{display:flex;flex-direction:column;gap:18px}
.fcard{border:1px solid var(--line);border-radius:12px;overflow:hidden;border-left:4px solid var(--sev-info)}
.fcard.crit{border-left-color:var(--sev-crit)}.fcard.high{border-left-color:var(--sev-high)}
.fcard.med{border-left-color:var(--sev-med)}.fcard.low{border-left-color:var(--sev-low)}
.fcard-head{padding:15px 18px;display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap}
.fcard-head .t{flex:1;min-width:200px}.fcard-head .id{font-family:var(--mono);font-size:11px;color:var(--ink-3)}
.fcard-head h3{font-size:16px;font-weight:800;margin-top:3px}
.fcard-head .ep{font-family:var(--mono);font-size:12px;color:var(--ink-2);margin-top:6px;word-break:break-all}
.fcard-body{padding:2px 18px 18px;display:flex;flex-direction:column;gap:14px}
.essence{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--line);border:1px solid var(--line);border-radius:10px;overflow:hidden}
.essence>div{background:var(--paper);padding:12px 14px;min-width:0}
.essence .txt{overflow-wrap:anywhere;word-break:break-word}
.essence .lab{font-size:10.5px;letter-spacing:.06em;color:var(--ink-3);font-weight:700}
.essence .txt{font-size:13px;margin-top:5px;line-height:1.5}.essence .why .lab{color:var(--sev-high)}
.ai-flag{background:#fffbeb;border:1px solid #fde68a;border-left:4px solid var(--sev-med);border-radius:9px;
 padding:10px 13px;margin-bottom:12px;font-size:12.5px;color:#92400e;line-height:1.6}
.ai-flag-r{margin-top:5px;font-size:11.5px;color:#b45309}
.block{border:1px solid var(--line);border-radius:10px;overflow:hidden}
.block-h{font-size:11.5px;font-weight:700;color:var(--ink-2);padding:9px 13px;background:#f8fafc;border-bottom:1px solid var(--line)}
.block-b{padding:11px 13px;font-size:13px}
.code{font-family:var(--mono);font-size:12px;line-height:1.7;white-space:pre-wrap;word-break:break-all;color:var(--ink)}
.shot{margin-top:10px;border:1px solid var(--line);border-radius:8px;overflow:hidden;background:#f1f5f9}
.shot img{display:block;width:100%;max-height:340px;object-fit:contain;background:#f1f5f9}
.cov-summary{display:grid;grid-template-columns:repeat(4,1fr);gap:11px;margin-bottom:18px}
.cov-summary .box{border:1px solid var(--line);border-radius:10px;padding:13px;text-align:center}
.cov-summary .box .n{font-size:22px;font-weight:800;font-variant-numeric:tabular-nums}.cov-summary .box .l{font-size:11px;color:var(--ink-2);margin-top:4px}
.cov-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:7px}
.cov-cell{display:flex;align-items:center;gap:8px;padding:9px 11px;border:1px solid var(--line);border-radius:8px;font-size:12px}
.cov-cell .s{width:8px;height:8px;border-radius:50%;flex:none}
.cov-cell.confirmed{border-color:#fecaca;background:#fef6f6}.cov-cell.confirmed .s{background:var(--sev-crit)}
.cov-cell.possible .s{background:var(--sev-med)}.cov-cell.clean .s{background:var(--ok)}
.cov-cell.na{color:var(--ink-3)}.cov-cell.na .s{background:var(--ink-3)}
.cov-name{flex:1}
.rec{display:flex;flex-direction:column;gap:9px}
.rec .item{display:flex;gap:12px;align-items:flex-start;font-size:13px;padding:11px 14px;border:1px solid var(--line);border-radius:10px}
.rec .item .chip{flex:none;margin-top:1px}
.rec .item .rt{font-weight:700;color:var(--ink);margin-bottom:3px}
.rec .item .rd{color:var(--ink-2);line-height:1.6}
.lead{font-size:14px;line-height:1.8;color:var(--ink);margin-bottom:14px}
.bul{margin:0;padding-left:0;list-style:none;display:flex;flex-direction:column;gap:9px}
.bul li{position:relative;padding-left:20px;font-size:13.5px;line-height:1.7;color:var(--ink-2)}
.bul li::before{content:"";position:absolute;left:2px;top:9px;width:6px;height:6px;border-radius:50%;background:var(--brand-2)}
table.kv{width:100%;border-collapse:collapse;font-size:13.5px}
table.kv th{width:120px;text-align:left;color:var(--ink-2);font-weight:600;padding:12px 14px;background:#f8fafc;border:1px solid var(--line);border-right:none;vertical-align:top;white-space:nowrap}
table.kv td{padding:12px 14px;border:1px solid var(--line);border-left:none;color:var(--ink)}
.crit{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.crit-b{border:1px solid var(--line);border-radius:11px;padding:14px 16px}
.crit-h{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--brand-2);font-weight:800;margin-bottom:7px}
.crit-d{font-size:13px;line-height:1.7;color:var(--ink)}
.sub-h{font-size:14px;font-weight:800;color:var(--ink);margin:0 0 12px;padding-bottom:8px;border-bottom:2px solid var(--line)}
.appx{font-size:12px;color:var(--ink-2)}.appx table{width:100%;border-collapse:collapse;margin-top:8px}
.appx td{padding:6px 8px;border-bottom:1px solid var(--line-2)}
.foot{text-align:center;font-size:11px;color:var(--ink-3);padding-top:8px}
@media print{
 body{background:#fff}
 .watermark{position:fixed}
 .doc{max-width:none;padding:0;gap:0}
 /* 섹션마다 강제 개행하지 않는다(짧은 섹션이 한 페이지씩 차지해 늘어지고 끝에 빈 페이지가 생기던 문제).
    표지만 단독 페이지, 그 외엔 자연스럽게 흐르고 '주요 섹션'(.brk)만 새 페이지에서 시작한다. */
 .page{border:none;box-shadow:none;border-radius:0;padding:0 0 18px}
 .cover{page-break-after:always;padding:52px 0}
 .page.brk{page-break-before:always;padding-top:8px}
 .fcard,.cov-cell,tr,.priority .pill,.block,.essence>div,.rec .item,.crit-b,.pill{break-inside:avoid;page-break-inside:avoid}
 thead{display:table-header-group}          /* 여러 페이지로 나뉜 표의 헤더 반복 */
 .sec-head{break-after:avoid;page-break-after:avoid}   /* 섹션 제목이 페이지 하단에 홀로 남지 않도록 */
}
"""


def _finding_card(f, idx) -> str:
    ko, cls = _sev(f)
    one, why, fix = _essence(f)
    ev = _clean_evidence(f)                 # 도구 원문 덤프 제거 · 핵심 한 줄
    pl = f.get("payload")
    if pl and str(pl) not in ev:            # 삽입 페이로드를 근거에 명시(재현성)
        ev = (f"삽입 페이로드: {pl}\n{ev}" if ev else f"삽입 페이로드: {pl}")
    poc = _poc_for(f)
    shot = _screenshot_data_uri(f)
    cwe = f.get("cwe") or ""
    parts = [f'<article class="fcard {cls}">',
             '<div class="fcard-head"><div class="t">',
             f'<div class="id">FINDING-{idx:02d}{(" · " + _e(cwe)) if cwe else ""}</div>',
             f'<h3>{_e(f.get("title") or "취약점")}</h3>',
             f'<div class="ep">{_e(_endpoint(f))}</div></div>',
             f'<span class="chip {cls}">{ko}</span></div>',
             '<div class="fcard-body">']
    # AI 앙상블 오탐 의심 배너(룰 판정은 유지 · 삭제 안 함 — 수동 확인 권장)
    if f.get("ai_fp_flag"):
        _votes = _e(f.get("ai_fp_votes") or "")
        _rsn = "; ".join(str(r) for r in (f.get("ai_fp_reasons") or [])[:3])
        parts.append(
            '<div class="ai-flag">🧪 <b>AI 앙상블 오탐 의심</b>'
            + (f' · {_votes}표' if _votes else '')
            + ' — 룰 판정은 유지되나 <b>수동 확인</b>을 권장합니다.'
            + (f'<div class="ai-flag-r">판정 근거: {_e(_rsn)}</div>' if _rsn else '')
            + '</div>')
    parts += [
             '<div class="essence">',
             f'<div><div class="lab">한 줄 요약</div><div class="txt">{_e(one)}</div></div>',
             f'<div class="why"><div class="lab">왜 위험한가</div><div class="txt">{_e(why)}</div></div>',
             f'<div><div class="lab">조치 방법</div><div class="txt">{_e(fix)}</div></div>',
             '</div>']
    if ev:
        parts.append('<div class="block"><div class="block-h">기술 근거 (Evidence)</div>'
                     f'<div class="block-b"><div class="code">{_e(ev)}</div>')
        if shot:
            parts.append(f'<div class="shot"><img src="{shot}" alt="evidence screenshot"></div>')
        parts.append('</div></div>')
    elif shot:
        parts.append('<div class="block"><div class="block-h">증거 스크린샷</div>'
                     f'<div class="block-b"><div class="shot"><img src="{shot}" alt="evidence"></div></div></div>')
    if poc:
        parts.append('<div class="block"><div class="block-h">재현 방법 (비파괴)</div>'
                     f'<div class="block-b"><div class="code">{_e(poc)}</div></div></div>')
    parts.append('</div></article>')
    return "".join(parts)


# 점검 항목(스캐너가 탐지하는 취약점 클래스) · 위험도 기준표 — 표시 전용
_TIER_LABEL = {"crit": "Critical", "high": "High", "med": "Medium", "low": "Low", "info": "Info"}
_SCAN_COVERAGE = [
    ("SQL 인젝션 (SQLi)", "crit"),
    ("명령어 인젝션 (OS Command Injection)", "crit"),
    ("서버사이드 템플릿 인젝션 (SSTI)", "crit"),
    ("서버사이드 요청 위조 (SSRF)", "crit"),
    ("안전하지 않은 역직렬화 (Insecure Deserialization)", "crit"),
    ("React2Shell — RSC 역직렬화 원격코드실행 (CVE-2025-55182)", "crit"),
    ("인증 우회 (Authentication Bypass)", "crit"),
    ("크로스사이트 스크립팅 (XSS · 반사/저장/DOM)", "high"),
    ("XML 외부 개체 주입 (XXE)", "high"),
    ("파일 포함·경로 탐색 (LFI · Path Traversal)", "high"),
    ("접근통제 미흡 (IDOR · BAC)", "high"),
    ("무인증 쓰기 접근통제 (작성·변조·삭제)", "high"),
    ("민감정보·시크릿 노출 (API Key·Token)", "high"),
    ("클라이언트 인증·토큰 우회 (JS Auth Bypass)", "high"),
    ("크로스사이트 요청 위조 (CSRF)", "high"),
    ("오픈 리다이렉트 (Open Redirect)", "med"),
    ("클릭재킹 (Clickjacking)", "med"),
    ("취약한 TLS/SSL 구성", "med"),
    ("교차 출처 자원 공유 오류 (CORS)", "med"),
    ("콘텐츠 보안 정책 미흡·우회 (CSP · base-uri)", "med"),
    ("세션·쿠키 보안 미흡", "med"),
    ("보안 헤더 미설정", "low"),
    ("위험한 HTTP 메서드 (TRACE 등)", "low"),
    ("디렉터리 리스팅", "low"),
    ("관리자·백업 파일 노출", "low"),
    ("Swagger·Actuator 노출", "low"),
    ("JSONP 오용", "low"),
    ("서비스·기술스택 식별", "info"),
    ("서버·버전 정보 노출", "info"),
    ("하위 도메인 열거 (Subdomain)", "info"),
    ("robots·sitemap·이메일 정보 수집", "info"),
]

_COV_STATUS = {"confirmed": ("confirmed", "취약 확인"), "possible": ("possible", "가능·검토"),
               "tested_clean": ("clean", "검사·안전"), "blocked": ("na", "정책 차단"),
               "not_reached": ("na", "미도달")}


def generate_html(scan: dict, theme_name: str | None = None) -> str:
    analysis = scan.get("analysis") or {}
    domain = scan.get("domain", "")
    created = scan.get("created_at", "")
    org = _org_name()
    summary = analysis.get("summary") or {}
    by_sev = summary.get("by_severity") or {}
    # 오탐 억제(_fp_suppressed) 항목은 고객용 요약(HTML/PDF)에서 제외한다 — 점수·분포·대시보드가
    # 이미 억제 항목을 차감하므로(_eff_severity_counts) 개요 목록도 동일하게 맞춰 '확인됨' 오표시를 막는다.
    # (기존엔 judgment!=양호 만 필터해, 억제된 오탐이 고객 보고서에 '확인됨'으로 노출되던 문제)
    findings = [f for f in (analysis.get("findings") or [])
                if f.get("judgment") != "양호" and not f.get("_fp_suppressed")]
    # 발견된 취약점은 Critical→Low 순으로 표시(개요·상세 공통)
    findings.sort(key=lambda f: _SEV_RANK.get(_sev(f)[1], 9))
    surface = analysis.get("attack_surface_items") or []
    cov_matrix = (analysis.get("detection_coverage") or {}).get("matrix") or []

    crit = int(by_sev.get("Critical", 0)); high = int(by_sev.get("High", 0))
    med = int(by_sev.get("Medium", 0)); low = int(by_sev.get("Low", 0))
    total = len(findings)
    # 결정적 리포트번호(DOCX 와 동일 포맷·유도) — abs(hash)는 실행마다 달라져 DOCX/HTML 불일치했음
    import hashlib as _hl
    from datetime import datetime as _dt
    _rno = int(_hl.md5((domain or "").encode("utf-8")).hexdigest()[:8], 16) % 10000
    report_no = f"ASR-{_dt.now():%Y%m%d}-{_rno:04d}"

    # 종합 위험도
    if crit:
        risk_label, risk_bg = "종합 위험도 · 매우 높음", "var(--sev-crit)"
    elif high:
        risk_label, risk_bg = "종합 위험도 · 높음", "var(--sev-high)"
    elif med:
        risk_label, risk_bg = "종합 위험도 · 보통", "var(--sev-med)"
    elif total:
        risk_label, risk_bg = "종합 위험도 · 낮음", "var(--sev-low)"
    else:
        risk_label, risk_bg = "종합 위험도 · 양호", "var(--ok)"

    # 우선 조치(심각도 순 상위 3)
    ordered = sorted(findings, key=lambda f: _SEV_RANK.get(_sev(f)[1], 9))
    priority = ordered[:3]

    P = ['<!doctype html><html lang="ko"><head><meta charset="utf-8">'
         f'<title>Eoseureum · Security Assessment Report — {_e(domain)}</title>'
         f'<style>{_CSS}</style></head><body>',
         '<div class="watermark">CONFIDENTIAL</div>',
         '<div class="doc">']

    # ── 표지 ──
    P.append(
        '<section class="page cover">'
        '<div class="brand"><div class="brand-mark">E</div>'
        '<div><div class="brand-name">Eoseureum</div>'
        '<div class="brand-sub">AI SECURITY ASSESSMENT PLATFORM</div></div></div>'
        '<h1 class="cover-title">웹 애플리케이션<br>취약점 점검 보고서</h1>'
        '<div class="cover-meta">'
        f'<div><div class="k">점검 대상</div><div class="v mono">{_e(domain)}</div></div>'
        f'<div><div class="k">보고서 번호</div><div class="v mono">{_e(report_no)}</div></div>'
        f'<div><div class="k">점검 일자</div><div class="v tnum">{_e(created)}</div></div>'
        f'<div><div class="k">작성 기관</div><div class="v">{_e(org)}</div></div></div>'
        f'<div class="risk-strip"><span class="risk-badge" style="background:{risk_bg}">{risk_label}</span>'
        f'<p class="muted" style="font-size:13.5px">확인된 취약점 <b style="color:var(--ink)">{total}건</b>'
        + (f' 중 <b style="color:var(--sev-crit)">치명적 {crit}건</b>' if crit else '')
        + (f'·높음 {high}건' if high else '') + ' — 아래 요약을 참조하십시오.</p></div>'
        '<div class="cover-stats">'
        f'<div class="stat"><div class="n tnum" style="color:var(--sev-crit)">{crit}</div><div class="l">치명적</div></div>'
        f'<div class="stat"><div class="n tnum" style="color:var(--sev-high)">{high}</div><div class="l">높음</div></div>'
        f'<div class="stat"><div class="n tnum" style="color:var(--sev-med)">{med}</div><div class="l">보통</div></div>'
        f'<div class="stat"><div class="n tnum" style="color:var(--sev-low)">{low}</div><div class="l">낮음</div></div>'
        f'<div class="stat"><div class="n tnum">{len(surface)}</div><div class="l">공격 표면</div></div>'
        '</div></section>')

    # ── 1. 점검 목적 ──
    P.append(
        '<section class="page"><div class="sec-head"><span class="sec-no">01</span>'
        '<span class="sec-title">점검 목적</span><span class="sec-en">Purpose</span></div>'
        f'<p class="lead">본 모의해킹은 <b>{_e(domain)}</b> 웹 애플리케이션에 존재할 수 있는 보안 '
        '취약점을 공격자 관점에서 사전에 식별·검증하여, 실제 침해로 이어지기 전에 조치할 수 있도록 '
        '지원하는 것을 목적으로 합니다. 확인된 취약점은 재현(실증)을 통해 오탐을 배제하고, 심각도와 '
        '대응 우선순위를 함께 제시합니다.</p>'
        '<ul class="bul">'
        '<li>인가된 범위 내에서 서비스에 영향을 주지 않는 비파괴 방식으로 점검을 수행합니다.</li>'
        '<li>실증된 항목만 <b>‘확인’</b>으로 보고하고, 미확인 항목은 참고로 구분합니다.</li>'
        '<li>담당자가 바로 조치할 수 있도록 재현 방법과 권고를 함께 제공합니다.</li>'
        '</ul></section>')

    # ── 2. 점검 대상 ──
    _ports = set()
    for hr_ in (scan.get("results") or []):
        for p in (hr_.get("open_ports") or []):
            _ports.add(p)
        for svc in (hr_.get("services") or []):
            if svc.get("port"):
                _ports.add(svc.get("port"))
    ports_txt = ", ".join(str(p) for p in sorted(_ports, key=lambda x: (str(x)))) or "80, 443"
    scope_txt = analysis.get("scope_note") or "대상 도메인 및 동일 출처(same-origin) 하위 경로"
    auth_txt = "인증 세션 기반 점검" if analysis.get("authenticated") else "비인증(공개 표면) 점검"
    P.append(
        '<section class="page"><div class="sec-head"><span class="sec-no">02</span>'
        '<span class="sec-title">점검 대상</span><span class="sec-en">Target &amp; Scope</span></div>'
        '<table class="kv"><tbody>'
        f'<tr><th>대상 URL</th><td class="mono">{_e(domain)}</td></tr>'
        f'<tr><th>점검 범위</th><td>{_e(scope_txt)}</td></tr>'
        f'<tr><th>확인 포트</th><td class="mono">{_e(ports_txt)}</td></tr>'
        f'<tr><th>점검 일자</th><td class="tnum">{_e(created)}</td></tr>'
        f'<tr><th>점검 방식</th><td>{_e(auth_txt)} · 자동 점검 + 수동 실증</td></tr>'
        f'<tr><th>확인 취약점</th><td><b>{total}건</b>'
        + (f' (치명적 {crit} · 높음 {high} · 보통 {med} · 낮음 {low})' if total else '')
        + '</td></tr></tbody></table></section>')

    # ── 3. 점검 항목 및 위험도 ──
    _cnt = {}
    for _n, _c in _SCAN_COVERAGE:
        _cnt[_c] = _cnt.get(_c, 0) + 1
    scan_rows = "".join(
        f'<tr><td class="num">{i+1:02d}</td><td>{_e(name)}</td>'
        f'<td class="tcell"><span class="chip {cls}">{_TIER_LABEL[cls]}</span></td></tr>'
        for i, (name, cls) in enumerate(_SCAN_COVERAGE))
    P.append(
        '<section class="page"><div class="sec-head"><span class="sec-no">03</span>'
        '<span class="sec-title">점검 항목 및 위험도</span><span class="sec-en">Scan Coverage &amp; Severity</span></div>'
        f'<p class="lead">본 점검에서 탐지하는 취약점 항목과 위험도 기준입니다. 총 <b>{len(_SCAN_COVERAGE)}종</b>'
        f' — Critical {_cnt.get("crit",0)} · High {_cnt.get("high",0)} · Medium {_cnt.get("med",0)}'
        f' · Low {_cnt.get("low",0)} · Info {_cnt.get("info",0)}.</p>'
        '<table class="ov scan-tbl"><thead><tr><th style="width:36px">#</th>'
        '<th>점검 항목 (취약점)</th><th style="width:110px">위험도</th></tr></thead>'
        f'<tbody>{scan_rows}</tbody></table></section>')

    # ── 4. 총평 ──
    donut = _donut_bg(crit, high, med, low)
    pr_rows = "".join(
        f'<div class="pill"><span class="rank">{i+1}</span>'
        f'<span class="chip {_sev(f)[1]}">{_sev(f)[0]}</span>'
        f'<span>{_e(f.get("title") or "")}</span></div>' for i, f in enumerate(priority))
    P.append(
        '<section class="page brk"><div class="sec-head"><span class="sec-no">04</span>'
        '<span class="sec-title">총평</span><span class="sec-en">Executive Summary</span></div>'
        '<div class="exec"><div>'
        f'<div class="donut" style="background:{donut}"><div class="donut-c">'
        f'<div class="n tnum">{total}</div><div class="l">확인 취약점</div></div></div>'
        '<div class="legend">'
        f'<div class="r"><span class="dot" style="background:var(--sev-crit)"></span>치명적 {crit}</div>'
        f'<div class="r"><span class="dot" style="background:var(--sev-high)"></span>높음 {high}</div>'
        f'<div class="r"><span class="dot" style="background:var(--sev-med)"></span>보통 {med}</div>'
        f'<div class="r"><span class="dot" style="background:var(--sev-low)"></span>낮음 {low}</div>'
        '</div></div>'
        f'<div><p>본 점검은 <b>{_e(domain)}</b> 웹 애플리케이션을 대상으로 수행되었으며, 총 '
        f'<b>{total}건</b>의 취약점이 실증(재현) 확인되었습니다. 심각도가 높은 항목은 세션 탈취·계정 '
        '무단 접근 등으로 직결되므로 우선 조치가 필요합니다.</p>'
        f'<div class="eyebrow" style="margin-top:16px">먼저 조치할 것</div>'
        f'<div class="priority">{pr_rows or "<div class=\'muted\' style=\'font-size:13px\'>확인된 취약점이 없습니다.</div>"}</div>'
        '</div></div></section>')

    # ── 발견 개요 ──
    rows = "".join(
        f'<tr><td class="num">{i+1:02d}</td>'
        f'<td><span class="chip {_sev(f)[1]}">{_sev(f)[0]}</span></td>'
        f'<td>{_e(f.get("title") or "")}</td>'
        f'<td class="cwe">{_e(f.get("cwe") or "-")}</td>'
        f'<td><span class="status-ok">확인됨</span></td></tr>' for i, f in enumerate(findings))
    P.append(
        '<section class="page"><div class="sec-head"><span class="sec-no">05</span>'
        '<span class="sec-title">발견된 취약점</span><span class="sec-en">Findings Overview</span></div>'
        '<table class="ov"><thead><tr><th style="width:36px">#</th><th style="width:86px">심각도</th>'
        '<th>취약점</th><th style="width:100px">CWE</th><th style="width:84px">상태</th></tr></thead>'
        f'<tbody>{rows or "<tr><td colspan=5 class=muted style=padding:16px>확인된 취약점이 없습니다.</td></tr>"}</tbody></table></section>')

    # ── 취약점 상세 ──
    cards = "".join(_finding_card(f, i + 1) for i, f in enumerate(findings))
    P.append(
        '<section class="page brk"><div class="sec-head"><span class="sec-no">06</span>'
        '<span class="sec-title">취약점 상세</span><span class="sec-en">Findings Detail</span></div>'
        '<p class="muted" style="font-size:12.5px;margin:-6px 0 16px">각 항목의 상세 재현·전체 로그·단계별 '
        '조치는 별도 상세 보고서(Word)를 참조하십시오.</p>'
        f'<div class="cards">{cards}</div></section>')

    # ── 7. 대응방안 ──
    recs = []
    for f in ordered:
        r = _first_sentence(f.get("recommendation") or "", 140)
        if r and r not in recs:
            recs.append((_sev(f), _e(f.get("title") or ""), r))
    rec_html = "".join(
        f'<div class="item"><span class="chip {sev[1]}">{sev[0]}</span>'
        f'<div><div class="rt">{title}</div><div class="rd">{_e(r)}</div></div></div>'
        for (sev, title, r) in recs[:10])
    P.append('<section class="page"><div class="sec-head"><span class="sec-no">07</span>'
             '<span class="sec-title">대응방안</span><span class="sec-en">Recommendations</span></div>'
             '<p class="muted" style="font-size:12.5px;margin:-6px 0 16px">심각도 순으로 정리한 핵심 조치입니다. '
             '항목별 상세 조치는 상세 보고서(Word)를 참조하십시오.</p>'
             + (f'<div class="rec">{rec_html}</div>' if rec_html
                else '<p class="muted" style="font-size:13px">개별 취약점의 권고 조치를 참조하십시오.</p>')
             + '</section>')

    # ── 8. 부록 (탐지 커버리지 + Report QA) ──
    qa = analysis.get("report_qa") or {}
    P.append('<section class="page brk"><div class="sec-head"><span class="sec-no">08</span>'
             '<span class="sec-title">부록</span><span class="sec-en">Developer Appendix</span></div>')
    # (a) 탐지 커버리지
    P.append('<h3 class="sub-h">탐지 커버리지 · Detection Coverage</h3>')
    if cov_matrix:
        c_conf = sum(1 for r in cov_matrix if r.get("status") == "confirmed")
        c_pos = sum(1 for r in cov_matrix if r.get("status") == "possible")
        c_clean = sum(1 for r in cov_matrix if r.get("status") == "tested_clean")
        c_nr = sum(1 for r in cov_matrix if r.get("status") in ("not_reached", "blocked"))
        cells = "".join(
            f'<div class="cov-cell {_COV_STATUS.get(r.get("status"), ("na",""))[0]}">'
            f'<span class="s"></span><span class="cov-name">{_e(r.get("technique") or "")}</span></div>'
            for r in cov_matrix)
        clean_reason = next((r.get("reason") for r in cov_matrix
                             if r.get("status") == "tested_clean" and r.get("reason")), "검사 수행 · 취약점 미발견")
        P.append(
            f'<p class="muted" style="font-size:12.5px;margin-bottom:12px">총 {len(cov_matrix)}개 기법 수행. '
            f"'미도달'은 해당 입력 표면이 대상에 없어 도달하지 못한 항목으로 정직하게 구분합니다. "
            f'({_e(clean_reason)})</p>'
            '<div class="cov-summary">'
            f'<div class="box"><div class="n" style="color:var(--sev-crit)">{c_conf}</div><div class="l">취약 확인</div></div>'
            f'<div class="box"><div class="n" style="color:var(--sev-med)">{c_pos}</div><div class="l">가능·검토</div></div>'
            f'<div class="box"><div class="n" style="color:var(--ok)">{c_clean}</div><div class="l">검사·안전</div></div>'
            f'<div class="box"><div class="n" style="color:var(--ink-3)">{c_nr}</div><div class="l">미도달</div></div></div>'
            f'<div class="cov-grid">{cells}</div>')
    else:
        P.append('<p class="muted" style="font-size:12.5px">탐지 커버리지 데이터가 없습니다.</p>')
    # (b) Report QA (외부 도구 상태 표는 노출하지 않음)
    P.append('<h3 class="sub-h" style="margin-top:22px">리포트 무결성 · Report QA</h3>'
             '<div class="appx">리포트 무결성 점검 — '
             + ((f'검토 항목 {len(qa.get("checks", []))}건, '
                 f'지적 {int(qa.get("issues_found", 0)) + len(qa.get("html_pdf_issues", []))}건.')
                if qa else '이상 없음.')
             + '</div>'
             f'<p class="foot">{_e(org)} · {_e(report_no)} · 본 문서는 인가된 점검 범위 내에서 수행되었습니다.</p>'
             '</section>')

    P.append('</div></body></html>')
    return "".join(P)
