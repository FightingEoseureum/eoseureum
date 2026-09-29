"""P6: 파일 업로드 → 코드 실행 '차등' 실증.

핵심 회귀 방지: 정적 서빙(text/plain, 원문 그대로) 은 실행으로 오판하지 않는다(오탐 배제).
실행(6*7=42, 원문 미노출) 만 code_execution=CRITICAL 로 확정.
"""
import asyncio

import aiohttp
from aiohttp import web

import active_probing as ap
import rule_engine as re_mod


def _run(c):
    return asyncio.run(c)


async def _serve(upload_handler, file_handler):
    app = web.Application()
    app.router.add_route("*", "/upload", upload_handler)
    app.router.add_get("/uploads/{name}", file_handler)
    runner = web.AppRunner(app); await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}"


def _form_point(base):
    # 업로드 폼 GET 이 multipart+file input 을 돌려주도록 별도 핸들러가 필요하지만,
    # _probe_file_upload 는 pt['url'] 을 GET 해 폼 본문을 검사한다. 여기선 upload 엔드포인트를
    # 폼 페이지 겸용으로 쓰기 위해 GET 에도 폼 HTML 을 준다(아래 핸들러에서 처리).
    return [{"method": "POST", "url": f"{base}/upload", "params": {"file": ""},
             "source": "form"}]


_FORM_HTML = ('<form method="post" enctype="multipart/form-data">'
              '<input type="file" name="file"></form>')


def test_executes_uploaded_script_confirmed():
    store = {}

    async def t():
        async def upload(req):
            if req.method == "GET":
                return web.Response(text=_FORM_HTML, content_type="text/html")
            reader = await req.multipart()
            name = None
            async for part in reader:
                if part.name == "file":
                    name = part.filename
                    store[name] = await part.read()
            return web.Response(text=f"saved to /uploads/{name}", content_type="text/html")

        async def getfile(req):
            name = req.match_info["name"]
            raw = store.get(name, b"")
            # 서버가 코드를 '실행': 문구+산술식 → 계산된 문구 출력으로 치환(PHP/JSP/ASP)
            import re as _re
            _ph = "It_Was_Executed_By_Eoseureum"
            txt = raw.decode("utf-8", "ignore")
            txt = _re.sub(r'<\?php echo "' + _ph + r'="\.\(6\*7\);[^?]*\?>', _ph + "=42", txt)
            txt = _re.sub(r'<%=\s*"' + _ph + r'="\+\(6\*7\)\s*%>', _ph + "=42", txt)
            txt = _re.sub(r'<%="' + _ph + r'="&\(6\*7\)%>', _ph + "=42", txt)
            return web.Response(text=txt, content_type="text/html")

        runner, base = await _serve(upload, getfile)
        # 폼 페이지 GET 을 위해 upload 를 GET 도 허용하도록 라우트 추가
        try:
            async with aiohttp.ClientSession() as s:
                # _probe_file_upload 는 pt['url'] 을 GET 하므로 upload 가 폼 HTML 을 주도록 위에서 처리
                return await ap._probe_file_upload(s, base, _form_point(base), scan_id="u")
        finally:
            await runner.cleanup()

    r = _run(t())
    assert r and r.get("confirmed") is True
    assert r.get("code_execution") is True
    assert r.get("uploaded_url")


def test_static_serving_not_confirmed():
    """서버가 업로드 파일을 실행하지 않고 원문 그대로 서빙 → 실행 오판 금지."""
    store = {}

    async def t():
        async def upload(req):
            if req.method == "GET":
                return web.Response(text=_FORM_HTML, content_type="text/html")
            reader = await req.multipart()
            name = None
            async for part in reader:
                if part.name == "file":
                    name = part.filename
                    store[name] = await part.read()
            return web.Response(text=f"saved to /uploads/{name}", content_type="text/html")

        async def getfile(req):
            name = req.match_info["name"]
            # 실행 없이 원문 그대로(정적 서빙)
            return web.Response(body=store.get(name, b""), content_type="text/plain")

        runner, base = await _serve(upload, getfile)
        try:
            async with aiohttp.ClientSession() as s:
                return await ap._probe_file_upload(s, base, _form_point(base), scan_id="u")
        finally:
            await runner.cleanup()

    r = _run(t())
    # 실행 확증이 아니어야 한다(code_execution 아님). 무제한 폼 폴백이면 confirmed=False.
    assert not (r and r.get("code_execution"))


def test_attempts_differential_marker():
    """페이로드는 실행결과(42)≠원문(<?php) 이 되도록 구성 — 원문에 42 가 미리 있으면 안 됨."""
    atts = ap._upload_exec_attempts("EOSUPZ", "eosupz", proof=True)
    assert atts
    for a in atts:
        src = a["content"].decode()
        assert a["executed"] == "EOSUPZIt_Was_Executed_By_Eoseureum=42EOSUPZ"
        assert "=42" not in src.replace("6*7", "")  # 원문에 실행결과(=42) 가 미리 있지 않음(6*7 계산 필요)
        assert a["raw"] in src


def test_rule_engine_upgrades_upload_to_critical():
    probes = {"file_upload": {
        "url": "http://t/upload", "uploaded_url": "http://t/uploads/x.php",
        "engine": "PHP", "confirmed": True, "code_execution": True,
        "evidence": "업로드 RCE 실증", "cleanup_marker": "x.php",
    }}
    out = re_mod._build_active_probe_findings("t", 80, "http", probes, set())
    assert len(out) == 1
    f = out[0]
    assert f["severity"] == "CRITICAL"
    assert f["cvss_estimate"] == "9.8"
    assert "RCE" in f["title"]


def test_rule_engine_upload_without_execution_not_confirmed():
    """티어2 오탐 수정: 실행(code_execution) 미확인 업로드는 CONFIRMED 로 올리지 않는다.
    (실 프로브는 uploaded_url 을 code_execution 확정 시에만 부여하므로 실사용 손실 없음)"""
    probes = {"file_upload": {
        "url": "http://t/upload", "uploaded_url": "http://t/uploads/x.php",
        "confirmed": True, "evidence": "업로드 확인",  # code_execution 없음
    }}
    out = re_mod._build_active_probe_findings("t", 80, "http", probes, set())
    assert out == []   # 실행 실증 없으면 확정 소견 미생성(오탐 방지)


def test_rule_engine_upload_with_execution_is_critical():
    """실행(code_execution) 확정 업로드는 CRITICAL 로 유지(정상 경로)."""
    probes = {"file_upload": {
        "url": "http://t/upload", "uploaded_url": "http://t/uploads/x.php",
        "engine": "PHP", "confirmed": True, "code_execution": True,
        "evidence": "업로드 RCE 실증",
    }}
    out = re_mod._build_active_probe_findings("t", 80, "http", probes, set())
    assert len(out) == 1 and out[0]["severity"] == "CRITICAL"
