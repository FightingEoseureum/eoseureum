"""
poc_generator.py — 확정 취약점(finding)마다 '독립 실행 가능한 Python PoC 스크립트'를 생성한다.

벤치마크 리포트의 산출물(재현 스크립트)에 대응. 각 PoC 는:
  - 표준 requests 만 사용(외부 의존 최소), 응답 분석 원시함수를 인라인(sandbox 계약 재현).
  - baseline(정상) → 재현 요청 → verdict(반사/증거 기반) 순으로 비파괴 관찰.
  - 요청 간 최소 지연(rate limit), 테스트 값 사용. 파괴적 동작 없음.

finding dict(활성 프로브/rule_engine 스키마)에서 method/url/param/payload/evidence 를 읽어 조립한다.
"""
from __future__ import annotations

import json
import re

_PRIMITIVES = '''\
import re, time, sys
try:
    import requests
except ImportError:
    print("pip install requests 필요"); sys.exit(1)

def pause(s=0.5):
    time.sleep(s)

# sandbox 응답 분석 원시함수(인라인)
_ERR = re.compile(r"(error|invalid|exception|forbidden|unauthorized|denied|실패|오류|권한\\s*없)", re.I)
def find_errors(doc):
    if not isinstance(doc, str): return []
    out, seen = [], set()
    for m in _ERR.finditer(doc):
        s = re.sub(r"\\s+"," ", doc[max(0,m.start()-60):m.end()+60]).strip()
        if s not in seen: seen.add(s); out.append(s)
        if len(out) >= 10: break
    return out
def find_reflected(doc, pat, ctx=60):
    if not isinstance(doc, str) or not pat: return []
    return [doc[max(0,m.start()-ctx):m.end()+ctx] for m in re.finditer(re.escape(pat), doc)][:10]
'''


def _py(v) -> str:
    """파이썬 리터럴로 안전 직렬화."""
    return json.dumps(v, ensure_ascii=False)


# 클래스별 '기대 신호'(재현 후 무엇을 보면 취약인지) — 한 줄.
_POC_SIGNALS = {
    "sqli": "응답에 DB 에러/추가 데이터 노출(정상 요청과 차이)",
    "cmdi": "응답에 명령 출력(고정 마커 EOSEUREUM_RCE_*)이 반사",
    "lfi": "응답에 파일 내용(/etc/passwd 등) 노출",
    "open_redirect": "3xx 응답 Location 이 외부 도메인으로 이동",
    "ssti": "수식이 평가된 결과(예: 49)가 응답에 출력",
    "xxe": "외부 엔티티로 파일 내용/콜백 노출",
    "ssrf": "스캐너 콜백 도달 또는 내부 응답 반영",
    "crlf": "응답 헤더에 주입한 개행/헤더 반영",
    "cors": "Access-Control-Allow-Origin 이 요청 Origin 을 그대로 반사",
    "nosql": "인증 우회 또는 정상 대비 응답 차이",
    "csrf": "토큰 없이 상태 변경 요청이 수락됨",
    "jsonp": "응답이 콜백 함수로 감싸져 반환(XSSI 가능)",
    "open_redirect_token": "토큰/URL 이 외부로 전달됨",
}


def _detect_class(finding: dict) -> str:
    """finding 의 type/title/category/cwe/payload 로 취약점 클래스를 추정(type 이 없어도 동작)."""
    hay = " ".join(str(finding.get(k) or "") for k in
                   ("type", "title", "category", "name", "cwe")).lower()
    pl = str(finding.get("payload") or "").lower()

    def has(*ks):
        return any(k in hay for k in ks)

    if has("xss", "cross-site script", "cross site script") or \
       any(s in pl for s in ("<script", "onerror=", "onload=", "<svg", "javascript:", "alert(")):
        return "xss"
    if has("sql injection", "sqli", "cwe-89") or ("sql" in hay and "inj" in hay) or \
       any(s in pl for s in ("union select", "' or ", "1=1", "-- -", "sleep(", "' and ")):
        return "sqli"
    # 파일 업로드(웹쉘/RCE)는 title 에 'rce' 가 있어 cmdi 로 오분류되므로 먼저 판정한다.
    if has("파일 업로드", "file upload", "웹쉘", "webshell", "cwe-434") or \
       (isinstance(finding.get("probe_detail"), dict)
            and finding["probe_detail"].get("uploaded_url")):
        return "file_upload"
    if has("command inj", "cmd inj", "os command", "명령 실행", "rce", "cwe-78", "cwe-77"):
        return "cmdi"
    if has("lfi", "local file", "path travers", "directory travers", "cwe-22") or \
       "../" in pl or "..%2f" in pl:
        return "lfi"
    if has("open redirect", "cwe-601"):
        return "open_redirect"
    if has("ssti", "template inject", "cwe-1336"):
        return "ssti"
    if has("xxe", "xml external", "cwe-611"):
        return "xxe"
    if has("ssrf", "server-side request", "cwe-918"):
        return "ssrf"
    if has("crlf", "response split", "cwe-113"):
        return "crlf"
    if has("cors"):
        return "cors"
    if has("nosql"):
        return "nosql"
    if has("csrf", "cross-site request", "cwe-352"):
        return "csrf"
    if has("jsonp"):
        return "jsonp"
    return (finding.get("type") or "").lower()


def _poc_name(finding: dict) -> str:
    t = (finding.get("title") or finding.get("type") or "취약점").strip()
    return t if len(t) <= 40 else (t[:40] + "…")


def generate_poc(finding: dict) -> str:
    """finding → '간결한' 재현(PoC) 스니펫(3~4줄). 클래스에 맞춰 최소한만.
    - XSS 류: 삽입 스크립트/페이로드만(그것만 있어도 재현 충분).
    - 그 외: curl 한 줄 + 기대 신호 한 줄.
    (과거의 장문 독립실행 스크립트는 폐지 — 이해 위주로 짧게)."""
    if not isinstance(finding, dict):
        return ""
    url = (finding.get("evidence_url") or finding.get("url")
           or (finding.get("affected_endpoints") or [""])[0] or "")
    if not url:
        return ""
    cls = _detect_class(finding)
    # 정확한 값은 probe_detail 에 있는 경우가 많다(최상위엔 없을 수 있음) → 폴백으로 읽는다.
    pd = finding.get("probe_detail") if isinstance(finding.get("probe_detail"), dict) else {}
    method = (finding.get("method") or pd.get("method") or "GET").upper()
    param = finding.get("param") or pd.get("param") or ""
    payload = finding.get("payload") if finding.get("payload") is not None else pd.get("payload")
    name = _poc_name(finding)
    where = f"파라미터 '{param}'" if param else "입력값"

    # ── 파일 업로드 → RCE: '무엇을 업로드해 무엇이 실행됐는지'를 구체적으로 재현 ──
    if cls == "file_upload":
        up = pd.get("uploaded_url") or ""
        form = pd.get("url") or url
        if up:
            return (f"# {name} — 무해 PHP(문구+산술 출력)를 이미지로 위장해 업로드 후 되받아 실행\n"
                    f"# proof.php 내용: <?php echo \"It_Was_Executed_By_Eoseureum=\".(6*7); ?>\n"
                    f"# 1) 업로드(인증 세션 필요):\n"
                    f"curl -s -b \"<로그인 세션 쿠키>\" "
                    f"-F \"uploaded=@proof.php;type=image/jpeg\" -F \"Upload=Upload\" '{form}'\n"
                    f"# 2) 업로드된 파일 접근 → 서버가 코드를 '실행'해 문구 출력(=코드 실행 확증):\n"
                    f"curl -s '{up}'\n"
                    f"# 기대 출력: It_Was_Executed_By_Eoseureum=42   (=42 는 6×7 서버 계산값. 원문 \"(6*7)\" 이 보이면 정적 서빙 → 취약 아님)")
        return (f"# {name} — 위험 확장자 업로드 폼\n"
                f"curl -s '{form}'\n"
                f"# 기대: 업로드한 스크립트가 서버에서 실행되어 계산 결과 반환")

    # ── XSS 류: 삽입 스크립트/페이로드만 ──
    if cls == "xss":
        pl = payload or "<script>alert('EOSEUREUM_XSS_PROOF')</script>"
        # 저장형(제출 URL·확인 URL 이 있는 경우): 어디에 저장되어 어디서 실행되는지 구체적으로.
        submit_url = pd.get("submit_url") or (url if method == "POST" else "")
        verify_url = pd.get("verify_url") or ""
        if pd.get("type") == "stored" or verify_url:
            _p = param or "입력 파라미터"
            lines = [f"# {name} — 저장형: 폼에 스크립트 저장 후 재방문 시 실행"]
            lines.append(f"# 1) 저장(인증 세션 필요): {submit_url or url} 의 '{_p}' 에 아래 페이로드 제출")
            lines.append(f"페이로드: {pl}")
            if verify_url:
                lines.append(f"# 2) 저장 페이지 재방문 → 페이로드가 그대로 반영되면 방문자 브라우저에서 실행:")
                lines.append(f"curl -s '{verify_url}' | grep -F \"{str(pl)[:40]}\"")
            lines.append(f"# (그 외 폼의 필수 필드·제출 버튼 값도 함께 전송해야 저장됩니다)")
            return "\n".join(lines)
        if method != "POST" and param:
            sep = "&" if "?" in url else "?"
            return (f"# {name} — {where}에 스크립트 주입\n"
                    f"{url}{sep}{param}={pl}\n"
                    f"# → 응답에 그대로 반사/저장되면 스크립트 실행(취약)")
        return (f"# {name} — {where}에 스크립트 주입 ({method} {url})\n"
                f"페이로드: {pl}\n"
                f"# → 응답에 그대로 반사/저장되면 실행(취약)")

    # ── 그 외: curl 한 줄 + 기대 신호 ──
    pl = payload if payload is not None else "<PAYLOAD>"
    sig = _POC_SIGNALS.get(cls, "정상 요청 대비 응답 차이·오류·반사 신호 확인")
    if method == "POST":
        req = f"curl -s -X POST '{url}' -d '{(param or 'param')}={pl}'"
    elif param:
        sep = "&" if "?" in url else "?"
        req = f"curl -s '{url}{sep}{param}={pl}'"
    else:
        req = f"curl -s '{url}'"
    return (f"# {name} — {('파라미터 ' + param) if param else '대상'}에 주입 후 확인\n"
            f"{req}\n"
            f"# 기대: {sig}")


# ── AI 생성 PoC 안전 검증기 ────────────────────────────────────────────────────
# AI(qwen)가 만든 PoC 는 '이미 확정된' finding 재현용이라 위협은 작지만, 파괴적 코드가 섞이면
# 안 되므로 정적 거부 패턴으로 걸러낸다. 하나라도 걸리면 폐기(결정적 PoC 만 유지). 스캐너는
# 이 코드를 절대 자동 실행하지 않는다(사용자 수동 검토·실행 전제, 결정적 PoC 와 동일 취급).
_POC_DESTRUCTIVE_RE = re.compile(
    r"(rm\s+-rf|rmdir|shutil\.rmtree|os\.remove|os\.unlink|os\.rmdir|"
    r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b|\bTRUNCATE\b|\bDELETE\s+FROM\b|\bUPDATE\s+\w+\s+SET\b|"
    r"\bshutdown\b|\breboot\b|\bmkfs\b|\bdd\s+if=|>\s*/dev/|:\(\)\s*\{|fork\s*bomb|"
    r"chmod\s+-R|chown\s+-R|\bformat\b|\beval\(|\bexec\(|__import__\(|"
    r"subprocess|os\.system|os\.popen|pty\.|socket\.socket|open\([^)]*['\"]w)",
    re.IGNORECASE)


def _is_safe_poc(code: str) -> bool:
    """AI PoC 정적 안전성: 파괴적/셸/파일쓰기/코드실행 패턴이 없어야 True. requests 기반만 허용."""
    if not code or len(code) > 20000:
        return False
    if _POC_DESTRUCTIVE_RE.search(code):
        return False
    # 재현은 requests 기반이어야 한다(임의 시스템 조작 금지).
    if "requests" not in code:
        return False
    return True


def generate_ai_poc(finding: dict, ai_fn) -> str | None:
    """확정 finding 에 대해 AI 가 '비파괴 requests 기반' PoC 를 작성. 안전검증 통과분만 반환.

    ai_fn: 동기 콜러블(prompt)->str (ai_provider.make_sync_ai_fn, 워커 스레드에서 호출).
    실패/미가용/안전검증 실패 시 None → 호출부는 결정적 PoC 만 유지."""
    if ai_fn is None or not isinstance(finding, dict):
        return None
    title = finding.get("title") or finding.get("type") or "Vulnerability"
    url = (finding.get("evidence_url") or finding.get("url")
           or (finding.get("affected_endpoints") or [""])[0] or "")
    method = (finding.get("method") or "GET").upper()
    param = finding.get("param") or ""
    payload = finding.get("payload")
    evidence = finding.get("evidence") or finding.get("evidence_detail") or ""
    prompt = (
        "당신은 인가된 모의해킹의 PoC 작성자입니다. 아래는 스캐너가 '이미 확정한' 취약점입니다. "
        "이 취약점을 '재현·관찰'하는 독립 실행 Python 스크립트를 작성하세요.\n"
        "제약(반드시 준수):\n"
        "1) 표준 requests 라이브러리만 사용. subprocess/os.system/파일쓰기/eval/exec/소켓 금지.\n"
        "2) 파괴적 동작 절대 금지(데이터 삭제/변경, DROP/DELETE/UPDATE, 계정변경, 대량요청 금지).\n"
        "3) baseline(정상) → 재현요청 → 관찰(반사/상태코드/헤더) 순의 비파괴 관찰만.\n"
        "4) 대상 URL 만 요청. 다른 호스트로 데이터 전송 금지.\n"
        "5) 코드만 출력(```python 블록 하나). 설명 산문 금지.\n\n"
        f"[취약점] {title}\nURL: {url}\nMETHOD: {method}\nPARAM: {param}\n"
        f"PAYLOAD: {payload}\n근거: {str(evidence)[:400]}\n")
    try:
        raw = ai_fn(prompt) or ""
    except Exception:
        return None
    # 코드블록 추출
    m = re.search(r"```(?:python)?\s*(.+?)```", raw, re.DOTALL)
    code = (m.group(1) if m else raw).strip()
    if not _is_safe_poc(code):
        return None
    header = (f"#!/usr/bin/env python3\n"
              f"# ⚠️ AI(qwen) 생성 PoC — 자동 실행 금지, 반드시 수동 검토 후 인가된 대상에만 실행.\n"
              f"# 실증의 근거는 결정적 PoC(f['poc'])와 리포트를 우선하세요.\n")
    return header + code


def attach_pocs(analysis: dict, max_pocs: int = 30, ai_fn=None) -> int:
    """analysis 의 확정 취약 finding 에 poc 스크립트를 부착한다. 부착 건수 반환.

    ai_fn 이 주어지면(동기 브리지) 각 확정 finding 에 'AI 생성 PoC'도 f["poc_ai"] 로 추가한다.
    결정적 PoC(f["poc"])는 항상 유지되며(불변), AI PoC 는 안전검증 통과분만·검토용으로만 붙는다."""
    n = 0
    for f in (analysis.get("findings") or []):
        if n >= max_pocs:
            break
        if not isinstance(f, dict) or f.get("judgment") != "취약":
            continue
        conf = (f.get("confidence") or "").upper()
        if not (conf.startswith("CONFIRMED") or f.get("probe_confirmed") is True):
            continue
        try:
            f["poc"] = generate_poc(f)
            n += 1
        except Exception:
            continue
        if ai_fn is not None:
            try:
                ai_code = generate_ai_poc(f, ai_fn)
                if ai_code:
                    f["poc_ai"] = ai_code
            except Exception:
                pass
    return n
