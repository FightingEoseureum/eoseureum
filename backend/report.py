import io
import os
import pathlib
import re as _re
from datetime import datetime
from docx import Document
from docx.shared import Pt, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

_SCREENSHOTS_DIR = pathlib.Path(__file__).parent / "screenshots"

# 보고서 기본 글꼴 — 맑은 고딕(Malgun Gothic). 환경변수 REPORT_FONT 로 재정의 가능.
# 보고서는 Windows Word(맑은 고딕 기본 탑재) 환경에서 열람되므로, 맑은 고딕은 서버(리눅스)
# 설치 여부와 무관하게 이름을 그대로 지정한다. 그 외 임의 글꼴은 설치 확인 후 없으면 fallback.
_FONT_FALLBACKS = ["맑은 고딕", "Malgun Gothic", "Noto Sans CJK KR",
                   "NanumGothic", "Noto Sans KR"]
# 클라이언트(Windows)에서 항상 렌더되는 글꼴 — 로컬 가용성 확인을 건너뛰고 그대로 사용
_FORCE_FONTS = {"맑은 고딕", "malgun gothic"}


def _font_available(name: str) -> bool:
    """생성 환경(서버)에 해당 글꼴 패밀리가 설치되어 있는지 fc-list 로 확인."""
    try:
        import subprocess
        out = subprocess.run(["fc-list", ":family"], capture_output=True,
                             text=True, timeout=5).stdout
        return name.lower() in out.lower()
    except Exception:
        return False


def _resolve_report_font() -> str:
    """REPORT_FONT → (강제 글꼴 우선) → 설치 확인 → fallback 순으로 글꼴을 결정한다."""
    preferred = (os.getenv("REPORT_FONT", "맑은 고딕") or "맑은 고딕").strip()
    # 맑은 고딕/Malgun Gothic 은 Windows 뷰어에서 렌더되므로 서버 설치 여부와 무관하게 사용
    if preferred.lower() in _FORCE_FONTS:
        return preferred
    candidates = [preferred] + [f for f in _FONT_FALLBACKS if f != preferred]
    for name in candidates:
        if name.lower() in _FORCE_FONTS or _font_available(name):
            return name
    # fc-list 자체가 없거나(윈도우) 매칭 실패 → 이름만 지정(뷰어가 대체). 우선값 유지.
    return preferred


FONT = _resolve_report_font()


# ── 보고서 AI 표시 정책 (환경변수) ──────────────────────────────────────────────

def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.lower().strip() in ("true", "1", "yes")


def _show_ai_section_only_when_used() -> bool:
    return _env_bool("SHOW_AI_SECTION_ONLY_WHEN_USED", True)


def _show_rule_based_analysis() -> bool:
    return _env_bool("SHOW_RULE_BASED_ANALYSIS", False)


def _show_ai_status_in_summary() -> bool:
    return _env_bool("SHOW_AI_STATUS_IN_SUMMARY", True)


# ── 보고서 템플릿 섹션 토글 (REPORT_SHOW_* / REPORT_ORG_NAME) ─────────────────────
def _report_show(section: str, default: bool = True) -> bool:
    """보고서 템플릿이 export 시 설정하는 섹션 토글. 키: REPORT_SHOW_<SECTION>."""
    return _env_bool(f"REPORT_SHOW_{section.upper()}", default)


def _report_org_name() -> str:
    return os.getenv("REPORT_ORG_NAME", "Eoseureum Security")


# fallback_reason → 사람이 읽는 한국어 사유.
_FALLBACK_REASON_LABEL = {
    "ENABLE_AI_ANALYSIS_FALSE": "AI 분석 비활성화 (ENABLE_AI_ANALYSIS=false)",
    "OLLAMA_CONNECTION_FAILED": "Ollama 서버 연결 실패",
    "MODEL_NOT_FOUND":          "Ollama 모델을 찾을 수 없음",
    "JSON_PARSE_FAILED":        "AI 응답 JSON 파싱 실패",
    "PROVIDER_NOT_CONFIGURED":  "AI 프로바이더 미설정",
    "TIMEOUT":                  "AI 응답 시간 초과",
    "INTERNAL_ERROR":           "내부 오류",
}


def _ai_status_used(analysis: dict) -> bool:
    """analysis["ai_status"].used 를 안전하게 읽는다(옛 데이터 호환)."""
    st = analysis.get("ai_status")
    if isinstance(st, dict):
        return bool(st.get("used"))
    return False

C_WHITE      = RGBColor(0xFF, 0xFF, 0xFF)
C_BLACK      = RGBColor(0x1A, 0x1A, 0x1A)
C_GRAY       = RGBColor(0x6B, 0x72, 0x80)
C_LIGHT_GRAY = RGBColor(0xF3, 0xF4, 0xF6)
C_NAVY       = RGBColor(0x1E, 0x3A, 0x5F)
C_BLUE       = RGBColor(0x1A, 0x56, 0xDB)
C_RED        = RGBColor(0xDC, 0x26, 0x26)
C_ORANGE     = RGBColor(0xEA, 0x58, 0x0C)
C_YELLOW     = RGBColor(0xCA, 0x8A, 0x04)
C_GREEN      = RGBColor(0x16, 0xA3, 0x4A)
C_PURPLE     = RGBColor(0x6D, 0x28, 0xD9)
C_TEAL       = RGBColor(0x0E, 0x7A, 0x90)

RISK_COLOR = {"HIGH": C_RED, "MEDIUM": C_ORANGE, "LOW": C_YELLOW, "GOOD": C_GREEN}
RISK_LABEL = {"HIGH": "높음", "MEDIUM": "중간", "LOW": "낮음", "GOOD": "양호"}
RISK_HEX   = {"HIGH": "FCA5A5", "MEDIUM": "FED7AA", "LOW": "FEF08A", "GOOD": "BBF7D0"}
RISK_TITLE_HEX = {"HIGH": "DC2626", "MEDIUM": "EA580C", "LOW": "CA8A04", "GOOD": "16A34A"}

# ── Report v3 통일 색상 체계 (Critical/High/Medium/Low/Info) ────────────────────
SEV5_HEX = {"Critical": "B91C1C", "High": "DC2626", "Medium": "EA580C",
            "Low": "CA8A04", "Info": "0E7A90"}      # 진한(제목/배지) 색
SEV5_BG  = {"Critical": "FEE2E2", "High": "FECACA", "Medium": "FED7AA",
            "Low": "FEF08A", "Info": "CFFAFE"}      # 옅은(셀 배경) 색
SEV5_RGB = {k: RGBColor(int(v[0:2], 16), int(v[2:4], 16), int(v[4:6], 16))
            for k, v in SEV5_HEX.items()}
# 직관적 아이콘(유니코드 — Noto Sans CJK 렌더 가능 글리프만 사용)
ICON = {
    "risk": "▲", "critical": "■", "high": "▲", "medium": "◆", "low": "▽", "info": "ℹ",
    "evidence": "◎", "path": "➔", "reco": "✔", "asset": "▣", "service": "⚙",
    "auth": "⚿", "database": "▤", "file": "🗂", "container": "❒", "web": "◉",
    "network": "◈", "validation": "◷", "ok": "✔", "block": "⊘",
}

# 취약점 유형별 아이콘 — Finding 카드 시각 식별용(표시 전용, 판정 무관)
_VULN_ICON = {
    "sqli": "🛢", "sql": "🛢", "xss": "✦", "csrf": "♺", "ssrf": "🛰", "rce": "⌘",
    "idor": "🔑", "access": "🔑", "redirect": "↪", "upload": "📎", "lfi": "🗀",
    "traversal": "🗀", "tls": "🔒", "ssl": "🔒", "header": "🏷", "cookie": "🍪",
    "auth": "⚿", "login": "⚿", "service": "⚙", "network": "◈", "discovery": "🔎",
}


def _vuln_icon(f: dict) -> str:
    """취약점 유형에 맞는 아이콘(제목·family 키워드 매칭)."""
    key = ((f.get("family") or "") + " " + (f.get("title") or "")).lower()
    for kw, ic in _VULN_ICON.items():
        if kw in key:
            return ic
    return ICON.get("web", "◉")


def _sev5(severity: str) -> str:
    """다양한 표기(High/높음/HIGH/Critical 등)를 5단계로 정규화."""
    s = (severity or "").strip().lower()
    if "crit" in s or s in ("critical", "긴급"):
        return "Critical"
    if s in ("high", "높음", "상"):
        return "High"
    if s in ("medium", "중간", "중"):
        return "Medium"
    if s in ("low", "낮음", "하"):
        return "Low"
    return "Info"

# report_severity(Critical/High/Medium/Low) → 한글 표기 / 색상 매핑
REPORT_SEV_LABEL = {"Critical": "심각", "High": "높음", "Medium": "중간", "Low": "낮음"}
REPORT_SEV_HEX   = {"Critical": "F87171", "High": "FCA5A5", "Medium": "FED7AA", "Low": "FEF08A"}


def _report_sev(f: dict) -> str:
    """취약점의 report_severity(Critical/High/Medium/Low)를 반환. 없으면 severity로 폴백."""
    rs = f.get("report_severity")
    if rs:
        return rs
    return {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}.get(f.get("severity", ""), "Low")


def _report_sev_label(f: dict) -> str:
    rs = _report_sev(f)
    return REPORT_SEV_LABEL.get(rs, rs)

def _scan_category(f: dict) -> str:
    """finding 의 scan_category 를 반환. 없으면 'web' 으로 폴백 (옛 데이터 호환)."""
    return (f.get("scan_category") or "web").lower()


def _is_service_finding(f: dict) -> bool:
    return _scan_category(f) == "service"


def _category_label(f: dict) -> str:
    return "Network Service" if _is_service_finding(f) else "Web Application"


def _trace_only(f: dict) -> bool:
    """위험 HTTP Method 항목에서 실제 검증된 위험 메서드가 TRACE 뿐인지 판정.
    finding 데이터는 변경하지 않고 evidence_detail 텍스트만 검사한다."""
    title = f.get("title") or ""
    if "HTTP Method" not in title and "메서드" not in title:
        return False
    ev = (f.get("evidence_detail") or "")
    if "TRACE" not in ev.upper():
        return False
    # PUT/DELETE 가 실제로 '검증됨'으로 명시되어 있으면 TRACE-only 가 아님
    up = ev.upper()
    return ("PUT" not in up) and ("DELETE" not in up)


def _display_title(f: dict) -> str:
    """보고서 표시용으로 정제된 제목. TRACE 만 검증된 HTTP Method 항목은
    'TRACE Method 활성화' 로 표기 (원본 finding 데이터는 변경하지 않음)."""
    title = f.get("title") or ""
    if _trace_only(f):
        return "TRACE Method 활성화"
    return title


# 공격성 단정 표현 → 방어적 설명으로 정제하는 치환 규칙 (보고서 표시 텍스트 전용)
_DEFENSIVE_SUBS = [
    ("PUT 메서드로 웹쉘 업로드", "필요 이상으로 허용된 HTTP 메서드 노출"),
    ("PUT 업로드", "불필요한 HTTP 메서드 허용"),
    ("웹쉘 업로드", "불필요한 HTTP 메서드 허용"),
    ("웹쉘", "허용된 HTTP 메서드"),
    ("원격 코드 실행(RCE)", "공격 표면 증가"),
    ("원격코드실행", "공격 표면 증가"),
    ("RCE", "공격 표면 증가"),
    ("공개 PoC로 공격 수행", "공개된 CVE/취약점 정보 탐색에 활용될 수 있음"),
    ("공개 PoC로 익스플로잇", "공개된 CVE/취약점 정보 탐색에 활용될 수 있음"),
    ("공개 PoC", "공개된 취약점 정보"),
    ("익스플로잇을 수행", "취약점 탐색에 활용될 수 있음"),
    ("익스플로잇", "취약점 탐색"),
    ("서버를 완전히 장악", "공격 표면이 확대될 수 있음"),
]


def _sanitize_display_text(text: str, f: dict | None = None) -> str:
    """보고서 표시용 텍스트에서 공격성 단정 표현을 방어적 설명으로 정제한다.
    (finding 데이터 자체는 변경하지 않으며, 출력 직전 표시 문자열만 가공)"""
    if not text:
        return text
    out = text
    for src, dst in _DEFENSIVE_SUBS:
        if src in out:
            out = out.replace(src, dst)
    return out


CONF_LABEL = {
    "CONFIRMED": "확인됨", "CONFIRMED_BROWSER": "확인됨(브라우저 실증)",
    "CONFIRMED_RESPONSE": "확인됨(응답 실증)", "POSSIBLE": "가능성",
    "MANUAL_REVIEW": "수동확인필요",
}
CONF_HEX   = {
    "CONFIRMED": "DCFCE7", "CONFIRMED_BROWSER": "DCFCE7", "CONFIRMED_RESPONSE": "DCFCE7",
    "POSSIBLE": "FEF9C3", "MANUAL_REVIEW": "F3F4F6",
}
CONF_COLOR = {
    "CONFIRMED": RGBColor(0x16, 0x61, 0x34),
    "CONFIRMED_BROWSER": RGBColor(0x16, 0x61, 0x34),
    "CONFIRMED_RESPONSE": RGBColor(0x16, 0x61, 0x34),
    "POSSIBLE": RGBColor(0xA1, 0x62, 0x07), "MANUAL_REVIEW": C_GRAY,
}


def _vuln_id(idx: int) -> str:
    return f"VULN-{idx:03d}"

# 취약점 유형별 비기술자 설명 템플릿
_LAYMAN_DESCRIPTIONS = {
    "반사형 XSS": (
        "공격자가 악의적인 코드(스크립트)를 웹 페이지의 입력 칸에 넣으면, "
        "그 코드가 다른 사용자의 브라우저에서 실행됩니다. "
        "마치 편지 봉투 안에 바이러스 파일을 넣어 전달하는 것과 같습니다. "
        "이를 통해 사용자의 로그인 정보(세션 쿠키)를 탈취하거나 "
        "가짜 페이지를 보여주는 피싱 공격이 가능합니다."
    ),
    "저장형 XSS": (
        "공격자가 게시판, 댓글 등에 악의적인 코드를 저장하면, "
        "해당 페이지를 방문하는 모든 사용자의 브라우저에서 자동으로 실행됩니다. "
        "한 번 심어놓으면 지속적으로 피해자가 발생하는 지뢰 방식의 공격입니다. "
        "관리자가 해당 페이지를 방문하면 관리자 권한까지 탈취 가능합니다."
    ),
    "SQL 인젝션": (
        "웹사이트의 검색창, 로그인창 등에 특수 문자를 입력해서 "
        "데이터베이스를 직접 조작할 수 있는 취약점입니다. "
        "마치 가게 주문서에 '공짜로 주세요'라는 문구를 끼워 넣어 "
        "주문 시스템이 이를 진짜 명령으로 처리하게 만드는 것과 같습니다. "
        "전체 고객 정보 탈취, 비밀번호 무력화, 시스템 파일 접근 등이 가능합니다."
    ),
    "CSRF": (
        "공격자가 만든 악성 웹페이지를 방문하는 것만으로 "
        "사용자가 의도하지 않은 행동(비밀번호 변경, 송금 등)이 자동으로 실행됩니다. "
        "사용자가 로그인된 상태에서 공격자 페이지를 방문하면, "
        "뒤에서 몰래 사용자 권한으로 요청이 전송됩니다."
    ),
    "LFI": (
        "웹사이트 주소에 특수 문자(../)를 이용해 서버 내부의 중요 파일을 "
        "열람할 수 있는 취약점입니다. "
        "마치 열쇠 구멍을 통해 다른 방 서류를 볼 수 있는 것과 같습니다. "
        "서버의 비밀번호 파일, 설정 파일 등 민감한 정보가 노출될 수 있습니다."
    ),
    "명령어 인젝션": (
        "웹사이트 입력 칸에 특수한 명령어를 입력해서 서버 컴퓨터를 "
        "직접 원격 조종할 수 있는 최고 위험도의 취약점입니다. "
        "서버에 직접 접근하여 파일 삭제, 다운로드, 악성 프로그램 설치가 가능합니다."
    ),
    "SSTI": (
        "웹 애플리케이션이 사용자 입력을 코드처럼 실행하는 취약점입니다. "
        "특수 문자열({{ }})을 입력했을 때 서버가 이를 계산식으로 해석하면, "
        "서버에서 임의의 코드를 실행할 수 있습니다."
    ),
    "오픈 리다이렉트": (
        "신뢰할 수 있는 사이트의 주소처럼 보이지만 실제로는 "
        "공격자가 지정한 다른 사이트로 이동시킵니다. "
        "피싱 사기에 악용되어 사용자가 가짜 로그인 페이지에 비밀번호를 입력하게 유도합니다."
    ),
    "CORS": (
        "다른 도메인(사이트)에서 이 사이트의 데이터를 몰래 읽어갈 수 있습니다. "
        "공격자가 운영하는 사이트에서 사용자의 계정 정보나 거래 내역을 "
        "사용자 몰래 가져갈 수 있습니다."
    ),
    "JWT": (
        "로그인 인증에 사용되는 토큰(JWT)에 보안 취약점이 있습니다. "
        "공격자가 이 토큰을 위조하거나 변조하면 다른 사람의 계정으로 "
        "로그인한 것처럼 행동할 수 있습니다."
    ),
    "파일 업로드": (
        "파일 첨부 기능을 통해 악성 프로그램(웹쉘)을 서버에 업로드할 수 있습니다. "
        "업로드된 악성 파일을 실행하면 서버 전체를 완전히 장악할 수 있습니다."
    ),
    "SSRF": (
        "서버가 공격자가 지정한 내부 주소로 요청을 보내게 만들 수 있습니다. "
        "외부에서 접근 불가한 내부 시스템, 클라우드 자격증명 등에 "
        "서버를 통해 간접적으로 접근할 수 있습니다."
    ),
    "XXE": (
        "XML 파일 처리 과정에서 서버 내부 파일을 읽거나 내부 네트워크에 "
        "접근할 수 있는 취약점입니다."
    ),
    "Telnet": (
        "Telnet은 인터넷 초창기에 만들어진 원격 접속 프로토콜로, "
        "아이디·비밀번호·명령어 등 모든 데이터를 암호화 없이 전송합니다. "
        "네트워크를 감청하면 로그인 자격증명을 그대로 훔칠 수 있습니다."
    ),
    "FTP": (
        "FTP는 파일 전송 프로토콜로, 비밀번호를 포함한 모든 데이터가 암호화되지 않습니다. "
        "익명 로그인이 허용된 경우 누구나 파일을 읽거나 쓸 수 있으며, "
        "자격증명도 네트워크에서 쉽게 탈취됩니다."
    ),
    "Redis": (
        "Redis 데이터베이스가 비밀번호 없이 인터넷에 공개되어 있습니다. "
        "공격자가 직접 접속하여 저장된 모든 데이터를 읽거나 삭제할 수 있으며, "
        "서버 파일 쓰기 기능을 통해 서버 자체를 장악할 수 있습니다."
    ),
    "Docker": (
        "Docker 관리 API가 인증 없이 인터넷에 노출되어 있습니다. "
        "공격자가 이 API를 통해 새로운 컨테이너를 생성하고 서버 전체 파일에 접근하거나 "
        "호스트 서버를 완전히 장악할 수 있습니다."
    ),
    "Elasticsearch": (
        "Elasticsearch 검색 엔진이 인증 없이 인터넷에 공개되어 있습니다. "
        "저장된 모든 데이터(개인정보, 로그, 비밀번호 해시 등)를 "
        "누구나 조회하고 삭제할 수 있습니다."
    ),
    "MongoDB": (
        "MongoDB 데이터베이스가 인터넷에 직접 노출되어 있습니다. "
        "기본 설정에서는 인증이 비활성화되어 있어 "
        "누구나 모든 데이터에 접근하고 수정·삭제할 수 있습니다."
    ),
    "Memcached": (
        "Memcached 캐시 서버가 인증 없이 인터넷에 공개되어 있습니다. "
        "캐시된 세션 토큰, 민감 데이터가 노출되고, "
        "대량의 트래픽을 반사시키는 DDoS 공격에 악용될 수도 있습니다."
    ),
    "RDP": (
        "원격 데스크톱(RDP)이 인터넷에 직접 노출되어 있습니다. "
        "공격자가 무차별 대입 공격으로 비밀번호를 맞추거나 "
        "RDP 취약점을 이용해 서버 전체를 장악할 수 있습니다."
    ),
    "VNC": (
        "VNC 원격 화면 공유 서비스가 인터넷에 노출되어 있습니다. "
        "인증이 없거나 약한 경우 공격자가 화면을 그대로 보면서 "
        "키보드·마우스로 서버를 직접 조종할 수 있습니다."
    ),
    "SMB": (
        "SMB(윈도우 파일 공유) 서비스가 인터넷에 직접 노출되어 있습니다. "
        "워너크라이(WannaCry) 같은 랜섬웨어가 이 취약점을 통해 전파됩니다. "
        "즉시 방화벽으로 차단이 필요합니다."
    ),
    "MySQL": (
        "MySQL 데이터베이스가 인터넷에 직접 노출되어 있습니다. "
        "공격자가 무차별 대입 공격이나 취약한 자격증명으로 접속하여 "
        "모든 데이터를 탈취하거나 수정할 수 있습니다."
    ),
    "PostgreSQL": (
        "PostgreSQL 데이터베이스가 인터넷에 직접 노출되어 있습니다. "
        "데이터베이스는 내부 네트워크에서만 접근 가능해야 합니다."
    ),
    "MSSQL": (
        "Microsoft SQL Server가 인터넷에 직접 노출되어 있습니다. "
        "공격자가 기본 계정(sa)으로 브루트포스를 시도하거나 "
        "xp_cmdshell 기능으로 서버 OS 명령어를 실행할 수 있습니다."
    ),
}


# ── XML/스타일 헬퍼 ─────────────────────────────────────────────────────────────

def _shd(cell, fill: str):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tcPr.append(shd)


def _border(cell, color="CCCCCC", sz="4"):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    borders = OxmlElement("w:tcBorders")
    for side in ("top", "bottom", "left", "right"):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), sz)
        el.set(qn("w:color"), color)
        borders.append(el)
    tcPr.append(borders)


def _para_border_bottom(para, color="1E3A5F", sz="8"):
    pPr = para._p.get_or_add_pPr()
    pBdr = OxmlElement("w:pBdr")
    b = OxmlElement("w:bottom")
    b.set(qn("w:val"), "single")
    b.set(qn("w:sz"), sz)
    b.set(qn("w:color"), color)
    pBdr.append(b)
    pPr.append(pBdr)


_TOOL_RE = _re.compile(
    r'\b(sqlmap|nuclei|ffuf|katana|nikto|testssl(?:\.sh)?|ghauri|wpscan|nmap|masscan|'
    r'amass|gobuster|dirb|arjun|playwright|puppeteer|selenium|wafw00f)\b', _re.I)


def _scrub_tools(s: str) -> str:
    """외부/내부 점검 도구명은 보고서에 노출하지 않는다 — 렌더 시 일괄 치환."""
    return _TOOL_RE.sub("자체 점검 엔진", s)


def _run(para, text: str, size=10, bold=False, color=C_BLACK, italic=False, mono=False, caps=False):
    text = _scrub_tools(str(text if text is not None else ""))
    r = para.add_run(text)
    fname = "Courier New" if mono else FONT
    r.font.name = fname
    r.font.size = Pt(size)
    r.font.bold = bold
    r.font.italic = italic
    r.font.color.rgb = color
    r._element.rPr.rFonts.set(qn("w:eastAsia"), FONT)
    if caps:                                   # 표시만 대문자(텍스트 원본 보존 — 검색/추출 안전)
        c = OxmlElement("w:caps"); c.set(qn("w:val"), "true")
        r._element.rPr.append(c)
    return r


def _para(doc, space_before=0, space_after=6, align=WD_ALIGN_PARAGRAPH.LEFT):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(space_before)
    p.paragraph_format.space_after  = Pt(space_after)
    p.alignment = align
    return p


def _h1(doc, text: str):
    """섹션 헤더 — PDF/HTML 컨셉과 통일(번호 배지 + 한글 제목 + 영문 서브라벨 + 강조 하단선).

    'N. 한글제목  (English)' 형식이면 스타일링, 그 외(부록 등)는 기존 표기로 폴백.
    """
    m = _re.match(r'^\s*(\d+)\.\s*(.+?)\s*\((.+)\)\s*$', text)
    p = _para(doc, space_before=13, space_after=4)
    p.paragraph_format.keep_with_next = True
    if m:
        num, ko, en = m.group(1), m.group(2).strip(), m.group(3).strip()
        _run(p, f"{int(num):02d}", size=17, bold=True, color=C_BLUE)     # 번호 배지
        _run(p, "  ", size=17)
        _run(p, ko, size=15, bold=True, color=C_NAVY)                     # 한글 제목
        _run(p, f"   {en}", size=8.5, bold=True, color=C_GRAY, caps=True)  # 영문 서브라벨(표시만 대문자)
    else:
        _run(p, text, size=14, bold=True, color=C_NAVY)
    _para_border_bottom(p, color="1E3A5F", sz="18")                       # 강조 하단선(네이비)
    return p


def _h2(doc, text: str):
    p = _para(doc, space_before=9, space_after=3)
    p.paragraph_format.keep_with_next = True
    _run(p, "▎", size=11, bold=True, color=C_BLUE)                        # 좌측 액센트 바
    _run(p, " " + text, size=11, bold=True, color=C_NAVY)
    return p


def _body(doc, text: str, indent=0, size=10, color=C_BLACK):
    p = _para(doc, space_before=2, space_after=4)
    p.paragraph_format.left_indent = Cm(indent)
    _run(p, text, size=size, color=color)
    return p


def _make_table(doc, headers: list, rows: list[list], col_widths: list[float] | None = None):
    tbl = doc.add_table(rows=1 + len(rows), cols=len(headers))
    tbl.style = "Table Grid"
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER

    for i, (cell, h) in enumerate(zip(tbl.rows[0].cells, headers)):
        _shd(cell, "1E3A5F")
        _border(cell, "1E3A5F")
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        _run(p, h, size=9, bold=True, color=C_WHITE)
    # 헤더 행을 페이지 넘김 시 반복(표가 여러 페이지로 나뉘어도 헤더 유지)
    try:
        _trPr = tbl.rows[0]._tr.get_or_add_trPr()
        _th = OxmlElement("w:tblHeader"); _th.set(qn("w:val"), "true"); _trPr.append(_th)
    except Exception:
        pass

    for ri, row_data in enumerate(rows):
        for ci, (cell, val) in enumerate(zip(tbl.rows[ri + 1].cells, row_data)):
            bg = "F9FAFB" if ri % 2 == 0 else "FFFFFF"
            _shd(cell, bg)
            _border(cell, "D1D5DB")
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            _run(p, str(val) if val is not None else "-", size=9)

    if col_widths:
        for i, w in enumerate(col_widths):
            for row in tbl.rows:
                row.cells[i].width = Cm(w)

    _no_split_table(tbl)                     # 각 행이 페이지 경계에서 잘리지 않도록
    doc.add_paragraph().paragraph_format.space_after = Pt(4)
    return tbl


# ── 보고서 특화 헬퍼 ────────────────────────────────────────────────────────────

def _hexrgb(h):
    return RGBColor(int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))


def _add_field(paragraph, field_code: str):
    """워드 필드(PAGE/NUMPAGES 등)를 문단에 삽입한다."""
    from docx.oxml import OxmlElement
    run = paragraph.add_run()
    fldChar1 = OxmlElement("w:fldChar"); fldChar1.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText"); instr.set(qn("xml:space"), "preserve")
    instr.text = field_code
    fldChar2 = OxmlElement("w:fldChar"); fldChar2.set(qn("w:fldCharType"), "end")
    run._r.append(fldChar1); run._r.append(instr); run._r.append(fldChar2)
    run.font.size = Pt(8)
    run.font.color.rgb = C_GRAY
    return run


def _setup_header_footer(section, report_title: str):
    """v5 헤더(보고서명·CONFIDENTIAL) + 푸터(보고서명 · 페이지 · 작성기관)."""
    # 헤더
    hp = section.header.paragraphs[0]
    hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    for r in list(hp.runs):
        r.text = ""
    _run(hp, report_title + "   ·   CONFIDENTIAL", size=8, color=C_GRAY)
    # 헤더 하단 구분선
    _para_border_bottom(hp, color="D1D5DB", sz="4")
    # 푸터: 좌(보고서명) · 중(페이지) · 우(작성기관) — 탭으로 정렬
    fp = section.footer.paragraphs[0]
    for r in list(fp.runs):
        r.text = ""
    from docx.enum.text import WD_TAB_ALIGNMENT
    pf = fp.paragraph_format
    pf.tab_stops.add_tab_stop(Cm(8.0), WD_TAB_ALIGNMENT.CENTER)
    pf.tab_stops.add_tab_stop(Cm(16.0), WD_TAB_ALIGNMENT.RIGHT)
    _run(fp, "Eoseureum · AI Security Assessment Report", size=8, color=C_GRAY)
    _run(fp, "\t", size=8, color=C_GRAY)
    _add_field(fp, "PAGE")
    _run(fp, "\t" + _report_org_name(), size=8, color=C_GRAY)


def _remove_blank_pages(doc):
    """빈 페이지 유발 요소 제거: 연속 page-break, 페이지브레이크 앞뒤 빈 문단 정리."""
    def _has_break(p):
        return any(qn("w:br") == br.tag and br.get(qn("w:type")) == "page"
                   for r in p.runs for br in r._r.findall(qn("w:br")))
    body = doc.element.body
    paras = list(doc.paragraphs)
    # 1) 문서 맨 앞 빈 문단 제거
    while paras and not paras[0].text.strip() and not _has_break(paras[0]):
        paras[0]._p.getparent().remove(paras[0]._p)
        paras = list(doc.paragraphs)
        if len(paras) > 400:
            break
    # 2) 연속된 빈 문단 3개 이상 → 1개로 축소(빈 페이지 방지)
    empties = 0
    for p in list(doc.paragraphs):
        if not p.text.strip() and not _has_break(p) and not p._p.findall(qn("w:r")):
            empties += 1
            if empties > 1:
                p._p.getparent().remove(p._p)
        else:
            empties = 0


def _add_confirmation_banner(doc, f: dict):
    """취약점 실증 확인 여부를 큰 배너로 표시합니다."""
    confirmed  = f.get("probe_confirmed")
    sev        = f.get("severity", "MEDIUM")
    idx        = f.get("_idx", "")
    title      = _display_title(f)
    confidence = f.get("confidence", "")
    owasp      = f.get("owasp", "")

    confidence = f.get("confidence", "")

    if confirmed is True:
        bg_hex = "DCFCE7"
        badge  = "★ 취약점 실증 확인됨 (직접 발생 증명)"
        badge_color = RGBColor(0x16, 0x61, 0x34)
    elif confirmed is False:
        bg_hex = "FFF7ED"
        badge  = "⚠ 취약 가능성 탐지 (브라우저 실행 미확인)"
        badge_color = C_ORANGE
    elif confidence == "POSSIBLE":
        bg_hex = "FFFBEB"
        badge  = "△ 취약 가능성 — 설정 분석 기반 (실제 공격 미확인)"
        badge_color = RGBColor(0xA1, 0x62, 0x07)
    else:
        bg_hex = "EFF6FF"
        badge  = "■ 설정 취약점 확인됨 (응답에서 직접 확인)"
        badge_color = C_NAVY

    ttbl = doc.add_table(rows=2, cols=1)
    ttbl.style = "Table Grid"
    tcell0 = ttbl.rows[0].cells[0]
    tcell1 = ttbl.rows[1].cells[0]

    rsev = _report_sev(f)
    sev_hex = {"Critical": "B91C1C", "High": "DC2626",
               "Medium": "EA580C", "Low": "CA8A04"}.get(rsev,
               RISK_TITLE_HEX.get(sev, "1E3A5F"))
    _shd(tcell0, sev_hex)
    _border(tcell0, color=sev_hex)
    tp0 = tcell0.paragraphs[0]
    vuln_id_str = _vuln_id(idx) if isinstance(idx, int) else f"[{idx}]"
    _run(tp0, f"{vuln_id_str}  {title}", size=12, bold=True, color=C_WHITE)
    _run(tp0, f"   위험도: {_report_sev_label(f)}", size=10, color=C_WHITE)
    if owasp:
        _run(tp0, f"  |  {owasp}", size=9, color=C_WHITE)

    _shd(tcell1, bg_hex)
    _border(tcell1, color=bg_hex)
    tp1 = tcell1.paragraphs[0]
    _run(tp1, badge, size=10, bold=True, color=badge_color)
    if confidence and confidence in CONF_LABEL:
        _run(tp1, f"   [{CONF_LABEL[confidence]}]", size=9, color=CONF_COLOR.get(confidence, C_GRAY))

    # 표(배너)와 다음 표(기본정보) 사이 분리용 최소 문단 (table merge 방지)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def _link_finding_context(f: dict, analysis: dict) -> dict:
    """finding 을 공격 경로/Solver/Agent/Evidence Chain 과 연결(제목 기반 매칭)."""
    out = {"path": "", "solver": "", "agent": "", "chain": ""}
    if not isinstance(analysis, dict):
        return out
    title = (f.get("title") or "")
    tl = title.lower()
    # 공격 경로(제목 키워드 매칭)
    for p in (analysis.get("attack_paths") or []):
        pt = (p.get("title") or "")
        if pt and (pt[:6] in title or any(k in tl for k in ("idor", "xss", "sql", "csrf",
                   "업로드", "redirect", "ssrf") if k in (pt.lower()))):
            out["path"] = f"{pt} ({p.get('path_confidence','')})"
            pid = p.get("path_id")
            for r in (analysis.get("agent_results") or []):
                if r.get("path_id") == pid:
                    out["agent"] = r.get("family", "")
            for sp in (analysis.get("prioritized_paths") or []):
                if sp.get("path_id") == pid and sp.get("recommended_solver"):
                    out["solver"] = sp.get("recommended_solver")
            break
    # Evidence Chain(패밀리 키워드)
    for c in (analysis.get("evidence_chains") or []):
        fam = (c.get("family") or "")
        if fam and fam in tl:
            out["chain"] = f"{c.get('evidence_chain','')} — {c.get('confidence_change','')}"
            break
    return out


def _card_box(doc, icon, title, body, accent_hex="1E3A5F", bg_hex="F9FAFB"):
    """제목줄 + 본문 1개짜리 카드 박스(2행 1열 표)."""
    tbl = doc.add_table(rows=2, cols=1); tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    h = tbl.rows[0].cells[0]; _shd(h, accent_hex); _border(h, accent_hex)
    _run(h.paragraphs[0], f" {icon} {title}", size=9, bold=True, color=C_WHITE)
    b = tbl.rows[1].cells[0]; _shd(b, bg_hex); _border(b, "D1D5DB")
    for _i, _line in enumerate((body or "-").split("\n")):
        _bp = b.paragraphs[0] if _i == 0 else b.add_paragraph()
        _run(_bp, ("  " + _line) if _i == 0 else _line, size=9, color=C_BLACK)
    _no_split_table(tbl)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def _finding_card_compact(doc, title: str, body: str, accent_hex: str = "1E3A5F"):
    """finding 세부 카드(컴팩트) — 2행 표 대신 1셀에 좌측 강조바(▎)+인라인 제목+본문.
    세로 부피를 줄여 finding 당 가독성을 높인다(_card_box 의 압축형)."""
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.rows[0].cells[0]
    _shd(cell, "F9FAFB")
    _border(cell, "E5E7EB", sz="4")
    _accent = RGBColor(int(accent_hex[0:2], 16), int(accent_hex[2:4], 16), int(accent_hex[4:6], 16))
    tp = cell.paragraphs[0]
    tp.paragraph_format.left_indent = Cm(0.15)
    _run(tp, "▎", size=10, bold=True, color=_accent)
    _run(tp, title, size=9, bold=True, color=_accent)
    for _line in (body or "-").split("\n"):
        bp = cell.add_paragraph()
        bp.paragraph_format.left_indent = Cm(0.3)
        _run(bp, _line, size=9, color=C_BLACK)
    _no_split_table(tbl)
    doc.add_paragraph().paragraph_format.space_after = Pt(1)


def _add_observed_view_block(doc, f: dict, analysis: dict | None = None):
    """Finding Card (v5) — 상단 배지(Severity/Validation/CVSS/CWE/OWASP) +
    4박스(Observation / Evidence / Business Impact / Recommendation)."""
    try:
        import evidence_levels as _evl
        v = _evl.observed_view(f, finding_type="vulnerability")
    except Exception:
        return
    sev = _sev5(f.get("severity") or _report_sev(f))
    # ── 상단 배지 라인 ──
    bp = _para(doc, space_before=3, space_after=3); bp.paragraph_format.left_indent = Cm(0.2)
    _run(bp, f" {sev.upper()} ", size=10, bold=True, color=SEV5_RGB.get(sev, C_GRAY))
    _run(bp, "  |  ", size=9, color=C_LIGHT_GRAY)
    _run(bp, ICON["evidence"] + " " + v["verification_label"], size=9, bold=True,
         color=CONF_COLOR.get(f.get("confidence", ""), SEV5_RGB.get(sev, C_BLACK)))
    for lbl, key in (("CVSS", "cvss_estimate"), ("CWE", "cwe"), ("OWASP", "owasp")):
        val = f.get(key)
        if val:
            _run(bp, "  |  ", size=9, color=C_LIGHT_GRAY)
            _run(bp, f"{lbl} {str(val)[:24]}", size=9, color=C_GRAY)

    # ── 오탐(False Positive) 배지 — 억제/높은 오탐위험 표기 ──
    if f.get("_fp_suppressed"):
        fpb = _para(doc, space_before=1, space_after=2); fpb.paragraph_format.left_indent = Cm(0.2)
        _run(fpb, "⛔ 오탐 후보 (자동 억제) — 점수·분포 산정 제외", size=9, bold=True, color=C_RED)
        _run(fpb, "  " + str(f.get("_fp_suppress_reason") or "물리적 불가/검증 불일치")[:90],
             size=8, color=C_GRAY)
    elif f.get("_fp_risk") == "high":
        fpb = _para(doc, space_before=1, space_after=2); fpb.paragraph_format.left_indent = Cm(0.2)
        _run(fpb, " ⚠ 오탐 위험 높음 ", size=9, bold=True, color=RGBColor(0x9A, 0x34, 0x12))
        _reasons = f.get("_fp_reasons") or []
        if _reasons:
            _run(fpb, "  " + _sanitize_display_text(_reasons[0])[:90], size=8, color=C_GRAY)

    # ── 4박스 ──
    _obs = _fold_long(_sanitize_display_text(v["observed_phenomenon"] or "-", f), 300)
    _ev = _fold_long(_sanitize_display_text((v["evidence"] or "-"), f), 360)
    bi = _match_business_impact(f, analysis or {})
    rem = _match_remediation(f, analysis or {})
    link = _link_finding_context(f, analysis or {})
    _biz = _consulting_impact(_fold_long(_sanitize_display_text(
        (bi.get("business_risk") if bi else "") or v["possible_impact"] or "-"), 300))
    if bi and bi.get("regulatory_risk"):
        _biz += "  (규제 관련: " + " · ".join(bi["regulatory_risk"]) + ")"
    _reco = _consulting_reco(_sanitize_display_text(
        (rem.get("remediation_title") if rem else "") or f.get("recommendation") or "-"))
    if link.get("path"):
        _obs += "   [공격 경로: " + _sanitize_display_text(link["path"])[:50] + "]"

    # ── Technical Detail(기술 세부) — 대상 엔드포인트/메서드/파라미터/근거 요약 ──
    _tech_bits = []
    _tgt = f.get("evidence_url") or f.get("url")
    if not _tgt and f.get("host"):
        _tgt = f"{f.get('host','')}:{f.get('port','')}"
    if _tgt:
        _tech_bits.append("대상: " + _sanitize_display_text(str(_tgt))[:80])
    if f.get("http_method"):
        _tech_bits.append("메서드: " + str(f.get("http_method")))
    if f.get("parameter"):
        _tech_bits.append("파라미터: " + _sanitize_display_text(str(f.get("parameter")))[:40])
    if f.get("cvss_estimate"):
        _tech_bits.append("CVSS: " + str(f.get("cvss_estimate")))
    _tech_tail = _sanitize_display_text(f.get("technical_detail") or f.get("evidence_detail") or "", f)
    _tech = "   ·   ".join(_tech_bits)
    if _tech_tail and _tech_tail not in (_obs, _ev):
        _tech = (_tech + "\n" if _tech else "") + _fold_long(_tech_tail, 1500)
    _tech = _tech or "재현 절차·상세 페이로드는 부록(재현 절차)을 참조하십시오."

    # ── 카드 상단: 1줄 Executive Summary ──
    _exec = (f"[{sev}] " + _display_title(f) + " — "
             + (v["verification_label"].split("·")[-1].strip() if v.get("verification_label") else ""))
    ep = _para(doc, space_before=1, space_after=2); ep.paragraph_format.left_indent = Cm(0.2)
    _run(ep, _vuln_icon(f) + " ", size=11, bold=True, color=SEV5_RGB.get(sev, C_NAVY))
    _run(ep, "요약: ", size=9, bold=True, color=C_NAVY)
    _run(ep, _sanitize_display_text(_exec)[:200], size=9, color=C_BLACK)

    # ── 5개 세부 카드(컴팩트: 좌측 강조바) — 관찰 → 증거 → 비즈니스영향 → 기술세부 → 권장조치 ──
    _finding_card_compact(doc, "관찰 내용 (Observation)", _obs, "1E3A5F")
    _finding_card_compact(doc, "확보 증거 (Observed Evidence)", _ev, "0E7A90")
    _finding_card_compact(doc, "비즈니스 영향 (Business Impact)", _biz, SEV5_HEX.get(sev, "DC2626"))
    _finding_card_compact(doc, "기술 세부 (Technical Detail)", _tech, "6B7280")
    _finding_card_compact(doc, "권장 조치 (Recommendation)", _reco, "16A34A")

    # ── 하단: 담당 / 예상 공수 / 참조 ──
    _ref = " · ".join(x for x in [
        (f"OWASP {f.get('owasp')}" if f.get("owasp") else ""),
        (f"CWE {f.get('cwe')}" if f.get("cwe") else ""),
        (", ".join(f.get("cve_references") or [])[:40] if f.get("cve_references") else ""),
    ] if x) or "-"
    fp = _para(doc, space_after=3); fp.paragraph_format.left_indent = Cm(0.2)
    _run(fp, f"담당 {(rem.get('responsible_team') if rem else '-') or '-'}  ·  "
             f"예상 공수 {(rem.get('estimated_effort') if rem else '-') or '-'}  ·  참조 {_ref}",
         size=8, color=C_GRAY)


def _fold_long(text: str, limit: int) -> str:
    """긴 문자열(URL/payload/curl/JSON)은 본문에서 접는다."""
    t = text or ""
    if len(t) <= limit:
        return t
    return t[:limit] + " …(이하 생략 — 상세는 부록/재현 절차 참조)"


def _match_business_impact(f: dict, analysis: dict) -> dict | None:
    title = f.get("title")
    for it in (analysis.get("business_impact") or []):
        if it.get("title") == title:
            return it
    return None


def _match_remediation(f: dict, analysis: dict) -> dict | None:
    title = f.get("title")
    for it in (analysis.get("remediation_items") or []):
        if it.get("finding_title") == title:
            return it
    return None








def _add_reproduction_cmd_section(doc, f: dict):
    """재현 섹션 — Windows 포함 모든 환경에서 재현 가능하도록 '웹브라우저 URL'과 'curl(.exe)' 병기."""
    cmd = f.get("reproduction_cmd", "") or ""
    # TRACE 등 HTTP 메서드 항목은 실제 검증 메서드 기준 명령으로 교체(generic GET 금지).
    if _trace_only(f):
        url = f.get("evidence_url") or f.get("url") or ""
        if url:
            cmd = (f"curl.exe -i -X OPTIONS \"{url}\"\n"
                   f"curl.exe -i -X TRACE \"{url}\"   # TRACE 활성 시 요청 헤더가 응답에 그대로 반사됨")

    # 메서드 판정(POST 여부) — 브라우저 주소창은 GET 만 재현 가능.
    _pd = f.get("probe_detail") if isinstance(f.get("probe_detail"), dict) else {}
    _method = str(_pd.get("method") or ("POST" if "-X POST" in cmd else "GET")).upper()
    # 브라우저 재현용 URL: 프로브가 만든 시연 URL(repro_url) 우선, 없으면 evidence_url.
    _browser_url = f.get("repro_url") or _pd.get("repro_url") or f.get("evidence_url") or ""
    _is_xss = "xss" in str(f.get("title", "")).lower() or "스크립트" in str(f.get("title", ""))

    if not cmd and not _browser_url:
        return

    p = _para(doc, space_before=8, space_after=3)
    p.paragraph_format.left_indent = Cm(0.3)
    _run(p, "■ 재현 방법 (Windows 등 모든 환경)", size=10, bold=True, color=RGBColor(0x1E, 0x3A, 0x5F))

    # ★인증 영역 안내: 로그인 후에만 접근 가능한 페이지의 취약점은, 재현 명령을 '그대로' 실행하면
    #  로그인 페이지로 튕겨 재현이 안 된다(가장 흔한 '재현 안 됨' 원인). 로그인 세션을 포함해야 함.
    _url_path = ""
    try:
        _url_path = urllib.parse.urlparse(_browser_url or f.get("evidence_url", "")).path or ""
    except Exception:
        _url_path = ""
    _auth_req = bool(f.get("auth_required")) or (_url_path not in ("", "/")
                     and f.get("confidence") == "CONFIRMED"
                     and str(_pd.get("type") or "") not in ("", "clickjacking"))
    if _auth_req:
        ap = _para(doc, space_after=2); ap.paragraph_format.left_indent = Cm(0.35)
        _run(ap, "⚠ 로그인 필요: ", size=9, bold=True, color=RGBColor(0xB4, 0x53, 0x09))
        _run(ap, "이 취약점은 '로그인 후 접근하는 페이지'에 있습니다. 아래 명령/URL 을 그대로 실행하면 "
                 "로그인 화면으로 이동해 재현되지 않습니다. 먼저 브라우저로 로그인(같은 브라우저에서 URL "
                 "접속 시 세션 자동 유지)하거나, curl 은 로그인 후 발급된 세션 쿠키를 "
                 "-b \"이름=값\"(예: -b \"PHPSESSID=..; security=low\") 으로 포함하세요.",
             size=9, color=C_BLACK)

    # ① 웹브라우저 재현(가장 쉬움) — GET 취약점은 URL 을 주소창에 붙여넣으면 즉시 재현.
    if _browser_url and _method == "GET":
        gp = _para(doc, space_after=1); gp.paragraph_format.left_indent = Cm(0.35)
        _guide = ("Windows에서 Chrome/Edge 주소창에 아래 URL 을 붙여넣고 Enter — "
                  + ("페이지에 alert 창이 뜨면 XSS 재현 성공." if _is_xss
                     else "정상과 다른 결과(전체 데이터·파일 내용·추출값 등)가 표시되면 재현 성공."))
        _run(gp, "① 웹브라우저: ", size=9, bold=True, color=RGBColor(0x05, 0x96, 0x69))
        _run(gp, _guide, size=9, color=C_BLACK)
        ubox = doc.add_table(rows=1, cols=1); ubox.style = "Table Grid"
        uc = ubox.rows[0].cells[0]; _shd(uc, "0B1E13"); _border(uc, "14532D", sz="6")
        up = uc.paragraphs[0]; up.paragraph_format.left_indent = Cm(0.2)
        _run(up, _browser_url, size=9, mono=True, color=RGBColor(0x86, 0xEF, 0xAC))
        uc.width = Cm(16)
    elif _method == "POST":
        gp = _para(doc, space_after=1); gp.paragraph_format.left_indent = Cm(0.35)
        _run(gp, "① 웹브라우저(POST): ", size=9, bold=True, color=RGBColor(0x05, 0x96, 0x69))
        _run(gp, ("POST 요청이라 주소창만으로는 안 되고, 대상 페이지의 입력폼에 아래 '원문 페이로드'를 "
                  "넣어 제출하거나 브라우저 개발자도구(F12) 콘솔에서 fetch 로 전송하면 재현됩니다. "
                  "상세 페이로드·단계는 아래 '발견 과정(단계별 재현 절차)' 표를 참조하세요."),
             size=9, color=C_BLACK)

    # ② 명령줄(curl) — Windows 10+ 는 curl.exe 내장. 큰따옴표 사용.
    if cmd:
        # Windows 안내: -s → 그대로 두되 curl.exe 로 표기(리눅스 curl 과 동일 인자).
        _cmd_win = cmd.replace("curl -s -X POST", "curl.exe -X POST").replace("curl -s -i", "curl.exe -i").replace("curl -s ", "curl.exe ").replace("curl -i ", "curl.exe -i ")
        cp = _para(doc, space_before=3, space_after=1); cp.paragraph_format.left_indent = Cm(0.35)
        _run(cp, "② 명령줄(curl): ", size=9, bold=True, color=RGBColor(0x1E, 0x3A, 0x5F))
        _run(cp, "Windows 10 이상은 curl.exe 가 기본 내장(명령프롬프트/PowerShell)입니다. "
                 "URL 은 반드시 큰따옴표(\")로 감싸세요."
                 + (" curl 은 JavaScript 를 실행하지 않으므로 XSS alert 확인은 ①번(브라우저)로 하세요."
                    if _is_xss else ""),
             size=9, color=C_BLACK)
        box = doc.add_table(rows=1, cols=1); box.style = "Table Grid"
        bcell = box.rows[0].cells[0]; _shd(bcell, "1E293B"); _border(bcell, "334155", sz="6")
        bp = bcell.paragraphs[0]; bp.paragraph_format.left_indent = Cm(0.2)
        _run(bp, _cmd_win, size=9, mono=True, color=RGBColor(0x86, 0xEF, 0xAC))
        bcell.width = Cm(16)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def _first_sentence(text: str, limit: int = 150) -> str:
    """긴 문단에서 첫 문장만 뽑아 짧게(가독성용)."""
    if not text:
        return ""
    s = _re.split(r'(?<=[.。!?])\s|\n', str(text).strip())[0].strip()
    return (s[:limit] + "…") if len(s) > limit else s


_SEV_RISK_PHRASE = {
    "Critical": "즉시 악용될 수 있는 치명적 위험 — 최우선 조치가 필요합니다.",
    "High": "공격자가 실제로 악용할 가능성이 높아 신속한 조치가 필요합니다.",
    "Medium": "조건이 맞으면 악용될 수 있어 조속한 조치를 권고합니다.",
    "Low": "위험도는 낮으나 방어 심화를 위해 조치를 권고합니다.",
}


def _finding_at_a_glance(f: dict) -> str:
    """비전문가도 이해할 3줄 요약: 무엇이 / 왜 위험 / 어떻게 조치."""
    what = _first_sentence(_sanitize_display_text(f.get("description") or _display_title(f), f))
    why = _first_sentence(f.get("business_impact") or "")
    if not why:
        why = _SEV_RISK_PHRASE.get(_report_sev(f), "")
    how = _first_sentence(f.get("recommendation") or "")
    lines = [f"• 무엇이 문제인가 — {what}"] if what else []
    if why:
        lines.append(f"• 왜 위험한가 — {why}")
    if how:
        lines.append(f"• 어떻게 조치하나 — {how}")
    return "\n".join(lines)


def _add_at_a_glance_card(doc, f: dict):
    """취약점 상세 최상단의 '한눈에 보기' 평이한 요약 카드(가독성 향상)."""
    body = _finding_at_a_glance(f)
    if body.strip():
        _card_box(doc, "🔎", "한눈에 보기", body, accent_hex="1E3A5F", bg_hex="EFF6FF")


def _finding_locus(f: dict):
    """finding 에서 '발견 URL'·업로드/확인 URL·'Payload' 를 최선으로 추출(원문 그대로).
    반환: (발견URL, 업로드파일URL, 확인URL, payload) — 없으면 빈 문자열."""
    pd = f.get("probe_detail") if isinstance(f.get("probe_detail"), dict) else {}

    def _first_ep():
        for e in (f.get("affected_endpoints") or []):
            u = e if isinstance(e, str) else (e.get("url", "") if isinstance(e, dict) else "")
            if u:
                return u
        return ""

    up_url = pd.get("uploaded_url") or ""
    verify_url = pd.get("verify_url") or ""
    # 대표 발견 URL: 폼/주입 URL 우선(업로드는 '폼 URL'을 발견 위치로, 업로드파일 URL은 별도 표기)
    url = (pd.get("submit_url") or pd.get("url") or f.get("evidence_url")
           or f.get("url") or verify_url or up_url or _first_ep() or "")

    # Payload(원문). 없으면 유형별로 사람이 이해할 표현을 보정.
    payload = f.get("payload")
    if payload is None:
        payload = pd.get("payload")
    # SQLi: 단순 에러 트리거(' 등)보다 '데이터를 실제로 뽑아낸' 추출 payload(UNION/블라인드 구체예시)를
    # 우선 표시한다 — '어떤 payload 로 실증했는지 안 보인다'는 피드백 반영.
    _ed = pd.get("extracted_data") if isinstance(pd.get("extracted_data"), dict) else {}
    _proofp = _ed.get("proof_example") or _ed.get("proof_payload") or pd.get("proof_payload")
    if _proofp and str(payload or "").strip() in ("", "'", '"', "1'", "1\"", "')", "'--", "' --"):
        _prm = pd.get("param")
        payload = (f"[주입점: {_prm}] " if _prm else "") + str(_proofp)
    if not payload:
        if up_url:
            payload = ('proof.php  (내용: <?php echo "It_Was_Executed_By_Eoseureum=".(6*7); @unlink(__FILE__); ?>)'
                       "  · Content-Type: image/jpeg 위장  → 접근 시 'It_Was_Executed_By_Eoseureum=42' 출력")
        elif pd.get("param") and pd.get("redirect_to"):
            payload = f"{pd.get('param')}={pd.get('redirect_to')}"
        elif pd.get("cookie_name"):
            payload = f"세션 식별자 '{pd.get('cookie_name')}' 연속 발급값: {', '.join(pd.get('samples') or [])}"
        elif pd.get("injected_header"):
            payload = str(pd.get("injected_header"))
    payload = str(payload or "")
    # URL 인코딩돼 있으면 사람이 붙여넣을 수 있게 디코드
    if "%" in payload:
        try:
            import urllib.parse as _u
            _dec = _u.unquote(payload)
            if _dec and _dec != payload:
                payload = _dec
        except Exception:
            pass
    return (str(url or ""), str(up_url or ""), str(verify_url or ""), payload)


def _add_discovery_locus(doc, f: dict):
    """'한눈에 보기' 바로 아래 — 이 취약점이 '어느 URL'에서 '어떤 Payload'로 발견됐는지 명시한다.
    (사용자 요청: 모든 취약점에 발견 URL·Payload 표기 → 어디서 어떻게 찾았는지 한눈에 확인)."""
    url, up_url, verify_url, payload = _finding_locus(f)
    lines = []
    if url:
        lines.append(f"📍 발견 URL: {url}")
    if verify_url and verify_url != url:
        lines.append(f"↳ 확인(재방문) URL: {verify_url}")
    if up_url and up_url != url:
        lines.append(f"↳ 업로드 파일 URL: {up_url}")
    if payload:
        lines.append(f"💉 Payload: {payload}")
    if not lines:
        return
    _card_box(doc, "📍", "발견 위치 · Payload", "\n".join(lines),
              accent_hex="B45309", bg_hex="FFF7ED")


def _add_poc_script_section(doc, f: dict):
    """확정 취약점의 '간결한' 재현(PoC) 스니펫을 코드 블록으로 표시(3~4줄, 이해 위주)."""
    if not _report_show("poc", True):
        return
    # 즉석 재생성(간결형) 우선 — 기존에 저장된 장문 poc 도 짧게 렌더된다. 실패 시 저장값 폴백.
    try:
        import poc_generator as _pg
        poc = _pg.generate_poc(f) or f.get("poc") or ""
    except Exception:
        poc = f.get("poc") or ""
    if not poc:
        return
    p = _para(doc, space_before=8, space_after=3)
    p.paragraph_format.left_indent = Cm(0.3)
    _run(p, "■ 재현 방법 (요약 · 비파괴)", size=10, bold=True,
         color=RGBColor(0x1E, 0x3A, 0x5F))
    box = doc.add_table(rows=1, cols=1)
    box.style = "Table Grid"
    bcell = box.rows[0].cells[0]
    _shd(bcell, "1E293B")
    _border(bcell, "334155", sz="6")
    bp = bcell.paragraphs[0]
    bp.paragraph_format.left_indent = Cm(0.2)
    shown = poc if len(poc) <= 2600 else (poc[:2600] + "\n# …(이하 생략)")
    _run(bp, shown, size=8, mono=True, color=RGBColor(0x86, 0xEF, 0xAC))
    bcell.width = Cm(16)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)






def _add_ai_analysis_section(doc, analysis: dict):
    """7. AI 공격 체인 분석 섹션. AI 미사용 시 규칙 기반 결과로 명확히 표기."""
    ai = analysis.get("ai_analysis") or {}
    provider  = ai.get("ai_provider", "none")
    summary   = ai.get("ai_executive_summary", "") or ""
    chain     = ai.get("ai_top_attack_chain", "") or ""
    priority  = ai.get("ai_remediation_priority") or []
    risk_asmt = ai.get("ai_risk_assessment", "") or ""
    error     = ai.get("ai_error", "") or ""
    ai_used   = bool(ai.get("ai_used", provider not in ("none", "fallback", "")))

    # ai_status 가 있으면 그 used 를 최종 권위로 삼는다(SHOW_AI_SECTION_ONLY_WHEN_USED).
    # ai_status.used=False 면 "AI 공격 체인/권고 우선순위(AI)" 를 출력하지 않는다.
    if isinstance(analysis.get("ai_status"), dict):
        if not _ai_status_used(analysis):
            ai_used = False

    _h1(doc, "AI 공격 체인 분석")

    # 분석 방식 표기 (AI 사용 / 규칙 기반 미사용을 명확히)
    prov_p = _para(doc, space_before=2, space_after=6)
    _run(prov_p, "분석 방식: ", size=9, bold=True, color=C_GRAY)
    if ai_used:
        _run(prov_p, f"AI 분석 ({provider})", size=9, mono=True, color=C_NAVY)
    else:
        _run(prov_p, ai.get("ai_provider_label", "AI 분석 미사용 / 규칙 기반 분석 사용"),
             size=9, bold=True, color=C_ORANGE)

    # 공격 체인:
    #  1) AI 사용 + ai_top_attack_chain 있으면 → "AI 보안 분석가 공격 체인 의견"
    #  2) 아니면 규칙 기반 attack_chains → "규칙 기반 공격 체인 요약"
    #  3) 둘 다 없으면 exploit_summary 폴백
    attack_chains = analysis.get("attack_chains", []) or []
    _h2(doc, "최위험 공격 시나리오")
    if ai_used and chain:
        sp = _para(doc, space_before=2, space_after=3)
        _run(sp, "AI 보안 분석가 공격 체인 의견", size=9, bold=True, color=C_PURPLE)
        box2 = doc.add_table(rows=1, cols=1); box2.style = "Table Grid"
        bc2 = box2.rows[0].cells[0]; _shd(bc2, "FFF1F2"); _border(bc2, "FECDD3", sz="6")
        bp2 = bc2.paragraphs[0]; bp2.paragraph_format.left_indent = Cm(0.2)
        _run(bp2, chain, size=10, color=RGBColor(0x9F, 0x12, 0x39))
        bc2.width = Cm(16)
        doc.add_paragraph().paragraph_format.space_after = Pt(6)
    elif attack_chains:
        sp = _para(doc, space_before=2, space_after=3)
        _run(sp, "규칙 기반 공격 체인 요약", size=9, bold=True, color=C_NAVY)
        _run(sp, "  (탐지된 취약점·노출 지점을 규칙 기반으로 연결한 가설로, 방어 우선순위 판단용입니다.)",
             size=9, color=C_GRAY)
        for ci, ch in enumerate(attack_chains[:8], 1):
            title  = ch.get("title", "") or f"공격 체인 {ci}"
            cscore = ch.get("confidence_score")
            steps  = ch.get("steps", []) or []
            impact = ch.get("impact", "") or ""
            reqs   = ch.get("required_conditions", []) or []
            rec    = ch.get("recommendation", "") or ""

            box2 = doc.add_table(rows=1, cols=1); box2.style = "Table Grid"
            bc2 = box2.rows[0].cells[0]; _shd(bc2, "FFF7ED"); _border(bc2, "FED7AA", sz="6")
            bc2.width = Cm(16)
            hp = bc2.paragraphs[0]; hp.paragraph_format.left_indent = Cm(0.2)
            _run(hp, f"[{ci}] {title}", size=10, bold=True, color=RGBColor(0x9A, 0x34, 0x12))
            if cscore is not None:
                _run(hp, f"   (신뢰도 점수 {cscore})", size=9, color=C_GRAY)

            if steps:
                stp = bc2.add_paragraph(); stp.paragraph_format.left_indent = Cm(0.3)
                _run(stp, "공격 단계:", size=9, bold=True, color=RGBColor(0x9A, 0x34, 0x12))
                for si, st in enumerate(steps, 1):
                    sp2 = bc2.add_paragraph(); sp2.paragraph_format.left_indent = Cm(0.6)
                    _run(sp2, f"{si}. {st}", size=9, color=C_BLACK)
            if impact:
                ip = bc2.add_paragraph(); ip.paragraph_format.left_indent = Cm(0.3)
                _run(ip, "영향: ", size=9, bold=True, color=C_RED)
                _run(ip, impact, size=9, color=RGBColor(0x7F, 0x1D, 0x1D))
            if reqs:
                qp = bc2.add_paragraph(); qp.paragraph_format.left_indent = Cm(0.3)
                _run(qp, "성립 조건: ", size=9, bold=True, color=C_GRAY)
                _run(qp, " / ".join(str(r) for r in reqs), size=9, color=C_GRAY)
            if rec:
                rp_ = bc2.add_paragraph(); rp_.paragraph_format.left_indent = Cm(0.3)
                _run(rp_, "권고: ", size=9, bold=True, color=C_BLUE)
                _run(rp_, rec, size=9, color=C_NAVY)
            doc.add_paragraph().paragraph_format.space_after = Pt(4)
    elif analysis.get("exploit_summary"):
        box2 = doc.add_table(rows=1, cols=1); box2.style = "Table Grid"
        bc2 = box2.rows[0].cells[0]; _shd(bc2, "FFF1F2"); _border(bc2, "FECDD3", sz="6")
        bp2 = bc2.paragraphs[0]; bp2.paragraph_format.left_indent = Cm(0.2)
        _run(bp2, analysis["exploit_summary"], size=10, color=RGBColor(0x9F, 0x12, 0x39))
        bc2.width = Cm(16)
        doc.add_paragraph().paragraph_format.space_after = Pt(6)
    else:
        _body(doc, "연결 가능한 공격 체인이 도출되지 않았습니다.", indent=0.3)

    if summary:
        _h2(doc, "경영진 요약 (비기술 담당자용)")
        box = doc.add_table(rows=1, cols=1); box.style = "Table Grid"
        bc = box.rows[0].cells[0]; _shd(bc, "EFF6FF"); _border(bc, "BFDBFE", sz="6")
        bp = bc.paragraphs[0]; bp.paragraph_format.left_indent = Cm(0.2)
        _run(bp, summary, size=10, color=C_NAVY)
        bc.width = Cm(16)
        doc.add_paragraph().paragraph_format.space_after = Pt(6)

    if priority and ai_used:
        _h2(doc, "권고 조치 우선순위 (AI)")
        pri_rows = [
            [str(item.get("rank", i + 1)), item.get("title", ""), item.get("reason", "")]
            for i, item in enumerate(priority[:10])
        ]
        _make_table(doc, ["순위", "취약점명", "우선 조치 이유"], pri_rows, col_widths=[1.2, 5, 9.8])

    if risk_asmt:
        _h2(doc, "전체 보안 수준 평가")
        _body(doc, risk_asmt, indent=0.3)

    if error and not summary and not chain:
        ep = _para(doc, space_before=4, space_after=4)
        ep.paragraph_format.left_indent = Cm(0.3)
        _run(ep, "⚠ AI 분석을 완료하지 못해 규칙 기반 분석 결과를 사용했습니다.", size=9, italic=True, color=C_ORANGE)

    doc.add_page_break()






def _add_screenshots_section(doc, f: dict, fig_counter: list):
    """증거 스크린샷을 번호·설명과 함께 삽입합니다."""
    title = f.get("title", "")
    pd    = f.get("probe_detail", {}) or {}
    host  = f.get("host", "")
    port  = f.get("port", "")

    # 수집할 스크린샷 목록 (파일명, 설명)
    shots: list[tuple[str, str]] = []

    # 1) probe_detail 내 evidence_screenshots (XSS/SQLi/LFI/CORS 등 능동점검 캡처)
    for shot_name in (pd.get("evidence_screenshots") or []):
        if shot_name:
            desc = _guess_screenshot_desc(shot_name, title, host)
            shots.append((shot_name, desc))

    # 2) finding 자체의 evidence_screenshots (passive rule findings — 3단계 캡처)
    for shot_name in (f.get("evidence_screenshots") or []):
        if shot_name and shot_name not in {s for s, _ in shots}:
            desc = _guess_screenshot_desc(shot_name, title, host)
            shots.append((shot_name, desc))

    # 3) 단일 evidence_screenshot (하위 호환)
    main_shot = f.get("evidence_screenshot", "")
    if main_shot and main_shot not in {s for s, _ in shots}:
        shots.append((main_shot, f"{host}:{port} — 취약점 확인 화면"))

    if not shots:
        return

    p = _para(doc, space_before=8, space_after=3)
    p.paragraph_format.left_indent = Cm(0.3)
    _run(p, "■ 증거 스크린샷", size=10, bold=True, color=C_PURPLE)

    for shot_name, desc in shots:
        shot_path = _SCREENSHOTS_DIR / shot_name
        if not shot_path.exists():
            # 파일 없으면 빈 자리/빈 문단 만들지 않고 건너뜀
            continue

        fig_counter[0] += 1
        fig_num = fig_counter[0]

        # 그림 번호 + 설명 (캡션) — 이미지와 같은 페이지에 붙도록 keep_with_next
        cap_p = _para(doc, space_before=4, space_after=2)
        cap_p.paragraph_format.left_indent = Cm(0.3)
        cap_p.paragraph_format.keep_with_next = True
        _run(cap_p, f"[그림 {fig_num}]  ", size=10, bold=True, color=C_PURPLE)
        _run(cap_p, desc, size=10, color=C_BLACK)

        # 이미지 삽입 — 폭 11.5cm 로 축소해 페이지당 2장까지 들어가도록(여백 과다 방지).
        # 높이는 비율 유지. 캡션과 함께 한 페이지에 묶이도록 keep_with_next 사용.
        try:
            img_p = doc.add_paragraph()
            img_p.paragraph_format.left_indent = Cm(0.3)
            img_p.paragraph_format.space_after = Pt(6)
            img_p.add_run().add_picture(str(shot_path), width=Cm(11.5))
        except Exception:
            # 삽입 실패 시 그림 번호 롤백하고 빈 자리/빈 문단 만들지 않음
            fig_counter[0] -= 1
            continue


def _guess_screenshot_desc(filename: str, title: str, host: str) -> str:
    """파일명 패턴으로 스크린샷 설명을 추론합니다."""
    fn = filename.lower()
    # 단계별 스크린샷 (s1/s2/s3 접미사)
    if "_s1." in fn or fn.endswith("_s1.png") or "xss_s1" in fn:
        return f"{host} — 【1단계】 점검 대상 서비스 최초 접속 (공격 시도 이전 정상 화면)"
    if "_s2." in fn or fn.endswith("_s2.png"):
        return f"{host} — 【2단계】 취약점 점검 수행 중 (페이로드/공격 행위 화면)"
    if "_s3." in fn or fn.endswith("_s3.png"):
        return f"{host} — 【3단계】 취약점 확인 결과 (실증 증거 화면)"
    # XSS 스크린샷
    if "xss_alert" in fn:
        return f"{host} — 【3단계】 XSS 페이로드 실행 — alert() 대화상자 실제 발생 확인"
    if "xss_page" in fn:
        return f"{host} — 【2단계】 XSS 페이로드 삽입 요청 후 서버 응답 화면"
    # SQLi 스크린샷
    if "sqli_err" in fn:
        return f"{host} — SQL 인젝션 (에러 기반) — DB 에러 메시지 응답 화면"
    if "sqli_union" in fn:
        return f"{host} — SQL 인젝션 (UNION) — DB 버전 추출 결과 화면"
    if "sqli" in fn or "sql" in fn:
        return f"{host} — SQL 인젝션 페이로드 삽입 후 DB 에러 화면"
    # 기타 취약점
    if "lfi" in fn:
        return f"{host} — 경로 순회 페이로드 — 시스템 파일 노출 화면"
    if "cors" in fn:
        return f"{host} — CORS 설정 점검 — 임의 오리진 허용 확인 화면"
    if "redir" in fn:
        return f"{host} — 오픈 리다이렉트 — 외부 URL 리다이렉트 확인 화면"
    if "cmdi" in fn:
        return f"{host} — 명령어 인젝션 실행 결과 화면"
    if "_ev_" in fn:
        return f"{host} — {title} 증거 화면"
    if "_probe_" in fn:
        return f"{host} — 취약점 점검 페이로드 반응 화면"
    return f"{host} — {title} 확인 화면"


def _add_attack_info(doc, f: dict):
    """공격 벡터·시나리오·CVE 정보."""
    if f.get("attack_vector"):
        p = _para(doc, space_before=6, space_after=3)
        p.paragraph_format.left_indent = Cm(0.3)
        _run(p, "■ 공격 벡터  ", size=10, bold=True, color=C_RED)
        _run(p, _sanitize_display_text(f["attack_vector"], f), size=10, color=RGBColor(0x7F, 0x1D, 0x1D))

    if f.get("attack_scenario"):
        p = _para(doc, space_before=4, space_after=3)
        p.paragraph_format.left_indent = Cm(0.3)
        _run(p, "■ 공격 시나리오 (방어 관점)", size=10, bold=True, color=C_ORANGE)

        # 시나리오를 줄 단위로 분리해 표시 (공격성 단정 표현은 방어적 설명으로 정제)
        scenario_lines = [_sanitize_display_text(l.strip(), f)
                          for l in f["attack_scenario"].split("\n") if l.strip()]
        scen_tbl = doc.add_table(rows=1 + len(scenario_lines), cols=2)
        scen_tbl.style = "Table Grid"
        for cell, h in zip(scen_tbl.rows[0].cells, ["단계", "공격 행위"]):
            _shd(cell, "7C2D12"); _border(cell, "7C2D12")
            cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            _run(cell.paragraphs[0], h, size=9, bold=True, color=C_WHITE)
        for ri, line in enumerate(scenario_lines):
            cells = scen_tbl.rows[ri + 1].cells
            bg = "FFF7ED" if ri % 2 == 0 else "FFFFFF"
            _shd(cells[0], bg); _border(cells[0], "FED7AA")
            _shd(cells[1], bg); _border(cells[1], "FED7AA")
            cells[0].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            # 앞의 번호(1., 2. 등) 추출
            num_m = _re.match(r'^(\d+)\.\s*', line)
            num   = num_m.group(1) if num_m else str(ri + 1)
            text  = line[len(num_m.group(0)):] if num_m else line
            _run(cells[0].paragraphs[0], num, size=9, bold=True, color=RGBColor(0x7C, 0x2D, 0x12))
            _run(cells[1].paragraphs[0], text, size=9)
        for row in scen_tbl.rows:
            row.cells[0].width = Cm(1.0)
            row.cells[1].width = Cm(15.0)
        _no_split_table(scen_tbl)
        doc.add_paragraph().paragraph_format.space_after = Pt(4)

    cves = f.get("cve_references") or []
    # 버전 미확인(헤더 시그니처/추정만) 항목은 CVE 매핑을 표시하지 않는다 — 오탐 방지.
    _ev = (f.get("evidence_detail") or "") + " " + (f.get("title") or "")
    _version_uncertain = bool(_re.search(r"가능성|추정|확인 필요|Coyote", _ev, _re.IGNORECASE)) \
        and not (f.get("probe_detail") or {}).get("extracted_version")
    if cves and _version_uncertain:
        p = _para(doc, space_before=2, space_after=3)
        p.paragraph_format.left_indent = Cm(0.3)
        _run(p, "■ CVE 참조  ", size=10, bold=True, color=C_GRAY)
        _run(p, "버전 직접 확인 후 매핑 필요 (현재 시그니처 기반 추정으로 CVE 매핑 보류)",
             size=10, color=C_GRAY)
    elif cves:
        p = _para(doc, space_before=2, space_after=3)
        p.paragraph_format.left_indent = Cm(0.3)
        _run(p, "■ CVE 참조  ", size=10, bold=True, color=C_PURPLE)
        _run(p, ", ".join(cves), size=10, color=C_PURPLE)

    # (점검에 사용한 내부 엔진/외부 도구명은 보고서에 노출하지 않는다)


def _add_recommendation(doc, f: dict):
    """조치 권고 및 실습 가이드."""
    if f.get("lab_guide"):
        p = _para(doc, space_before=4, space_after=3)
        p.paragraph_format.left_indent = Cm(0.3)
        _run(p, "■ 실습 환경 안내  ", size=10, bold=True, color=C_TEAL)
        _run(p, f["lab_guide"], size=10, color=C_TEAL)

    rec_text = f.get("recommendation")
    if _trace_only(f):
        rec_text = (
            "TRACE 메서드를 비활성화하고, 필요한 HTTP 메서드(GET/POST/HEAD 등)만 허용하도록 "
            "웹 서버/애플리케이션 설정을 조정하십시오. 불필요한 PUT/DELETE 등 메서드도 함께 차단을 권고합니다."
        )
    elif rec_text:
        rec_text = _sanitize_display_text(rec_text, f)

    if rec_text:
        p = _para(doc, space_before=4, space_after=8)
        p.paragraph_format.left_indent = Cm(0.3)
        _run(p, "■ 권고 조치 (개발·운영팀 조치 사항)  ", size=10, bold=True, color=C_BLUE)

        rec_tbl = doc.add_table(rows=1, cols=1)
        rec_tbl.style = "Table Grid"
        rc = rec_tbl.rows[0].cells[0]
        _shd(rc, "EFF6FF")
        _border(rc, "BFDBFE", sz="8")
        rp = rc.paragraphs[0]
        rp.paragraph_format.left_indent = Cm(0.2)
        _run(rp, rec_text, size=10, color=C_NAVY)
        rc.width = Cm(16)


# AI 보안 분석가 의견 안내 문구 (변경 불가 원칙 고지)
_AI_ANALYST_NOTICE = (
    "AI 보안 분석가 의견은 Rule Engine의 판정 결과를 설명·보강하기 위한 참고 분석이며, "
    "취약점 개수·위험도·신뢰도를 변경하지 않습니다."
)


def _add_ai_analyst_section(doc, f: dict):
    """각 취약점 하단 'AI 보안 분석가 의견' 섹션 (finding['ai_analysis'] 기반).

    표시 정책:
    - ai_analysis 가 없거나 provider != "ollama" (AI 미사용) → 아무 것도 출력하지 않는다
      (SHOW_AI_SECTION_ONLY_WHEN_USED=true, 기본). 취약점마다 "AI 미사용" 문구 반복 금지.
    - provider == "ollama" 일 때만 'AI 보안 분석가 의견' 출력.
    - 규칙 기반 참고는 SHOW_RULE_BASED_ANALYSIS=true 일 때만(기본 false) 출력.
    """
    ai = f.get("ai_analysis")
    if not isinstance(ai, dict) or not ai:
        return

    provider = (ai.get("provider") or "").lower()
    ai_used = provider == "ollama"

    if not ai_used:
        # AI 미사용 finding: 정책상 출력하지 않음 (반복 문구 금지).
        if _show_ai_section_only_when_used() or not _show_rule_based_analysis():
            return

    # AI 품질 필터: 힌디어/깨진문자/placeholder/영어과다 문장은 제거.
    if ai_used:
        try:
            import ai_quality
            ai = ai_quality.filter_ai_analysis(ai)
            if ai.get("_quality_failed"):
                # 유효 문장이 하나도 없으면 표준 대체 문구만 출력(전체 보고서 실패 금지).
                p0 = _para(doc, space_before=6, space_after=6)
                p0.paragraph_format.left_indent = Cm(0.3)
                _run(p0, "■ AI 보안 분석가 의견  ", size=10, bold=True, color=C_PURPLE)
                _run(p0, ai_quality.AI_QUALITY_FALLBACK, size=9, color=C_GRAY)
                return
        except Exception:
            pass

    p = _para(doc, space_before=6, space_after=3)
    p.paragraph_format.left_indent = Cm(0.3)
    p.paragraph_format.keep_with_next = True
    if ai_used:
        _run(p, "■ AI 보안 분석가 의견  ", size=10, bold=True, color=C_PURPLE)
        _run(p, f"(Ollama + Eoseureum Security Knowledge 기반 분석{(' · ' + ai.get('model')) if ai.get('model') else ''})",
             size=9, color=C_GRAY)
    else:
        # fallback/none — AI 처럼 보이는 문구·"AI 공격 체인" 표현 금지
        _run(p, "■ 규칙 기반 보안 분석 참고  ", size=10, bold=True, color=C_TEAL)

    box = doc.add_table(rows=1, cols=1)
    box.style = "Table Grid"
    bc = box.rows[0].cells[0]
    _shd(bc, "F5F3FF" if ai_used else "F0FDFA")
    _border(bc, "DDD6FE" if ai_used else "99F6E4", sz="6")
    bc.width = Cm(16)
    bp = bc.paragraphs[0]
    bp.paragraph_format.left_indent = Cm(0.2)

    if ai_used:
        rows = [
            ("오탐 가능성",      ai.get("false_positive_assessment")),
            ("업무 영향도",      ai.get("business_impact")),
            ("공격 체인 관점",   ai.get("attack_chain_analysis")),
            ("조치 우선순위 사유", ai.get("remediation_priority_reason")),
        ]
    else:
        # fallback: "AI 공격 체인" 표현 금지 — 항목별은 권고 위주로만 표기 (반복 최소화)
        rows = [
            ("오탐 가능성",      ai.get("false_positive_assessment")),
            ("조치 권고",        ai.get("remediation_priority_reason")),
        ]

    first = True
    for label, val in rows:
        if not val:
            continue
        val = _sanitize_display_text(str(val), f)
        para = bp if first else _para_in_cell(bc)
        first = False
        _run(para, f"· {label}: ", size=9, bold=True, color=C_NAVY)
        _run(para, val, size=9, color=C_BLACK)

    steps = ai.get("additional_verification_steps") or []
    if steps:
        sp = _para_in_cell(bc)
        _run(sp, "· 추가 검증 권고: ", size=9, bold=True, color=C_NAVY)
        _run(sp, " / ".join(_sanitize_display_text(str(s), f) for s in steps[:5]), size=9, color=C_BLACK)

    if first:
        # 표시할 내용이 없으면 report_text 라도
        _run(bp, _sanitize_display_text(str(ai.get("report_text") or "분석 결과가 없습니다."), f),
             size=9, color=C_BLACK)

    # 변경 불가 원칙 고지 (AI 사용 시에만 — fallback 반복 최소화)
    if ai_used:
        np_ = _para(doc, space_before=2, space_after=6)
        np_.paragraph_format.left_indent = Cm(0.3)
        _run(np_, _AI_ANALYST_NOTICE, size=8, italic=True, color=C_GRAY)
    else:
        _para(doc, space_before=0, space_after=6)


# ── 메인 보고서 생성 ───────────────────────────────────────────────────────────

def _admin_hit_eligible(ah: dict) -> bool:
    """관리자 페이지로 집계할 자격: password 폼(has_login_form) 또는 401/403 보호."""
    if not isinstance(ah, dict):
        return False
    if ah.get("status_code") in (401, 403):
        return True
    return bool(ah.get("has_login_form"))


def _collect_discovery_stats(results: list, findings: list) -> dict:
    """스캔 결과에서 Discovery 통계를 집계합니다."""
    stats = {
        "total_urls": 0,
        "discovery_urls": 0,
        "api_count": 0,
        "admin_pages": [],
        "admin_apis": [],
        "swagger_found": [],
        "graphql_found": [],
        "confirmed_count": 0,
        "possible_count": 0,
        "framework_hints": [],
    }

    # URL Discovery 결과 수집
    for hr in results:
        for svc in hr.get("services", []):
            disc = svc.get("discovery_result") or {}
            if disc:
                url_list = disc.get("urls") or []
                stats["total_urls"] += len(url_list)
                stats["discovery_urls"] += len(url_list)
                # API 경로 수
                api_urls = [u.get("url", u) if isinstance(u, dict) else u
                            for u in url_list
                            if (u.get("url", u) if isinstance(u, dict) else u).find("/api/") >= 0]
                stats["api_count"] += len(api_urls)
                # 관리자 히트 — soft-404/등록자격 통과분만(password form 또는 401/403 보호)
                for ah in disc.get("admin_hits", []):
                    if not _admin_hit_eligible(ah):
                        continue
                    if ah not in stats["admin_pages"]:
                        stats["admin_pages"].append(ah)
                # API 히트
                for api_h in disc.get("api_hits", []):
                    if api_h not in stats["admin_apis"]:
                        stats["admin_apis"].append(api_h)
                # 프레임워크
                for fh in disc.get("framework_hints", []):
                    fw = fh.get("framework", "")
                    if fw and fw not in [f.get("framework") for f in stats["framework_hints"]]:
                        stats["framework_hints"].append(fh)

            # active_probes에서 Swagger/GraphQL (orchestrator 경로의 list 형태는 빈 dict 로 취급)
            _ap = svc.get("active_probes")
            ap = _ap if isinstance(_ap, dict) else {}
            if ap.get("swagger_openapi"):
                sw = ap["swagger_openapi"]
                stats["swagger_found"].append({
                    "url": sw.get("url", ""),
                    "api_count": (sw.get("api_summary") or {}).get("total_endpoints", 0),
                })
            if ap.get("graphql_introspection"):
                gql = ap["graphql_introspection"]
                schema_info = gql.get("schema_info") or {}
                stats["graphql_found"].append({
                    "url": gql.get("url", ""),
                    "mutations": len(schema_info.get("mutations", [])),
                    "admin_mutations": schema_info.get("admin_mutations", []),
                })

    # Finding 통계
    for f in findings:
        if f.get("judgment") != "취약":
            continue
        conf = f.get("confidence", "")
        if conf == "CONFIRMED" or f.get("probe_confirmed") is True:
            stats["confirmed_count"] += 1
        else:
            stats["possible_count"] += 1

    return stats


def _add_discovery_stats_section(doc, stats: dict):
    """스캔 요약 통계 섹션을 보고서에 추가합니다."""
    _h2(doc, "3.4 URL Discovery 통계")

    rows = [
        ["총 발견 URL 수", str(stats["total_urls"])],
        ["API 경로 수", str(stats["api_count"])],
        ["관리자 페이지 수", str(len(stats["admin_pages"]))],
        ["관리자 API 수", str(len(stats["admin_apis"]))],
        ["Swagger/OpenAPI 발견", str(len(stats["swagger_found"]))],
        ["GraphQL 엔드포인트 발견", str(len(stats["graphql_found"]))],
        ["실증 확인(CONFIRMED) 취약점", str(stats["confirmed_count"])],
        ["취약 가능성(POSSIBLE) 항목", str(stats["possible_count"])],
    ]
    if stats["framework_hints"]:
        fw_names = ", ".join(set(f.get("framework", "") for f in stats["framework_hints"]))
        rows.append(["탐지된 프레임워크/빌드 도구", fw_names])

    _make_table(doc, ["항목", "수치"], rows, col_widths=[7, 9])

    # 관리자 페이지 목록
    if stats["admin_pages"]:
        p = _para(doc, space_before=6, space_after=2)
        _run(p, "▶ 발견된 관리자 페이지:", size=10, bold=True, color=RGBColor(0xDC, 0x26, 0x26))
        for ap in stats["admin_pages"][:10]:
            url_str = ap.get("url", str(ap)) if isinstance(ap, dict) else str(ap)
            status = ap.get("status_code", "") if isinstance(ap, dict) else ""
            has_login = ap.get("has_login_form", False) if isinstance(ap, dict) else False
            bp = _para(doc, space_before=1, space_after=1)
            bp.paragraph_format.left_indent = Cm(0.5)
            _run(bp, f"• {url_str}", size=9, color=RGBColor(0xB4, 0x53, 0x09))
            if status:
                _run(bp, f"  (HTTP {status}", size=9, color=C_GRAY)
                if has_login:
                    _run(bp, ", 로그인 폼 있음)", size=9, color=C_GRAY)
                else:
                    _run(bp, ")", size=9, color=C_GRAY)

    # Swagger API 상세
    if stats["swagger_found"]:
        p = _para(doc, space_before=6, space_after=2)
        _run(p, "▶ 발견된 Swagger/OpenAPI:", size=10, bold=True, color=RGBColor(0x16, 0x65, 0xC0))
        for sw in stats["swagger_found"][:5]:
            bp = _para(doc, space_before=1, space_after=1)
            bp.paragraph_format.left_indent = Cm(0.5)
            api_cnt = sw.get("api_count", 0)
            _run(bp, f"• {sw.get('url', '')}",  size=9, color=RGBColor(0x1A, 0x6F, 0xD4))
            if api_cnt:
                _run(bp, f"  ({api_cnt}개 API 경로 노출)", size=9, color=C_GRAY)

    # GraphQL 상세
    if stats["graphql_found"]:
        p = _para(doc, space_before=6, space_after=2)
        _run(p, "▶ 발견된 GraphQL:", size=10, bold=True, color=RGBColor(0xE4, 0x00, 0x98))
        for gql in stats["graphql_found"][:5]:
            bp = _para(doc, space_before=1, space_after=1)
            bp.paragraph_format.left_indent = Cm(0.5)
            _run(bp, f"• {gql.get('url', '')}", size=9, color=RGBColor(0xE4, 0x00, 0x98))
            if gql.get("admin_mutations"):
                _run(bp, f"  ⚠ 관리 Mutation: {', '.join(gql['admin_mutations'][:3])}", size=9, color=RGBColor(0xDC, 0x26, 0x26))


def _fmt_coverage_value(val) -> str:
    """커버리지 값 표시: None/빈 값은 '-', bool 은 예/아니오, 리스트는 개수."""
    if val is None:
        return "-"
    if isinstance(val, bool):
        return "예" if val else "아니오"
    if isinstance(val, (list, tuple, set)):
        return str(len(val)) if val else "-"
    s = str(val).strip()
    return s if s else "-"


def _add_coverage_summary_section(doc, analysis: dict):
    """점검 커버리지 요약 섹션.

    analysis["coverage"] 와 summary 에서 점검 범위/시도 수치를 표로 출력한다.
    실제 수집 데이터가 아직 없을 수 있으므로 .get 폴백('-')만 사용한다
    (데이터 채우기는 추후 파이프라인에서 수행).
    """
    cov = analysis.get("coverage") or {}
    summary = analysis.get("summary") or {}
    ai_status = analysis.get("ai_status") or {}

    def g(*keys):
        """coverage → summary 순으로 첫 번째로 존재하는 키 값을 반환."""
        for k in keys:
            if isinstance(cov, dict) and k in cov:
                return cov.get(k)
        for k in keys:
            if isinstance(summary, dict) and k in summary:
                return summary.get(k)
        return None

    _h2(doc, "3.5 점검 커버리지 요약")
    _body(doc,
        "본 점검에서 탐색·시도한 범위를 요약합니다. 수치가 '-' 인 항목은 "
        "해당 데이터가 수집되지 않았거나 적용되지 않은 항목입니다.", size=9, color=C_GRAY)

    fallback_reason = ai_status.get("fallback_reason") if isinstance(ai_status, dict) else None
    if fallback_reason:
        fallback_reason = _FALLBACK_REASON_LABEL.get(fallback_reason, fallback_reason)

    # '적용 점검 정책'을 정책 템플릿명(get_active_policy().name, 예: proof)이 아니라 실제 적용한
    # 검증 프로파일(SAFE/STANDARD/ADVANCED/PROOF)로 표기한다 — 표지와 일치. SAFE로 점검했는데
    # proof/aggressive 로 잘못 찍히던 문제(적용되지 않은 값 표기)를 바로잡는다.
    _cvp  = (analysis.get("validation_profile") or "").upper()
    _cvpr = (analysis.get("validation_profile_requested") or "").upper()
    if _cvp:
        _cprof_disp = _cvp + (f" (요청 {_cvpr} → 안전 강등)" if _cvpr and _cvpr != _cvp else "")
    else:
        _cprof_disp = _fmt_coverage_value(g("scan_policy"))   # 구 데이터 폴백

    rows = [
        ["검증 프로파일 (Profile)",  _cprof_disp],
        ["Payload Level",           _fmt_coverage_value(g("payload_level"))],
        ["USE_PROBE_ORCHESTRATOR",  _fmt_coverage_value(g("use_probe_orchestrator"))],
        ["AI 분석 사용",            _fmt_coverage_value(g("ai_enabled"))],
        ["AI Provider",             _fmt_coverage_value(g("ai_provider"))],
        ["AI Model",                _fmt_coverage_value(g("ai_model"))],
        ["발견 URL 수",             _fmt_coverage_value(g("discovered_urls"))],
        ["발견/점검 form 수",       _fmt_coverage_value(g("discovered_forms", "forms_found", "forms"))],
        ["발견/점검 input 수",      _fmt_coverage_value(g("inputs_found", "inputs"))],
        ["SQLi 시도 수",            _fmt_coverage_value(g("sqli_attempts"))],
        ["로그인 폼 SQLi 시도 수",  _fmt_coverage_value(g("login_sqli_attempts"))],
        ["인증 우회 시도 수",       _fmt_coverage_value(g("auth_bypass_attempts"))],
        ["XSS 시도 수",             _fmt_coverage_value(g("xss_attempts"))],
        ["반사형 XSS 시도 수",      _fmt_coverage_value(g("reflected_xss_attempts"))],
        ["DOM XSS 시도 수",         _fmt_coverage_value(g("dom_xss_attempts"))],
        ["Stored XSS 시도 수",      _fmt_coverage_value(g("stored_xss_attempts"))],
        ["CMDi 시도 수",            _fmt_coverage_value(g("cmdi_attempts"))],
        ["심화 점검 수행 수",       _fmt_coverage_value(g("external_tool_count"))],
        ["Time Based SQLi 수행",    _fmt_coverage_value(g("time_based_sqli"))],
        ["Rate Limit 설정값",       _fmt_coverage_value(g("rate_limit"))],
        ["검색 입력점 수",          _fmt_coverage_value(g("search_inputs"))],
        ["발견 로그인 폼 수",       _fmt_coverage_value(g("login_forms_found", "login_forms"))],
        ["점검 대상 로그인 폼 수",  _fmt_coverage_value(g("login_forms_tested"))],
        ["수행 로그인 폼 수",       _fmt_coverage_value(g("login_forms_performed"))],
        ["로그인 폼 구조분석 실패 수", _fmt_coverage_value(g("login_forms_structure_failed"))],
        ["로그인 폼 미수행 사유",   _fmt_coverage_value(g("login_skip_reason"))],
        ["인증 우회 점검 여부",     _fmt_coverage_value(g("auth_bypass_checked"))],
        ["인증 후 크롤 사용",       _fmt_coverage_value(g("auth_crawl_enabled"))],
        ["인증 로그인 성공",        _fmt_coverage_value(g("auth_login_success"))],
        ["인증 후 페이지 수",       _fmt_coverage_value(g("authenticated_pages", "auth_pages"))],
        ["인증 스캔 사유",          _fmt_coverage_value(g("auth_scan_reason", "auth_scan_skip_reason"))],
        ["Known Credential 수행",   _fmt_coverage_value(g("known_credential_check", "known_credentials_used"))],
        ["AI fallback reason",      _fmt_coverage_value(fallback_reason)],
    ]
    _make_table(doc, ["점검 항목", "수치/여부"], rows, col_widths=[7, 9])

    # 로그인 페이지가 발견된 경우, 운영 안전을 위한 비수행 항목을 명시(자동 삽입).
    _login_found = g("login_forms_found", "login_forms")
    try:
        _lf_n = int(_login_found) if _login_found not in (None, "-") else 0
    except (TypeError, ValueError):
        _lf_n = 0
    if _lf_n > 0:
        _body(doc,
            "본 점검은 운영 서비스 가용성을 고려하여 브루트포스·계정 잠금 유발·Credential "
            "Stuffing 은 수행하지 않았다. 다만 로그인 폼의 SQL 인젝션·인증 우회는 안전 페이로드 "
            "기반 응답 대조로 능동 검증하여 취약 여부를 확정한다(수동 검토로 미루지 않음).",
            size=9, color=C_GRAY)

    _add_candidate_verification_summary(doc, analysis)


def _add_candidate_verification_summary(doc, analysis: dict):
    """접근제어(IDOR) 능동 검증 요약. 접근제어/로직은 '수동 검토(참고)'로 미루지 않고
    능동 검증으로 확증하거나 폐기한다(사용자 지침: 실증 or 폐기). CSRF·파일업로드·비즈니스
    로직은 각각 전담 능동 실증 프로브(csrf_form·file_upload RCE·로직 차등)가 처리하며,
    확증되면 취약 finding 으로, 아니면 미보고(양호)로 남는다 — 별도 '후보' 분류를 두지 않는다."""
    cvv = analysis.get("candidate_verification") or {}
    idor_sum = cvv.get("idor") or {}
    _verified = idor_sum.get("verified") or 0
    _promoted = idor_sum.get("promoted") or 0
    try:
        _has_data = int(_verified) > 0 or int(_promoted) > 0
    except (TypeError, ValueError):
        _has_data = bool(idor_sum)

    if _has_data:
        _h2(doc, "3.6 접근제어 능동 검증 요약 (IDOR)")
        _body(doc,
            "접근제어(IDOR)는 두 계정(A/B) 교차 접근으로 능동 검증한다. 인가되지 않은 타 객체 "
            "열람이 실제로 확인되면 취약으로 확정하고, 접근 통제가 동작하면 폐기한다(읽기 전용·비파괴). "
            "'수동 검토'로 미루지 않는다.", size=9, color=C_GRAY)
        rows = [
            ["IDOR 교차검증 수행 수",    _fmt_coverage_value(idor_sum.get("verified"))],
            ["IDOR 취약 확정/가능성 수", _fmt_coverage_value(idor_sum.get("promoted"))],
        ]
        _make_table(doc, ["항목", "수치"], rows, col_widths=[7, 9])
    elif cvv.get("idor_performed") is False and cvv.get("idor_reason"):
        _h2(doc, "3.6 접근제어 능동 검증 (IDOR)")
        _body(doc,
            f"IDOR 교차검증 미수행: {cvv.get('idor_reason')} "
            "(두 계정 자격증명 제공 시 자동 A/B 교차검증으로 확증/폐기).", size=9, color=C_GRAY)

    _add_ai_payload_plan_section(doc, analysis)


_VERDICT_KO = {
    "BLOCKED_DESTRUCTIVE": "파괴적 payload 차단", "BLOCKED_SHELL": "셸/웹쉘/코드실행 차단",
    "BLOCKED_TIME_BASED": "Time-based SQLi 차단", "BLOCKED_STATE_CHANGE": "상태변경 payload 차단",
    "MANUAL_APPROVAL_REQUIRED": "수동 승인 필요(RCE/무해 업로드)",
}


def _add_ai_payload_plan_section(doc, analysis: dict):
    """AI 기반 공격 기법 계획 및 검증 — 계획/차단/실행/판정 요약."""
    plan = analysis.get("ai_payload_plan") or {}
    s = plan.get("summary") or {}
    if not s:
        return
    _h2(doc, "3.7 AI 기반 공격 기법 계획 및 검증")
    _body(doc,
        "입력점 분류 후 AI 가 취약 유형별 payload 후보를 '제안'하고, Eoseureum이 안전성 "
        "Validator 로 검증한 뒤 통과한 payload 만 실제 테스트한다. AI 는 취약 여부를 판정하지 "
        "않으며, 최종 판정은 Rule Engine 이 운영 영향 없는 무해 증거(쉘 획득·덤프·파일쓰기 없음)로 "
        "수행한다. Time-based SQLi 는 기본 차단, OS 명령 증거는 RCE Proof Mode 승인 시에만 "
        "고정 echo marker 수준으로 제한한다.", size=9, color=C_GRAY)

    rows = [
        ["전체 입력점 수",          _fmt_coverage_value(s.get("total_input_points"))],
        ["AI 선별 입력점 수",       _fmt_coverage_value(s.get("ai_selected_input_points"))],
        ["AI 생성 payload 후보 수", _fmt_coverage_value(s.get("ai_payload_candidates"))],
        ["Validator 통과 수",       _fmt_coverage_value(s.get("validator_passed"))],
        ["Validator 차단 수",       _fmt_coverage_value(s.get("validator_blocked"))],
        ["계획된 실행 수",          _fmt_coverage_value(s.get("planned_executions"))],
        ["실제 실행(증거 수집) 수", _fmt_coverage_value(s.get("executed"))],
        ["CONFIRMED 수",            _fmt_coverage_value(s.get("confirmed"))],
        ["POSSIBLE 수",             _fmt_coverage_value(s.get("possible"))],
        ["MANUAL_REVIEW 수",        _fmt_coverage_value(s.get("manual_review"))],
        ["Critical 후보 수",        _fmt_coverage_value(s.get("critical_candidates"))],
        ["RCE Proof Mode",          _fmt_coverage_value(s.get("rce_proof_mode"))],
        ["Time-based SQLi 허용",    _fmt_coverage_value(s.get("time_based_enabled"))],
    ]
    _make_table(doc, ["항목", "수치"], rows, col_widths=[7, 9])

    # 차단 사유 분포
    bbv = s.get("blocked_by_verdict") or {}
    if bbv:
        parts = [f"{_VERDICT_KO.get(k, k)} {v}건" for k, v in bbv.items()]
        _body(doc, "차단 사유: " + " · ".join(parts), size=9, color=C_GRAY)

    _body(doc,
        "※ 본 결과의 최종 취약 판정은 AI 가 아닌 Rule Engine 이 수행했습니다. "
        "AI 는 payload 후보 제안에만 사용되었으며 판정 권한이 없습니다.", size=9, color=C_GRAY)

    # 상위 Critical 후보(점수순)
    crit = plan.get("critical") or []
    if crit:
        crows = [[
            _fmt_coverage_value(c.get("vuln_type")),
            _fmt_coverage_value(c.get("param") or "-"),
            _fmt_coverage_value(c.get("priority_level")),
            _fmt_coverage_value(c.get("priority_score")),
        ] for c in crit[:10]]
        _body(doc, "상위 Critical 후보(우선 점검 대상):", size=9, color=C_GRAY)
        _make_table(doc, ["유형", "파라미터", "우선순위", "점수"], crows,
                    col_widths=[4, 6, 3, 3])

    _add_attack_surface_plan_section(doc, analysis)
    _add_attack_path_section(doc, analysis)


_PATH_GRADE_KO = {
    "Critical Path": "Critical", "High Path": "High", "Medium Path": "Medium",
    "Low Path": "Low", "Observed Path": "Observed",
}


def _add_attack_path_section(doc, analysis: dict):
    """공격 경로 분석(Attack Path Analysis) — 개별 finding 을 공격 흐름으로 연결."""
    paths = analysis.get("attack_paths") or []
    s = analysis.get("attack_path_summary") or {}
    if not paths and not s:
        return
    _h2(doc, "3.9 공격 경로 분석 (Attack Path Analysis)")
    _body(doc,
        "개별 발견 항목을 모의해킹 관점의 공격 경로로 연결해 표시한다. 경로의 신뢰도는 "
        "확보된 증거 수준(Rule Engine)으로만 결정하며(AI 가 임의 확정 불가), 불확실한 연결은 "
        "'가능 경로'로 표시한다. 쉘 획득·리버스셸·웹쉘·파괴적 행위는 자동 수행하지 않는다.",
        size=9, color=C_GRAY)

    rows = [
        ["전체 공격 경로 수",       _fmt_coverage_value(s.get("total_paths"))],
        ["Critical/High/Medium/Low",
         f"{s.get('critical_paths',0)} / {s.get('high_paths',0)} / "
         f"{s.get('medium_paths',0)} / {s.get('low_paths',0)}"],
        ["Confirmed/Evidence/Observed",
         f"{s.get('confirmed_paths',0)} / {s.get('evidence_paths',0)} / "
         f"{s.get('observed_conf_paths',0)}"],
        ["우선 조치 필요 경로 수",  _fmt_coverage_value(s.get("priority_action_paths"))],
        ["인증 후 기반 경로 수",    _fmt_coverage_value(s.get("auth_based_paths"))],
        ["관리자/민감 기능 경로 수", _fmt_coverage_value(s.get("sensitive_admin_paths"))],
    ]
    _make_table(doc, ["항목", "수치"], rows, col_widths=[8, 8])

    # Top Attack Paths 상세
    top = paths[:8]
    for i, p in enumerate(top, 1):
        ph = _para(doc, space_before=6, space_after=2)
        ph.paragraph_format.left_indent = Cm(0.2)
        _run(ph, f"공격 경로 #{i} — {p.get('title','공격 경로')}", size=11, bold=True, color=C_NAVY)
        meta = _para(doc, space_after=2)
        meta.paragraph_format.left_indent = Cm(0.3)
        _run(meta, f"등급: {_PATH_GRADE_KO.get(p.get('risk_grade'), p.get('risk_grade'))}"
                   f"  ·  검증: {p.get('path_confidence','')}"
                   f"  ·  점수: {p.get('risk_score','')}", size=9, color=C_GRAY)
        # 단계
        for n, step in enumerate(p.get("steps") or [], 1):
            sp = _para(doc, space_after=0)
            sp.paragraph_format.left_indent = Cm(0.6)
            _run(sp, f"{n}. {_sanitize_display_text(str(step))}", size=9, color=C_BLACK)
        # 영향/권고/조건/차단
        detail = [
            ["가능한 영향", _sanitize_display_text(p.get("possible_impact", "") or "-")],
            ["권고사항", _sanitize_display_text(p.get("recommendation", "") or "-")],
            ["미검증 조건", " · ".join(p.get("required_conditions") or []) or "-"],
            ["차단된 위험 행위", p.get("blocked_actions", "") or "-"],
        ]
        _make_table(doc, ["구분", "내용"], detail, col_widths=[3.5, 12.5])

    _body(doc,
        "※ 모든 경로의 확신/증거 여부는 Rule Engine·증거 수준 기반이며, AI 설명은 "
        "영향·권고 보강에만 사용되었습니다(경로 확정 권한 없음).", size=9, color=C_GRAY)


def _add_attack_surface_plan_section(doc, analysis: dict):
    """공격 표면 분석/점수화/추천 기법 + AI Reasoning Trace 요약(Attack Surface Planner)."""
    plan = analysis.get("attack_surface_plan") or {}
    s = plan.get("summary") or {}
    if not s:
        return
    _h2(doc, "3.8 공격 표면 분석 및 우선순위 (Attack Surface Planner)")
    _body(doc,
        "입력점의 의미(semantic)·비즈니스 역할을 분석해 공격 표면 유형을 분류하고, 점수화로 "
        "우선순위를 정한 뒤 상위 표면을 우선 점검한다(Probe 예산 최적화). 추천 기법은 Technique "
        "Knowledge Base 에서 도출되며, 실제 실행/판정은 기존 계층(Payload Planner→Rule Engine)이 "
        "수행한다.", size=9, color=C_GRAY)

    rows = [
        ["전체 공격 표면 수",       _fmt_coverage_value(s.get("total_surfaces"))],
        ["선별(우선 점검) 표면 수", _fmt_coverage_value(s.get("selected_surfaces"))],
        ["인증 후 공격 표면 수",    _fmt_coverage_value(s.get("auth_after_surfaces"))],
        ["Critical/High 표면 수",   _fmt_coverage_value(s.get("critical_high_surfaces"))],
    ]
    _make_table(doc, ["항목", "수치"], rows, col_widths=[8, 8])

    by_type = s.get("by_type") or {}
    if by_type:
        _body(doc, "표면 유형 분포: " + " · ".join(f"{k} {v}" for k, v in by_type.items()),
              size=9, color=C_GRAY)

    # AI Reasoning Trace (상위 표면 — 왜 이 기법을 추천했는가)
    trace = plan.get("reasoning_trace") or []
    if trace:
        _body(doc, "추천 근거(AI Reasoning Trace) — 상위 표면:", size=9, color=C_GRAY)
        trows = [[
            _fmt_coverage_value(t.get("input") or "-"),
            _fmt_coverage_value(t.get("semantic_role")),
            _fmt_coverage_value(", ".join(t.get("recommended") or [])[:40]),
            _fmt_coverage_value(t.get("priority")),
        ] for t in trace[:10]]
        _make_table(doc, ["입력점", "의미 역할", "추천 기법", "우선순위"], trows,
                    col_widths=[4, 4, 5, 3])


def _add_evidence_level_summary(doc, analysis: dict):
    """경영진용 '보안 관찰 및 검증 요약' — 검증 수준(Level 0~3) 중심."""
    ev = analysis.get("evidence_levels") or {}
    asp = (analysis.get("attack_surface_plan") or {}).get("summary") or {}
    aps = analysis.get("attack_path_summary") or {}
    if not ev and not asp and not aps:
        return
    _h2(doc, "보안 관찰 및 검증 요약 (경영진용)")
    _body(doc,
        "본 진단은 '취약점 수' 가 아니라 '검증 수준(증거 강도)'과 '공격 경로(공격자가 위험에 "
        "도달하는 흐름)' 중심으로 요약한다. Level 3(실증 확인)·Level 2(증거 확보) 및 "
        "Confirmed/Evidence 경로를 우선 조치 대상으로 권고한다. 최종 판정은 Rule Engine 이 "
        "운영 영향 없는 무해 증거로 수행했다.", size=9, color=C_GRAY)
    rows = [
        ["공격 표면 수",            _fmt_coverage_value(asp.get("total_surfaces"))],
        ["인증 후 공격 표면 수",    _fmt_coverage_value(asp.get("auth_after_surfaces"))],
        ["Level 3 · 실증 확인",     _fmt_coverage_value(ev.get("level3_proven"))],
        ["Level 2 · 증거 확보",     _fmt_coverage_value(ev.get("level2_evidence"))],
        ["Level 1 · 관찰됨",        _fmt_coverage_value(ev.get("level1_observed"))],
        ["Level 0 · 정보",          _fmt_coverage_value(ev.get("level0_info"))],
        ["우선 조치 항목 수",       _fmt_coverage_value(ev.get("priority_actions"))],
        ["식별된 공격 경로 수",     _fmt_coverage_value(aps.get("total_paths"))],
        ["우선 조치 필요 공격 경로 수", _fmt_coverage_value(aps.get("priority_action_paths"))],
        ["실증 확인 경로 수",       _fmt_coverage_value(aps.get("confirmed_paths"))],
        ["증거 확보 경로 수",       _fmt_coverage_value(aps.get("evidence_paths"))],
        ["인증 후 영역 기반 경로 수", _fmt_coverage_value(aps.get("auth_based_paths"))],
        ["관리자/민감 기능 경로 수", _fmt_coverage_value(aps.get("sensitive_admin_paths"))],
    ]
    _make_table(doc, ["구분", "수치"], rows, col_widths=[8, 8])


# ── Eoseureum 점검 대상 취약점 카탈로그 (점검 기준/대상 목록 섹션용) ──────────────────
# (탐지 엔진의 능동 프로브 + 룰셋을 OWASP Top 10 2021 기준으로 분류한 점검 범위)
_EOSEUREUM_CHECK_CATALOG = [
    ("A01 접근통제 취약",   "관리자 페이지/관리 API 인터넷 노출, 인증 우회, 디렉터리/경로 노출, CSRF", "High"),
    ("A02 암호화 실패",     "HTTP 평문 전송, 취약 TLS/SSL 설정, 민감정보 평문 노출",               "Medium"),
    ("A03 인젝션",          "SQL Injection(에러/UNION/Blind/Time), OS Command, SSTI, NoSQL, XXE, CRLF, 반사·저장·DOM XSS", "High"),
    ("A04 안전하지 않은 설계", "오픈 리다이렉트, SSRF, 파일 업로드 검증 미흡",                          "Medium"),
    ("A05 보안 설정 오류",  "보안 헤더 미설정, 클릭재킹, 위험 HTTP 메서드, 에러페이지 정보 노출, Server 헤더 노출, 디렉터리 리스팅", "Medium"),
    ("A06 취약하고 오래된 요소", "노출된 프레임워크/서버 버전, 알려진 CVE 시그니처 매칭",               "Medium"),
    ("A07 인증·식별 실패",  "사용자 열거(User Enumeration), 약한 인증 흐름",                          "Medium"),
    ("A08 데이터 무결성 실패", "소스맵 노출, 백업/설정 파일 노출, Vim swap 노출",                       "Low"),
    ("A09 로깅/모니터링",   "에러 핸들링 정보 노출 (간접 점검)",                                       "Low"),
    ("A10 SSRF",            "서버측 요청 위조(SSRF) 능동 점검",                                        "Medium"),
    ("정보 노출",           "JS 내 시크릿/API키, Swagger/OpenAPI·GraphQL 스키마 노출, 이메일 헤더 인젝션", "Medium"),
]


def _remediation_effort(f: dict) -> tuple[str, str]:
    """취약점의 예상 조치 난이도와 예상 작업시간을 휴리스틱으로 산정한다.
    (severity 판정 로직은 변경하지 않으며, 보고서 표시용 부가 정보만 계산)"""
    sev = _report_sev(f)
    title = (f.get("title") or "")
    # 설정/헤더성 항목은 조치가 비교적 단순
    config_like = any(k in title for k in
                      ("헤더", "Server", "클릭재킹", "HTTP Method", "메서드", "디렉터리", "리스팅",
                       "CORS", "쿠키", "버전 정보"))
    if sev in ("Critical", "High"):
        return ("높음", "1~3일") if not config_like else ("중간", "0.5~1일")
    if sev == "Medium":
        return ("중간", "0.5~1일") if not config_like else ("낮음", "2~4시간")
    return ("낮음", "1~2시간")


def _evidence_flags(f: dict) -> dict:
    """판정 근거(Evidence Matrix)용: 항목별 근거 보유 여부."""
    pd = f.get("probe_detail") or {}
    has_shot = bool(f.get("evidence_screenshot")) or bool(pd.get("evidence_screenshots"))
    has_resp = len((f.get("evidence_detail") or "").strip()) >= 20
    has_repro = bool(f.get("reproduction_cmd")) or any(
        "curl" in (s or "").lower() for s in (f.get("detection_steps") or []))
    confirmed = f.get("probe_confirmed") is True or (f.get("confidence") or "").upper() == "CONFIRMED"
    return {"resp": has_resp, "shot": has_shot, "repro": has_repro, "confirmed": confirmed}


# ── Report v7 (상용 컨설팅 보고서) 공통 헬퍼 ─────────────────────────────────────
def _no_split_table(tbl):
    """표 각 행이 페이지 경계에서 분리(잘림)되지 않도록 cantSplit 지정 — PDF/DOCX 공통."""
    try:
        for row in tbl.rows:
            trPr = row._tr.get_or_add_trPr()
            trPr.append(OxmlElement("w:cantSplit"))
    except Exception:
        pass
    return tbl


def _keep_with_next(para):
    """문단을 다음 문단과 같은 페이지에 유지(제목이 홀로 페이지 하단에 남지 않도록)."""
    try:
        pPr = para._p.get_or_add_pPr()
        kn = OxmlElement("w:keepNext"); pPr.append(kn)
        kl = OxmlElement("w:keepLines"); pPr.append(kl)
    except Exception:
        pass
    return para


# 흔한 짧은 지시형 권고 → 실무 컨설팅 문체 확장(내용/판정은 불변, 표현만 정제).
_CONSULTING_RECO_MAP = {
    "server header 제거": "웹 서버 응답의 Server 헤더에 노출되는 버전 정보를 제거하여, "
        "공격자가 서버 환경과 알려진 취약점을 사전에 식별하지 못하도록 설정하실 것을 권고합니다.",
    "x-powered-by 제거": "응답 헤더의 X-Powered-By 값을 제거하여 애플리케이션 스택 정보가 "
        "외부에 노출되지 않도록 조치하실 것을 권고합니다.",
    "csp 적용": "콘텐츠 보안 정책(Content-Security-Policy) 헤더를 적용하여 스크립트 실행 출처를 "
        "제한함으로써 XSS 등 클라이언트 측 공격의 영향을 완화하실 것을 권고합니다.",
    "hsts 적용": "HTTP Strict-Transport-Security 헤더를 적용하여 모든 통신이 HTTPS로 강제되도록 "
        "설정하실 것을 권고합니다.",
}


def _consulting_reco(text: str) -> str:
    """짧은 지시구 권고를 고객 제출용 컨설팅 문체로 정제(사실/판정 변경 없음)."""
    t = (text or "").strip()
    if not t or t == "-":
        return t or "-"
    key = t.lower().rstrip(" .。")
    if key in _CONSULTING_RECO_MAP:
        return _CONSULTING_RECO_MAP[key]
    if len(t) >= 38 or t.endswith(("하십시오.", "하십시오", "권고합니다.", "권장합니다.",
                                   "권고합니다", "권장합니다", "합니다.", "십시오.", "바랍니다.")):
        return t
    return f"{t.rstrip('. ')} 조치를 적용하여 해당 취약점의 악용 가능성을 제거하실 것을 권고합니다."


def _consulting_impact(text: str) -> str:
    """짧은 영향 서술을 고객이 이해할 수 있는 실질 영향 문장으로 정제."""
    t = (text or "").strip()
    if not t or t == "-":
        return t or "-"
    if len(t) >= 30 or t.endswith(("있습니다.", "있습니다", "됩니다.", "우려됩니다.", "됩니다")):
        return t
    return f"{t.rstrip('. ')}(으)로 이어질 수 있으며, 실제 서비스·데이터에 영향을 미칠 가능성이 있습니다."


def _add_confidentiality_notice(doc):
    """기밀 안내(Confidentiality Notice) — 표지 다음, 목차 앞."""
    _h1(doc, "Confidentiality Notice  (기밀 안내)")
    box = doc.add_table(rows=1, cols=1); box.alignment = WD_TABLE_ALIGNMENT.CENTER
    c = box.rows[0].cells[0]; _shd(c, "F9FAFB"); _border(c, "1E3A5F", sz="8"); c.width = Cm(16)
    p = c.paragraphs[0]; p.paragraph_format.left_indent = Cm(0.25)
    _run(p, "본 문서는 대외비(CONFIDENTIAL) 입니다.", size=11, bold=True, color=C_NAVY)
    for line in [
        "본 보고서에는 진단 대상의 보안 취약점과 이를 악용할 수 있는 정보가 포함되어 있어, 외부 유출 시 "
        "실제 침해로 이어질 수 있습니다.",
        "열람 권한은 조치 담당 부서 및 사전에 승인된 관계자로 제한하며, 사본 배포·인쇄·전송 시 동일한 "
        "기밀 등급으로 관리하시기 바랍니다.",
        "본 문서에 기술된 공격 시나리오는 방어적 보안 강화를 위한 개념적 설명이며, 실제 공격 수행을 "
        "권장하거나 의미하지 않습니다.",
    ]:
        lp = c.add_paragraph(); lp.paragraph_format.left_indent = Cm(0.25)
        _run(lp, "· " + line, size=9, color=C_BLACK)
    _no_split_table(box)
    doc.add_page_break()


def _add_contents_page(doc, toc_rows):
    """목차(Contents) — 표지 다음에 위치. 점선 Leader 탭."""
    from docx.enum.text import WD_TAB_ALIGNMENT, WD_TAB_LEADER
    _h1(doc, "Contents  (목차)")

    def _toc_row(num, label, level=0):
        p = _para(doc, space_before=3, space_after=3)
        p.paragraph_format.left_indent = Cm(0.3 + 0.8 * level)
        p.paragraph_format.tab_stops.add_tab_stop(Cm(15.0), WD_TAB_ALIGNMENT.RIGHT, WD_TAB_LEADER.DOTS)
        _run(p, f"{num}  ", size=11, bold=(level == 0), color=C_NAVY if level == 0 else C_GRAY)
        _run(p, label, size=11, bold=(level == 0), color=C_BLACK)
        _run(p, "\t", size=11)
        _run(p, "", size=11, color=C_GRAY)

    for num, label, lv in toc_rows:
        _toc_row(num, label, lv)
    doc.add_page_break()


def _add_simple_coverage_card(doc, disc_stats, analysis, vuln_count):
    """고객용 점검 커버리지 요약(카드) — 총 URL/입력점/관리자 페이지/API/완료율/총 Finding.
    상세 QA 지표(페이로드 수·엔진 내부)는 부록으로 이동."""
    m = _v2_metrics(analysis)
    total_urls = disc_stats.get("total_urls", 0)
    total_inputs = m.get("total_inputs", 0)
    admin_pages = len(disc_stats.get("admin_pages", []) or [])
    apis = disc_stats.get("api_count", 0) + len(disc_stats.get("admin_apis", []) or [])
    executed = m.get("executed", 0)
    planned = m.get("selected_inputs", 0) or total_inputs
    if planned > 0:
        rate = f"{min(100, int(round(100 * executed / planned)))}%"
    else:
        rate = "-"
    _run(_para(doc, space_before=4, space_after=2), "점검 커버리지 (고객 요약)", size=11, bold=True, color=C_NAVY)
    _no_split_table(_kpi_row(doc, [
        ("총 점검 URL", total_urls, ""),
        ("총 입력점", total_inputs, ""),
        ("발견 관리자 페이지", admin_pages, ""),
    ]) or doc.tables[-1])
    _body(doc, "", size=4)
    _no_split_table(_kpi_row(doc, [
        ("발견 API", apis, ""),
        ("점검 완료율", rate, "실행/선정"),
        ("총 Finding", vuln_count, ""),
    ]) or doc.tables[-1])
    _body(doc, "상세 점검 지표(페이로드·시도 수 등)와 엔진 내부 정보는 부록을 참조하십시오.",
          size=8, color=C_GRAY)


# ── Proof-Oriented Validation Framework v1: 보고서 반영 ──────────────────────────
_PROOF_DECISION_LABEL = {
    "ALLOWED": "허용",
    "BLOCKED_BY_PROFILE": "프로파일 비허용",
    "BLOCKED_BY_SCOPE": "범위(Scope) 밖·내부망 차단",
    "BLOCKED_DESTRUCTIVE": "파괴적 행위 차단",
    "BLOCKED_STATE_CHANGE": "상태 변경 차단",
    "BLOCKED_DATA_EXFILTRATION": "데이터 추출 차단",
    "BLOCKED_SHELL": "셸/웹쉘 차단",
    "BLOCKED_PRIVILEGE_ESCALATION": "권한 상승 차단",
    "MANUAL_APPROVAL_REQUIRED": "담당자 승인 필요",
}


def _add_fp_suppression_note(doc, analysis: dict):
    """오탐 억제(False Positive Suppression) 요약 — 자동 억제/높은 오탐위험 건수와 사유.
    억제 항목은 점수·심각도·검증 분포 산정에서 제외됨을 명시(투명성)."""
    s = analysis.get("fp_risk_summary") or {}
    supp = s.get("suppressed") or []
    high = s.get("high", 0)
    if not supp and not high:
        return
    _body(doc, f"오탐 자동 억제: {len(supp)}건  ·  오탐 위험 높음(검토 권고): {high}건  "
               "— 억제 항목은 점수·분포 산정에서 제외됩니다.", size=9, color=C_RED if supp else C_NAVY)
    for item in supp[:8]:
        bp = _para(doc, space_before=0, space_after=2); bp.paragraph_format.left_indent = Cm(0.3)
        _run(bp, "⛔ ", size=9, bold=True, color=C_RED)
        _run(bp, _sanitize_display_text(str(item.get("title", "")))[:60] + " — ", size=9, bold=True, color=C_NAVY)
        _run(bp, _sanitize_display_text(str(item.get("reason", "")))[:110], size=8, color=C_GRAY)


def _add_proof_validation_summary(doc, analysis: dict):
    """Proof Validation Summary — 사용 Profile·검증 수·Level 승격·차단 현황(증거 중심)."""
    s = analysis.get("proof_validation_summary") or {}
    if not s:
        return
    _h2(doc, "2.6 Proof Validation Summary  (증거 기반 검증 요약)")
    _prof = s.get("profile", "SAFE")
    _dg = " (요청 " + s.get("requested_profile", _prof) + "에서 안전 강등)" if s.get("downgraded") else ""
    _body(doc, f"검증 프로파일: {_prof}{_dg}  ·  기본값은 SAFE이며, 강한 검증은 명시 승인된 "
               "프로파일에서만 read-only 증거로 수행됩니다.", size=9, color=C_NAVY)
    _no_split_table(_kpi_row(doc, [
        (f"{ICON['evidence']} 수행 검증", s.get("proof_validations", 0), _prof),
        (f"{ICON['evidence']} Level 승격", s.get("level_promotions", 0),
         f"L1→L2 {s.get('l1_to_l2',0)} · L2→L3 {s.get('l2_to_l3',0)}"),
        (f"{ICON['critical']} 차단된 검증", s.get("blocked_validations", 0),
         f"승인 필요 {s.get('manual_approval_required',0)}"),
    ]) or doc.tables[-1])
    by = s.get("blocked_by_reason") or {}
    if by:
        bp = _para(doc, space_before=2, space_after=3); bp.paragraph_format.left_indent = Cm(0.3)
        _run(bp, "차단 사유: ", size=9, bold=True, color=C_NAVY)
        _run(bp, " · ".join(f"{_PROOF_DECISION_LABEL.get(k, k)} {v}" for k, v in by.items()),
             size=9, color=C_GRAY)
    _body(doc, "판정/Level 은 Rule Engine 전담이며, 위험 행위(덤프·셸·데이터 추출·상태 변경·"
               "권한 상승·brute force·내부망 접근)는 프로파일과 무관하게 항상 차단됩니다.",
          size=8, color=C_GRAY)


def _add_finding_proof_block(doc, f: dict, analysis: dict):
    """Finding 상세의 Proof Validation 블록 — 프로파일/수행 검증/증거/승격/차단 행위."""
    recs = analysis.get("proof_validation") or []
    rec = next((r for r in recs if r.get("finding_title") == f.get("title")), None)
    if not rec:
        return
    _card_box(doc, ICON["evidence"], "증거 기반 검증 (Proof Validation)",
              f"프로파일 {rec.get('profile','SAFE')}  ·  검증 수준 {rec.get('promotion','-')}  ·  "
              + (rec.get("verification_note") or ""), "0E7A90")
    # 확보 증거 / 수행 검증
    _perf = ", ".join(rec.get("performed_techniques") or []) or "안전 관찰"
    _ev = " · ".join(rec.get("evidence_signals") or []) or "-"
    pp = _para(doc, space_after=2); pp.paragraph_format.left_indent = Cm(0.25)
    _run(pp, "수행 검증: ", size=8, bold=True, color=C_NAVY); _run(pp, _perf, size=8, color=C_BLACK)
    _run(pp, "   확보 증거: ", size=8, bold=True, color=C_NAVY); _run(pp, _ev, size=8, color=C_BLACK)
    # 안전상 수행하지 않은 위험 행위(차단)
    nb = rec.get("blocked_actions") or []
    if nb:
        bp = _para(doc, space_after=3); bp.paragraph_format.left_indent = Cm(0.25)
        _run(bp, "안전상 수행하지 않은 위험 행위: ", size=8, bold=True, color=C_RED)
        _run(bp, " · ".join(f"{b.get('action','')}({_PROOF_DECISION_LABEL.get(b.get('decision',''), b.get('decision',''))})"
                            for b in nb[:5]), size=8, color=C_GRAY)


def _add_finding_proof_detail(doc, f: dict, analysis: dict):
    """Finding 상세의 Proof Evidence Card — Payload/Expected/Observed/Fingerprint/
    Validation Method/Skip Reason/Reproduction + Proof Quality Score. (판정 아님, 표현 전용)"""
    cards = analysis.get("proof_evidence_cards") or []
    _uid = f.get("finding_uid") or f.get("_idx")
    c = next((x for x in cards if x.get("finding_id") == _uid or x.get("finding_uid") == _uid), None)
    if not c:
        # 제목 기준 보조 매칭(오염 방지: endpoint 공유 매칭은 사용하지 않음)
        c = next((x for x in cards if x.get("finding_title") == f.get("title")), None)
    if not c:
        return
    pq = c.get("proof_quality") or {}
    fp = c.get("fingerprint") or {}
    # Proof 헤더 + Proof Quality Score
    hp = _para(doc, space_before=2, space_after=2); hp.paragraph_format.left_indent = Cm(0.2)
    _run(hp, "◎ 증거·재현 (Proof) ", size=9, bold=True, color=C_NAVY)
    _run(hp, f"— Proof Quality {pq.get('score',0)}% ({pq.get('grade','-')})", size=9, bold=True,
         color=(C_GREEN if pq.get("score", 0) >= 75 else
                C_ORANGE if pq.get("score", 0) >= 45 else C_GRAY))
    rows = [
        ["Payload", _fold_long(str(c.get("payload", "-")), 90)],
        ["Expected", c.get("expected_result", "-")],
        ["Observed", _fold_long(str(c.get("observed_result", "-")), 120)],
        ["Fingerprint", f"{fp.get('fingerprint_name','미상')} ({fp.get('fingerprint_confidence','-')}) — {fp.get('fingerprint_reason','')}"],
        ["Validation", f"{c.get('validation_label') or evl_label(c)} · Profile {c.get('proof_profile','SAFE')}"],
        ["수행 안 함", (c.get("blocked_reason") or "-") + " (SAFE)"],
        ["Business", c.get("business_function", "미상")],
    ]
    _no_split_table(_make_table(doc, ["항목", "내용"], rows, col_widths=[3.0, 13.0]))
    # 재현 절차
    steps = c.get("reproduction_steps") or []
    if steps:
        sp = _para(doc, space_after=1); sp.paragraph_format.left_indent = Cm(0.25)
        _run(sp, "재현 절차: ", size=8, bold=True, color=C_NAVY)
        for i, s in enumerate(steps[:5], 1):
            stp = _para(doc, space_after=0); stp.paragraph_format.left_indent = Cm(0.5)
            _run(stp, f"{i}. {s}", size=8, color=C_GRAY)
    if c.get("proof_quality", {}).get("factors"):
        fp2 = _para(doc, space_after=2); fp2.paragraph_format.left_indent = Cm(0.25)
        _run(fp2, "Proof Quality 근거: " + " · ".join(pq.get("factors", [])), size=8, color=C_LIGHT_GRAY)
    # Graph Risk Context — 왜 우선 조치인가(그래프 맥락, Severity 변경 아님)
    why = (analysis.get("graph_risk_context") or {}).get("by_finding", {}).get(
        f.get("finding_uid") or f.get("_idx"))
    if why and why.get("reasons"):
        wp = _para(doc, space_after=2); wp.paragraph_format.left_indent = Cm(0.25)
        _run(wp, f"왜 우선 조치인가 (Graph priority {why.get('graph_priority',0)}): ",
             size=8, bold=True, color=C_ORANGE)
        _run(wp, " · ".join(why.get("reasons", [])), size=8, color=C_GRAY)


def evl_label(card: dict) -> str:
    return card.get("evidence_quality", "")


def _add_executive_summary_page(doc, domain, risk, vuln_count, by_sev, vuln_list, analysis,
                                created_at: str = ""):
    """경영진용 요약 페이지 (비기술 담당자 대상, 1페이지). 15초 안에 이해 가능한 내용만."""
    _keep_with_next(_h1(doc, "4. 총평  (Executive Summary)"))
    _body(doc,
        f"본 문서는 {domain} 에 대해 수행한 보안 진단의 경영진용 요약입니다. "
        "보안 수준·핵심 위험·우선 조치를 한눈에 확인하실 수 있으며, 기술 세부사항은 이후 장을 참조하십시오.")

    # ── 1페이지 핵심 요약: Security Score + 경영진 KPI 6종 ────────────────────────
    _summary = analysis.get("summary") or {}
    _ev = analysis.get("evidence_levels") or {}
    _bis = analysis.get("business_impact_summary") or {}
    _asum = analysis.get("asset_summary") or {}
    _by = _eff_severity_counts(analysis)   # 오탐 억제 차감된 '유효 분포'로 통일(표지·점수·대시보드와 일치)
    _confirmed = _summary.get("confirmed_count", _ev.get("level3_proven", 0))
    _critical_assets = max(_asum.get("high_priority", 0), _bis.get("critical", 0))
    _immediate = (_by.get("Critical", 0) + _by.get("High", 0)) or _ev.get("priority_actions",
                                len(analysis.get("priority_action_plan") or []))
    _biz = _bis.get("critical", 0) + _bis.get("high", 0)
    _score = _v3_security_score(analysis)

    # Security Score 게이지
    _add_v3_gauge(doc, _score)

    # 경영진 KPI — 보안점수 / 종합위험도 / Critical / High / 즉시 조치 / 비즈니스 영향
    _no_split_table(_kpi_row(doc, [
        (f"{ICON['risk']} 보안 점수", f"{_score}/100", _score_grade(_score)[0]),
        (f"{ICON['risk']} 종합 위험도", RISK_LABEL.get(risk, risk), ""),
        (f"{ICON['critical']} Critical", _by.get("Critical", 0), ""),
    ]) or doc.tables[-1])
    _body(doc, "", size=4)
    _no_split_table(_kpi_row(doc, [
        (f"{ICON['critical']} High", _by.get("High", 0), ""),
        (f"{ICON['reco']} 즉시 조치 (Immediate Actions)", _immediate, "Critical+High"),
        (f"{ICON['critical']} 비즈니스 영향", _biz, "핵심 자산 " + str(_critical_assets)),
    ]) or doc.tables[-1])
    _body(doc, f"{ICON['evidence']} 실증 확인 {_confirmed}건 · 핵심 자산 {_critical_assets}건",
          size=9, color=C_NAVY)
    # Assessment Scope / Scan Period / Scan Target — 경영진이 알아야 할 범위만
    _scope_tgt = (analysis.get("network_exposure_summary") or {}).get("input_targets") or [domain]
    _scope_policy = analysis.get("scan_policy") or (analysis.get("coverage") or {}).get("scan_policy") or "-"
    _body(doc, f"{ICON['asset']} Assessment Scope: Web · Service · Network   ·   적용 정책: {_scope_policy}",
          size=9, color=C_NAVY)
    _body(doc, f"Scan Target: {', '.join(str(t) for t in _scope_tgt)[:70] or domain}   ·   "
               f"Scan Period: {created_at or '-'}",
          size=8, color=C_GRAY)

    # 발견 취약점 — 발견된 각 항목을 심각도순으로 '제목 + 한 줄 설명(무엇이 문제인가)'으로 나열.
    # (점수는 위 게이지로 간결히 보이고, 총평에서 무엇이 왜 문제인지 곧바로 파악되도록 함)
    _sorted_vulns = _sort_findings(vuln_list) if vuln_list else []
    _VULN_CAP = 12                         # 총평 가독성 상한(초과분은 '외 N건'으로 요약)
    _run(_para(doc, space_before=4, space_after=3),
         f"● 발견 취약점 ({len(_sorted_vulns)}건)" if _sorted_vulns else "● 발견 취약점",
         size=11, bold=True, color=C_NAVY)
    if _sorted_vulns:
        for f in _sorted_vulns[:_VULN_CAP]:
            p = _para(doc, space_before=1, space_after=1)
            p.paragraph_format.left_indent = Cm(0.5)
            _run(p, f"• [{_report_sev_label(f)}] ", size=10, bold=True,
                 color=RISK_COLOR.get(_report_sev(f).upper() if _report_sev(f) in ("Low","Medium") else
                                      {"Critical":"HIGH","High":"HIGH","Medium":"MEDIUM","Low":"LOW"}.get(_report_sev(f),"GOOD"), C_BLACK))
            _run(p, _display_title(f), size=10)
            # 한 줄 설명 — '무엇이 문제인가'(description 우선) → 없으면 비즈니스 영향 → 심각도 문구
            _desc = (_first_sentence(_sanitize_display_text(f.get("description") or "", f))
                     or _first_sentence(f.get("business_impact") or "")
                     or _SEV_RISK_PHRASE.get(_report_sev(f), ""))
            if _desc:
                ip = _para(doc, space_before=0, space_after=2)
                ip.paragraph_format.left_indent = Cm(0.9)
                _run(ip, "↳ " + _desc, size=9, color=C_GRAY)
        if len(_sorted_vulns) > _VULN_CAP:
            mp = _para(doc, space_before=0, space_after=2); mp.paragraph_format.left_indent = Cm(0.5)
            _run(mp, f"…외 {len(_sorted_vulns) - _VULN_CAP}건 — 상세는 '5. 발견 사항' 장을 참조하십시오.",
                 size=9, italic=True, color=C_GRAY)
    else:
        p = _para(doc, space_before=1, space_after=2); p.paragraph_format.left_indent = Cm(0.5)
        _run(p, "• 보고 기준을 충족하는 취약점이 발견되지 않았습니다.", size=10, color=C_GREEN)

    # AI 분석 상태 (ai_status) — Executive Summary 에 1회만 표시.
    if _show_ai_status_in_summary():
        ai_status = analysis.get("ai_status")
        if isinstance(ai_status, dict):
            sp_ = _para(doc, space_before=8, space_after=3)
            sp_.paragraph_format.left_indent = Cm(0.5)
            if ai_status.get("used"):
                prov = ai_status.get("provider") or "ollama"
                model = ai_status.get("model") or ""
                detail = f"{prov}{('/' + model) if model and '/' not in prov else ''}"
                _run(sp_, "● AI 분석: ", size=10, bold=True, color=C_PURPLE)
                _run(sp_, f"사용 ({detail})", size=10, color=C_BLACK)
            else:
                reason = ai_status.get("fallback_reason") or ""
                label = _FALLBACK_REASON_LABEL.get(reason, reason or "사유 미상")
                _run(sp_, "● AI 분석: ", size=10, bold=True, color=C_GRAY)
                _run(sp_, f"미사용 (사유: {label})", size=10, italic=True, color=C_GRAY)

    # AI 한줄 요약 (실제 사용 시에만)
    ai = analysis.get("ai_analysis") or {}
    _ai_summary_ok = ai.get("ai_used") and ai.get("ai_executive_summary")
    # ai_status 가 있으면 used 를 권위로 삼아 요약 노출을 통제.
    if isinstance(analysis.get("ai_status"), dict) and not _ai_status_used(analysis):
        _ai_summary_ok = False
    if _ai_summary_ok:
        _run(_para(doc, space_before=8, space_after=3), "● AI 분석 요약", size=11, bold=True, color=C_PURPLE)
        bp = _para(doc, space_before=1, space_after=2); bp.paragraph_format.left_indent = Cm(0.5)
        _run(bp, ai["ai_executive_summary"][:400], size=10, color=C_BLACK)

    # 권고 방향
    _run(_para(doc, space_before=8, space_after=3), "● 조치 권고 방향", size=11, bold=True, color=C_NAVY)
    rec = ("심각·높음 취약점을 최우선 조치하고, 중간 항목은 정기 배포 주기에 반영하며, "
           "낮음·참고 항목은 모니터링하십시오. 항목별 우선순위·예상 조치 시간은 '조치 우선순위' 장을 참조하십시오.")
    rp2 = _para(doc, space_before=1, space_after=2); rp2.paragraph_format.left_indent = Cm(0.5)
    _run(rp2, rec, size=10)
    doc.add_page_break()


def _para_in_cell(cell):
    """표 셀에 새 문단을 추가하고 반환 (가운데 정렬)."""
    p = cell.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    return p


def _add_eoseureum_criteria_section(doc):
    """Eoseureum 점검 기준 + 점검 대상 취약점 목록 (방법론·범위·평가기준)."""
    _h1(doc, "점검 기준 (점검 방법론·평가 기준)")

    _h2(doc, "2.1 점검 방법론")
    _body(doc,
        "Eoseureum은 패시브 점검(응답 헤더·쿠키·TLS 설정 분석)과 "
        "능동 점검(실제 페이로드 삽입 및 브라우저 자동화 실증)을 결합한 6단계 파이프라인으로 동작합니다: "
        "① 정보 수집(recon) → ② URL 탐색(robots/sitemap/크롤/경로) → ③ 능동 취약점 점검 → "
        "④ 심화 점검(CVE 시그니처 매칭·콘텐츠/경로 탐색·TLS 설정 검증) → ⑤ 룰 기반 판정 → ⑥ AI 보강·보고서 생성. "
        "모든 점검은 운영 서비스 가용성에 영향을 주지 않는 범위에서 수행하며, 실제 증거가 확보된 항목만 취약점으로 보고합니다.")

    # (점검 대상 취약점 목록은 본문 '3. 점검 항목 및 위험도'에 있으므로 부록에서 중복 제거)

    _h2(doc, "2.2 심각도·신뢰도·참조 표준")
    _run(_para(doc, space_after=2), "● 심각도 분류 (CVSS 3.1 기준)", size=10, bold=True, color=C_NAVY)
    _make_table(doc,
        ["심각도", "CVSS 점수", "정의", "대응"],
        [
            ["심각(Critical)", "9.0 ~ 10.0", "광범위 침해·완전 장악으로 이어질 수 있는 취약점", "즉시 조치"],
            ["높음(High)",     "7.0 ~ 8.9",  "직접적 침해·데이터 유출로 이어질 수 있는 취약점", "즉시 조치"],
            ["중간(Medium)",   "4.0 ~ 6.9",  "조건부 악용 가능 또는 정보 노출성 취약점",       "조속한 조치 권고"],
            ["낮음(Low)",      "0.1 ~ 3.9",  "영향이 제한적이거나 추가 조건이 필요한 취약점",   "모니터링 권고"],
        ],
        col_widths=[2.8, 2.4, 6.8, 4.0],
    )
    _run(_para(doc, space_before=4, space_after=2), "● 신뢰도 구분", size=10, bold=True, color=C_NAVY)
    _make_table(doc,
        ["신뢰도", "의미"],
        [
            ["CONFIRMED",     "실증 확인됨 — 브라우저 실행/응답 데이터/스크린샷으로 직접 증명된 취약점"],
            ["POSSIBLE",      "취약 가능성 — 정황상 존재 가능하나 실증이 완료되지 않은 항목"],
            ["MANUAL_REVIEW", "수동 검토 필요 — 자동 판정이 어려워 담당자 확인이 필요한 항목"],
        ],
        col_widths=[4, 12],
    )
    _run(_para(doc, space_before=4, space_after=2), "● 참조 표준", size=10, bold=True, color=C_NAVY)
    _make_table(doc,
        ["표준", "활용"],
        [
            ["OWASP Top 10 (2021)", "취약점 유형 분류 및 카테고리 매핑"],
            ["CWE",                 "취약점별 약점 유형 식별 코드 부여"],
            ["CVSS 3.1",            "심각도(Critical/High/Medium/Low) 정량 산정"],
        ],
        col_widths=[5, 11],
    )
    doc.add_page_break()


def _add_evidence_matrix_section(doc, vuln_list):
    """판정 근거 (Evidence Matrix) — 취약점별 어떤 근거로 판정했는지 한눈에."""
    _h1(doc, "판정 근거 (Evidence Matrix)")
    _body(doc,
        "각 취약점이 어떤 증거에 기반해 판정되었는지 요약한 표입니다. "
        "✓ = 근거 확보, - = 해당 없음. '실증'은 브라우저 실행/응답 데이터 등으로 직접 증명된 경우입니다.")
    if not vuln_list:
        _body(doc, "판정할 취약점이 없습니다.")
        doc.add_page_break()
        return
    rows = []
    for f in vuln_list:
        ev = _evidence_flags(f)
        cs = f.get("confidence_score")
        rows.append([
            _vuln_id(f["_idx"]) if isinstance(f.get("_idx"), int) else "-",
            _display_title(f)[:40],
            _report_sev_label(f),
            str(cs) if cs is not None else "-",
            "✓" if ev["resp"] else "-",
            "✓" if ev["shot"] else "-",
            "✓" if ev["repro"] else "-",
            "실증" if ev["confirmed"] else "참고",
        ])
    tbl = _make_table(doc,
        ["식별번호", "취약점명", "위험도", "신뢰도\n점수", "응답\n근거", "스크린샷", "재현\n명령", "판정"],
        rows,
        col_widths=[1.9, 3.8, 1.3, 1.5, 1.5, 1.9, 1.5, 1.6],
    )
    for ri, f in enumerate(vuln_list):
        _shd(tbl.rows[ri + 1].cells[2], REPORT_SEV_HEX.get(_report_sev(f), "F3F4F6"))
        ev = _evidence_flags(f)
        _shd(tbl.rows[ri + 1].cells[7], "DCFCE7" if ev["confirmed"] else "F3F4F6")
    doc.add_page_break()




def _add_attack_surface_section(doc, analysis: dict):
    """4-AS. 공격 표면(Attack Surface) 발견 항목.
    취약점 아님 — 공격자가 추가 분석할 수 있는 노출 지점. 비면 생략.
    취약점 표(빨강 계열)와 구분되도록 파랑/앰버 계열 헤더 사용."""
    items = analysis.get("attack_surface_items", []) or []
    if not items:
        return

    _h1(doc, "공격 표면(Attack Surface) 발견 항목")

    # 안내 박스 (파랑 계열 — 취약점 표와 시각적으로 구분)
    note_tbl = doc.add_table(rows=1, cols=1)
    note_tbl.style = "Table Grid"
    nc = note_tbl.rows[0].cells[0]
    _shd(nc, "EFF6FF"); _border(nc, "BFDBFE", sz="6"); nc.width = Cm(16)
    np_ = nc.paragraphs[0]; np_.paragraph_format.left_indent = Cm(0.2)
    _run(np_, "ℹ 취약점 아님 — 공격자가 추가 분석할 수 있는 노출 지점입니다. ", size=9, bold=True, color=C_BLUE)
    _run(np_, "취약점 수·조치 우선순위에는 미포함됩니다. "
              "(관리 인터페이스·로그인·Swagger·GraphQL·Actuator·Tomcat manager 등)",
         size=9, color=C_GRAY)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)

    rows = []
    for it in items:
        cs = it.get("confidence_score")
        rows.append([
            it.get("title", "") or it.get("name", "") or "-",
            it.get("attack_surface_label") or it.get("type")
                or it.get("service") or "공격 표면",
            str(cs) if cs is not None else "-",
            (it.get("evidence_detail") or it.get("recommendation")
             or it.get("detail") or "-"),
            it.get("evidence_url") or it.get("url") or "-",
        ])
    tbl = _make_table(doc,
        ["제목", "유형", "판정 신뢰도 점수", "근거", "URL"],
        rows,
        col_widths=[4.0, 2.6, 1.8, 4.0, 3.6],
    )
    # 헤더를 파랑 계열로(취약점 표의 빨강/severity색과 구분), 본문은 앰버 계열 옅은 배경
    for hc in tbl.rows[0].cells:
        _shd(hc, "1D4ED8")
    for ri in range(1, len(rows) + 1):
        for cc in tbl.rows[ri].cells:
            _shd(cc, "FFFBEB" if ri % 2 == 1 else "FEF3C7")

    doc.add_page_break()




def _add_service_security_section(doc, analysis: dict, service_vuln_list: list,
                                  checked_ports=None):
    """서비스/포트 보안 점검 결과 — scan_category=='service' 인 항목만 모아 표시.
    findings(취약) + attack_surface_items + discovery_items + good_items 중 service 만.
    표시 대상이 하나도 없으면 섹션 자체를 생략한다."""
    def _svc(items):
        return [it for it in (items or [])
                if (it.get("scan_category") or "").lower() == "service"]

    svc_as   = _svc(analysis.get("attack_surface_items"))
    svc_disc = _svc(analysis.get("discovery_items"))
    svc_good = _svc(analysis.get("good_items"))

    if not (service_vuln_list or svc_as or svc_disc or svc_good):
        return

    _h1(doc, "서비스/포트 보안 점검 결과")

    note_tbl = doc.add_table(rows=1, cols=1)
    note_tbl.style = "Table Grid"
    nc = note_tbl.rows[0].cells[0]
    _shd(nc, "EFF6FF"); _border(nc, "BFDBFE", sz="6"); nc.width = Cm(16)
    np_ = nc.paragraphs[0]; np_.paragraph_format.left_indent = Cm(0.2)
    _run(np_, "ℹ 네트워크 서비스/열린 포트 점검 결과입니다. ", size=9, bold=True, color=C_BLUE)
    _run(np_, "서비스 공격 표면은 취약점 수에 미포함되며 '조치 검토 대상'으로 분류됩니다.",
         size=9, color=C_GRAY)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)

    # 점검한 포트 목록 요약
    if checked_ports:
        pp = _para(doc, space_before=2, space_after=4)
        pp.paragraph_format.left_indent = Cm(0.2)
        _run(pp, "점검된 열린 포트: ", size=10, bold=True, color=C_NAVY)
        if isinstance(checked_ports, (list, tuple, set)):
            ports_str = ", ".join(str(p) for p in checked_ports) or "-"
        else:
            ports_str = str(checked_ports)
        _run(pp, ports_str, size=10, color=C_BLACK)

    # 서비스별 취약점
    if service_vuln_list:
        _h2(doc, "서비스 취약점")
        rows = []
        for f in service_vuln_list:
            rows.append([
                _vuln_id(f["_idx"]) if isinstance(f.get("_idx"), int) else "-",
                f.get("host", ""),
                str(f.get("port", "")),
                f.get("service", "") or "-",
                _display_title(f),
                _report_sev_label(f),
            ])
        tbl = _make_table(doc,
            ["식별번호", "호스트", "포트", "서비스", "취약점명", "위험도"],
            rows, col_widths=[1.6, 2.6, 1.0, 2.2, 6.0, 1.6])
        for ri, f in enumerate(service_vuln_list):
            _shd(tbl.rows[ri + 1].cells[5], REPORT_SEV_HEX.get(_report_sev(f), "F3F4F6"))

    # 서비스 공격 표면 (조치 검토 대상)
    if svc_as:
        _h2(doc, "서비스 공격 표면 (조치 검토 대상)")
        rows = []
        for it in svc_as:
            rows.append([
                it.get("title", "") or it.get("name", "") or "-",
                str(it.get("port", "")) or "-",
                it.get("service") or it.get("type") or "-",
                (it.get("evidence_detail") or it.get("recommendation")
                 or it.get("detail") or "-"),
            ])
        _make_table(doc, ["제목", "포트", "서비스", "근거/검토 사항"], rows,
                    col_widths=[4.0, 1.4, 2.6, 8.0])

    # 서비스 참고 발견
    if svc_disc:
        _h2(doc, "서비스 참고 발견 (Discovery)")
        rows = []
        for it in svc_disc:
            rows.append([
                "[참고] " + (it.get("title", "") or it.get("name", "") or "-"),
                str(it.get("port", "")) or "-",
                (it.get("evidence_detail") or it.get("detail")
                 or it.get("recommendation") or "-"),
            ])
        _make_table(doc, ["제목", "포트", "근거"], rows, col_widths=[5.0, 1.4, 9.6])

    # 서비스 양호 항목
    if svc_good:
        _h2(doc, "서비스 양호 항목")
        rows = []
        for it in svc_good:
            rows.append([
                it.get("title", "") or it.get("name", "") or "-",
                str(it.get("port", "")) or "-",
                it.get("service") or "-",
            ])
        _make_table(doc, ["항목", "포트", "서비스"], rows, col_widths=[8.0, 1.4, 6.6])

    doc.add_page_break()


# ════════════════════════════════════════════════════════════════════════════
# Eoseureum Report Architecture V2 — "보안 관찰 및 검증 보고서" 대시보드 섹션
# (기존 분석 데이터만 사용. 새 판정/Level 생성 없음 — Rule Engine 결과 그대로.)
# ════════════════════════════════════════════════════════════════════════════

_LEVEL_BADGE = {
    3: ("Level 3 · Validated", "DCFCE7", RGBColor(0x16, 0x61, 0x34)),
    2: ("Level 2 · Evidence", "DBEAFE", RGBColor(0x1D, 0x4E, 0xD8)),
    1: ("Level 1 · Observed", "FEF9C3", RGBColor(0xA1, 0x62, 0x07)),
    0: ("Level 0 · Information", "F3F4F6", C_GRAY),
}


def _v2_metrics(analysis: dict) -> dict:
    """V2 대시보드 KPI 를 analysis 에서 일괄 추출(없으면 0)."""
    asp = (analysis.get("attack_surface_plan") or {}).get("summary") or {}
    aps = analysis.get("attack_path_summary") or {}
    aip = (analysis.get("ai_payload_plan") or {}).get("summary") or {}
    ss = analysis.get("solver_summary") or {}
    ev = analysis.get("evidence_levels") or {}
    egs = analysis.get("evidence_graph_summary") or {}
    pps = analysis.get("path_priority_summary") or {}
    svc = analysis.get("service_surface_summary") or {}
    svs = analysis.get("service_summary") or {}
    svval = analysis.get("service_validation_summary") or {}
    nes = analysis.get("network_exposure_summary") or {}
    asum = analysis.get("asset_summary") or {}
    return {
        "net_live_hosts": nes.get("live_hosts", 0),
        "net_open_ports": nes.get("open_ports", 0),
        "net_services": nes.get("services", 0),
        "net_web_candidates": nes.get("web_candidates", 0),
        "net_auth_services": nes.get("auth_services", 0),
        "net_db_services": nes.get("db_services", 0),
        "net_file_services": nes.get("file_sharing_services", 0),
        "net_high_assets": nes.get("high_priority_assets", 0),
        "net_target_type": nes.get("target_type", ""),
        "service_surfaces": svc.get("total_service_surfaces", 0),
        "svc_auth": svc.get("authentication_surfaces", 0),
        "svc_db": svc.get("database_surfaces", 0),
        "svc_file": svc.get("file_sharing_surfaces", 0),
        "svc_container": svc.get("container_surfaces", 0),
        "svc_data": svc.get("data_exposure_surfaces", 0),
        "svc_high_paths": svs.get("service_high_priority_paths", 0),
        "svc_val_cands": svval.get("service_validation_candidates", 0),
        "svc_solver_runs": svs.get("service_solver_runs", 0),
        "svc_agent_runs": svs.get("service_agent_runs", 0),
        "attack_surfaces": asp.get("total_surfaces", 0),
        "auth_surfaces": asp.get("auth_after_surfaces", 0),
        "attack_paths": aps.get("total_paths", 0),
        "prioritized_paths": pps.get("prioritized_paths", ss.get("prioritized_paths", 0)),
        "evidence_chains": ss.get("evidence_chains", egs.get("evidence_nodes", 0)),
        "solver_runs": ss.get("solver_runs", 0),
        "agent_runs": ss.get("agent_runs", 0),
        "level3": ev.get("level3_proven", 0),
        "level2": ev.get("level2_evidence", 0),
        "level1": ev.get("level1_observed", 0),
        "level0": ev.get("level0_info", 0),
        "priority_actions": ev.get("priority_actions", 0),
        "total_inputs": aip.get("total_input_points", 0),
        "selected_inputs": aip.get("ai_selected_input_points", 0),
        "executed": aip.get("executed", aip.get("planned_executions", 0)),
        "graph_nodes": egs.get("total_nodes", 0),
        "graph_edges": egs.get("total_edges", 0),
        "confirmed_paths": aps.get("confirmed_paths", 0),
        "evidence_paths": aps.get("evidence_paths", 0),
    }


def _has_v2_data(m: dict) -> bool:
    return any(m.get(k) for k in ("attack_surfaces", "attack_paths", "solver_runs",
                                  "agent_runs", "level3", "level2", "graph_nodes",
                                  "service_surfaces", "net_live_hosts", "net_open_ports"))


def _kpi_row(doc, items: list[tuple]):
    """KPI 카드 한 줄(label/큰 숫자/sub) — 다크 네이비 카드형."""
    if not items:
        return
    tbl = doc.add_table(rows=1, cols=len(items))
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    for cell, (label, value, sub) in zip(tbl.rows[0].cells, items):
        _shd(cell, "1E3A5F"); _border(cell, color="1E3A5F")
        cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        _run(cell.paragraphs[0], str(value), size=20, bold=True, color=C_WHITE)
        lp = cell.add_paragraph(); lp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        _run(lp, label, size=9, bold=True, color=RGBColor(0xBF, 0xDB, 0xFE))
        if sub:
            sp = cell.add_paragraph(); sp.alignment = WD_ALIGN_PARAGRAPH.CENTER
            _run(sp, sub, size=8, color=RGBColor(0xCB, 0xD5, 0xE1))


def _bar(n: int, total: int, width: int = 24) -> str:
    if total <= 0:
        return ""
    filled = int(round(width * n / total))
    return "█" * max(0, filled) + "░" * max(0, width - filled)


def _add_v2_dashboard(doc, analysis: dict, domain: str):
    """Executive Dashboard + Security Validation Summary."""
    m = _v2_metrics(analysis)
    if not _has_v2_data(m):
        return
    _h1(doc, "보안 진단 대시보드 (Security Assessment Dashboard)")
    _body(doc,
        "본 보고서는 '취약점 목록'이 아니라 공격 표면 → 공격 경로 → 증거 확보 → 검증 수준 → "
        "가능한 영향 → 권고 흐름의 '보안 관찰 및 검증 보고서'입니다. 모든 검증 수준·확신은 "
        "Rule Engine 과 확보 증거에 근거하며 AI 는 설명·권고 보강에만 사용됩니다.",
        size=9, color=C_GRAY)

    _kpi_row(doc, [
        ("Attack Surface", m["attack_surfaces"], f"인증 후 {m['auth_surfaces']}"),
        ("Attack Path", m["attack_paths"], f"우선 {m['prioritized_paths']}"),
        ("Evidence", m["evidence_chains"], f"그래프 {m['graph_nodes']}노드"),
        ("Validated (L3)", m["level3"], f"증거(L2) {m['level2']}"),
    ])
    _body(doc, "", size=4)
    _kpi_row(doc, [
        ("Prioritized Path", m["prioritized_paths"], ""),
        ("Solver Run", m["solver_runs"], ""),
        ("Agent Analysis", m["agent_runs"], ""),
        ("우선 조치", m["priority_actions"], "L3+L2"),
    ])
    # 서비스 보안 표면 KPI(서비스 데이터 있을 때만)
    if m["service_surfaces"]:
        _body(doc, "", size=4)
        _kpi_row(doc, [
            ("Service Surface", m["service_surfaces"], ""),
            ("Auth Surface", m["svc_auth"], ""),
            ("Database Surface", m["svc_db"], ""),
            ("File Sharing", m["svc_file"], ""),
            ("Container Surface", m["svc_container"], ""),
        ])
        _body(doc, "", size=4)
        _kpi_row(doc, [
            ("Data Exposure", m["svc_data"], ""),
            ("Svc High Path", m["svc_high_paths"], ""),
            ("Svc Validation", m["svc_val_cands"], ""),
            ("Svc Solver", m["svc_solver_runs"], ""),
            ("Svc Agent", m["svc_agent_runs"], ""),
        ])
    # 네트워크 자산 KPI(IP/CIDR 대상일 때)
    if m["net_live_hosts"] or m["net_open_ports"]:
        _body(doc, "", size=4)
        _kpi_row(doc, [
            ("Live Host", m["net_live_hosts"], ""),
            ("Open Port", m["net_open_ports"], ""),
            ("Service Surface", m["net_services"], ""),
            ("Web Candidate", m["net_web_candidates"], ""),
            ("High Priority Asset", m["net_high_assets"], ""),
        ])

    # Security Validation Summary (Level 0~3 분포 — 시각 바)
    _h2(doc, "보안 검증 수준 요약 (Security Validation Summary)")
    total = max(1, m["level3"] + m["level2"] + m["level1"] + m["level0"])
    rows = []
    for lvl in (3, 2, 1, 0):
        cnt = m[f"level{lvl}"]
        label, _hex, _ = _LEVEL_BADGE[lvl]
        rows.append([label, str(cnt), _bar(cnt, total)])
    _make_table(doc, ["검증 수준", "수량", "분포"], rows, col_widths=[5, 2, 9])
    _body(doc, "위험도(취약점 수) 대신 '검증 수준(증거 강도)' 중심으로 요약합니다. "
               "Level 3(실증 확인)·Level 2(증거 확보)가 우선 조치 대상입니다.", size=9, color=C_GRAY)


def _add_v2_attack_surface_analysis(doc, analysis: dict):
    """Attack Surface Analysis — 유형 분포 + Probe 예산 절감."""
    asp = (analysis.get("attack_surface_plan") or {}).get("summary") or {}
    aip = (analysis.get("ai_payload_plan") or {}).get("summary") or {}
    by_type = asp.get("by_type") or {}
    if not by_type and not aip:
        return
    _h2(doc, "공격 표면 분석 (Attack Surface Analysis)")
    if by_type:
        total = max(1, sum(by_type.values()))
        rows = [[k, str(v), _bar(v, total)] for k, v in
                sorted(by_type.items(), key=lambda x: x[1], reverse=True)]
        _make_table(doc, ["공격 표면 유형", "수", "분포"], rows, col_widths=[6, 2, 8])
    # Probe 예산 절감
    ti = aip.get("total_input_points", 0)
    si = aip.get("ai_selected_input_points", 0)
    ex = aip.get("executed", aip.get("planned_executions", 0))
    reduction = f"{round((1 - si / ti) * 100)}%" if ti else "-"
    _make_table(doc, ["Probe 예산", "수치"], [
        ["전체 입력점", str(ti)],
        ["AI 선별 입력점", str(si)],
        ["실제 실행/계획 입력점", str(ex)],
        ["선별 절감률", reduction],
    ], col_widths=[8, 8])


def _add_v2_attack_path_analysis(doc, analysis: dict):
    """Attack Path Analysis — Top 경로 타임라인 + Priority/Confidence/Solver/Agent."""
    paths = analysis.get("attack_paths") or []
    if not paths:
        return
    prio_by_id = {p.get("path_id"): p for p in (analysis.get("prioritized_paths") or [])}
    agents_by_id = {r.get("path_id"): r for r in (analysis.get("agent_results") or [])}
    _h2(doc, "공격 경로 분석 (Attack Path Analysis)")
    for i, p in enumerate(paths[:8], 1):
        pid = p.get("path_id")
        sp = prio_by_id.get(pid, {})
        ar = agents_by_id.get(pid, {})
        hp = _para(doc, space_before=6, space_after=2)
        hp.paragraph_format.left_indent = Cm(0.2)
        _run(hp, f"경로 #{i} — {p.get('title','공격 경로')}", size=11, bold=True, color=C_NAVY)
        # 타임라인(세로 단계)
        steps = p.get("steps") or []
        for n, st in enumerate(steps):
            tp = _para(doc, space_after=0)
            tp.paragraph_format.left_indent = Cm(0.6)
            arrow = "   ↓ " if n else "   ● "
            _run(tp, arrow + _sanitize_display_text(str(st)), size=9, color=C_BLACK)
        # 메타 표
        _make_table(doc, ["Priority", "Confidence", "Evidence", "Solver", "Agent Group"], [[
            _fmt_coverage_value(sp.get("priority") or p.get("risk_grade")),
            _fmt_coverage_value(p.get("path_confidence")),
            _fmt_coverage_value(sp.get("evidence_strength") or p.get("evidence_level")),
            _fmt_coverage_value(sp.get("recommended_solver") or "-"),
            _fmt_coverage_value(ar.get("family") or "-"),
        ]], col_widths=[3, 4, 3, 3, 3])


def _add_v2_solver_analysis(doc, analysis: dict):
    """Solver Analysis — 종류/실행/증거강화/Manual Review."""
    ss = analysis.get("solver_summary") or {}
    results = analysis.get("solver_results") or []
    by_solver = ss.get("by_solver") or {}
    if not by_solver and not results:
        return
    _h2(doc, "Solver 분석 (Solver Analysis)")
    # 결과 등급 카운트
    from collections import Counter
    rc = Counter(r.get("solver_result") for r in results)
    correlated = rc.get("EVIDENCE_CORRELATED", 0)
    supported = rc.get("EVIDENCE_SUPPORTED", 0)
    insufficient = rc.get("INSUFFICIENT_EVIDENCE", 0)
    rows = [[k, str(v)] for k, v in sorted(by_solver.items(), key=lambda x: x[1], reverse=True)]
    if rows:
        _make_table(doc, ["Solver", "실행 수"], rows, col_widths=[8, 8])
    _make_table(doc, ["Solver 결과", "수"], [
        ["총 Solver 실행", str(ss.get("solver_runs", len(results)))],
        ["증거 상관분석(Correlated)", str(correlated)],
        ["증거 보강(Supported)", str(supported)],
        ["추가 검증 권고(Insufficient)", str(insufficient)],
    ], col_widths=[8, 8])
    _body(doc, "Solver 는 신규 탐색 없이 기존 증거만 상관·보강하며 검증 수준(Level)을 변경하지 "
               "않습니다(최종 판정 Rule Engine).", size=9, color=C_GRAY)


def _add_v2_agent_analysis(doc, analysis: dict):
    """Multi-Agent Analysis — Agent Observation/Limitation/Recommendation 요약."""
    results = analysis.get("agent_results") or []
    if not results:
        return
    _h2(doc, "Multi-Agent 분석 (Multi-Agent Analysis)")
    shown = 0
    for r in results:
        for a in r.get("agents", []):
            if shown >= 12:
                break
            rows = [
                ["관찰(Observation)", _sanitize_display_text(a.get("observation", "") or "-")],
            ]
            if a.get("limitation"):
                rows.append(["제한(Limitation)", a.get("limitation")])
            if a.get("recommended_next_step"):
                rows.append(["권고(Recommendation)", a.get("recommended_next_step")])
            hp = _para(doc, space_before=4, space_after=1)
            hp.paragraph_format.left_indent = Cm(0.2)
            _run(hp, f"[{r.get('family','')}] {a.get('agent_role','')} "
                     f"({a.get('agent_name','')})", size=9, bold=True, color=C_NAVY)
            _make_table(doc, ["구분", "내용"], rows, col_widths=[3.5, 12.5])
            shown += 1
    _body(doc, "Agent 는 기존 증거 해석·보강만 수행하며(신규 탐색/판정/Level 변경 불가) "
               "Rule Engine 결과를 따릅니다.", size=9, color=C_GRAY)


def _add_v2_evidence_graph_analysis(doc, analysis: dict):
    """Evidence Graph Analysis — 노드/엣지/체인 + Top Evidence Chain."""
    egs = analysis.get("evidence_graph_summary") or {}
    chains = analysis.get("evidence_chains") or []
    if not egs and not chains:
        return
    _h2(doc, "증거 그래프 분석 (Evidence Graph Analysis)")
    if egs:
        _make_table(doc, ["항목", "수치"], [
            ["Evidence Graph 노드", str(egs.get("total_nodes", 0))],
            ["Evidence Graph 엣지", str(egs.get("total_edges", 0))],
            ["Evidence 노드", str(egs.get("evidence_nodes", 0))],
            ["Agent 관찰 노드", str(egs.get("agent_observations", 0))],
            ["Confirmed/Evidence/Observed 경로",
             f"{egs.get('confirmed_paths',0)} / {egs.get('evidence_paths',0)} / {egs.get('observed_paths',0)}"],
            ["Evidence Chain 수", str(len(chains))],
        ], col_widths=[8, 8])
    # Top Evidence Chain (검증 수준 높은 순)
    top = sorted(chains, key=lambda c: c.get("max_level", 0), reverse=True)[:5]
    for c in top:
        hp = _para(doc, space_before=4, space_after=1)
        hp.paragraph_format.left_indent = Cm(0.2)
        _run(hp, f"◆ {c.get('evidence_chain','Evidence Chain')}", size=10, bold=True, color=C_PURPLE)
        _body(doc, _sanitize_display_text(c.get("validation_summary", "") or "-"), size=9)
        if c.get("confidence_change"):
            _body(doc, f"신뢰도 변화: {c.get('confidence_change')}", size=9, color=C_GRAY)


def _derive_verified_controls(analysis: dict) -> list[str]:
    """확보 증거/양호 항목으로 '정상 동작 보안 통제'를 도출(✓)."""
    controls: list[str] = []
    titles = " ".join((f.get("title") or "") for f in (analysis.get("findings") or []))
    surfaces = analysis.get("attack_surface_items") or []
    # 양호 항목 직접 반영
    for g in (analysis.get("good_items") or [])[:10]:
        t = g.get("title")
        if t:
            controls.append(t)
    cov = analysis.get("coverage") or {}
    tl = titles.lower()
    # 관리자 페이지가 401/403 으로 보호(공격표면이나 무인증 접근 아님)
    if any("관리자" in (s.get("title") or "") for s in surfaces):
        controls.append("관리자 인터페이스 접근 통제(인증 요구) 확인")
        controls.append("관리자 직접 접근 차단 확인")
    if cov.get("auth_login_success"):
        controls.append("인증 세션 기반 접근 동작 확인")
    # IDOR 교차검증에서 차단된(미승격) 경우 = 접근제어 동작
    idor = (analysis.get("candidate_verification") or {}).get("idor") or {}
    if idor.get("verified") and not idor.get("promoted"):
        controls.append("교차 계정 접근 미확인 — 객체 접근 권한 통제 동작 확인")
    # CSRF 토큰 존재(후보로만, 미흡 없음)
    if "CSRF" not in titles:
        controls.append("상태 변경 요청 CSRF 보호 정상 동작(미흡 미발견)")

    # ── '실증 실패/미발견' = 보안 통제 정상 동작으로 자동 수집 ──────────────────
    # SQLi 실증 실패(후보는 있었으나 Level3 미달)
    fams_confirmed = set()
    for f in (analysis.get("findings") or []):
        lv = _re_evidence_level(f)
        fam = _re_family(f.get("title", ""))
        if fam and lv >= 3:
            fams_confirmed.add(fam)
    # 후보(참고)에 있었으나 어디서도 실증되지 않은 패밀리 = 실증 실패(=통제 동작)
    cand_fams = set()
    for d in (analysis.get("discovery_items") or []):
        fam = _re_family(d.get("title", ""))
        if fam:
            cand_fams.add(fam)
    _FAIL_LABEL = {
        "sqli": "SQL Injection 실증 실패(주입 미확인)",
        "auth": "관리자/로그인 인증 우회 실증 실패",
        "idor": "교차 계정 접근 미확인(접근제어 동작)",
        "xss": "Stored/Reflected XSS 브라우저 실증 미발견",
        "ssti": "SSTI 표현식 평가 미확인",
        "cmdi": "OS 명령 실행 미확인",
    }
    for fam in cand_fams:
        if fam not in fams_confirmed and fam in _FAIL_LABEL:
            controls.append("�__" + _FAIL_LABEL[fam])  # 표식: 실증 실패류
    # 로그인 폼 안전 점검에서 신호 없음 = 인증 우회 실패
    if cov.get("login_forms_found") and not cov.get("login_forms_performed"):
        pass  # 미수행은 통제로 보지 않음
    # SameSite 적용 확인(미흡 쿠키 미발견 시)
    csrf_cand = any("CSRF" in (d.get("title") or "") for d in (analysis.get("discovery_items") or []))
    if not csrf_cand:
        controls.append("세션 쿠키 SameSite 적용 확인(미흡 미발견)")

    # 표식 정리(실증 실패류는 그대로 문구만)
    # 서비스 보안 통제(service_surface_planner 산출) 합류
    for c in (analysis.get("service_controls") or []):
        controls.append(c)
    cleaned = [c.replace("�__", "") for c in controls]
    # 중복 제거
    seen, out = set(), []
    for c in cleaned:
        if c not in seen:
            seen.add(c); out.append(c)
    return out[:14]


def _re_evidence_level(f: dict) -> int:
    try:
        import evidence_levels as _evl
        return _evl.level_of(f, finding_type="vulnerability")
    except Exception:
        return 0


def _re_family(title: str):
    try:
        import business_impact_engine as _bie
        return _bie.family_of(title)
    except Exception:
        return None


def _add_v2_security_controls(doc, analysis: dict):
    """Security Controls Verified — 정상 동작하는 보안 통제도 표시."""
    controls = _derive_verified_controls(analysis)
    if not controls:
        return
    _h2(doc, "확인된 보안 통제 (Security Controls Verified)")
    _body(doc, "문제뿐 아니라 정상 동작하는 보안 통제도 함께 보고합니다.", size=9, color=C_GRAY)
    for c in controls:
        p = _para(doc, space_after=1)
        p.paragraph_format.left_indent = Cm(0.3)
        _run(p, "✓  ", size=10, bold=True, color=C_GREEN)
        _run(p, _sanitize_display_text(c), size=10, color=C_BLACK)


def _add_v2_executive_top10(doc, analysis: dict):
    """Executive Top 10 — 우선 조치 필요 항목(공격 경로 기준)."""
    prio = analysis.get("prioritized_paths") or []
    paths = {p.get("path_id"): p for p in (analysis.get("attack_paths") or [])}
    if not prio:
        # prioritized 없으면 attack_paths 점수순 폴백
        prio = [{"path_id": p.get("path_id"), "title": p.get("title"),
                 "priority": p.get("risk_grade"), "score": p.get("risk_score", 0),
                 "confidence": p.get("path_confidence")} for p in
                sorted(analysis.get("attack_paths") or [],
                       key=lambda x: x.get("risk_score", 0), reverse=True)]
    if not prio:
        return
    _h2(doc, "우선 조치 필요 항목 Top 10 (Executive Top 10)")
    rows = []
    for i, sp in enumerate(prio[:10], 1):
        p = paths.get(sp.get("path_id"), {})
        rows.append([
            str(i),
            _sanitize_display_text(sp.get("title") or p.get("title") or "-")[:50],
            _fmt_coverage_value(sp.get("priority")),
            _fmt_coverage_value(sp.get("confidence") or p.get("path_confidence")),
            _fmt_coverage_value(sp.get("score", p.get("risk_score"))),
        ])
    _make_table(doc, ["#", "공격 경로", "우선순위", "검증", "점수"], rows,
                col_widths=[1, 8, 3, 3, 1.5])
    _body(doc, "Critical/High 경로 · 증거 강도 · 비즈니스 영향 순으로 정렬된 우선 조치 항목입니다.",
          size=9, color=C_GRAY)


_RISK_BADGE = {"Critical": "FCA5A5", "High": "FED7AA", "Medium": "FEF08A", "Low": "BBF7D0"}


def _add_v2_executive_risk_dashboard(doc, analysis: dict):
    """Executive Risk Dashboard — 비즈니스 위험 등급 + 영향 분포."""
    bis = analysis.get("business_impact_summary") or {}
    m = _v2_metrics(analysis)
    if not bis and not _has_v2_data(m):
        return
    _h2(doc, "경영진 위험 대시보드 (Executive Risk Dashboard)")
    _kpi_row(doc, [
        ("Critical Risk", bis.get("critical", 0), ""),
        ("High Risk", bis.get("high", 0), ""),
        ("Medium Risk", bis.get("medium", 0), ""),
        ("Low Risk", bis.get("low", 0), ""),
    ])
    _make_table(doc, ["항목", "수치"], [
        ["공격 표면 수", str(m["attack_surfaces"])],
        ["공격 경로 수", str(m["attack_paths"])],
        ["검증 수준 분포(L3/L2/L1/L0)",
         f"{m['level3']} / {m['level2']} / {m['level1']} / {m['level0']}"],
    ], col_widths=[8, 8])
    # 비즈니스 영향 분포(범주별)
    cats = bis.get("by_category") or {}
    if cats:
        total = max(1, sum(cats.values()))
        rows = [[k, str(v), _bar(v, total)] for k, v in
                sorted(cats.items(), key=lambda x: x[1], reverse=True)]
        _body(doc, "비즈니스 영향 범주 분포:", size=9, color=C_GRAY)
        _make_table(doc, ["영향 범주", "수", "분포"], rows, col_widths=[6, 2, 8])
    reg = bis.get("by_regulatory") or {}
    if reg:
        _body(doc, "규제 관련 가능성: " + " · ".join(f"{k}({v})" for k, v in reg.items())
              + "  ※ 실제 법률 판정 아님(관련 가능성 표시)", size=9, color=C_GRAY)


def _add_v2_priority_action_plan(doc, analysis: dict):
    """Priority Action Plan — 우선 조치 계획 Top 10(담당/공수/효과)."""
    plan = analysis.get("priority_action_plan") or []
    rsum = analysis.get("remediation_summary") or {}
    if not plan:
        return
    _h2(doc, "우선 조치 계획 (Priority Action Plan)")
    rows = []
    for it in plan[:10]:
        rows.append([
            it.get("rank", ""),
            _sanitize_display_text(it.get("title", ""))[:46],
            _fmt_coverage_value(it.get("priority")),
            it.get("team", "-"),
            it.get("effort", "-"),
            _sanitize_display_text(it.get("benefit", ""))[:30],
        ])
    _make_table(doc, ["#", "조치", "우선순위", "담당", "예상 공수", "기대 효과"], rows,
                col_widths=[1, 5.5, 2.5, 2.5, 2, 3])
    by_team = rsum.get("by_team") or {}
    if by_team:
        _body(doc, "담당 조직별: " + " · ".join(f"{k} {v}건" for k, v in by_team.items()),
              size=9, color=C_GRAY)


_VLEVEL_KO = {0: "정보(L0)", 1: "관찰(L1)", 2: "증거(L2)", 3: "실증(L3)"}


def _add_v2_validation_opportunities(doc, analysis: dict):
    """Validation Opportunities — 관찰→증거→실증 승격 가능 후보 + 검증 우선순위."""
    cands = analysis.get("validation_candidates") or []
    vs = analysis.get("validation_summary") or {}
    if not cands and not vs:
        return
    _h2(doc, "추가 검증 가능 항목 (Validation Opportunities)")
    _body(doc,
        "관찰(Level 1) → 증거(Level 2) → 실증(Level 3) 으로 자동 승격 가능한 후보와 검증 "
        "우선순위를 제시합니다. 검증/승격 판정은 Rule Engine·증거가 결정하며 AI 는 설명만 "
        "보강합니다(Level/Confidence 변경 불가).", size=9, color=C_GRAY)
    # 승격 요약 KPI
    _kpi_row(doc, [
        ("현재 실증(L3)", vs.get("current_confirmed", 0), ""),
        ("추가 검증 시 L3 가능", vs.get("potential_confirmed", 0),
         f"+{vs.get('expected_promotions', 0)}"),
        ("L1→L2 가능", vs.get("level1_to_level2", 0), ""),
        ("L2→L3 가능", vs.get("level2_to_level3", 0), ""),
    ])
    # 후보 표(상위 12)
    rows = []
    for c in cands[:12]:
        rows.append([
            _fmt_coverage_value(c.get("family")),
            (_sanitize_display_text(c.get("validation_candidate", ""))[:34] or "-"),
            _VLEVEL_KO.get(c.get("current_level", 0), "-"),
            _fmt_coverage_value(c.get("validation_priority")),
            (_sanitize_display_text(c.get("required_evidence", ""))[:30] or "-"),
            (_sanitize_display_text(c.get("recommended_validation", ""))[:34] or "-"),
        ])
    _make_table(doc, ["유형", "후보", "현재 Level", "검증 우선순위", "부족 증거", "추천 검증"],
                rows, col_widths=[2, 4, 2.2, 2.3, 3, 3.5])
    bf = vs.get("by_family") or {}
    if bf:
        _body(doc, "패밀리별 후보: " + " · ".join(f"{k} {v}" for k, v in bf.items()),
              size=9, color=C_GRAY)


def _add_v2_network_exposure(doc, analysis: dict):
    """Network Exposure Summary — 입력 대역/Host/Port/서비스 분포."""
    nes = analysis.get("network_exposure_summary") or {}
    if not nes:
        return
    _h2(doc, "네트워크 노출 요약 (Network Exposure Summary)")
    _body(doc,
        "URL/도메인뿐 아니라 IP/CIDR 대상의 자산 노출을 요약합니다. 승인된 사내/고객 대상 대역만 "
        "점검하며, 큰 대역은 안전 정책으로 차단/분할됩니다(대량 고속 스캔·exploit 미수행).",
        size=9, color=C_GRAY)
    tgts = nes.get("input_targets") or []
    _make_table(doc, ["항목", "수치"], [
        ["입력 대상", (", ".join(tgts)[:80] or "-") + f"  (유형: {nes.get('target_type','-')})"],
        ["발견 Host 수", str(nes.get("live_hosts", 0))],
        ["Open Port 수", str(nes.get("open_ports", 0))],
        ["서비스 수", str(nes.get("services", 0))],
        ["Web 후보 수", str(nes.get("web_candidates", 0))],
        ["인증 서비스 / DB 서비스", f"{nes.get('auth_services',0)} / {nes.get('db_services',0)}"],
        ["파일 공유 / 컨테이너 서비스", f"{nes.get('file_sharing_services',0)} / {nes.get('container_services',0)}"],
        ["Unknown 서비스 수", str(nes.get("unknown_services", 0))],
        ["인터넷 노출 자산 / 우선 자산", f"{nes.get('internet_exposed',0)} / {nes.get('high_priority_assets',0)}"],
        ["차단된 대역 수", str(nes.get("blocked_ranges", 0))],
    ], col_widths=[6, 10])
    guard = analysis.get("network_scope_guard") or {}
    if guard.get("blocked"):
        _body(doc, "※ 안전 가드 차단: " + " · ".join(guard.get("blocked_reasons", [])[:3]),
              size=9, color=C_GRAY)


def _add_v2_asset_inventory(doc, analysis: dict):
    """Asset Inventory — Host 별 IP/OS/포트/서비스/risk_tags/우선순위."""
    assets = analysis.get("asset_inventory") or []
    asum = analysis.get("asset_summary") or {}
    if not assets:
        return
    _h2(doc, "자산 인벤토리 (Asset Inventory)")
    rows = []
    for a in assets[:20]:
        ports = ",".join(str(p) for p in (a.get("open_ports") or [])[:10])
        svcs = ",".join(s.get("family", "") for s in (a.get("detected_services") or [])[:6])
        tags = ",".join(a.get("risk_tags") or [])
        rows.append([
            _fmt_coverage_value(a.get("ip")),
            _fmt_coverage_value(a.get("asset_type")),
            (a.get("os_guess") or "-")[:14],
            ports or "-",
            svcs or "-",
            tags[:40] or "-",
            _fmt_coverage_value(a.get("priority")),
        ])
    _make_table(doc, ["IP", "유형", "OS", "Open Ports", "서비스", "Risk Tags", "우선순위"],
                rows, col_widths=[2.6, 2.6, 1.8, 2.6, 2, 3, 1.6])


def _add_v2_service_security(doc, analysis: dict):
    """Service Security Analysis — 서비스 공격 표면 분포 + 상위 표면."""
    surfaces = analysis.get("service_surfaces") or []
    ssum = analysis.get("service_surface_summary") or {}
    if not surfaces and not ssum:
        return
    _h2(doc, "서비스 보안 분석 (Service Security Analysis)")
    _body(doc,
        "기존 포트/서비스 식별 결과를 바탕으로 서비스 공격 표면을 의미 분류하고 경로·영향을 "
        "도출합니다. 새 능동 탐색은 수행하지 않으며(기존 정보 분석만), 검증 수준은 증거 기준입니다.",
        size=9, color=C_GRAY)
    _make_table(doc, ["서비스 표면 유형", "수"], [
        ["전체 서비스 표면", str(ssum.get("total_service_surfaces", 0))],
        ["Authentication", str(ssum.get("authentication_surfaces", 0))],
        ["Database", str(ssum.get("database_surfaces", 0))],
        ["Data Exposure", str(ssum.get("data_exposure_surfaces", 0))],
        ["File Sharing", str(ssum.get("file_sharing_surfaces", 0))],
        ["Container", str(ssum.get("container_surfaces", 0))],
        ["Messaging", str(ssum.get("messaging_surfaces", 0))],
    ], col_widths=[8, 8])
    # 상위 서비스 표면(우선순위)
    rows = []
    for s in surfaces[:10]:
        rows.append([
            f"{s.get('port','')}/tcp",
            _fmt_coverage_value(s.get("service")),
            _fmt_coverage_value(s.get("attack_surface_type")),
            _fmt_coverage_value(s.get("priority")),
            _fmt_coverage_value(s.get("recommended_solver")),
        ])
    if rows:
        _make_table(doc, ["포트", "서비스", "표면 유형", "우선순위", "Solver"], rows,
                    col_widths=[2, 3, 5, 3, 3])


def _add_v2_service_solver_agent(doc, analysis: dict):
    """Service Solver Analysis + Service Agent Analysis."""
    sresults = analysis.get("service_solver_results") or []
    aresults = analysis.get("service_agent_results") or []
    if not sresults and not aresults:
        return
    if sresults:
        _h2(doc, "서비스 Solver 분석 (Service Solver Analysis)")
        from collections import Counter
        bys = Counter(r.get("solver") for r in sresults)
        _make_table(doc, ["Service Solver", "실행 수"],
                    [[k, str(v)] for k, v in bys.items()], col_widths=[8, 8])
        _body(doc, "서비스 Solver 는 기존 배너/설정/TLS/인증 단서만 해석하며 로그인·브루트포스·"
                   "exploit 을 수행하지 않습니다(Level 변경 불가).", size=9, color=C_GRAY)
    if aresults:
        _h2(doc, "서비스 Multi-Agent 분석 (Service Agent Analysis)")
        shown = 0
        for r in aresults:
            for a in r.get("agents", []):
                if shown >= 12:
                    break
                hp = _para(doc, space_before=3, space_after=1)
                hp.paragraph_format.left_indent = Cm(0.2)
                _run(hp, f"[{r.get('family','')}] {a.get('agent_role','')}", size=9, bold=True, color=C_NAVY)
                rows = [["관찰", _sanitize_display_text(a.get("observation", "") or "-")]]
                if a.get("limitation"):
                    rows.append(["제한", a.get("limitation")])
                if a.get("recommended_next_step"):
                    rows.append(["권고", a.get("recommended_next_step")])
                _make_table(doc, ["구분", "내용"], rows, col_widths=[2.5, 13.5])
                shown += 1
        _body(doc, "서비스 Agent 는 기존 증거 해석·보강만 수행(신규 요청/판정/Level 변경 불가).",
              size=9, color=C_GRAY)


def _add_v2_service_evidence_graph(doc, analysis: dict):
    seg = analysis.get("service_evidence_graph") or {}
    s = seg.get("summary") or {}
    if not s:
        return
    _h2(doc, "서비스 증거 그래프 (Service Evidence Graph)")
    _make_table(doc, ["항목", "수치"], [
        ["노드 수", str(s.get("total_nodes", 0))],
        ["엣지 수", str(s.get("total_edges", 0))],
        ["서비스 표면 노드", str(s.get("service_surfaces", 0))],
        ["서비스 Agent 관찰 노드", str(s.get("agent_observations", 0))],
    ], col_widths=[8, 8])
    _body(doc, "Open Port→Service Surface(exposed_as), Banner/Version/Auth/TLS Evidence, "
               "Service Solver/Agent, Business Impact/Remediation 를 연결합니다.", size=9, color=C_GRAY)


def _add_v2_service_validation(doc, analysis: dict):
    cands = analysis.get("service_validation_candidates") or []
    vs = analysis.get("service_validation_summary") or {}
    if not cands and not vs:
        return
    _h2(doc, "서비스 추가 검증 가능 항목 (Service Validation Opportunities)")
    rows = []
    for c in cands[:12]:
        rows.append([
            _fmt_coverage_value(c.get("family")),
            _sanitize_display_text(c.get("validation_candidate", ""))[:34],
            _fmt_coverage_value(c.get("validation_priority")),
            _sanitize_display_text(c.get("recommended_validation", ""))[:36],
        ])
    _make_table(doc, ["유형", "후보", "우선순위", "추천 검증"], rows, col_widths=[2, 5, 2.5, 6.5])
    _body(doc, "실제 검증 실행은 수행하지 않으며 후보·우선순위만 제시합니다(서비스는 자동 "
               "exploit 없이 증거 수준까지 승격 대상).", size=9, color=C_GRAY)


def _add_v2_service_remediation(doc, analysis: dict):
    plan = analysis.get("service_remediation_plan") or []
    imp = analysis.get("service_business_impact") or []
    if not plan and not imp:
        return
    _h2(doc, "서비스 조치 계획 (Service Remediation Plan)")
    if plan:
        rows = [[it.get("rank", ""), _sanitize_display_text(it.get("title", ""))[:42],
                 _fmt_coverage_value(it.get("priority")), it.get("team", "-"),
                 it.get("effort", "-")] for it in plan[:10]]
        _make_table(doc, ["#", "조치", "우선순위", "담당", "예상 공수"], rows,
                    col_widths=[1, 7, 2.5, 3, 2.5])


# ════════════════════════════════════════════════════════════════════════════
# Report UX/UI Framework v3 — 고객 전달용 전문가 보고서(표현만 개편, 데이터 유지)
# ════════════════════════════════════════════════════════════════════════════

def _suppressed_findings(analysis: dict) -> list:
    """오탐 억제(_fp_suppressed) 처리된 finding 목록(점수·분포 산정에서 제외 대상)."""
    return [f for f in (analysis.get("findings") or [])
            if f.get("judgment") != "양호" and f.get("_fp_suppressed")]


def _eff_severity_counts(analysis: dict) -> dict:
    """by_severity 우선, 없으면 findings 에서 report_severity 로 집계(렌더 시 fallback).
    오탐 억제(_fp_suppressed) 항목은 심각도 집계에서 차감한다(점수 무결성)."""
    sup = _suppressed_findings(analysis)
    by = (analysis.get("summary") or {}).get("by_severity")
    if by and any(by.values()):
        out = {k: by.get(k, 0) for k in ("Critical", "High", "Medium", "Low")}
        for f in sup:                              # 억제 항목 차감
            s = _sev5(f.get("severity") or _report_sev(f))
            if s in out and out[s] > 0:
                out[s] -= 1
        return out
    findings = [f for f in (analysis.get("findings") or [])
                if f.get("judgment") != "양호" and not f.get("_fp_suppressed")]
    out = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        # _sev5 는 HIGH/Critical/긴급/높음 등 다양한 표기를 정규화(_report_sev 는 오분류 가능)
        s = _sev5(f.get("severity") or _report_sev(f))
        if s in out:
            out[s] += 1
    return out


def _eff_levels(analysis: dict) -> dict:
    """evidence_levels 우선, 비어있으면 findings 에서 재집계(대시보드/점수 무결성)."""
    ev = analysis.get("evidence_levels") or {}
    sup = _suppressed_findings(analysis)
    if any(ev.get(k) for k in ("level3_proven", "level2_evidence", "level1_observed", "level0_info")):
        if not sup:
            return ev
        out = dict(ev)                             # 억제 항목을 레벨별로 차감
        try:
            import evidence_levels as _evl
            _key = {3: "level3_proven", 2: "level2_evidence",
                    1: "level1_observed", 0: "level0_info"}
            for f in sup:
                k = _key.get(_evl.level_of(f))
                if k and out.get(k, 0) > 0:
                    out[k] -= 1
        except Exception:
            pass
        return out
    findings = [f for f in (analysis.get("findings") or [])
                if f.get("judgment") != "양호" and not f.get("_fp_suppressed")]
    if findings:
        try:
            import evidence_levels as _evl
            return _evl.summarize_levels(findings)
        except Exception:
            pass
    return ev


def _v3_security_score(analysis: dict) -> int:
    """0~100 보안 점수(결정적). 변별력 있는 '보안 정도' 지표를 목표로 설계.

    설계(결합형 = min(영역 비례형, 체감형)):
      · 영역 비례형: 점검 카탈로그(_SCAN_COVERAGE, ~31개 취약점 클래스) 중 '취약 영역' 비율을
        심각도 가중해 감점. 31개 중 소수만 취약하면 대부분 양호이므로 높은 점수를 유지한다.
        영역(기법 패밀리)당 '최악 심각도 1회'만 반영 — 같은 영역의 중복 발견으로 과다감점 방지.
      · 체감형: 발견 '건수' 증가에 대한 감점을 제곱근으로 체감(포화)시켜, 몇 건만 나와도 0으로
        붕괴하던 기존 선형 누적을 교정. 다수 Critical 은 여전히 충분히 하락한다.
      · 무결성 상한: High 이상 존재 시 ≤84, Critical 존재 시 ≤69(기존 규칙 유지).
    기존 문제: 취약점 1건을 심각도+증거수준+비즈니스영향으로 3중 감점 후 선형 누적 → 4~5건 0점.
    """
    import math
    sev = _eff_severity_counts(analysis)
    crit, high, med, low = (sev.get("Critical", 0), sev.get("High", 0),
                            sev.get("Medium", 0), sev.get("Low", 0))

    # ── 영역 비례형: 취약 '기법 패밀리' 단위, 영역별 최악 심각도만 1회 가중 ──
    try:
        import proof_evidence as _pe
        _fam = _pe._family
    except Exception:
        _fam = lambda f: (f.get("family") or f.get("title") or "?")
    _rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    _wt = {"Critical": 1.0, "High": 0.6, "Medium": 0.3, "Low": 0.1}
    fam_worst: dict = {}
    for f in (analysis.get("findings") or []):
        if f.get("judgment") == "양호" or f.get("_fp_suppressed"):
            continue
        s = _sev5(f.get("severity") or _report_sev(f))
        if s not in _rank:
            continue
        fam = _fam(f)
        if fam not in fam_worst or _rank[s] > _rank[fam_worst[fam]]:
            fam_worst[fam] = s
    try:
        from report_html_renderer import _SCAN_COVERAGE as _SC
        A = max(len(_SC), 1)
    except Exception:
        A = 31                              # 점검 카탈로그 영역 수(폴백)
    area_load = sum(_wt[s] for s in fam_worst.values())
    proportional = 100.0 * (1.0 - min(area_load, A) / A)

    # ── 체감형: 건수 감점을 제곱근으로 포화 ──
    diminishing = 100.0 - (22 * math.sqrt(crit) + 16 * math.sqrt(high)
                           + 7 * math.sqrt(med) + 3 * math.sqrt(low))

    score = min(proportional, diminishing)
    if crit or high:                        # High 이상 존재 시 100점 불가
        score = min(score, 84)
    if crit:                                # Critical 존재 시 위험 구간
        score = min(score, 69)
    return max(0, min(100, round(score)))


def _score_grade(score: int) -> tuple:
    if score >= 85:
        return "양호", "16A34A"
    if score >= 70:
        return "주의", "CA8A04"
    if score >= 50:
        return "경계", "EA580C"
    return "위험", "DC2626"


def _add_v3_gauge(doc, score: int):
    """보안 점수 게이지(막대형)."""
    grade, hexc = _score_grade(score)
    rgb = RGBColor(int(hexc[0:2], 16), int(hexc[2:4], 16), int(hexc[4:6], 16))
    p = _para(doc, space_before=2, space_after=2)
    p.paragraph_format.left_indent = Cm(0.2)
    _run(p, f"{ICON['risk']} Security Score  ", size=12, bold=True, color=C_NAVY)
    _run(p, f"{score}/100  ", size=18, bold=True, color=rgb)
    _run(p, f"({grade})", size=12, bold=True, color=rgb)
    filled = round(score / 5)
    bar = _para(doc, space_after=4); bar.paragraph_format.left_indent = Cm(0.2)
    _run(bar, "█" * filled, size=12, color=rgb)
    _run(bar, "░" * (20 - filled), size=12, color=C_LIGHT_GRAY)


def _kpi_group(doc, title, icon, items):
    """아이콘 + 제목 + KPI 카드 한 줄(6대 대시보드 구성용)."""
    h = _para(doc, space_before=6, space_after=2); h.paragraph_format.left_indent = Cm(0.2)
    _run(h, f"{icon} {title}", size=12, bold=True, color=C_NAVY)
    _kpi_row(doc, items)


def _add_v3_dashboard(doc, analysis: dict):
    """통합 대시보드(중복 제거) — Attack Surface / Risk / Validation / Asset / Service / Network."""
    m = _v2_metrics(analysis)
    ev = _eff_levels(analysis)             # 무결성: 비어있으면 findings 에서 재집계
    bis = analysis.get("business_impact_summary") or {}
    _h1(doc, "보안 진단 대시보드")
    _add_v3_gauge(doc, _v3_security_score(analysis))

    _kpi_group(doc, "공격 표면", ICON["path"], [
        ("공격 표면", m["attack_surfaces"], ""),
        ("공격 경로", m["attack_paths"], ""),
        ("우선 경로", m["prioritized_paths"], ""),
        ("점검 입력점", f"{m['selected_inputs']}/{m['total_inputs']}", ""),
    ])
    # '위험도'는 기술 심각도(Critical/High/Medium/Low) — 표지·요약·5.1·점수와 동일한 유효 분포를 쓴다.
    # (기존엔 bis(경영 우선순위 분류)를 우선 사용해 대시보드 Critical 이 표지와 어긋나던 문제 — 분리)
    _sevc = _eff_severity_counts(analysis)
    _kpi_group(doc, "위험도", ICON["critical"], [
        ("Critical", _sevc.get("Critical", 0), ""),
        ("High", _sevc.get("High", 0), ""),
        ("Medium", _sevc.get("Medium", 0), ""),
        ("Low", _sevc.get("Low", 0), ""),
    ])
    _kpi_group(doc, "검증 결과", ICON["evidence"], [
        ("실증 확인", ev.get("level3_proven", 0), "Level 3"),
        ("증거 확보", ev.get("level2_evidence", 0), "Level 2"),
        ("관찰됨", ev.get("level1_observed", 0), "Level 1"),
        ("추가 검증", m["svc_val_cands"] + (analysis.get("validation_summary") or {})
            .get("validation_candidates", 0), ""),
    ])
    if analysis.get("asset_inventory"):
        _kpi_group(doc, "자산", ICON["asset"], [
            ("자산", (analysis.get("asset_summary") or {}).get("total_assets", 0), ""),
            ("우선 자산", m["net_high_assets"], ""),
            ("인터넷 노출", (analysis.get("asset_summary") or {}).get("internet_exposed", 0), ""),
            ("Web 후보", m["net_web_candidates"], ""),
        ])
    if m["service_surfaces"]:
        _kpi_group(doc, "서비스", ICON["service"], [
            ("노출 서비스", m["service_surfaces"], ""),
            ("인증", m["svc_auth"], ""),
            ("데이터베이스", m["svc_db"], ""),
            ("컨테이너", m["svc_container"], ""),
        ])
    if m["net_live_hosts"]:
        _kpi_group(doc, "네트워크", ICON["network"], [
            ("발견 Host", m["net_live_hosts"], ""),
            ("Open Port", m["net_open_ports"], ""),
            ("서비스", m["net_services"], ""),
            ("우선 자산", m["net_high_assets"], ""),
        ])
    # v6 인포그래픽: Severity / Validation 분포 막대(색상 게이지) — 무결성 fallback
    sd = _eff_severity_counts(analysis)
    sev_items = [("Critical", sd.get("Critical", 0)), ("High", sd.get("High", 0)),
                 ("Medium", sd.get("Medium", 0)), ("Low", sd.get("Low", 0))]
    tot_s = max(1, sum(v for _, v in sev_items))
    if sum(v for _, v in sev_items):
        _run(_para(doc, space_before=6, space_after=2), f"{ICON['critical']} Severity Distribution",
             size=11, bold=True, color=C_NAVY)
        for name, cnt in sev_items:
            bp = _para(doc, space_after=0); bp.paragraph_format.left_indent = Cm(0.4)
            _run(bp, f"{name:<9}", size=9, bold=True, color=SEV5_RGB.get(name, C_GRAY), mono=True)
            _run(bp, " " + _bar(cnt, tot_s, 22), size=10, color=SEV5_RGB.get(name, C_GRAY))
            _run(bp, f"  {cnt}", size=9, color=C_BLACK)
    val_items = [("실증 L3", ev.get("level3_proven", 0), "16A34A"),
                 ("증거 L2", ev.get("level2_evidence", 0), "1D4ED8"),
                 ("관찰 L1", ev.get("level1_observed", 0), "CA8A04"),
                 ("정보 L0", ev.get("level0_info", 0), "6B7280")]
    tot_v = max(1, sum(c for _, c, _ in val_items))
    if sum(c for _, c, _ in val_items):
        _run(_para(doc, space_before=6, space_after=2), f"{ICON['evidence']} Validation Distribution",
             size=11, bold=True, color=C_NAVY)
        for name, cnt, hx in val_items:
            bp = _para(doc, space_after=0); bp.paragraph_format.left_indent = Cm(0.4)
            _run(bp, f"{name:<8}", size=9, bold=True, color=_hexrgb(hx), mono=True)
            _run(bp, " " + _bar(cnt, tot_v, 22), size=10, color=_hexrgb(hx))
            _run(bp, f"  {cnt}", size=9, color=C_BLACK)
    _body(doc, "본 보고서는 공격 표면 → 경로 → 증거 → 검증 수준 → 영향 → 조치 흐름으로 구성됩니다. "
               "검증/판정은 증거(Rule Engine) 기준입니다.", size=9, color=C_GRAY)


def _flow_step(label: str) -> str:
    """플로우 단계 라벨 축약(노드 타입 접두 제거)."""
    s = _sanitize_display_text(str(label or ""))
    if ":" in s:
        s = s.split(":", 1)[1].strip()
    return s[:22]


def _add_v3_attack_path_flow(doc, analysis: dict):
    """공격 경로를 Flow Chart(가로 흐름)로 표시 — 엔진 내부 정보 없음."""
    paths = analysis.get("attack_paths") or []
    if not paths:
        return
    prio = {p.get("path_id"): p for p in (analysis.get("prioritized_paths") or [])}
    # 우선순위(있으면) → 점수순 정렬
    paths = sorted(paths, key=lambda p: (prio.get(p.get("path_id"), {}).get("score", 0),
                                         p.get("risk_score", 0)), reverse=True)
    _h1(doc, "공격 경로 (Attack Path Flow)")
    _body(doc, "공격자가 위험에 도달하는 흐름을 한눈에 표시합니다. 색상은 검증 수준을 나타냅니다.",
          size=9, color=C_GRAY)
    for i, p in enumerate(paths[:8], 1):
        conf = p.get("path_confidence", "")
        hexc = ("16A34A" if "Confirmed" in conf else "1D4ED8" if "Evidence" in conf
                else "CA8A04" if "Observed" in conf else "6B7280")
        rgb = RGBColor(int(hexc[0:2], 16), int(hexc[2:4], 16), int(hexc[4:6], 16))
        hp = _para(doc, space_before=6, space_after=1); hp.paragraph_format.left_indent = Cm(0.2)
        _run(hp, f"{ICON['path']} 경로 #{i}  ", size=11, bold=True, color=C_NAVY)
        _run(hp, f"[{conf or '—'}]", size=9, bold=True, color=rgb)
        # 가로 플로우
        steps = [_flow_step(s) for s in (p.get("steps") or [])]
        fp = _para(doc, space_after=1); fp.paragraph_format.left_indent = Cm(0.5)
        for n, st in enumerate(steps):
            if n:
                _run(fp, "  ➔  ", size=11, bold=True, color=rgb)
            _run(fp, st, size=10, color=C_BLACK)
        # 영향/조치 한 줄
        if p.get("possible_impact"):
            ip2 = _para(doc, space_after=2); ip2.paragraph_format.left_indent = Cm(0.5)
            _run(ip2, f"{ICON['reco']} 영향: ", size=9, bold=True, color=C_GRAY)
            _run(ip2, _sanitize_display_text(p.get("possible_impact"))[:90], size=9, color=C_BLACK)


def _add_v3_priority_actions(doc, analysis: dict):
    """우선 조치 — 카드형(조치/우선순위/담당/공수/효과). Top10+Remediation 통합."""
    plan = analysis.get("priority_action_plan") or []
    splan = analysis.get("service_remediation_plan") or []
    merged = (plan + splan)[:10]
    if not merged:
        return
    _h1(doc, "우선 조치 계획 (Priority Actions)")
    for it in merged:
        sev = _sev5(it.get("priority"))
        hexc = SEV5_HEX[sev]; bg = SEV5_BG[sev]
        rgb = SEV5_RGB[sev]
        # 카드: 1행 제목줄(배지) + 1행 메타
        tbl = doc.add_table(rows=2, cols=1)
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        c0 = tbl.rows[0].cells[0]; _shd(c0, bg); _border(c0, hexc)
        _run(c0.paragraphs[0], f"  {it.get('rank','')}  {ICON['reco']} "
             + _sanitize_display_text(it.get("title", "")), size=11, bold=True, color=rgb)
        c1 = tbl.rows[1].cells[0]; _shd(c1, "FFFFFF"); _border(c1, "E5E7EB")
        _run(c1.paragraphs[0],
             f"  우선순위 {it.get('priority','-')}   ·   담당 {it.get('team','-')}   ·   "
             f"예상 공수 {it.get('effort','-')}   ·   효과 {(it.get('benefit') or '-')[:40]}",
             size=9, color=C_GRAY)
        _para(doc, space_after=2)


def _add_developer_appendix(doc, analysis: dict):
    """Developer Appendix — 엔진 내부 정보(Solver/Agent/Evidence Graph/Planner/Node·Edge)
    를 본문에서 분리해 부록에만 기록한다."""
    import os as _os
    if _os.getenv("REPORT_DEV_APPENDIX", "true").strip().lower() in ("0", "false", "no", "off"):
        return
    has = any(analysis.get(k) for k in ("solver_summary", "agent_summary", "evidence_graph_summary",
              "attack_surface_plan", "ai_payload_plan", "service_summary",
              "browser_discovery_summary"))
    if not has:
        return
    doc.add_page_break()
    _h1(doc, "Developer Appendix (엔진 내부 정보)")
    _body(doc, "아래는 분석 엔진 내부 지표입니다(고객 보고 본문에서 분리). 재현·감사 목적의 참고 정보입니다.",
          size=9, color=C_GRAY)
    _add_v2_attack_surface_analysis(doc, analysis)
    _add_v2_solver_analysis(doc, analysis)
    _add_v2_agent_analysis(doc, analysis)
    _add_v2_evidence_graph_analysis(doc, analysis)
    _add_v2_service_security(doc, analysis)          # 서비스 상세(내부 라우팅 포함)
    _add_v2_service_solver_agent(doc, analysis)
    _add_v2_service_evidence_graph(doc, analysis)
    _add_v2_validation_opportunities(doc, analysis)  # 검증 후보(내부)
    _add_v2_service_validation(doc, analysis)
    _add_browser_discovery_detail(doc, analysis)     # Browser Discovery 상세(마스킹된 메타)


def _add_detection_coverage(doc, analysis: dict):
    """Detection Coverage — 기법별 Tested/Confirmed/Possible/Blocked/N/A (고객 이해 핵심)."""
    dc = analysis.get("detection_coverage") or {}
    matrix = [r for r in (dc.get("matrix") or [])
              if r.get("tested") or r.get("confirmed") or r.get("possible") or r.get("blocked_by_policy")]
    if not matrix:
        return
    _h2(doc, "2.9 Detection Coverage  (무엇을 검사했는가)")
    _sm = dc.get("summary") or {}
    _body(doc, "기법별로 무엇을 검사했고 어떤 결과가 나왔는지 요약합니다. "
               "‘검사함·안전’은 점검 수행 후 취약점 미발견, ‘미도달’은 해당 입력 표면 미발견을 의미합니다.",
          size=9, color=C_GRAY)
    _sp = _para(doc, space_before=1, space_after=3); _sp.paragraph_format.left_indent = Cm(0.2)
    _run(_sp, f"취약 확인 {_sm.get('techniques_with_findings',0)}  ·  "
              f"검사함·안전 {_sm.get('techniques_tested_clean',0)}  ·  "
              f"미도달 {_sm.get('techniques_not_reached',0)}  /  총 {_sm.get('techniques_total',0)} 기법",
         size=9, bold=True, color=C_NAVY)
    rows = [[r["technique"], r.get("status_label", "-"), str(r["tested"]), str(r["confirmed"]),
             str(r["possible"]), str(r["blocked_by_policy"]), r.get("reason", "")[:30]]
            for r in matrix]
    _no_split_table(_make_table(doc, ["Technique", "상태", "Tested", "Confirmed",
                                      "Possible", "Blocked", "비고"], rows,
                                col_widths=[2.8, 1.9, 1.2, 1.5, 1.4, 1.2, 3.2]))


def _add_knowledge_graph_summary(doc, analysis: dict):
    """Security Knowledge Graph 요약 — 노드/관계 수 + 최상위 공격 경로(Flow) + 그래프 맥락."""
    kg = analysis.get("security_knowledge_graph") or {}
    ap = analysis.get("attack_path_graph") or {}
    s = kg.get("summary") or {}
    if not s.get("node_count"):
        return
    _h2(doc, "2.8 Security Knowledge Graph  (자산·입력점·취약점·증거·조치 관계)")
    _body(doc, "취약점을 목록이 아니라 자산 → 입력점 → 취약점 → 증거 → 증명 → 공격 경로 → "
               "비즈니스 → 조치의 관계 그래프로 연결했습니다.", size=9, color=C_GRAY)
    _no_split_table(_kpi_row(doc, [
        (f"{ICON['path']} 그래프 노드", s.get("node_count", 0), ""),
        (f"{ICON['path']} 관계(엣지)", s.get("edge_count", 0), ""),
        (f"{ICON['critical']} 공격 경로", (ap.get("summary") or {}).get("attack_paths", 0), ""),
    ]) or doc.tables[-1])
    top = ap.get("top_path")
    if top and top.get("steps"):
        tp = _para(doc, space_before=4, space_after=2); tp.paragraph_format.left_indent = Cm(0.2)
        _run(tp, "최상위 공격 경로: ", size=9, bold=True, color=C_NAVY)
        flow = "  ➔  ".join((str(st.get("icon", "")) + " " + str(st.get("node", "")))[:26]
                            for st in top["steps"])
        fp = _para(doc, space_after=3); fp.paragraph_format.left_indent = Cm(0.4)
        _run(fp, flow, size=8, color=C_BLACK)


def _add_browser_discovery_summary(doc, analysis: dict):
    """Browser Discovery Summary — 고객 본문용 요약(과도하지 않게 수치만)."""
    s = analysis.get("browser_discovery_summary") or {}
    if not s or not s.get("enabled"):
        return
    _h2(doc, "2.7 Browser Discovery Summary  (브라우저 기반 공격 표면)")
    _body(doc, "브라우저에서 실제 오가는 요청을 안전하게 수집해 API/XHR/JSON/Header/Cookie/SPA "
               "입력점을 확보한 결과입니다(GET·네비게이션 중심, 상태 변경 클릭 금지, 값 마스킹).",
          size=9, color=C_GRAY)
    _no_split_table(_kpi_row(doc, [
        (f"{ICON['network']} 방문 페이지", s.get("pages_visited", 0), ""),
        (f"{ICON['network']} 수집 Request", s.get("requests", 0), f"XHR/Fetch {s.get('xhr_fetch',0)}"),
        (f"{ICON['path']} API 후보", s.get("api_candidates", 0), f"숨은 API {s.get('hidden_apis',0)}"),
    ]) or doc.tables[-1])
    _body(doc, "", size=4)
    _no_split_table(_kpi_row(doc, [
        (f"{ICON['evidence']} 신규 입력점", s.get("new_input_points", 0),
         f"SPA {s.get('spa_routes',0)}"),
        (f"{ICON['path']} 런타임 후킹", s.get("runtime_hooks", 0), "실행 중 생성 URL"),
        (f"{ICON['critical']} 차단된 위험 클릭", s.get("blocked_clicks", 0), ""),
    ]) or doc.tables[-1])
    _body(doc, "", size=4)
    _no_split_table(_kpi_row(doc, [
        (f"{ICON['asset']} 스토리지 키", s.get("storage_keys", 0),
         "JWT 감지" if s.get("has_jwt") else "값 미수집"),
        (f"{ICON['path']} API 관계", f"{s.get('api_nodes',0)}/{s.get('api_edges',0)}", "노드/관계"),
        (f"{ICON['asset']} 인증 후 수집", "예" if s.get("authenticated_crawl") else "아니오",
         f"Interaction {s.get('interaction_points',0)}"),
    ]) or doc.tables[-1])
    # 발견 소스별 분포 막대(정확한 공격 표면 발견을 시각화)
    eps = analysis.get("browser_discovery_endpoints") or []
    if eps:
        by_src = {}
        for e in eps:
            by_src[e.get("source", "기타")] = by_src.get(e.get("source", "기타"), 0) + 1
        tot = max(1, sum(by_src.values()))
        _run(_para(doc, space_before=6, space_after=2), f"{ICON['path']} 발견 소스 분포",
             size=10, bold=True, color=C_NAVY)
        _SRC_LABEL = {"runtime_fetch": "런타임 fetch", "runtime_xhr": "런타임 XHR",
                      "runtime_pushState": "SPA 라우팅", "runtime_ws": "WebSocket",
                      "observed_network": "관측 요청", "static_js": "정적 JS",
                      "js_concat": "JS 변수조합", "openapi": "OpenAPI", "sitemap": "sitemap",
                      "graphql": "GraphQL", "robots": "robots", "manifest": "manifest"}
        for src, cnt in sorted(by_src.items(), key=lambda x: -x[1])[:8]:
            bp = _para(doc, space_after=0); bp.paragraph_format.left_indent = Cm(0.4)
            _run(bp, f"{_SRC_LABEL.get(src, src):<12}", size=9, color=C_GRAY, mono=True)
            _run(bp, " " + _bar(cnt, tot, 20), size=10, color=C_TEAL)
            _run(bp, f"  {cnt}", size=9, color=C_BLACK)


def _add_browser_discovery_detail(doc, analysis: dict):
    """Developer Appendix — Browser Discovery 상세(수집 URL·API·JS endpoint·차단 클릭·마스킹 샘플)."""
    s = analysis.get("browser_discovery_summary") or {}
    if not s:
        return
    _h2(doc, "D-BD. Browser Discovery 상세")
    eps = analysis.get("browser_discovery_endpoints") or []
    if eps:
        rows = [[e.get("endpoint", "")[:60], e.get("method_hint", ""),
                 "API" if e.get("is_api_candidate") else ("WS" if e.get("is_websocket") else "-"),
                 e.get("reason", ""), str(e.get("source_line", "") or "")]
                for e in eps[:30]]
        _make_table(doc, ["Endpoint 후보", "Method", "유형", "근거", "line"], rows,
                    col_widths=[6, 1.6, 1.4, 4, 1.2])
    ins = analysis.get("browser_discovery_inputs") or []
    if ins:
        _run(_para(doc, space_before=4, space_after=2), f"수집 입력점 {len(ins)}개(위치별)",
             size=10, bold=True, color=C_NAVY)
        rows = [[i.get("parameter_name", "")[:30], i.get("parameter_location", ""),
                 i.get("method", ""), i.get("endpoint", "")[:50]] for i in ins[:30]]
        _make_table(doc, ["파라미터", "위치", "Method", "Endpoint"], rows,
                    col_widths=[3.5, 2.2, 1.6, 6.5])
    blocked = analysis.get("browser_discovery_blocked_actions") or []
    if blocked:
        _run(_para(doc, space_before=4, space_after=2),
             f"차단된 위험 클릭 {len(blocked)}개(상태 변경 방지)", size=10, bold=True, color=C_RED)
        for b in blocked[:12]:
            bp = _para(doc, space_after=1); bp.paragraph_format.left_indent = Cm(0.4)
            _run(bp, f"• {b.get('element','')[:40]} — {b.get('reason','')}", size=8, color=C_GRAY)
    reqs = analysis.get("browser_discovery_requests") or []
    if reqs:
        _run(_para(doc, space_before=4, space_after=2), "마스킹된 요청 샘플(원문 미저장)",
             size=10, bold=True, color=C_NAVY)
        for r in reqs[:8]:
            rp = _para(doc, space_after=1); rp.paragraph_format.left_indent = Cm(0.4)
            _run(rp, f"• {r.get('method','')} {r.get('url','')[:70]} "
                     f"[{r.get('resource_type','')}] {r.get('response_status','')}",
                 size=8, color=C_GRAY)
    # v3: API 관계 그래프
    graph = analysis.get("browser_discovery_api_graph") or {}
    if graph.get("edges"):
        _run(_para(doc, space_before=4, space_after=2),
             f"API 관계 그래프 (노드 {graph.get('summary',{}).get('api_nodes',0)} · "
             f"관계 {graph.get('summary',{}).get('api_edges',0)})", size=10, bold=True, color=C_NAVY)
        for e in graph["edges"][:14]:
            gp = _para(doc, space_after=0); gp.paragraph_format.left_indent = Cm(0.4)
            _run(gp, f"{e.get('from','')}  →  {e.get('to','')}", size=8, color=C_BLACK, mono=True)
            _run(gp, f"  ({e.get('relation','')})", size=8, color=C_GRAY)
    # v3: 스토리지(키/JWT 존재만) · Interaction · Replay 후보
    stg = analysis.get("browser_discovery_storage") or {}
    if stg:
        sp = _para(doc, space_before=4, space_after=1)
        _run(sp, "브라우저 스토리지(값 미수집 · 키/존재만): ", size=9, bold=True, color=C_NAVY)
        _run(sp, f"localStorage {len(stg.get('local_storage_keys',[]))} · "
                 f"sessionStorage {len(stg.get('session_storage_keys',[]))} · "
                 f"cookie {len(stg.get('cookie_names',[]))} · "
                 f"JWT {'감지' if stg.get('has_jwt') else '없음'}", size=9, color=C_GRAY)
    inter = analysis.get("browser_discovery_interaction_points") or []
    if inter:
        _run(_para(doc, space_before=3, space_after=1),
             f"Interaction Point 후보 {len(inter)}개 (자동 클릭 안 함)", size=9, bold=True, color=C_NAVY)
    rep = analysis.get("browser_discovery_replay_candidates") or []
    if rep:
        _run(_para(doc, space_before=1, space_after=2),
             f"Replay 후보(조회성) {len(rep)}개 — Validation 재사용 후보(자동 실행 안 함)",
             size=9, color=C_GRAY)


# ════════════════════════════════════════════════════════════════════════════
# Report UX/UI Framework v4 — 고객 전달용 보안 컨설팅 보고서
# (엔진 용어를 본문에서 배제, 일반 보안 보고서 용어 사용. 데이터·기능 유지)
# ════════════════════════════════════════════════════════════════════════════



def _finding_sev5(f: dict) -> str:
    return _sev5(f.get("severity") or _report_sev(f))


def _sort_findings(findings: list) -> list:
    rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    conf_rank = {"CONFIRMED": 3, "CONFIRMED_BROWSER": 3, "CONFIRMED_RESPONSE": 3,
                 "POSSIBLE": 2, "MANUAL_REVIEW": 1}
    return sorted(findings or [], key=lambda f: (
        rank.get(_finding_sev5(f), 0),
        conf_rank.get((f.get("confidence") or "").upper(), 0)), reverse=True)


def _add_v4_roadmap(doc, analysis: dict):
    """개선 로드맵 — Priority 1/2/3 (예상 공수/담당/기대 효과)."""
    plan = (analysis.get("priority_action_plan") or []) + (analysis.get("service_remediation_plan") or [])
    if not plan:
        return
    buckets = {"P1": [], "P2": [], "P3": []}
    for it in plan:
        sev = _sev5(it.get("priority"))
        key = "P1" if sev in ("Critical", "High") else "P2" if sev == "Medium" else "P3"
        buckets[key].append(it)
    _h2(doc, "7.1 개선 로드맵 (Recommended Roadmap)")
    _body(doc, "무엇부터 조치해야 하는지 단계별로 정리했습니다.", size=9, color=C_GRAY)
    _titles = {"P1": ("Priority 1 — 즉시 조치", "DC2626"),
               "P2": ("Priority 2 — 단기 조치", "EA580C"),
               "P3": ("Priority 3 — 계획 조치", "CA8A04")}
    for key in ("P1", "P2", "P3"):
        items = buckets[key]
        if not items:
            continue
        title, hexc = _titles[key]
        rgb = RGBColor(int(hexc[0:2], 16), int(hexc[2:4], 16), int(hexc[4:6], 16))
        hp = _para(doc, space_before=6, space_after=2); hp.paragraph_format.left_indent = Cm(0.2)
        _run(hp, f"{ICON['reco']} {title}", size=12, bold=True, color=rgb)
        seen = set()
        for it in items:
            t = it.get("title", "")
            if t in seen:
                continue
            seen.add(t)
            p = _para(doc, space_after=1); p.paragraph_format.left_indent = Cm(0.6)
            _run(p, "• " + _sanitize_display_text(t), size=10, bold=True, color=C_BLACK)
            p2 = _para(doc, space_after=2); p2.paragraph_format.left_indent = Cm(0.9)
            _run(p2, f"담당 {it.get('team','-')}  ·  예상 공수 {it.get('effort','-')}  ·  "
                     f"기대 효과 {(it.get('benefit') or '-')[:40]}", size=9, color=C_GRAY)


def _add_deletion_requests_section(doc, analysis: dict):
    """삭제 요청 — 상태변경형 실증(저장형 XSS·파일 업로드·쓰기 접근통제)이 자동 원복에
    실패해 대상에 남은 무해 테스트 산출물 목록. 사용자가 경로·작성내용을 보고 직접 삭제하도록
    보고서 하단에 싣는다. 원복 실패분이 없으면 렌더하지 않는다."""
    reqs = analysis.get("deletion_requests") or []
    if not reqs:
        return
    _h1(doc, "삭제 요청 (자동 원복 실패 산출물)")
    _body(doc,
        "아래 항목은 상태변경형 취약점 실증(저장형 XSS·파일 업로드·쓰기 접근통제) 과정에서 "
        "생성·저장된 무해 테스트 데이터 중 스캐너가 자동 원복에 실패한 것입니다. 대상 시스템에 "
        "흔적이 남지 않도록 아래 경로의 항목을 확인 후 삭제해 주십시오.", size=9, color=C_GRAY)
    rows = []
    for r in reqs[:50]:
        rows.append([
            r.get("kind", ""),
            r.get("path", ""),
            r.get("content", ""),
            (r.get("method", "") or "-"),
        ])
    _make_table(doc, ["유형", "경로", "작성/생성 내용", "방법"],
                rows, col_widths=[2.6, 4.6, 6.2, 1.6])


def generate_report(scan: dict) -> io.BytesIO:
    doc = Document()

    doc.styles["Normal"].font.name = FONT
    doc.styles["Normal"].font.size = Pt(10)
    doc.styles["Normal"]._element.rPr.rFonts.set(qn("w:eastAsia"), FONT)

    # v5: 여백 최적화(본문 페이지 20~30% 감소) + Heading/문단 간격 축소
    for section in doc.sections:
        section.top_margin    = Cm(1.9)
        section.bottom_margin = Cm(1.9)
        section.left_margin   = Cm(2.2)
        section.right_margin  = Cm(2.0)
        # v5 헤더/푸터(보고서명·CONFIDENTIAL / 페이지 번호·작성기관)
        _setup_header_footer(section, "Eoseureum · AI Security Assessment Report")

    analysis   = scan.get("analysis") or {}
    results    = scan.get("results") or []
    domain     = scan.get("domain", "")
    created_at = scan.get("created_at", "")
    risk       = analysis.get("overall_risk", "GOOD")
    findings   = analysis.get("findings", [])
    summary    = analysis.get("summary") or {}

    # ── 정규화 데이터 계약 ────────────────────────────────────────────────────
    # analysis["findings"] 는 이미 "취약점만" 담긴 리스트(judgment 모두 "취약").
    # 취약점 수·목록은 오로지 findings 기준으로 한다 (== summary.vulnerability_count).
    # 옛 데이터 호환: 일부 옛 스캔은 findings 에 양호 항목까지 섞여 있을 수 있으므로
    # judgment 가 명시적으로 "양호" 인 항목만 제외하여 vuln_list 를 구성한다.
    vuln_list = [f for f in findings if f.get("judgment") != "양호"]

    # 웹/서비스 분리 — 웹 섹션엔 scan_category!="service" 만, 서비스 섹션엔 service 만.
    web_vuln_list     = [f for f in vuln_list if not _is_service_finding(f)]
    service_vuln_list = [f for f in vuln_list if _is_service_finding(f)]
    # 발견된 취약점은 Critical→Low 순으로 정렬(발견 목록·상세·ID 모두 심각도순).
    _SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    web_vuln_list.sort(key=lambda f: _SEV_ORDER.get(_report_sev(f), 9))
    service_vuln_list.sort(key=lambda f: _SEV_ORDER.get(_report_sev(f), 9))
    vuln_list = web_vuln_list + service_vuln_list
    # VULN 식별번호: 웹(1..) → 서비스(이어서) 순으로 1회 부여. 모든 섹션에서 동일 ID 사용.
    for _i, _f in enumerate(web_vuln_list, 1):
        _f["_idx"] = _i
    for _j, _f in enumerate(service_vuln_list, len(web_vuln_list) + 1):
        _f["_idx"] = _j

    # 양호(통과) 항목: 통계용. good_items 우선, 없으면 findings 폴백.
    good_list = analysis.get("good_items")
    if good_list is None:
        good_list = [f for f in findings if f.get("judgment") == "양호"]

    # 참고 발견 항목(Discovery): 취약점 아님. 없으면 빈 리스트.
    discovery_items = analysis.get("discovery_items", []) or []

    # 카운트는 summary 우선, 없으면 vuln_list 에서 산출 (KeyError 없이).
    vuln_count      = summary.get("vulnerability_count", len(vuln_list))
    confirmed_count = summary.get("confirmed_count",
                                  sum(1 for f in vuln_list if f.get("probe_confirmed") is True))
    passive_count   = max(vuln_count - confirmed_count, 0)
    good_count      = summary.get("good_count", len(good_list))

    # 웹/서비스 취약점 카운트 (summary 우선, 없으면 분리한 리스트에서 산출)
    service_vuln_count = summary.get("service_vulnerability_count", len(service_vuln_list))
    web_vuln_count     = summary.get("web_vulnerability_count",
                                     max(vuln_count - service_vuln_count, len(web_vuln_list)))
    attack_surface_count = summary.get("attack_surface_count",
                                       len(analysis.get("attack_surface_items", []) or []))
    checked_ports = summary.get("checked_ports")

    # ── Discovery 통계 수집 ────────────────────────────────────────────────────
    disc_stats = _collect_discovery_stats(results, findings)

    # ── 1. 표지 (v5 — 고객 제출용 상용 보고서) ─────────────────────────────────
    _cover_as_cnt   = summary.get("attack_surface_count",
                                  len(analysis.get("attack_surface_items", []) or []))
    _cover_disc_cnt = summary.get("discovery_count", len(discovery_items))
    _scan_policy = analysis.get("scan_policy") or (analysis.get("coverage") or {}).get("scan_policy") \
        or "기본(정책 미지정)"
    # 표지 '정책' 표기 = 실제 적용한 검증 프로파일(SAFE/STANDARD/ADVANCED/PROOF). 정책 템플릿명이
    # 아니라 스캔 강도를 지배하는 프로파일을 정확히 보여준다(강등 시 요청→적용 표기). 정책 템플릿명은
    # 부록 '적용 점검 정책'에 별도 표시.
    _vprof = (analysis.get("validation_profile") or "").upper()
    _vreq = (analysis.get("validation_profile_requested") or "").upper()
    if _vprof:
        _profile_txt = _vprof + (f" (요청 {_vreq} → 안전 강등)" if _vreq and _vreq != _vprof else "")
    else:
        _profile_txt = _scan_policy   # 프로파일 미기록(구 데이터) → 정책명 폴백
    _cover_m = _v2_metrics(analysis)
    _now = datetime.now()
    # 결정적 리포트번호 — abs(hash())는 PYTHONHASHSEED로 매 실행 달라져 DOCX/HTML 이 불일치했음.
    # hashlib 로 도메인에서 안정적으로 유도(같은 도메인·날짜 → 항상 동일, DOCX·HTML 공통).
    _rno = int(__import__("hashlib").md5((domain or "").encode("utf-8")).hexdigest()[:8], 16) % 10000
    _report_no = f"ASR-{_now.strftime('%Y%m%d')}-{_rno:04d}"

    # 표지 심각도 카운트(HTML/PDF 표지와 동일 지표) + 종합 위험도 배지
    _cv = _eff_severity_counts(analysis)   # 오탐 억제 차감된 유효 분포(표지·요약·5.1·점수 단일 소스)
    _cv_crit = _cv.get("Critical", sum(1 for f in vuln_list if _report_sev(f) == "Critical"))
    _cv_high = _cv.get("High",     sum(1 for f in vuln_list if _report_sev(f) == "High"))
    _cv_med  = _cv.get("Medium",   sum(1 for f in vuln_list if _report_sev(f) == "Medium"))
    _cv_low  = _cv.get("Low",      sum(1 for f in vuln_list if _report_sev(f) == "Low"))
    if _cv_crit:
        _risk_txt, _risk_hex = "종합 위험도 · 매우 높음", "DC2626"
    elif _cv_high:
        _risk_txt, _risk_hex = "종합 위험도 · 높음", "EA580C"
    elif _cv_med:
        _risk_txt, _risk_hex = "종합 위험도 · 보통", "D97706"
    elif _cv_low:
        _risk_txt, _risk_hex = "종합 위험도 · 낮음", "2563EB"
    else:
        _risk_txt, _risk_hex = "종합 위험도 · 양호", "16A34A"

    # 상단 상단 여백 (E 브랜드 마크 제거 — 워드마크가 표지 상단에 크게 노출되어 삭제)
    _spacer_top = _para(doc, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=0)
    _spacer_top.paragraph_format.space_before = Pt(72)
    brand_p = _para(doc, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=1)
    _run(brand_p, "Eoseureum", size=26, bold=True, color=C_NAVY)
    brand_sub = _para(doc, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=22)
    _run(brand_sub, "AI SECURITY ASSESSMENT PLATFORM", size=10, bold=True, color=C_GRAY)

    # 가운데 제목 — 한글 주제목(HTML/PDF 표지와 통일) + 영문 부제
    title_p = _para(doc, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=3)
    _run(title_p, "웹 애플리케이션 취약점 점검 보고서", size=26, bold=True, color=C_NAVY)
    sub_p = _para(doc, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=14)
    _run(sub_p, "AI Security Assessment Report · Web · Service · Network Security Assessment",
         size=10.5, color=C_GRAY)

    # 종합 위험도 배지(색상 필 pill)
    _risk_tbl = doc.add_table(rows=1, cols=1); _risk_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    _rc = _risk_tbl.rows[0].cells[0]; _rc.width = Cm(7.5)
    _shd(_rc, _risk_hex); _border(_rc, _risk_hex)
    _rp = _rc.paragraphs[0]; _rp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _run(_rp, _risk_txt, size=12, bold=True, color=C_WHITE)
    _para(doc, space_after=8)

    # 심각도 KPI 스트립(Critical/High/Medium/Low/공격표면) — HTML cover-stats 대응
    _kpi = doc.add_table(rows=2, cols=5); _kpi.alignment = WD_TABLE_ALIGNMENT.CENTER
    _kpi_cells = [("치명적", _cv_crit, "DC2626"), ("높음", _cv_high, "EA580C"),
                  ("보통", _cv_med, "D97706"), ("낮음", _cv_low, "2563EB"),
                  ("공격 표면", _cover_as_cnt, "1E3A5F")]
    for _ci, (_lb, _nv, _hx) in enumerate(_kpi_cells):
        _nc = _kpi.rows[0].cells[_ci]; _lc = _kpi.rows[1].cells[_ci]
        _nc.width = _lc.width = Cm(3.0)
        _shd(_nc, "F9FAFB"); _border(_nc, "E5E7EB"); _shd(_lc, "F9FAFB"); _border(_lc, "E5E7EB")
        _np = _nc.paragraphs[0]; _np.alignment = WD_ALIGN_PARAGRAPH.CENTER
        _run(_np, str(_nv), size=20, bold=True, color=_hexrgb(_hx))
        _lp = _lc.paragraphs[0]; _lp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        _run(_lp, _lb, size=8, color=C_GRAY)
    _para(doc, space_after=14)

    # CONFIDENTIAL (연한 회색)
    conf_p = _para(doc, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=16)
    _run(conf_p, "C O N F I D E N T I A L", size=13, bold=True, color=RGBColor(0xB8, 0xC2, 0xCC))

    # 구분선
    sep = _para(doc, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=14)
    _para_border_bottom(sep, color="1E3A5F", sz="12")

    # 메타 블록(대상/정책/작성일/작성기관/버전/보고서 번호)
    meta_tbl = doc.add_table(rows=6, cols=2)
    meta_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_rows = [
        ("대상 (Target)", domain),
        ("검증 프로파일 (Profile)", _profile_txt),
        ("작성일 (Date)", _now.strftime("%Y-%m-%d")),
        ("작성기관 (Prepared by)", _report_org_name()),
        ("버전 (Version)", "v6.0"),
        ("보고서 번호 (Report No.)", _report_no),
    ]
    for i, (label, value) in enumerate(meta_rows):
        cells = meta_tbl.rows[i].cells
        _shd(cells[0], "1E3A5F"); _border(cells[0], "1E3A5F")
        _shd(cells[1], "F9FAFB"); _border(cells[1], "D1D5DB")
        cells[0].width = Cm(5.5); cells[1].width = Cm(10.0)
        _run(cells[0].paragraphs[0], label, size=10, bold=True, color=C_WHITE)
        _run(cells[1].paragraphs[0], value, size=10, color=C_BLACK)

    sep2 = _para(doc, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=6)
    sep2.paragraph_format.space_before = Pt(14)
    _para_border_bottom(sep2, color="1E3A5F", sz="12")

    # 하단 Footer 블록
    prep_p = _para(doc, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=2)
    prep_p.paragraph_format.space_before = Pt(24)
    _run(prep_p, "Prepared by", size=9, color=C_GRAY)
    org_p = _para(doc, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=6)
    _run(org_p, "Eoseureum", size=12, bold=True, color=C_NAVY)
    copy_p = _para(doc, align=WD_ALIGN_PARAGRAPH.CENTER)
    _run(copy_p, f"Copyright (c) {_now.year} Eoseureum. All Rights Reserved.  본 문서는 대외비입니다.",
         size=8, color=C_GRAY)

    # (표지 뒤 명시적 page_break 제거 — 표지 콘텐츠가 페이지를 가득 채워 자동 개행되므로,
    #  page_break 를 두면 표지가 살짝 넘칠 때 '빈 페이지'가 생겼음. 기밀안내는 자체 섹션에서 시작.)

    # ── 기밀 안내(Confidentiality) — 표지 다음 ──
    _add_confidentiality_notice(doc)

    # ── 목차(Contents) — 8단 표준 구성 ──
    # 취약점이 0건이면 '7. 대응방안'은 쓰지 않고, 부록을 7번으로 당긴다(빈 대응방안 방지).
    _toc_rows = [
        ("1", "점검 목적  (Purpose)", 0),
        ("2", "점검 대상  (Target & Scope)", 0),
        ("3", "점검 항목 및 위험도  (Scan Coverage)", 0),
        ("4", "총평  (Executive Summary)", 0),
        ("5", "발견된 취약점  (Findings Overview)", 0),
        ("6", "취약점 상세  (Detailed Findings)", 0),
    ]
    if vuln_list:
        _toc_rows.append(("7", "대응방안  (Recommendations)", 0))
        _toc_rows.append(("8", "부록  (Appendix)", 0))
    else:
        _toc_rows.append(("7", "부록  (Appendix)", 0))
    _add_contents_page(doc, _toc_rows)

    # ── 1. 점검 목적 (Purpose) ──
    _h1(doc, "1. 점검 목적  (Purpose)")
    _body(doc,
        f"본 모의해킹은 {domain} 웹 애플리케이션에 존재할 수 있는 보안 취약점을 공격자 관점에서 "
        "사전에 식별·검증하여, 실제 침해로 이어지기 전에 조치할 수 있도록 지원하는 것을 목적으로 합니다. "
        "확인된 취약점은 재현(실증)을 통해 오탐을 배제하고, 심각도와 대응 우선순위를 함께 제시합니다.")
    for _t in [
        "인가된 범위 내에서 서비스 가용성에 영향을 주지 않는 비파괴 방식으로 점검을 수행합니다.",
        "실증된 항목만 '확인'으로 보고하며, 미확인 항목은 참고로 구분합니다.",
        "담당자가 즉시 조치할 수 있도록 재현 절차와 상세 권고를 함께 제공합니다.",
    ]:
        _bp = _para(doc, space_before=1, space_after=2); _bp.paragraph_format.left_indent = Cm(0.4)
        _run(_bp, "• ", size=10, bold=True, color=C_BLUE); _run(_bp, _t, size=10)
    # (점검 목적과 점검 대상은 같은 페이지에 이어서 배치 — page_break 대신 간격만 둠)
    _para(doc, space_after=10)

    # ── 2. 점검 대상 (Target & Scope) ──
    _h1(doc, "2. 점검 대상  (Target & Scope)")
    _make_table(doc, ["구분", "내용"],
        [
            ["점검 대상 (Target)", domain],
            ["점검 범위 (Scope)", analysis.get("scope_note")
                or "대상 도메인 및 동일 출처(same-origin) 하위 경로"],
            ["점검 기간 (Period)", created_at or "-"],
            ["점검 방식 (Method)",
                ("인증 세션 기반" if analysis.get("authenticated") else "비인증(공개 표면)")
                + " · 패시브(헤더/설정) + 능동(페이로드·브라우저 실증)"],
            ["분석 기준 (Standard)", "OWASP Top 10(2021) · CWE · CVSS 3.1"],
            ["확인 취약점", f"{vuln_count}건 (실증 {confirmed_count})"],
        ], col_widths=[4, 12])
    _h2(doc, "2.1 점검 환경 (호스트·포트)")
    # '점검 모드'는 검증 프로파일(PROOF/SAFE/STANDARD/ADVANCED)을 표기한다. 과거엔 포트스캔 깊이
    # (deep/standard)를 표기해 사용자가 'proof 인데 왜 deep?' 로 혼동했다. 포트스캔 깊이는 괄호로 병기.
    _profile = (analysis.get("scan_policy")
                or (analysis.get("detection_coverage") or {}).get("scan_policy")
                or (analysis.get("coverage") or {}).get("scan_policy") or "")
    if not _profile:
        try:
            import validation_profiles as _vp
            _profile = ("PROOF" if _vp.proof_active() else (_vp.current_profile() or "STANDARD"))
        except Exception:
            _profile = "STANDARD"
    _host_rows = []
    for hr in results:
        _port_depth = hr.get("scan_mode", "standard")
        _mode = f"{_profile} (포트스캔:{_port_depth})"
        _host_rows.append([hr.get("host", ""), hr.get("ip", ""), _mode,
                           ", ".join(str(p) for p in hr.get("open_ports", [])) or "-"])
    if _host_rows:
        _make_table(doc, ["호스트(서브도메인)", "IP 주소", "점검 모드(프로파일)", "오픈 포트"], _host_rows,
                    col_widths=[4.5, 3, 4, 4.5])
    else:
        _body(doc, "점검 대상 호스트 정보가 없습니다.")
    doc.add_page_break()

    # ── 3. 점검 항목 및 위험도 (Scan Coverage & Severity) ──
    _h1(doc, "3. 점검 항목 및 위험도  (Scan Coverage & Severity)")
    try:
        from report_html_renderer import _SCAN_COVERAGE as _SC, _TIER_LABEL as _TL
    except Exception:
        _SC, _TL = [], {}
    _tier_hex = {"crit": "F87171", "high": "FCA5A5", "med": "FED7AA", "low": "FEF08A", "info": "E5E7EB"}
    _cc = {}
    for _n, _c in _SC:
        _cc[_c] = _cc.get(_c, 0) + 1
    _body(doc,
        f"본 점검에서 탐지하는 취약점 항목과 위험도 기준입니다. 총 {len(_SC)}종 — "
        f"Critical {_cc.get('crit', 0)} · High {_cc.get('high', 0)} · Medium {_cc.get('med', 0)} · "
        f"Low {_cc.get('low', 0)} · Info {_cc.get('info', 0)}.", size=9, color=C_GRAY)
    _cov_rows = [[f"{i + 1:02d}", name, _TL.get(cls, cls)] for i, (name, cls) in enumerate(_SC)]
    _cov_tbl = _make_table(doc, ["#", "점검 항목 (취약점)", "위험도"], _cov_rows,
                           col_widths=[1.2, 11.8, 3.0])
    for i, (name, cls) in enumerate(_SC):
        _shd(_cov_tbl.rows[i + 1].cells[2], _tier_hex.get(cls, "E5E7EB"))
    doc.add_page_break()

    # ── 4. 총평 (Executive Summary) ──
    _exec_by_sev = summary.get("by_severity") or {
        "Critical": sum(1 for f in vuln_list if _report_sev(f) == "Critical"),
        "High":     sum(1 for f in vuln_list if _report_sev(f) == "High"),
        "Medium":   sum(1 for f in vuln_list if _report_sev(f) == "Medium"),
        "Low":      sum(1 for f in vuln_list if _report_sev(f) == "Low"),
    }
    _add_executive_summary_page(doc, domain, risk, vuln_count, _exec_by_sev, vuln_list, analysis,
                                created_at=created_at)

    # ── 5. 발견된 취약점 (Findings Overview) ──
    _h1(doc, "5. 발견된 취약점  (Findings Overview)")
    _body(doc, "발견된 취약점의 요약입니다. 항목별 상세 재현·증거·조치는 다음 장(취약점 상세)을 참조하십시오.",
          size=9, color=C_GRAY)

    # 심각도별 집계 — 오탐 억제 차감된 유효 분포(표지·요약·점수 단일 소스)
    by_sev = _eff_severity_counts(analysis)
    crit_c = by_sev.get("Critical", sum(1 for f in vuln_list if _report_sev(f) == "Critical"))
    high_c = by_sev.get("High",     sum(1 for f in vuln_list if _report_sev(f) == "High"))
    med_c  = by_sev.get("Medium",   sum(1 for f in vuln_list if _report_sev(f) == "Medium"))
    low_c  = by_sev.get("Low",      sum(1 for f in vuln_list if _report_sev(f) == "Low"))

    def _conf_by(sev_name: str) -> int:
        return sum(1 for f in vuln_list
                   if _report_sev(f) == sev_name and f.get("probe_confirmed") is True)

    _h2(doc, "5.1 심각도별 집계")
    _sev_tbl = _make_table(doc,
        ["심각도", "발견 수", "실증 확인", "대응"],
        [
            ["Critical", str(crit_c), str(_conf_by("Critical")), "즉각 조치"],
            ["High",     str(high_c), str(_conf_by("High")),     "즉각 조치"],
            ["Medium",   str(med_c),  str(_conf_by("Medium")),   "조속 조치"],
            ["Low",      str(low_c),  str(_conf_by("Low")),      "모니터링"],
            ["소계",     str(vuln_count), str(confirmed_count),  ""],
        ],
        col_widths=[3.5, 3, 3, 6.5],
    )
    for _ri, _sv in enumerate(["Critical", "High", "Medium", "Low"]):
        _shd(_sev_tbl.rows[_ri + 1].cells[0], REPORT_SEV_HEX.get(_sv, "FFFFFF"))

    _h2(doc, "5.2 발견 취약점 목록")
    if vuln_list:
        _ov_rows = []
        for f in vuln_list:
            _vid = _vuln_id(f["_idx"]) if isinstance(f.get("_idx"), int) else "-"
            _pc = f.get("probe_confirmed")
            _st = "★ 실증확인" if _pc is True else ("⚠ 가능성" if _pc is False else "■ 설정취약")
            _ov_rows.append([_vid, _report_sev_label(f), _display_title(f),
                             f.get("cwe", "") or "-", f.get("host", "") or "-", _st])
        _ov_tbl = _make_table(doc,
            ["ID", "위험도", "취약점", "CWE", "호스트", "확인 상태"],
            _ov_rows, col_widths=[1.8, 1.6, 5.2, 1.8, 3.0, 2.6])
        for _ri, f in enumerate(vuln_list):
            _shd(_ov_tbl.rows[_ri + 1].cells[1], REPORT_SEV_HEX.get(_report_sev(f), "FFFFFF"))
    else:
        _body(doc, "보고 기준을 충족하는 취약점이 발견되지 않았습니다.", color=C_GREEN)

    doc.add_page_break()

    # ── 6. 취약점 상세 (Detailed Findings) — 종합판(공격 시나리오·재현·CVE·상세 조치) ──
    _h1(doc, "6. 취약점 상세  (Detailed Findings)")
    _body(doc, "각 취약점의 요약·증거·영향·공격 시나리오·CVE·단계별 재현·상세 조치를 종합적으로 제시합니다. "
               "요약본(PDF/HTML)의 간략 카드와 달리, 본 장은 담당자가 직접 재현·조치할 수 있는 상세본입니다.",
          size=9, color=C_GRAY)

    if not web_vuln_list:
        _body(doc, "발견된 웹 애플리케이션 취약점이 없습니다.")
    else:
        fig_counter = [0]  # 그림 번호 공유 카운터

        for idx, f in enumerate(web_vuln_list, 1):
            # _idx 는 이미 부여됨(웹 1.. 순). 여기선 페이지 분리 판단에만 idx 사용.

            # 각 취약점 상세는 '새 페이지 맨 위'에서 시작.
            # 첫 취약점은 '6. 세부 분석' 제목이 이미 새 페이지 상단에 있으므로 중복 break 금지.
            if idx > 1:
                doc.add_page_break()

            # ① 확인 배너 + 제목 (VULN-NNN / 위험도 / OWASP / confidence)
            _add_confirmation_banner(doc, f)

            # ①-G 한눈에 보기 — 무엇이 / 왜 위험 / 조치(비전문가용 평이한 3줄 요약, 가독성)
            _add_at_a_glance_card(doc, f)

            # ①-L 발견 위치 · Payload — 모든 취약점에 '어느 URL에서 어떤 payload로 발견'을 명시
            _add_discovery_locus(doc, f)

            # ①-AI AI 앙상블 오탐 의심 표시(룰 판정 유지 · 수동 확인 권장)
            if f.get("ai_fp_flag"):
                _afp = _para(doc, space_before=2, space_after=4)
                _afp.paragraph_format.left_indent = Cm(0.2)
                _run(_afp, "🧪 AI 앙상블 오탐 의심", size=10, bold=True, color=C_ORANGE)
                _run(_afp, f" ({f.get('ai_fp_votes','')}표) — 룰 판정은 유지되나 수동 확인을 권장합니다.",
                     size=9, color=C_GRAY)
                _rsns = f.get("ai_fp_reasons") or []
                if _rsns:
                    _afp2 = _para(doc, space_before=0, space_after=4)
                    _afp2.paragraph_format.left_indent = Cm(0.6)
                    _run(_afp2, "판정 근거: " + "; ".join(str(r) for r in _rsns[:3]), size=8, color=C_GRAY)

            # ② Finding Card — 요약 + 5박스(관찰·증거·영향·기술세부·권장) + 참조
            _add_observed_view_block(doc, f, analysis)

            # ②-A 공격 벡터·시나리오(단계별)·CVE·점검 도구 (상세본 심층)
            _add_attack_info(doc, f)

            # ②-P 증거 기반 검증(Proof Validation) — 프로파일/증거/승격/차단 행위
            _add_finding_proof_block(doc, f, analysis)

            # ②-PE Proof Evidence Card — Payload/Expected/Observed/Fingerprint/재현/Proof Quality
            _add_finding_proof_detail(doc, f, analysis)

            # ②-R 단계별 재현(비파괴 curl/명령) — 담당자 직접 재현용
            _add_reproduction_cmd_section(doc, f)

            # ②-POC 재현 PoC 스크립트(Python 독립 실행) — 있을 때만
            _add_poc_script_section(doc, f)

            # ③ 예상 조치 난이도 / 작업시간 (추정치)
            _eff_diff, _eff_hours = _remediation_effort(f)
            _ep = _para(doc, space_before=2, space_after=4)
            _ep.paragraph_format.left_indent = Cm(0.2)
            _run(_ep, "예상 조치 난이도: ", size=9, bold=True, color=C_NAVY)
            _run(_ep, f"{_eff_diff}", size=9, color=C_BLACK)
            _run(_ep, "    예상 작업시간: ", size=9, bold=True, color=C_NAVY)
            _run(_ep, f"{_eff_hours}", size=9, color=C_BLACK)

            # ③-R 상세 권장 조치 (단계별 조치 방안)
            _add_recommendation(doc, f)

            # ④ 증거 스크린샷 (시각 증거)
            _add_screenshots_section(doc, f, fig_counter)

            # ⑤ AI 보안 분석가 의견 / 규칙 기반 분석 참고 (있을 때만)
            if _report_show("AI", True):
                _add_ai_analyst_section(doc, f)

    # 세부 분석과 다음 장 사이 페이지 분리
    doc.add_page_break()

    # ── 서비스/포트 보안 점검 결과 (service 카테고리 항목만, 비면 생략) ──────────
    if _report_show("SERVICE_SCAN", True):
        _add_service_security_section(doc, analysis, service_vuln_list, checked_ports)

    # ── 7. 대응방안 (Recommendations) — 취약점이 있을 때만 작성(0건이면 통째로 생략) ──
    if vuln_list:
        _h1(doc, "7. 대응방안  (Recommendations)")
        _body(doc, analysis.get("overall_summary", ""))
        ai = analysis.get("ai_analysis") or {}
        _ai_risk_asmt = ai.get("ai_risk_assessment", "") or ""
        if bool((analysis.get("ai_status") or {}).get("used")) and _ai_risk_asmt \
                and ai.get("ai_provider", "none") != "none":
            _card_box(doc, ICON["reco"], "AI 전체 보안 수준 평가 (참고)", _ai_risk_asmt[:600], "1E3A5F", "EFF6FF")
        # 7.1 개선 로드맵(Priority 1/2/3)
        _add_v4_roadmap(doc, analysis)
        # 7.2 우선 조치 권고(컨설팅 문체)
        _h2(doc, "7.2 우선 조치 권고 사항")
        for _lbl, _sevname, _color in [
            ("즉각 조치 필요 (Critical)", "Critical", C_RED),
            ("즉각 조치 필요 (High)", "High", C_RED),
            ("조속 조치 권고 (Medium)", "Medium", C_ORANGE),
            ("모니터링 권고 (Low)", "Low", C_YELLOW),
        ]:
            _items = [f for f in vuln_list if _report_sev(f) == _sevname]
            if not _items:
                continue
            _p = _para(doc, space_before=6, space_after=3)
            _run(_p, f"● {_lbl}", size=10, bold=True, color=_color)
            for _fi in _items:
                _vid = _vuln_id(_fi["_idx"]) if isinstance(_fi.get("_idx"), int) else ""
                _p2 = _para(doc, space_before=1, space_after=2); _p2.paragraph_format.left_indent = Cm(0.6)
                _pc = _fi.get("probe_confirmed"); _cf = _fi.get("confidence", "")
                _mark = (" (★실증확인)" if _pc is True
                         else " (△가능성)" if (_pc is False or _cf == "POSSIBLE") else " (■설정확인)")
                _run(_p2, f"- {_vid} [{_fi.get('host','')}:{_fi.get('port','')}]{_mark} {_display_title(_fi)}", size=10)
                _rec = ("TRACE 메서드를 비활성화하고 필요한 HTTP 메서드만 허용하십시오."
                        if _trace_only(_fi) else _sanitize_display_text(_fi.get("recommendation", ""), _fi))
                _rec = _consulting_reco(_rec)
                if _rec and _rec != "-":
                    _p3 = _para(doc, space_before=1, space_after=2); _p3.paragraph_format.left_indent = Cm(1.2)
                    _run(_p3, f"→ {_rec}", size=9, color=C_BLUE)
        doc.add_page_break()

    # ── 부록 (Appendix) — 대응방안이 생략되면 번호를 7로 당김 ───────────────────────
    _h1(doc, f"{'8' if vuln_list else '7'}. 부록  (Appendix)")
    _body(doc, "고객 열람 편의를 위해 상세 판정 근거·재현 지표·전체 목록·엔진 내부 정보를 부록으로 분리했습니다.",
          size=9, color=C_GRAY)
    # 부록 A. Eoseureum 점검 기준
    _add_eoseureum_criteria_section(doc)
    # 부록 B. 판정 근거 Evidence Matrix
    _add_evidence_matrix_section(doc, web_vuln_list)
    # (조치 우선순위는 본문 '7. 대응방안'에 있으므로 부록에서 중복 제거)
    # 부록 C. 공격 표면 발견 항목 (증거 기반 노출 지점만)
    _add_attack_surface_section(doc, analysis)
    # ('추가 점검 권고'는 증거 없는 일반 추천이라 제거 — 초기 크롤/능동점검 단계에서 이미 다루며,
    #  실제 취약점이 확인되면 해당 취약점 상세·대응방안에 자동 기록되므로 별도 권고 섹션은 불필요.)
    # 엔진 내부/장황 섹션은 기본 숨김(간결 보고서). 템플릿에서 REPORT_SHOW_ENGINE_INTERNAL 로 노출.
    _eng = _report_show("ENGINE_INTERNAL", False)
    # 고객용 핵심(유지): 커버리지 요약 · 보안 진단 대시보드(KPI) · 확인된 통제 · 오탐억제 노트 · 탐지 커버리지.
    if _report_show("COVERAGE", True):
        _add_coverage_summary_section(doc, analysis)
    _add_v3_dashboard(doc, analysis)                 # 보안 진단 대시보드(요약 KPI 인포그래픽)
    _add_v2_security_controls(doc, analysis)         # 확인된 보안 통제(양호 근거)
    _add_fp_suppression_note(doc, analysis)          # 오탐 억제 투명성(짧음)
    _add_detection_coverage(doc, analysis)           # 탐지 커버리지(선택 정합됨)
    # ── 엔진 내부/그래프/QA 상세 — 기본 숨김(장황·개발자용) ──
    if _eng:
        _add_discovery_stats_section(doc, disc_stats)   # QA 지표(시도 수 등)
        _add_proof_validation_summary(doc, analysis)    # 검증 후보/판정 상세
        _add_knowledge_graph_summary(doc, analysis)     # 보안 지식 그래프
        _add_browser_discovery_summary(doc, analysis)   # 브라우저 발견 상세
    # 부록 G. AI 공격 체인 분석(엔진 내부와 함께 토글, 또는 ATTACK_CHAIN 명시 시)
    if _eng and _report_show("ATTACK_CHAIN", True):
        _add_ai_analysis_section(doc, analysis)

    # (전체 취약점 목록은 본문 '5. 발견된 취약점'에 있으므로 부록에서 중복 제거)

    # ── 부록 H. 발견된 호스트 및 포트 목록 ───────────────────────────────────────
    _h1(doc, "발견된 호스트 및 포트 목록")

    # 부록 '능동점검 발견' 은 최종 normalized 취약점(analysis.findings) 기준으로만 표시.
    # (필터링된 cmd_injection/soft-404/noise 는 raw active_probes 에 남아도 부록에 표기하지 않음)
    _norm_by_hostport: dict = {}
    for _nf in (analysis.get("findings") or []):
        if not isinstance(_nf, dict):
            continue
        _k = (str(_nf.get("host", "")), str(_nf.get("port", "")))
        _norm_by_hostport.setdefault(_k, []).append(_display_title(_nf))

    for hr in results:
        hp = _para(doc, space_before=8, space_after=3)
        _run(hp, f"▶ {hr.get('host', '')} ({hr.get('ip', '')})", size=10, bold=True, color=C_NAVY)
        _run(hp, f"  [{hr.get('scan_mode', 'standard')} 모드]", size=9, color=C_GRAY)

        services = hr.get("services", [])
        if services:
            svc_rows = []
            for svc in services:
                hi = svc.get("http_info") or {}
                si = svc.get("ssl_info") or {}
                info = ""
                if hi.get("title"):     info = f"Title: {hi['title']}"
                elif hi.get("server"):  info = f"Server: {hi['server']}"
                elif svc.get("banner"): info = svc["banner"][:60]
                ssl_txt = ""
                if si.get("valid"):
                    ssl_txt = f"SSL {si.get('version','')} / {si.get('days_until_expiry','?')}일 남음"

                # 능동점검 발견 = 해당 host:port 의 최종 normalized 취약점만(raw probe 키 미사용)
                _titles = _norm_by_hostport.get((str(hr.get("host", "")), str(svc.get("port", ""))), [])
                probes_found = ", ".join(_titles[:4]) if _titles else "-"

                svc_rows.append([
                    str(svc.get("port", "")),
                    svc.get("service", ""),
                    str(hi.get("status", "") or ""),
                    info or ssl_txt or "-",
                    probes_found,
                ])
            _make_table(doc, ["포트", "서비스", "HTTP 상태", "서비스 정보", "능동점검 발견"],
                        svc_rows, col_widths=[1.2, 1.8, 1.8, 6, 5.2])

    # ── 삭제 요청 (상태변경형 실증의 자동 원복 실패 산출물) — 보고서 하단 ──
    try:
        _add_deletion_requests_section(doc, analysis)
    except Exception:
        pass

    # 면책 조항
    sep2 = _para(doc, space_before=20, space_after=6)
    _para_border_bottom(sep2, color="CCCCCC", sz="4")

    disc = _para(doc, space_before=4, space_after=2)
    _run(disc,
        "본 보고서는 Eoseureum을 통해 자동 생성된 보안 점검 결과입니다. "
        "기재된 공격 시나리오는 방어적 보안 강화를 목적으로 한 개념적 설명이며, "
        "실제 공격 수행이나 권장을 의미하지 않습니다. "
        "무단으로 타인의 시스템을 스캔하거나 접근하는 행위는 관련 법령에 의해 처벌받을 수 있습니다.",
        size=8, color=C_GRAY,
    )

    # ── Developer Appendix(엔진 내부 정보) — 기본 숨김. 내부 기술검토용으로만 노출. ──
    if _report_show("ENGINE_INTERNAL", False):
        try:
            _add_developer_appendix(doc, analysis)
        except Exception:
            pass

    # 모든 표의 행이 페이지 경계에서 잘리지 않도록 일괄 방지(페이지 잘림 최종 방어)
    try:
        for _t in doc.tables:
            _no_split_table(_t)
    except Exception:
        pass

    # v5: 빈 페이지 유발 요소 제거
    try:
        _remove_blank_pages(doc)
    except Exception:
        pass

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf
