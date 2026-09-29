"""
deep_detect.py — 심화 탐지용 '순수 로직'(NoSQL 판정 / 역직렬화 서명 탐지).

네트워크 없음·예외 미발생. 실제 요청은 active_probing 이 수행하고, 판정/서명 매칭만 여기서.
안전 원칙: 역직렬화는 '탐지(서명 존재)'만 한다 — 익스플로잇/가젯체인 생성 없음(SAFE).
"""
from __future__ import annotations

import re

# ── NoSQL: 연산자 주입 판정 ──────────────────────────────────────────────────
def judge_nosql_operator(normal_len: int, inj_len: int, control_len: int | None = None,
                         threshold: int = 100) -> bool:
    """연산자 주입($ne 등) 응답이 '연산자로 해석됐다'고 볼 수 있는지 판정.

    - 주입 응답이 정상(리터럴) 응답과 threshold 이상 차이나면 후보.
    - 대조군(control: $eq 불가능값 등, '항상 거짓')이 주어지면, 주입이 정상과도 다르고
      대조군과도 다를 때만 인정(단순 동적 콘텐츠 오탐 억제).
    """
    if inj_len is None or normal_len is None:
        return False
    if abs(inj_len - normal_len) < threshold:
        return False
    if control_len is not None:
        # 주입($ne=참) 과 대조군($eq=거짓)이 사실상 같으면 연산자 해석 아님(동적 콘텐츠)
        if abs(inj_len - control_len) < threshold:
            return False
    return True


def nosql_bracket_params(param: str) -> list[tuple[str, str]]:
    """쿼리 파라미터 브래킷 주입 후보 (key, value). 예: user[$ne]= / user[$gt]= / user[$regex]=."""
    return [
        (f"{param}[$ne]", "impossible_eoseureum_xyz_99999"),
        (f"{param}[$gt]", ""),
        (f"{param}[$regex]", ".*"),
    ]


# MongoDB/NoSQL 드라이버·DB 오류 시그니처(강한 양성 근거). 응답에 이게 있으면 연산자가 실제로
# DB 계층까지 전달·해석된 것으로 본다. 우리 payload 문자열(query[$ne] 등)이 페이지에 그대로
# 반사돼 오탐되지 않도록, '반사 가능한 연산자 토큰'은 제외하고 실제 드라이버/DB 오류 문구만 넣는다.
_MONGO_SIG = re.compile(
    r"(MongoError|MongoServerError|MongoServerSelectionError|MongoParseError|"
    r"CastError|BSONError|BSONTypeError|E11000|mongoose|pymongo|"
    r"unknown\s+(?:top\s+level\s+)?operator|BadValue|FailedToParse|"
    r"can't\s+canonicalize\s+query|Cannot\s+read\s+propert(?:y|ies)\s+of)",
    re.IGNORECASE,
)


def mongo_signature(text: str) -> str | None:
    """응답에 MongoDB 오류/드라이버 시그니처가 있으면 매칭 문자열을, 없으면 None을 반환한다."""
    if not text:
        return None
    m = _MONGO_SIG.search(text)
    return m.group(0) if m else None


# ── 역직렬화: 직렬화 객체 서명 탐지(탐지 전용) ─────────────────────────────────
# base64/hex/원문 형태의 직렬화 객체 시그니처. 최소 길이 요구로 오탐 억제.
_SERIALIZED_SIGS = [
    ("Java 직렬화 객체(base64)", re.compile(r"rO0AB[A-Za-z0-9+/=]{8,}")),      # \xac\xed\x00\x05
    ("Java 직렬화 객체(hex)", re.compile(r"(?<![0-9a-fA-F])aced0005[0-9a-fA-F]{6,}")),
    ("PHP 직렬화 객체", re.compile(r'O:\d+:"[^"]{1,120}":\d+:\{|a:\d+:\{[si]:')),
    (".NET ViewState(MAC 확인 필요)", re.compile(r"__VIEWSTATE")),
    ("Ruby Marshal(base64)", re.compile(r"(?<![A-Za-z0-9+/])BAh[A-Za-z0-9+/=]{8,}")),
    ("Python pickle(base64)", re.compile(r"(?<![A-Za-z0-9+/])gA[SJRW][A-Za-z0-9+/=]{8,}")),
]


def detect_serialized(text: str) -> list[tuple[str, str]]:
    """텍스트에서 직렬화 객체 서명을 찾는다. 반환 [(형식, 매칭샘플), ...] (중복 형식 1회)."""
    out, seen = [], set()
    if not text:
        return out
    for name, rx in _SERIALIZED_SIGS:
        m = rx.search(text)
        if m and name not in seen:
            seen.add(name)
            sample = m.group(0)[:60]
            out.append((name, sample))
    return out


def scan_sources_for_serialized(sources: dict) -> list[dict]:
    """여러 소스({label: text})에서 직렬화 서명을 스캔. 반환 finding-lite dict 리스트."""
    findings = []
    for label, text in (sources or {}).items():
        for fmt, sample in detect_serialized(str(text or "")):
            findings.append({"location": label, "format": fmt, "sample": sample})
    return findings
