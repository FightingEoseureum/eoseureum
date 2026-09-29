"""
api_audit.py — API 인지형 심층 점검 '순수 로직'(OpenAPI/Swagger 스펙 분석).

Swagger/OpenAPI 문서에서 오퍼레이션(경로·메서드·파라미터·본문 속성)을 추출하고,
- 과다 정보 노출(Excessive Data Exposure): 응답 JSON 에 민감 필드명 존재
- Mass Assignment 후보: 쓰기 오퍼레이션 본문에 권한/민감 속성(role/is_admin 등)
- BOLA 후보: 경로 파라미터가 객체 식별자({id}/{userId} 등)
를 판정한다. 네트워크는 active_probing._probe_api_deep 이 수행(GET 읽기 전용).

안전 원칙: 여기서 만드는 것은 '점검 계획/판정'뿐이며 상태 변경/쓰기 실행은 하지 않는다.
"""
from __future__ import annotations

import re

# 민감 필드명(과다 노출/Mass Assignment 공통) — 응답/본문 속성명에 나타나면 신호.
SENSITIVE_FIELD_RE = re.compile(
    r"^(pass(word|wd)?(_?(hash|salt))?|pwd|secret|salt|hash|token|access_token|refresh_token|"
    r"api_?key|private_?key|ssn|resident(_?number)?|주민(등록)?번호|card(_?number)?|"
    r"cvv|cvc|pin|security_?code|is_?admin|isadmin|role|roles|authority|authorities|"
    r"permission|permissions|grant|is_?verified|verified|balance|credit|점수|권한|비밀번호)$",
    re.IGNORECASE)

# Mass Assignment 로 특히 위험한 '권한/상태' 속성.
PRIVILEGE_FIELD_RE = re.compile(
    r"^(is_?admin|isadmin|admin|role|roles|authority|authorities|permission|permissions|"
    r"grant|is_?verified|verified|is_?active|active|status|balance|credit|point|"
    r"is_?staff|superuser|owner|approved)$",
    re.IGNORECASE)

# 객체 식별자형 경로 파라미터명(BOLA 후보).
_OBJECT_ID_RE = re.compile(
    r"^(id|.*_?id|.*Id|uid|uuid|no|seq|pk|.*number|.*_no|slug|key)$", re.IGNORECASE)

_HTTP_METHODS = {"get", "post", "put", "delete", "patch"}


def _resolve_ref(spec: dict, ref: str) -> dict:
    """'#/components/schemas/X' 또는 '#/definitions/X' 한 단계 해석."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return {}
    node = spec
    for part in ref[2:].split("/"):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return {}
    return node if isinstance(node, dict) else {}


def _schema_props(spec: dict, schema: dict, depth: int = 0) -> list[str]:
    """스키마(인라인/$ref)에서 속성명 리스트 추출(1~2단계 $ref 해석)."""
    if not isinstance(schema, dict) or depth > 3:
        return []
    if "$ref" in schema:
        return _schema_props(spec, _resolve_ref(spec, schema["$ref"]), depth + 1)
    props = schema.get("properties")
    out = []
    if isinstance(props, dict):
        out.extend(str(k) for k in props.keys())
    # allOf/oneOf/anyOf 병합
    for comb in ("allOf", "oneOf", "anyOf"):
        for sub in (schema.get(comb) or []):
            out.extend(_schema_props(spec, sub, depth + 1))
    return out


def _body_props(spec: dict, op: dict) -> list[str]:
    """오퍼레이션 요청 본문 속성명(OpenAPI 2 body param / 3 requestBody)."""
    out = []
    # OpenAPI 3
    rb = op.get("requestBody")
    if isinstance(rb, dict):
        content = rb.get("content") or {}
        for _ct, media in content.items():
            if isinstance(media, dict) and media.get("schema"):
                out.extend(_schema_props(spec, media["schema"]))
    # OpenAPI 2 (body parameter)
    for p in (op.get("parameters") or []):
        if isinstance(p, dict) and p.get("in") == "body" and p.get("schema"):
            out.extend(_schema_props(spec, p["schema"]))
    # 순서 보존 중복 제거
    seen, res = set(), []
    for k in out:
        if k not in seen:
            seen.add(k)
            res.append(k)
    return res


def parse_openapi_operations(spec: dict, base_origin: str = "", max_ops: int = 200) -> list[dict]:
    """OpenAPI 스펙 → 오퍼레이션 리스트.

    op: {method, path, url, path_params[], query_params[], required_query[], body_props[]}
    """
    ops: list[dict] = []
    if not isinstance(spec, dict):
        return ops
    base_path = ""
    if isinstance(spec.get("basePath"), str):
        base_path = spec["basePath"].rstrip("/")
    # servers(OpenAPI3) 의 basePath 유추(선택)
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return ops
    for path_str, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared_params = item.get("parameters") if isinstance(item.get("parameters"), list) else []
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            params = list(shared_params) + list(op.get("parameters") or [])
            path_params, query_params, required_query = [], [], []
            for p in params:
                if not isinstance(p, dict):
                    continue
                loc, name = p.get("in"), p.get("name")
                if not name:
                    continue
                if loc == "path":
                    path_params.append(name)
                elif loc == "query":
                    query_params.append(name)
                    if p.get("required"):
                        required_query.append(name)
            full_path = (base_path + path_str) if base_path else path_str
            ops.append({
                "method": method.upper(),
                "path": full_path,
                "url": (base_origin.rstrip("/") + full_path) if base_origin else full_path,
                "path_params": path_params,
                "query_params": query_params,
                "required_query": required_query,
                "body_props": _body_props(spec, op),
            })
            if len(ops) >= max_ops:
                return ops
    return ops


def fill_path_params(url: str, path_params: list, sample: str = "1") -> str:
    """경로 템플릿의 {param} 을 샘플값으로 치환(GET 과다노출 점검용)."""
    out = url
    for p in path_params or []:
        out = out.replace("{" + p + "}", sample)
    # 남은 임의 {x} 도 치환
    out = re.sub(r"\{[^}/]+\}", sample, out)
    return out


def resolvable_get_ops(operations: list, max_n: int = 15) -> list[dict]:
    """GET 이고 필수 쿼리 파라미터가 없는(또는 경로만으로 접근 가능한) 오퍼레이션(읽기 점검 대상)."""
    out = []
    for op in operations or []:
        if op.get("method") != "GET":
            continue
        if op.get("required_query"):
            continue  # 필수 쿼리 미상 → 오탐/에러 회피 위해 제외
        out.append(op)
        if len(out) >= max_n:
            break
    return out


def find_sensitive_fields(obj, _depth: int = 0, _acc: set | None = None) -> list[str]:
    """JSON(dict/list) 응답에서 민감 필드'명'이 키로 존재하는지 재귀 탐색."""
    acc = _acc if _acc is not None else set()
    if _depth > 6:
        return sorted(acc)
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and SENSITIVE_FIELD_RE.match(k.strip()):
                acc.add(k)
            find_sensitive_fields(v, _depth + 1, acc)
    elif isinstance(obj, list):
        for it in obj[:50]:
            find_sensitive_fields(it, _depth + 1, acc)
    return sorted(acc)


def mass_assignment_candidates(operations: list) -> list[dict]:
    """쓰기 오퍼레이션 본문에 권한/상태 속성이 있으면 Mass Assignment 후보."""
    out = []
    for op in operations or []:
        if op.get("method") not in ("POST", "PUT", "PATCH"):
            continue
        risky = [p for p in (op.get("body_props") or []) if PRIVILEGE_FIELD_RE.match(str(p).strip())]
        if risky:
            out.append({"method": op["method"], "path": op["path"], "fields": risky})
    return out


def bola_candidates(operations: list) -> list[dict]:
    """경로 파라미터가 객체 식별자인 오퍼레이션(BOLA/IDOR 교차검증 후보)."""
    out = []
    for op in operations or []:
        obj_ids = [p for p in (op.get("path_params") or []) if _OBJECT_ID_RE.match(str(p).strip())]
        if obj_ids:
            out.append({"method": op["method"], "path": op["path"],
                        "url": op.get("url", ""), "object_params": obj_ids})
    return out


# ── 비즈니스로직 안티패턴 라이브러리 ─────────────────────────────────────────────
# 스펙에서 도출한 오퍼레이션에 '알려진 비즈니스로직 취약 클래스'를 결정적으로 매칭해 후보를
# 생성한다. 각 후보는 SAFE 테스트 레시피(safe_test)를 함께 실어, 이후 SAFE 실행기/AI 슬롯이
# 그대로 검증에 쓸 수 있게 한다. (여기까지는 요청 미전송 · 판정 아님 · 후보 생성만)
_PRICE_FIELD_RE = re.compile(
    r"(?i)^(price|amount|total|subtotal|cost|fee|balance|qty|quantity|count|"
    r"discount|point|points|credit|credits|bonus|cashback)$")
_TOKEN_FIELD_RE = re.compile(
    r"(?i)^(token|coupon|voucher|nonce|otp|code|ticket|promo|promocode|giftcard)$")
_FLOW_PATH_RE = re.compile(
    r"(?i)/(checkout|confirm|complete|approve|pay|payment|finalize|settle|"
    r"cancel|refund|activate|deactivate|verify|grant|promote)")


def price_tampering_candidates(operations: list) -> list[dict]:
    """쓰기 오퍼레이션에 가격/수량/포인트류 파라미터가 있으면 값 조작 후보."""
    out = []
    for op in operations or []:
        if op.get("method") not in ("POST", "PUT", "PATCH"):
            continue
        allp = list(op.get("body_props") or []) + list(op.get("query_params") or [])
        hit = [p for p in allp if _PRICE_FIELD_RE.match(str(p).strip())]
        if hit:
            out.append({"pattern": "PRICE_TAMPER", "category": "가격/수량 조작",
                        "method": op["method"], "path": op["path"], "url": op.get("url", ""),
                        "params": hit, "severity_hint": "MEDIUM",
                        "safe_test": ("해당 파라미터를 낮은/음수/과대 값으로 변조 → 서버가 원값 대비 "
                                      "수용하는지 A/B 차등 확인(결제/커밋 미완료 · 비파괴)")})
    return out


def replay_candidates(operations: list) -> list[dict]:
    """일회성 토큰/쿠폰류 파라미터가 있으면 재사용(멱등성) 후보."""
    out = []
    for op in operations or []:
        if op.get("method") not in ("POST", "PUT", "PATCH", "GET"):
            continue
        allp = list(op.get("body_props") or []) + list(op.get("query_params") or [])
        hit = [p for p in allp if _TOKEN_FIELD_RE.match(str(p).strip())]
        if hit:
            out.append({"pattern": "REPLAY", "category": "멱등성/재사용",
                        "method": op["method"], "path": op["path"], "url": op.get("url", ""),
                        "params": hit, "severity_hint": "MEDIUM",
                        "safe_test": ("일회성 토큰/쿠폰을 2회 제출 → 2번째도 수용되면 재사용 취약 "
                                      "(비파괴 관찰 범위)")})
    return out


def flow_control_candidates(operations: list) -> list[dict]:
    """흐름/상태 민감 경로(checkout/confirm/pay/approve 등)의 상태변경 오퍼레이션 → 단계 우회 후보."""
    out = []
    for op in operations or []:
        if op.get("method") == "GET":
            continue
        if _FLOW_PATH_RE.search(op.get("path", "") or ""):
            out.append({"pattern": "STEP_SKIP", "category": "흐름/상태 우회",
                        "method": op["method"], "path": op["path"], "url": op.get("url", ""),
                        "params": [], "severity_hint": "MEDIUM",
                        "safe_test": ("선행 단계 없이 이 상태변경 엔드포인트를 직접 호출 → 상태머신 "
                                      "우회 여부 확인(비파괴 관찰)")})
    return out


import urllib.parse as _uparse

# 경로 세그먼트가 객체 식별자(숫자/UUID/해시)인지 — 스펙 없는 추론에서 path_params 판정용.
_ID_SEGMENT_RE = re.compile(r"^(\d{1,}|[0-9a-fA-F]{8,}|[0-9a-f]{8}-[0-9a-f]{4}-)")


def operations_from_points(points: list) -> list[dict]:
    """크롤/폼에서 발견한 입력점(active_probing points: {method,url,params,...})을
    안티패턴 라이브러리가 쓰는 operation 스키마로 변환한다(Swagger 스펙이 없을 때의 폴백).
      operation = {method, path, url, path_params, query_params, body_props}
    - 숫자/UUID/해시형 경로 세그먼트는 path_params(객체식별자)로 추정 → BOLA 후보에 사용.
    - GET 파라미터 → query_params, 쓰기(POST/PUT/PATCH) 파라미터 → body_props.
    """
    ops: list[dict] = []
    seen: set = set()
    for p in points or []:
        if not isinstance(p, dict):
            continue
        url = p.get("url") or ""
        method = (p.get("method") or "GET").upper()
        try:
            path = _uparse.urlparse(url).path or "/"
        except Exception:
            path = "/"
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        params = list((p.get("params") or {}).keys())
        # 크롤 URL 은 경로에 식별자 '값'(예: /invoices/8842)만 있고 스펙처럼 '{id}' 이름이 없다.
        # bola_candidates 는 path_params 를 이름(_OBJECT_ID_RE)으로 매칭하므로, 값이 식별자형인
        # 세그먼트는 합성 이름 'id' 로 표기해 BOLA 후보로 잡히게 한다.
        has_id_segment = any(seg and _ID_SEGMENT_RE.match(seg) for seg in path.split("/"))
        path_params = (["id"] if has_id_segment else []) + \
                      [k for k in params if _OBJECT_ID_RE.match(str(k))]
        op = {"method": method, "path": path, "url": url,
              "path_params": path_params,
              "query_params": params if method == "GET" else [],
              "body_props": params if method in ("POST", "PUT", "PATCH") else []}
        ops.append(op)
    return ops


def business_logic_candidates(operations: list, spec: dict | None = None) -> list[dict]:
    """모든 안티패턴 탐지기를 돌려 통합 후보 리스트를 반환(결정적). BOLA/Mass 를 공통 스키마로 포함.
    반환 후보: {pattern, category, method, path, url, params, severity_hint, safe_test}."""
    cands: list[dict] = []
    for c in bola_candidates(operations):
        cands.append({"pattern": "BOLA", "category": "접근제어(객체)",
                      "method": c["method"], "path": c["path"], "url": c.get("url", ""),
                      "params": c.get("object_params", []), "severity_hint": "HIGH",
                      "safe_test": "A/B 계정으로 동일 객체ID 교차 접근 → 타 계정 객체 노출 여부(읽기 전용)"})
    for c in mass_assignment_candidates(operations):
        cands.append({"pattern": "MASS_ASSIGN", "category": "권한 상승",
                      "method": c["method"], "path": c["path"], "url": c.get("url", ""),
                      "params": c.get("fields", []), "severity_hint": "HIGH",
                      "safe_test": ("권한/상태 속성(role/is_admin 등)을 상향값으로 포함 전송 → A/B "
                                    "재조회에 반영되면 확증(전송 후 원복)")})
    cands += price_tampering_candidates(operations)
    cands += replay_candidates(operations)
    cands += flow_control_candidates(operations)
    # (pattern, method, path) 기준 중복 제거
    seen, uniq = set(), []
    for c in cands:
        k = (c["pattern"], c["method"], c["path"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(c)
    return uniq
