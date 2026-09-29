"""
source_sqli_analyzer.py — 화이트박스(소스코드) SQL 인젝션 분석기.

배경(왜 필요한가):
  Eoseureum 의 기존 SQLi 탐지는 전부 블랙박스(HTTP 페이로드 전송)다. 그런데
  "사용자 입력이 SQL 에 닿기 전에 해싱/인코딩으로 변환"되는 코드는 어떤 페이로드를
  보내도 변환 후 값이 쿼리에 들어가므로 블랙박스로는 절대 트리거되지 않는다.
  예) Flask:
        password = request.form.get("password")
        if sql_filter(password): ...            # ① 필터는 '원본'을 검사
        db(f"... WHERE password='{encoder(password)}'")   # ② 쿼리엔 md5 digest 삽입
  encoder()=hashlib.md5(...).digest() 는 bytes 를 반환하고, f-string 에서 str(bytes)
  즉 b'\\x..' 리터럴 표현(항상 따옴표 포함)이 그대로 SQL 에 박힌다 → 필터를 우회하는
  SQL 인젝션. 이 클래스는 소스가 있어야만 정직하게 발견된다(승인된 grey-box 점검 전제).

무엇을 탐지하나:
  1) 동적 문자열로 만든 SQL 이 DB 싱크(execute/executemany/read_sql_query/…)로 흐름 (CWE-89).
  2) 그 안의 보간값이 요청 입력(request.form/args/cookies/json/…)에서 테인트됨.
  3) 필터/살균 함수가 '원본 입력'에 적용됐지만, 싱크에는 '변환된 값'이 들어가는
     필터↔싱크 변환 불일치(WAF 무력화). → High.
  4) bytes/.digest()/str(bytes) 가 따옴표로 감싼 SQL 문자열에 보간되는 repr 인젝션.

특성:
  - 표준 라이브러리 ast 만 사용(무해·정적). 대상 코드를 import/실행하지 않는다.
  - Rule Engine 판정 불변 원칙 존중: 여기서는 '증거(코드 위치/흐름)'만 산출하고
    최종 verdict/Severity 는 상위(rule_engine/report)가 결정하도록 중립 dict 로 반환한다.
"""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass, asdict


# ── DB 싱크(직접) ─────────────────────────────────────────────────────────────
# 함수명(attr 또는 name) 이 SQL 문자열을 첫 위치 인자로 받는 대표 API.
_DIRECT_SINK_NAMES = {
    "execute", "executemany", "executescript",   # sqlite3/DBAPI cursor·connection
    "read_sql_query", "read_sql",                 # pandas
    "text",                                       # sqlalchemy text() (raw)
    "raw",                                        # django .raw()
}

# ── 변환(해싱/인코딩) — 필터와 싱크 사이에 끼면 우회 가능 ──────────────────────
_TRANSFORM_HINTS = (
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "hashlib",
    "digest", "hexdigest", "encode", "decode", "b64encode", "b64decode",
    "urlsafe_b64encode", "quote", "unquote", "hexlify", "encoder", "encrypt",
    "encrypt", "hash", "pbkdf2", "hmac",
)

# ── 필터/살균/검증 함수명 힌트 ────────────────────────────────────────────────
_FILTER_HINTS = (
    "filter", "sanitize", "sanitise", "escape", "clean", "validate",
    "is_valid", "check", "whitelist", "blacklist", "block", "guard", "waf",
)

# ── 요청 입력 소스(Flask/Django/일반) ─────────────────────────────────────────
_REQUEST_ROOTS = ("request", "flask_request", "req")
_REQUEST_ATTRS = (
    "form", "args", "values", "cookies", "json", "data", "files",
    "get_json", "headers", "query_params", "POST", "GET", "body",
)

# SQL 로 보이는 최소 신호(문자열 조각 중 하나라도 포함)
_SQL_KEYWORDS = ("select ", "insert ", "update ", "delete ", "where ",
                 "from ", "union ", "values ", " set ", "order by")


def _name_of(node: ast.AST) -> str:
    """Attribute/Name 체인을 점 표기 문자열로."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name_of(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name_of(node.func)
    return ""


def _looks_sql(s: str) -> bool:
    low = s.lower()
    return any(k in low for k in _SQL_KEYWORDS)


def _contains_hint(text: str, hints) -> str | None:
    low = text.lower()
    for h in hints:
        if h in low:
            return h
    return None


@dataclass
class SourceFinding:
    file: str
    line: int
    sink: str                       # 싱크 호출 표현 (예: authTBL_select / conn.execute)
    snippet: str                    # 문제 코드 한 줄
    param: str = ""                 # 관련 요청 파라미터/변수
    taint_source: str = ""          # 예: request.form.get('password')
    transform: str = ""             # 예: md5(...).digest() / encoder()
    filter_applied: str = ""        # 예: sql_filter()
    severity: str = "High"
    confidence: str = "POSSIBLE"    # CONFIRMED | POSSIBLE (Rule Engine 이 최종 결정)
    kind: str = "dynamic_sql"       # dynamic_sql | filter_transform_mismatch | bytes_repr_injection
    cwe: str = "CWE-89"
    owasp: str = "A03:2021 - 인젝션"
    evidence: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class _FuncScope:
    """함수 단위 테인트 상태."""
    def __init__(self):
        self.tainted: dict[str, str] = {}      # var -> 소스 설명
        self.transformed: dict[str, str] = {}  # var -> 변환 설명(테인트+변환 흔적)
        self.filtered: dict[str, str] = {}      # var -> 적용된 필터 설명(원본에 대한)


class SqliSourceAnalyzer(ast.NodeVisitor):
    def __init__(self, filename: str, source: str):
        self.filename = filename
        self.source_lines = source.splitlines()
        self.findings: list[SourceFinding] = []
        # 1차 패스에서 수집: 파라미터를 그대로 DB 싱크로 넘기는 로컬 래퍼 함수명
        self.wrapper_sinks: set[str] = set()
        self._tree = ast.parse(source, filename=filename)

    # ── 진입점 ────────────────────────────────────────────────────────────────
    def run(self) -> list[SourceFinding]:
        self._discover_wrapper_sinks(self._tree)
        for node in self._tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._analyze_function(node)
            elif isinstance(node, ast.ClassDef):
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._analyze_function(sub)
        return self.findings

    def _snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    # ── 1차 패스: 로컬 래퍼 싱크 발견 ─────────────────────────────────────────
    def _discover_wrapper_sinks(self, tree: ast.Module):
        """def f(sql): conn.execute(sql) 처럼 인자를 직접 DB 싱크로 넘기면 f 도 싱크로 취급."""
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = [a.arg for a in node.args.args]
            if not params:
                continue
            for call in ast.walk(node):
                if not isinstance(call, ast.Call):
                    continue
                fname = _name_of(call.func).split(".")[-1]
                if fname not in _DIRECT_SINK_NAMES:
                    continue
                # 첫 위치 인자가 이 함수의 파라미터면 래퍼 싱크
                if call.args and isinstance(call.args[0], ast.Name) and call.args[0].id in params:
                    self.wrapper_sinks.add(node.name)

    def _is_sink_call(self, call: ast.Call) -> str:
        fname_full = _name_of(call.func)
        fname = fname_full.split(".")[-1]
        if fname in _DIRECT_SINK_NAMES:
            return fname_full
        if fname_full in self.wrapper_sinks or fname in self.wrapper_sinks:
            return fname_full
        return ""

    # ── 요청 입력/변환/필터 판별 ──────────────────────────────────────────────
    def _request_source_str(self, node: ast.AST) -> str:
        """node 가 요청 입력에서 유래하면 소스 설명 문자열, 아니면 ''."""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Attribute):
                dotted = _name_of(sub)
                parts = dotted.split(".")
                if parts[0] in _REQUEST_ROOTS and any(a in parts for a in _REQUEST_ATTRS):
                    try:
                        return ast.unparse(node)
                    except Exception:
                        return dotted
        return ""

    def _transform_in(self, node: ast.AST) -> str:
        """node 안에 해싱/인코딩 변환 흔적이 있으면 힌트 문자열."""
        for sub in ast.walk(node):
            if isinstance(sub, (ast.Call, ast.Attribute, ast.Name)):
                h = _contains_hint(_name_of(sub), _TRANSFORM_HINTS)
                if h:
                    try:
                        return ast.unparse(sub if isinstance(sub, ast.Call) else node)
                    except Exception:
                        return h
        return ""

    def _bytes_repr_risk(self, node: ast.AST) -> bool:
        """node 가 bytes 를 만들거나 str(bytes) 를 보간 → 따옴표 재삽입 위험."""
        for sub in ast.walk(node):
            n = _name_of(sub).lower()
            if n.endswith(".digest") or n.endswith("digest") and "hex" not in n:
                return True
            if n.endswith(".pack") or "urandom" in n:
                return True
        return False

    # ── 함수 단위 분석 ────────────────────────────────────────────────────────
    def _analyze_function(self, func: ast.AST):
        scope = _FuncScope()
        # 파라미터명 자체가 입력스러우면 약한 테인트(래퍼/헬퍼용)
        for a in getattr(func.args, "args", []):
            if any(k in a.arg.lower() for k in ("password", "passwd", "name", "input",
                                                "param", "key", "value", "query", "sql",
                                                "comment", "user", "id", "data")):
                scope.tainted.setdefault(a.arg, f"parameter '{a.arg}'")

        for stmt in ast.walk(func):
            # 대입: 테인트/변환/필터 전파
            if isinstance(stmt, ast.Assign):
                self._handle_assign(stmt, scope)
            # 필터 호출: if sql_filter(x): ...  또는 x = filter(x)
            if isinstance(stmt, ast.Call):
                self._note_filter(stmt, scope)
            # 싱크 호출 검사
            if isinstance(stmt, ast.Call):
                sink = self._is_sink_call(stmt)
                if sink and stmt.args:
                    self._inspect_sink(func, stmt, sink, scope)

    def _handle_assign(self, node: ast.Assign, scope: _FuncScope):
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not targets:
            return
        rhs = node.value
        src = self._request_source_str(rhs)
        # 우변이 기존 테인트 변수 참조?
        ref_tainted = ""
        for sub in ast.walk(rhs):
            if isinstance(sub, ast.Name) and sub.id in scope.tainted:
                ref_tainted = scope.tainted[sub.id]
        base_taint = src or ref_tainted
        trans = self._transform_in(rhs)
        for t in targets:
            if base_taint:
                scope.tainted[t] = base_taint
                if trans:
                    scope.transformed[t] = trans

    def _note_filter(self, call: ast.Call, scope: _FuncScope):
        fname = _name_of(call.func).split(".")[-1]
        if _contains_hint(fname, _FILTER_HINTS) and call.args:
            arg0 = call.args[0]
            if isinstance(arg0, ast.Name) and arg0.id in scope.tainted:
                scope.filtered[arg0.id] = _name_of(call.func)

    def _inspect_sink(self, func, call: ast.Call, sink: str, scope: _FuncScope):
        sql_arg = call.args[0]
        # 동적 문자열인가?
        dynamic, formatted_exprs = self._is_dynamic_sql(sql_arg)
        if not dynamic:
            return

        # SQL처럼 보이는지(상수 조각 확인) — 오탐 축소
        const_frag = "".join(
            v.value for v in ast.walk(sql_arg)
            if isinstance(v, ast.Constant) and isinstance(v.value, str)
        )
        if const_frag and not _looks_sql(const_frag):
            return

        # 보간된 각 표현을 평가하되, 변환/bytes 는 '테인트된 표현 자체'에만 귀속한다
        # (예: INSERT (...) VALUES ('{admin_name}', ..., '{os.urandom(16).hex()}') 에서
        #  admin_name 은 테인트지만 미변환, hex() 는 변환이지만 비테인트 → 오귀속 방지).
        tainted_src = ""
        transform_desc = ""
        filtered_desc = ""
        param_name = ""
        bytes_risk = False
        for expr in formatted_exprs:
            src = self._request_source_str(expr)
            expr_tainted = bool(src)
            names_transform = ""
            names_filter = ""
            for sub in ast.walk(expr):
                if isinstance(sub, ast.Name):
                    if sub.id in scope.tainted:
                        expr_tainted = True
                        if not tainted_src:
                            tainted_src = scope.tainted[sub.id]
                            param_name = sub.id
                    if sub.id in scope.transformed:
                        names_transform = scope.transformed[sub.id]
                    if sub.id in scope.filtered:
                        names_filter = scope.filtered[sub.id]
            if src and not tainted_src:
                tainted_src = src
            # 이 표현이 테인트일 때에만 변환/bytes 신호를 채택
            if expr_tainted:
                t = self._transform_in(expr) or names_transform
                if t:
                    transform_desc = t
                if self._bytes_repr_risk(expr):
                    bytes_risk = True
                if names_filter and not filtered_desc:
                    filtered_desc = names_filter

        if not tainted_src:
            # 요청 테인트가 확실치 않으면 '동적 SQL' 수준(수동검토)으로만 보고
            self.findings.append(SourceFinding(
                file=self.filename, line=call.lineno, sink=sink,
                snippet=self._snippet(call.lineno),
                severity="Medium", confidence="MANUAL_REVIEW", kind="dynamic_sql",
                evidence="동적으로 구성된 문자열이 DB 싱크로 전달됨(파라미터화 미사용 의심).",
                recommendation="플레이스홀더 기반 파라미터라이즈드 쿼리(예: execute(sql, params)) 사용.",
            ))
            return

        # 테인트 확인됨 → 심각도/종류 결정
        kind = "dynamic_sql"
        severity = "High"
        confidence = "POSSIBLE"
        ev = [f"요청 입력({tainted_src})이 파라미터라이즈드 없이 SQL 문자열에 보간됨."]
        rec = ["파라미터라이즈드 쿼리 사용(값 바인딩). 문자열 포매팅으로 SQL 구성 금지."]

        if filtered_desc and (transform_desc or bytes_risk):
            kind = "filter_transform_mismatch"
            confidence = "CONFIRMED"
            ev.append(
                f"필터 {filtered_desc}() 는 '원본 입력'에 적용되지만, 쿼리에는 변환된 값"
                f"({transform_desc or 'bytes'})이 삽입됨 → 필터가 검사한 문자열과 DB 가 받는"
                f" 문자열이 달라 WAF/필터가 무력화됨(필터 우회 SQLi)."
            )
            rec.append(
                "필터는 '실제 쿼리에 들어가는 값'에 적용하거나, 변환 후 값도 파라미터로 바인딩."
            )
        elif transform_desc or bytes_risk:
            confidence = "POSSIBLE"
            ev.append(
                f"입력이 변환({transform_desc or 'bytes'})을 거쳐 쿼리에 삽입됨 — 블랙박스"
                " 페이로드로는 트리거 불가(변환 후 값이 삽입되므로 소스 분석 필요)."
            )

        if bytes_risk:
            ev.append(
                "bytes/.digest() 값이 따옴표로 감싼 SQL 문자열에 보간됨: str(bytes) 표현이"
                " b'..' 로 렌더되어 따옴표를 재삽입 → 문자열 탈출/구문 조작 가능."
            )

        self.findings.append(SourceFinding(
            file=self.filename, line=call.lineno, sink=sink,
            snippet=self._snippet(call.lineno),
            param=param_name, taint_source=tainted_src,
            transform=transform_desc, filter_applied=filtered_desc,
            severity=severity, confidence=confidence, kind=kind,
            evidence=" ".join(ev), recommendation=" ".join(rec),
        ))

    def _is_dynamic_sql(self, node: ast.AST):
        """동적 SQL 여부 + 보간된 표현 리스트."""
        exprs: list[ast.AST] = []
        # f-string
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    exprs.append(v.value)
            return (len(exprs) > 0, exprs)
        # % 포매팅:  "..." % (a, b)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            right = node.right
            if isinstance(right, ast.Tuple):
                exprs.extend(right.elts)
            else:
                exprs.append(right)
            return (True, exprs)
        # 문자열 + 변수 결합
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            for side in (node.left, node.right):
                if not (isinstance(side, ast.Constant) and isinstance(side.value, str)):
                    exprs.append(side)
            has_str = any(isinstance(s, ast.Constant) and isinstance(s.value, str)
                          for s in (node.left, node.right))
            return (has_str and len(exprs) > 0, exprs)
        # "...".format(a, b)  /  " ".join([...])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("format", "format_map"):
                exprs.extend(node.args)
                exprs.extend(kw.value for kw in node.keywords)
                return (True, exprs)
        return (False, exprs)


def analyze_source_file(path: str) -> list[SourceFinding]:
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            src = f.read()
    except Exception:
        return []
    try:
        analyzer = SqliSourceAnalyzer(os.path.basename(path), src)
        return analyzer.run()
    except SyntaxError:
        return []
    except Exception:
        return []


def analyze_source_tree(root: str, max_files: int = 2000) -> list[SourceFinding]:
    """디렉터리(또는 단일 파일) 하위 *.py 를 분석."""
    findings: list[SourceFinding] = []
    if os.path.isfile(root) and root.endswith(".py"):
        return analyze_source_file(root)
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        # 잡음 디렉터리 제외
        dirnames[:] = [d for d in dirnames if d not in
                       ("node_modules", "venv", "venv_linux", ".git", "__pycache__", "dist")]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            n += 1
            if n > max_files:
                return findings
            findings.extend(analyze_source_file(os.path.join(dirpath, fn)))
    return findings


if __name__ == "__main__":
    import sys, json
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    res = analyze_source_tree(target)
    print(json.dumps([r.to_dict() for r in res], ensure_ascii=False, indent=2))
    print(f"\n총 {len(res)}건", file=sys.stderr)
