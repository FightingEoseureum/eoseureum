"""
attack_chain_engine.py — 규칙 기반 공격 체인 엔진 (방어적 분석 전용).

목적
  정규화된 탐지 결과(findings)와 공격 표면(attack_surface_items), 발견 항목(discovery_items),
  탐지된 기술 스택(technologies)을 입력으로 받아, 개별 항목만으로는 드러나지 않는
  '조합 위험(공격 체인)'을 규칙 기반으로 해석해 제시한다.

원칙 (절대 제약)
  - 입력 리스트(findings/attack_surface_items 등)는 읽기 전용으로만 다룬다. 개수·severity·
    confidence 등 어떤 필드도 변경하지 않으며, 필요 시 얕은 복사만 한다.
  - 결과는 공격 '실행 절차'가 아니라 방어적 분석·노출 확인·조치 검토 흐름으로 서술한다.
  - 근거 없는 새 취약점을 만들지 않는다. 체인은 입력 항목들의 '조합 해석'일 뿐이며,
    매칭되는 입력이 없으면 빈 체인 목록을 반환한다.

공개 인터페이스
  build_chains(findings, attack_surface_items=None, discovery_items=None,
               technologies=None) -> {"chains": [chain, ...]}
  각 chain = {
    "title": str,
    "confidence_score": int(0~100),   # 근거 강도(실증 finding 포함 시 높게, 표면/추정만이면 낮게)
    "steps": list[str],               # 정찰 → 노출 확인 → 조치 검토 흐름의 방어적 서술
    "impact": str,
    "required_conditions": list[str], # 악용 전제(유효 계정 탈취/기본 계정/취약 버전 등)
    "recommendation": str,
  }

순수 함수 — 네트워크/파일 접근 없음.
"""
import re

# ── 항목 텍스트 추출 ──────────────────────────────────────────────────────────
# 항목 dict 에서 매칭에 사용할 텍스트 필드들(제목·경로·증거 등)을 모아 소문자로 합친다.
_TEXT_FIELDS = (
    "title", "name", "path", "url", "evidence_url", "endpoint",
    "evidence_detail", "description", "detail", "label", "category",
    "product", "tech", "technology", "banner", "server",
)


def _item_text(item: dict) -> str:
    """항목의 검색 대상 텍스트를 소문자 문자열로 반환(읽기 전용)."""
    if not isinstance(item, dict):
        return str(item).lower()
    parts = []
    for key in _TEXT_FIELDS:
        val = item.get(key)
        if isinstance(val, str) and val:
            parts.append(val)
        elif isinstance(val, (list, tuple)):
            parts.extend(str(v) for v in val)
    return " ".join(parts).lower()


def _any_match(items, pattern) -> bool:
    """items 중 pattern 에 매칭되는 항목이 하나라도 있으면 True."""
    return any(pattern.search(_item_text(it)) for it in items)


def _matched(items, pattern) -> list:
    """pattern 에 매칭되는 항목의 얕은 복사본 목록(원본 불변)."""
    out = []
    for it in items:
        if pattern.search(_item_text(it)):
            out.append(dict(it) if isinstance(it, dict) else it)
    return out


def _has_confirmed_evidence(items) -> bool:
    """실증/확정 근거를 가진 항목이 있는지(읽기 전용 검사)."""
    for it in items:
        if not isinstance(it, dict):
            continue
        if it.get("probe_confirmed"):
            return True
        conf = it.get("confidence")
        if isinstance(conf, str) and conf.upper() in ("CONFIRMED", "CONFIG_CONFIRMED"):
            return True
    return False


def _clamp(score: int) -> int:
    """confidence_score 를 0~100 범위로 제한."""
    return max(0, min(100, int(score)))


# ── 매칭 패턴 ────────────────────────────────────────────────────────────────
_ADMIN_RE = re.compile(
    r"(/admin|/manager|관리자|관리\s*인터페이스|admin\s*panel|admin\s*login|"
    r"wp-admin|wp-login|로그인\s*폼|로그인\s*페이지|login\b|sign\s*in|phpmyadmin)",
    re.I,
)
_TOMCAT_MANAGER_RE = re.compile(
    r"(manager/html|host-manager|tomcat\s*manager|/manager\b)", re.I
)
_TOMCAT_TECH_RE = re.compile(r"(tomcat|apache\s*coyote|catalina)", re.I)
_SERVER_TECH_RE = re.compile(
    r"(server|tomcat|nginx|apache|iis|jetty|express|버전|version|배너|banner)", re.I
)
_SERVER_BANNER_RE = re.compile(
    r"(server\s*헤더|server\s*header|배너|banner|버전\s*노출|version\s*disclos|"
    r"x-powered-by|x-aspnet)",
    re.I,
)
_ERRORPAGE_RE = re.compile(
    r"(에러\s*페이지|error\s*page|stack\s*trace|스택\s*트레이스|예외\s*노출|"
    r"exception|디버그|debug|500\s*오류|whitelabel|tomcat\s*error)",
    re.I,
)
_CLICKJACK_RE = re.compile(
    r"(clickjacking|클릭재킹|x-frame-options|frame[\s-]*options|frame\s*ancestors)",
    re.I,
)
_API_META_RE = re.compile(
    r"(swagger|swagger-ui|openapi|open-?api|api-?docs|graphql|graphiql|"
    r"api\s*문서|api\s*메타)",
    re.I,
)
_ACTUATOR_RE = re.compile(
    r"(actuator|/env\b|/heapdump|/configprops|jolokia|/metrics\b|spring\s*boot\s*admin)",
    re.I,
)
_SOURCE_LEAK_RE = re.compile(
    r"(\.git/?\b|\.git/config|\.svn|\.env\b|env\s*파일|web\.xml|composer\.json|"
    r"소스\s*코드\s*노출|설정\s*파일\s*노출|backup|\.bak\b|dump\.sql)",
    re.I,
)


def _chain(title, confidence_score, steps, impact, required_conditions, recommendation):
    return {
        "title": title,
        "confidence_score": _clamp(confidence_score),
        "steps": list(steps),
        "impact": impact,
        "required_conditions": list(required_conditions),
        "recommendation": recommendation,
    }


def build_chains(findings, attack_surface_items=None, discovery_items=None,
                 technologies=None) -> dict:
    """입력 항목들의 조합을 해석해 방어적 공격 체인 목록을 생성한다.

    인자:
      findings: 실제 취약점 항목 리스트(읽기 전용)
      attack_surface_items: 공격 표면 항목 리스트(읽기 전용)
      discovery_items: 발견/참고 항목 리스트(읽기 전용)
      technologies: 탐지 기술 스택 리스트(읽기 전용)

    반환:
      {"chains": [chain, ...]}  — 매칭이 없으면 {"chains": []}
    """
    findings = findings or []
    attack_surface_items = attack_surface_items or []
    discovery_items = discovery_items or []
    technologies = technologies or []

    # 매칭 편의를 위한 합집합(원본 리스트는 변형하지 않음)
    surface_all = list(attack_surface_items) + list(discovery_items)
    all_items = list(findings) + surface_all + list(technologies)

    chains = []

    # 규칙 1: 관리 인터페이스 + 서버/기술 스택 → 관리 인터페이스 공격 표면
    admin_surface = _matched(surface_all, _ADMIN_RE)
    has_admin = bool(admin_surface)
    has_server_tech = _any_match(technologies, _SERVER_TECH_RE) or _any_match(
        findings, _SERVER_BANNER_RE
    )
    if has_admin and has_server_tech:
        confirmed = _has_confirmed_evidence(admin_surface)
        chains.append(_chain(
            title="관리 인터페이스 공격 표면",
            confidence_score=55 if confirmed else 40,
            steps=[
                "정찰: 노출된 관리/로그인 인터페이스와 함께 식별된 서버·프레임워크 버전을 대조한다.",
                "노출 확인: 해당 인터페이스가 인증을 요구하는지, 기본 계정·약한 자격 증명이 적용되어 "
                "있는지 점검한다.",
                "조치 검토: 관리 인터페이스의 외부 노출 범위를 축소하고 접근 통제를 강화한다.",
            ],
            impact="관리 인터페이스가 식별 가능한 기술 스택과 함께 외부에 노출되어, 자격 증명 "
                   "공격이나 알려진 취약점 탐색의 표적이 될 수 있다.",
            required_conditions=[
                "유효 계정 탈취 또는 기본/약한 계정 사용",
                "관리 인터페이스의 외부 접근 허용",
            ],
            recommendation="관리 인터페이스를 IP 허용목록/VPN 등으로 접근 제한하고, 기본 계정 제거 "
                           "및 강력한 인증(MFA)을 적용한다.",
        ))

    # 규칙 2: Tomcat manager + Tomcat technology → Tomcat 관리 인터페이스 노출 기반 공격 표면
    tomcat_mgr = _matched(surface_all, _TOMCAT_MANAGER_RE)
    has_tomcat_tech = _any_match(technologies, _TOMCAT_TECH_RE) or _any_match(
        all_items, _TOMCAT_TECH_RE
    )
    if tomcat_mgr and has_tomcat_tech:
        confirmed = _has_confirmed_evidence(tomcat_mgr)
        chains.append(_chain(
            title="Tomcat 관리 인터페이스 노출 기반 공격 표면",
            confidence_score=60 if confirmed else 45,
            steps=[
                "정찰: Tomcat manager/host-manager 경로 노출과 Tomcat 기술 스택을 함께 확인한다.",
                "노출 확인: manager 경로가 401/403 등 인증을 요구하는지, 기본 계정(tomcat/admin)이 "
                "비활성화되어 있는지 점검한다.",
                "조치 검토: manager 애플리케이션의 외부 노출을 차단하거나 접근을 제한한다.",
            ],
            impact="Tomcat manager 인터페이스가 노출되어, 약한 인증 시 애플리케이션 배포·서버 제어로 "
                   "이어질 수 있는 공격 표면이 존재한다.",
            required_conditions=[
                "Tomcat manager 기본 계정 사용 또는 유효 계정 탈취",
                "manager 애플리케이션의 외부 접근 허용",
            ],
            recommendation="Tomcat manager/host-manager 를 외부에서 차단하고, conf/tomcat-users.xml "
                           "의 기본 계정을 제거하며 RemoteAddrValve 로 접근 IP 를 제한한다.",
        ))

    # 규칙 3: 서버 버전/배너 노출 + 에러페이지 정보 노출 → 취약 버전 탐색 가능성
    banner_findings = _matched(findings, _SERVER_BANNER_RE)
    has_errorpage = _any_match(all_items, _ERRORPAGE_RE)
    if banner_findings and has_errorpage:
        confirmed = _has_confirmed_evidence(banner_findings)
        chains.append(_chain(
            title="기술 스택 기반 취약 버전 탐색 가능성",
            confidence_score=50 if confirmed else 35,
            steps=[
                "정찰: Server 헤더·배너로 노출된 제품/버전과 에러 페이지에 드러난 추가 정보를 종합한다.",
                "노출 확인: 노출된 버전이 알려진 취약점(CVE) 대상인지, 에러 페이지가 내부 경로·스택 "
                "트레이스를 드러내는지 점검한다.",
                "조치 검토: 버전 배너를 숨기고 사용자 정의 에러 페이지를 적용한다.",
            ],
            impact="버전 정보와 에러 페이지의 상세 노출이 결합되어, 공격자가 정확한 취약 버전을 식별하고 "
                   "표적 공격을 준비하기 쉬워진다.",
            required_conditions=[
                "노출된 버전이 알려진 취약점을 가진 취약 버전일 것",
            ],
            recommendation="Server/X-Powered-By 등 버전 배너를 제거하고, 상세 에러를 숨기는 사용자 "
                           "정의 에러 페이지를 적용하며 노출된 제품을 최신 버전으로 패치한다.",
        ))

    # 규칙 4: Clickjacking + 인증/관리 페이지 → 클릭재킹 위험
    clickjack_items = _matched(findings, _CLICKJACK_RE) + _matched(surface_all, _CLICKJACK_RE)
    if clickjack_items and has_admin:
        confirmed = _has_confirmed_evidence(clickjack_items)
        chains.append(_chain(
            title="사용자 행위 유도(클릭재킹) 위험",
            confidence_score=45 if confirmed else 30,
            steps=[
                "정찰: X-Frame-Options/CSP frame-ancestors 미설정과 인증·관리 페이지의 존재를 함께 "
                "확인한다.",
                "노출 확인: 인증/관리 페이지가 iframe 으로 삽입 가능한지 점검한다.",
                "조치 검토: 프레임 차단 헤더를 적용해 클릭재킹 표면을 제거한다.",
            ],
            impact="프레임 보호가 없는 상태에서 인증·관리 페이지가 노출되어, 사용자의 의도하지 않은 "
                   "행위(클릭재킹)를 유도당할 수 있다.",
            required_conditions=[
                "인증된 사용자가 공격자가 준비한 페이지를 방문",
                "대상 페이지의 프레임 보호 부재",
            ],
            recommendation="모든 인증/관리 페이지에 X-Frame-Options: DENY 또는 CSP "
                           "frame-ancestors 'none' 을 적용한다.",
        ))

    # 규칙 5: swagger/graphql/openapi 노출 → API 메타데이터 노출
    api_items = _matched(surface_all, _API_META_RE) + _matched(findings, _API_META_RE)
    if api_items:
        confirmed = _has_confirmed_evidence(api_items)
        chains.append(_chain(
            title="API 메타데이터 노출",
            confidence_score=50 if confirmed else 35,
            steps=[
                "정찰: Swagger/OpenAPI/GraphQL 등 API 문서·스키마 엔드포인트 노출 여부를 확인한다.",
                "노출 확인: 노출된 문서에서 인증 없이 호출 가능한 민감 엔드포인트가 있는지 점검한다.",
                "조치 검토: 운영 환경에서 API 문서 노출을 제한하고 엔드포인트별 인가를 점검한다.",
            ],
            impact="API 스키마/문서가 노출되어 내부 엔드포인트·파라미터 구조가 드러나면, 인가 결함이 "
                   "있는 API 에 대한 공격 준비가 쉬워진다.",
            required_conditions=[
                "노출된 API 중 인증·인가가 미흡한 엔드포인트 존재",
            ],
            recommendation="운영 환경에서 Swagger UI/GraphQL introspection 등 메타데이터 노출을 "
                           "비활성화하거나 인증 뒤로 옮기고, 엔드포인트별 접근 통제를 검증한다.",
        ))

    # 규칙 6: actuator/env 노출 → 민감 설정 정보 노출 가능성
    actuator_items = _matched(surface_all, _ACTUATOR_RE) + _matched(findings, _ACTUATOR_RE)
    if actuator_items:
        confirmed = _has_confirmed_evidence(actuator_items)
        chains.append(_chain(
            title="민감 설정 정보 노출 가능성",
            confidence_score=60 if confirmed else 40,
            steps=[
                "정찰: Spring Boot Actuator(/env, /configprops, /heapdump 등) 엔드포인트 노출을 "
                "확인한다.",
                "노출 확인: 해당 엔드포인트가 인증 없이 환경 변수·설정·힙덤프 등을 반환하는지 점검한다.",
                "조치 검토: 민감 actuator 엔드포인트를 비활성화하거나 인증을 강제한다.",
            ],
            impact="Actuator 엔드포인트를 통해 환경 변수·자격 증명·내부 설정이 노출되면, 후속 공격에 "
                   "활용될 수 있는 민감 정보가 유출된다.",
            required_conditions=[
                "민감 actuator 엔드포인트의 무인증 접근 허용",
            ],
            recommendation="management.endpoints.web.exposure 를 최소화하고, actuator 에 인증/인가를 "
                           "적용하며 /env·/heapdump 등 민감 엔드포인트를 비활성화한다.",
        ))

    # 규칙 7: .git/.env 등 소스/설정 노출 → 소스/설정 정보 노출
    source_items = _matched(findings, _SOURCE_LEAK_RE)
    if source_items:
        confirmed = _has_confirmed_evidence(source_items)
        chains.append(_chain(
            title="소스/설정 정보 노출",
            confidence_score=70 if confirmed else 50,
            steps=[
                "정찰: .git/.env/백업 파일 등 소스·설정 파일의 외부 접근 가능성을 확인한다.",
                "노출 확인: 노출된 파일에 자격 증명·시크릿·내부 구조 등 민감 정보가 포함되는지 점검한다.",
                "조치 검토: 노출 경로를 차단하고 유출된 시크릿을 즉시 폐기·교체한다.",
            ],
            impact="소스 코드·설정 파일 노출로 자격 증명·시크릿·내부 구조가 유출되면, 직접적인 침해나 "
                   "후속 공격의 핵심 정보로 악용될 수 있다.",
            required_conditions=[
                "노출 파일에 유효한 시크릿/자격 증명 또는 민감 구조 정보 포함",
            ],
            recommendation="웹 루트에서 .git/.env/백업 파일을 제거하고 해당 경로 접근을 차단하며, "
                           "노출되었을 가능성이 있는 모든 시크릿을 즉시 교체한다.",
        ))

    return {"chains": chains}
