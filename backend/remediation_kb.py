"""
remediation_kb.py — 조치(Remediation) 지식베이스(데이터 주도).

패밀리별 표준 조치(제목/설명/예상 공수/담당 조직/기대 효과/우선순위 가중)를 정의한다.
신규 항목은 REMEDIATION 에 추가하거나 register_remediation() 으로 코드 수정 없이 확장.
"""
from __future__ import annotations

# family → 조치 메타데이터
REMEDIATION: dict[str, dict] = {
    "idor": {
        "title": "객체 단위 접근 제어 검증 추가",
        "description": "객체 조회/수정 시 로그인 사용자와 객체 소유자 매핑을 서버에서 검증하고, "
                       "직접 참조 대신 권한 기반 조회 또는 간접 참조를 적용한다.",
        "effort": "1~3일", "team": "Backend",
        "benefit": "교차 계정 접근 차단 · 고객 데이터 보호", "weight": 5,
    },
    "xss": {
        "title": "출력 인코딩 및 입력 검증 적용",
        "description": "컨텍스트별 출력 인코딩(HTML/속성/스크립트)과 입력 검증, CSP 적용으로 "
                       "스크립트 실행을 차단한다.",
        "effort": "1~2일", "team": "Frontend",
        "benefit": "세션 탈취·악성 스크립트 실행 차단", "weight": 4,
    },
    "sqli": {
        "title": "파라미터화 쿼리(Prepared Statement) 적용",
        "description": "동적 쿼리를 파라미터 바인딩으로 전환하고, 최소 권한 DB 계정과 에러 메시지 "
                       "비표시를 적용한다.",
        "effort": "2~4일", "team": "Backend",
        "benefit": "DB 데이터 노출·변조 차단", "weight": 5,
    },
    "csrf": {
        "title": "CSRF 토큰·SameSite·Origin 검증 적용",
        "description": "상태 변경 요청에 CSRF 토큰을 발급·검증하고 세션 쿠키에 SameSite=Lax/Strict, "
                       "Origin/Referer 검증을 적용한다.",
        "effort": "1~2일", "team": "Backend",
        "benefit": "교차 출처 상태 변경 차단", "weight": 3,
    },
    "business_logic": {
        "title": "민감 값 서버측 재검증",
        "description": "가격/수량/권한/포인트 등 비즈니스 값을 서버에서 재계산·권한/소유/범위 "
                       "검증하고 클라이언트 입력을 신뢰하지 않는다.",
        "effort": "2~5일", "team": "Backend",
        "benefit": "가격 조작·권한 상승·금전 손실 방지", "weight": 4,
    },
    "upload": {
        "title": "업로드 검증 강화 및 실행 차단",
        "description": "서버측 확장자 화이트리스트·MIME·매직바이트 검증을 적용하고, 업로드 파일을 "
                       "실행 불가 경로에 저장하며 임의 파일명/경로를 차단한다.",
        "effort": "2~3일", "team": "Backend",
        "benefit": "악성 파일 처리·웹쉘 업로드 방지", "weight": 4,
    },
    "ssrf": {
        "title": "아웃바운드 요청 통제(SSRF 방어)",
        "description": "서버측 요청 목적지 화이트리스트를 적용하고 내부망/메타데이터(169.254.169.254 등) "
                       "접근을 차단한다.",
        "effort": "2~4일", "team": "Backend/Infra",
        "benefit": "내부 자산·클라우드 메타데이터 노출 차단", "weight": 4,
    },
    "redirect": {
        "title": "리다이렉트 대상 검증",
        "description": "redirect/next 파라미터에 화이트리스트 또는 상대경로 강제를 적용해 외부 도메인 "
                       "리다이렉트를 차단한다.",
        "effort": "1일", "team": "Backend",
        "benefit": "피싱·세션 우회 경유 차단", "weight": 2,
    },
    "auth": {
        "title": "인증 강화 및 안전한 세션 관리",
        "description": "로그인 입력 검증·계정 잠금/속도 제한, 안전한 세션 쿠키(HttpOnly/Secure/"
                       "SameSite)와 다중 인증을 적용한다.",
        "effort": "2~5일", "team": "Backend",
        "benefit": "인증 우회·세션 탈취 방지", "weight": 4,
    },
    "path_traversal": {
        "title": "경로 정규화 및 접근 제한",
        "description": "사용자 입력 경로를 정규화·화이트리스트 검증하고 허용 디렉터리 밖 접근을 차단한다.",
        "effort": "1~2일", "team": "Backend",
        "benefit": "서버 파일 노출 차단", "weight": 3,
    },
    "ssti": {
        "title": "템플릿 입력 분리·샌드박스",
        "description": "사용자 입력을 템플릿 표현식과 분리하고 안전한 템플릿 컨텍스트/샌드박스를 적용한다.",
        "effort": "2~3일", "team": "Backend",
        "benefit": "서버측 표현식 평가 차단", "weight": 4,
    },
    "cmdi": {
        "title": "OS 명령 호출 제거·안전 API 사용",
        "description": "외부 입력을 셸 명령에 전달하지 않고 안전한 API/인자 배열을 사용하며 입력을 "
                       "엄격히 검증한다.",
        "effort": "2~4일", "team": "Backend",
        "benefit": "OS 명령 실행 위험 차단", "weight": 5,
    },
}

# ── 서비스(Service Security Framework v2) 조치 ───────────────────────────────
_SVC_REMEDIATION = {
    "ssh": {"title": "SSH 외부 접근 제한 및 인증 강화",
            "description": "외부 접근을 VPN/Zero Trust로 제한하고 비밀번호 로그인 비활성·키 기반 "
                           "인증·MFA를 적용하며 포트 접근을 제어한다.",
            "effort": "1~2일", "team": "Infra/System", "benefit": "원격 관리자 접근 차단", "weight": 5},
    "rdp": {"title": "RDP 외부 노출 차단·다중 인증",
            "description": "RDP를 외부에서 차단하고 VPN 경유·NLA·MFA를 적용한다.",
            "effort": "1일", "team": "Infra/System", "benefit": "원격 데스크톱 무단 접근 차단", "weight": 5},
    "ftp": {"title": "FTP 익명 차단 및 FTPS/SFTP 적용",
            "description": "Anonymous 접속을 비활성화하고 평문 전송을 FTPS/SFTP로 대체하며 접근을 "
                           "제어한다.",
            "effort": "1일", "team": "Infra/System", "benefit": "파일 노출·평문 자격증명 위험 제거", "weight": 4},
    "smb": {"title": "SMB Guest 차단·Signing 활성·외부 차단",
            "description": "Guest/익명 접근을 차단하고 SMB Signing을 활성화하며 외부 노출을 차단하고 "
                           "공유 권한을 최소화한다.",
            "effort": "1~2일", "team": "Infra/System", "benefit": "파일 공유 노출·중간자 공격 방지", "weight": 4},
    "nfs": {"title": "NFS 접근 제어·외부 차단",
            "description": "NFS export 범위를 제한하고 외부 노출을 차단하며 인증/권한을 적용한다.",
            "effort": "1~2일", "team": "Infra/System", "benefit": "파일 시스템 노출 차단", "weight": 4},
    "mysql": {"title": "DB 외부 차단·인증 필수·네트워크 ACL",
              "description": "DB 외부 노출을 차단(방화벽/내부망)하고 인증을 필수화하며 최소 권한 계정과 "
                             "네트워크 ACL·전송 암호화를 적용한다.",
              "effort": "1~3일", "team": "DBA/Infra", "benefit": "민감 데이터 노출 차단", "weight": 5},
    "redis": {"title": "Redis 인증·Protected Mode·외부 차단",
              "description": "requirepass 인증과 Protected Mode를 활성화하고 외부 노출을 차단하며 "
                             "바인드 주소를 제한한다.",
              "effort": "1일", "team": "Infra/Backend", "benefit": "무인증 데이터 노출 차단", "weight": 5},
    "elasticsearch": {"title": "검색 클러스터 인증·외부 차단",
                      "description": "인증/보안 플러그인을 활성화하고 외부 노출을 차단하며 네트워크 ACL을 "
                                     "적용한다.",
                      "effort": "1~2일", "team": "Infra/Backend", "benefit": "검색 데이터 노출 차단", "weight": 4},
    "docker": {"title": "Docker API 외부 차단·TLS 인증",
               "description": "Docker API 외부 노출을 차단하고 TLS 상호 인증을 적용하며 관리망을 분리한다.",
               "effort": "1~2일", "team": "Platform/Infra", "benefit": "컨테이너/호스트 장악 차단", "weight": 5},
    "k8s": {"title": "Kubernetes API/kubelet 접근 통제",
            "description": "API Server/kubelet 익명 접근을 차단하고 RBAC·인증/인가를 강화하며 관리망을 "
                           "분리한다.",
            "effort": "2~3일", "team": "Platform/Infra", "benefit": "클러스터 제어 위험 차단", "weight": 5},
    "smtp": {"title": "SMTP 오픈 릴레이 차단·TLS 적용",
             "description": "오픈 릴레이를 차단하고 인증 발송과 STARTTLS/TLS를 적용하며 사용자 열거를 "
                            "방지한다.",
             "effort": "1일", "team": "Infra/System", "benefit": "메일 남용·정보 노출 방지", "weight": 3},
}
REMEDIATION.update(_SVC_REMEDIATION)
# DB 패밀리 별칭(동일 조치)
for _alias in ("postgresql", "mssql", "mongodb", "oracle"):
    REMEDIATION[_alias] = REMEDIATION["mysql"]
REMEDIATION["memcached"] = REMEDIATION["redis"]
REMEDIATION["ldap"] = REMEDIATION["telnet"] = REMEDIATION["ssh"]
REMEDIATION["imap"] = REMEDIATION["pop3"] = REMEDIATION["smtp"]

_DEFAULT = {
    "title": "보안 설정 강화 및 입력 검증",
    "description": "서버측 입력 검증·접근 통제·보안 헤더를 점검·강화한다.",
    "effort": "1~3일", "team": "Backend", "benefit": "공격 표면 감소", "weight": 1,
}


def register_remediation(family: str, meta: dict) -> None:
    if family:
        REMEDIATION[family.lower()] = {**_DEFAULT, **meta}


def get_remediation(family: str) -> dict:
    return REMEDIATION.get((family or "").lower(), _DEFAULT)


def all_families() -> list[str]:
    return list(REMEDIATION.keys())
