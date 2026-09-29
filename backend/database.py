import json
import os
from datetime import datetime, timedelta

import aiosqlite
from auth import hash_password

DB_PATH = os.getenv("DB_PATH", "scanner.db")

# 점검 주기 → 간격(일). 'manual' 은 자동 실행 안 함.
SCAN_CYCLE_DAYS = {"weekly": 7, "monthly": 30, "quarterly": 90}


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def compute_next_run(scan_cycle: str, scan_time: str = "03:00", base: datetime | None = None,
                     scan_day: int | None = None, scan_months: int | None = None) -> str | None:
    """다음 자동 점검 시각(문자열)을 계산한다.
    - scan_months(>0) 지정 시: '매월 scan_day 일, scan_months 개월마다' 로 계산(월간 커스텀).
    - 아니면 scan_cycle(weekly/monthly/quarterly) 의 일수 기반. manual/미지원은 None."""
    base = base or datetime.now()
    try:
        hh, mm = [int(x) for x in (scan_time or "03:00").split(":")[:2]]
    except Exception:
        hh, mm = 3, 0

    if scan_months and int(scan_months) > 0:
        import calendar
        months = max(1, int(scan_months))
        day = min(max(1, int(scan_day or 1)), 31)

        def _clamp(y, m, d):
            return min(d, calendar.monthrange(y, m)[1])

        y, m = base.year, base.month
        cand = base.replace(day=_clamp(y, m, day), hour=hh, minute=mm, second=0, microsecond=0)
        if cand <= base:                       # 이번 달 일자가 지났으면 months 만큼 전진
            total = (m - 1) + months
            y2, m2 = y + total // 12, total % 12 + 1
            cand = cand.replace(year=y2, month=m2, day=_clamp(y2, m2, day))
        return cand.strftime("%Y-%m-%d %H:%M:%S")

    days = SCAN_CYCLE_DAYS.get((scan_cycle or "").lower())
    if not days:
        return None
    nxt = base + timedelta(days=days)
    try:
        nxt = nxt.replace(hour=hh, minute=mm, second=0, microsecond=0)
    except Exception:
        pass
    return nxt.strftime("%Y-%m-%d %H:%M:%S")


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                can_scan INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running',
                results TEXT,
                analysis TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS domain_watchlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
                UNIQUE(domain, user_id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        await db.commit()

        # 마이그레이션: domain_watchlist 에 점검 스케줄 컬럼 추가(기존 데이터 보존)
        cur = await db.execute("PRAGMA table_info(domain_watchlist)")
        existing = {r[1] for r in await cur.fetchall()}
        _sched_cols = {
            "scan_cycle": "TEXT NOT NULL DEFAULT 'manual'",
            "scan_time":  "TEXT NOT NULL DEFAULT '03:00'",
            "enabled":    "INTEGER NOT NULL DEFAULT 0",
            "next_run":   "TEXT",
            "last_run":   "TEXT",
            "scan_day":   "INTEGER NOT NULL DEFAULT 1",   # 월 중 점검 일자(1~31)
            "scan_months": "INTEGER NOT NULL DEFAULT 0",  # 점검 주기(개월). 0=주기 없음(수동)
            # 등록 대상(URL)별 스캔 설정 — 위저드 프리필용(비밀번호는 저장하지 않음)
            "exclude_urls": "TEXT NOT NULL DEFAULT '[]'",       # 제외 하위경로/URL(JSON 배열)
            "time_budget_minutes": "INTEGER NOT NULL DEFAULT 0",  # 최대 진행 시간(분)
            "login_url":  "TEXT NOT NULL DEFAULT ''",
            "login_username": "TEXT NOT NULL DEFAULT ''",
            # 로그인 비밀번호 — Fernet(AES) 암호화 저장(at-rest). 평문 저장/응답/로그 금지.
            "login_password_enc": "TEXT NOT NULL DEFAULT ''",
        }
        for col, decl in _sched_cols.items():
            if col not in existing:
                await db.execute(f"ALTER TABLE domain_watchlist ADD COLUMN {col} {decl}")
        await db.commit()

        # 마이그레이션: scans 에 재개용 checkpoint(JSON) 컬럼 추가(기존 데이터 보존)
        cur = await db.execute("PRAGMA table_info(scans)")
        _scan_cols = {r[1] for r in await cur.fetchall()}
        if "checkpoint" not in _scan_cols:
            await db.execute("ALTER TABLE scans ADD COLUMN checkpoint TEXT")
            await db.commit()
        if "notes" not in _scan_cols:   # 스캔 출처 마커(예약 스캔 구분 등)
            await db.execute("ALTER TABLE scans ADD COLUMN notes TEXT NOT NULL DEFAULT ''")
            await db.commit()
        if "scan_config" not in _scan_cols:   # 대기 스캔의 제출 설정(JSON) — 스캔 전 수정 프리필용(비밀번호 제외)
            await db.execute("ALTER TABLE scans ADD COLUMN scan_config TEXT")
            await db.commit()

        # 마이그레이션: users 에 사용자별 총 스캔 쿼터(scan_quota) 추가(0 = 무제한)
        cur = await db.execute("PRAGMA table_info(users)")
        _ucols = {r[1] for r in await cur.fetchall()}
        if "scan_quota" not in _ucols:
            await db.execute("ALTER TABLE users ADD COLUMN scan_quota INTEGER NOT NULL DEFAULT 0")
            await db.commit()
        # 마이그레이션: 사용자별 '동시' 스캔 제한(max_concurrent_scans) 추가.
        #   0 = 전역 기본값(DEFAULT_MAX_CONCURRENT_SCANS) 사용. 관리자는 항상 무제한(코드에서 강제).
        if "max_concurrent_scans" not in _ucols:
            await db.execute(
                "ALTER TABLE users ADD COLUMN max_concurrent_scans INTEGER NOT NULL DEFAULT 0")
            await db.commit()
        # 마이그레이션: 사용자별 접근 허용 IP(allowed_ips) — 콤마/줄바꿈 구분, IP 또는 CIDR.
        #   빈 값 = 제한 없음(모든 IP 허용). 값이 있으면 해당 IP/대역에서만 접근 가능.
        if "allowed_ips" not in _ucols:
            await db.execute("ALTER TABLE users ADD COLUMN allowed_ips TEXT NOT NULL DEFAULT ''")
            await db.commit()

        cursor = await db.execute("SELECT id FROM users WHERE username = ?", ("admin",))
        if not await cursor.fetchone():
            await db.execute(
                "INSERT INTO users (username, password_hash, role, can_scan) VALUES (?, ?, ?, ?)",
                ("admin", hash_password("ChangeMe123!"), "admin", 1),
            )
            await db.commit()

        # ── 스캔 정책 / 보고서 템플릿 (정책 및 템플릿 메뉴) ──────────────────────
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                config TEXT NOT NULL DEFAULT '{}',
                is_active INTEGER NOT NULL DEFAULT 0,
                builtin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS report_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                options TEXT NOT NULL DEFAULT '{}',
                is_default INTEGER NOT NULL DEFAULT 0,
                builtin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
            )
        """)
        await db.commit()
        await _seed_policies_and_templates(db)


# 점검 정책 적용 대상 env 키(허용 목록) — 정책 config 는 이 키만 반영한다.
POLICY_ENV_KEYS = (
    "PROBE_PAYLOAD_LEVEL", "ENABLE_ADVANCED_PAYLOADS", "ENABLE_EXTENDED_XSS_PAYLOADS",
    "ENABLE_SQLMAP", "SQLMAP_ENUM_DBS", "ENABLE_TIME_BASED_SQLI",
    "SQLMAP_LEVEL", "SQLMAP_RISK", "SQLMAP_TECHNIQUE",
    "ENABLE_SERVICE_SCAN", "SERVICE_SCAN_USE_NMAP",
    "USE_PROBE_ORCHESTRATOR", "GLOBAL_ACTIVE_PROBE_RPS",
    "ENABLE_AUTH_SCAN", "ENABLE_KNOWN_CREDENTIAL_CHECK", "ENABLE_AI_ANALYSIS",
    "MAX_INJECTION_POINTS", "MAX_CRAWL_PAGES", "MAX_CRAWL_DEPTH",
    "AUTH_BYPASS_MAX_PER_POINT", "FFUF_WORDLIST", "FFUF_MAXTIME",
    "RCE_PROOF_MODE",   # OS 명령 무해 증거 모드(기본 OFF, 수동 승인 항목)
    # 정책=검증 프로파일 일치: 선택한 정책이 VALIDATION_PROFILE/ALLOW_PROOF_MODE 도 지배하게 하여
    # "Proof 정책 선택 = 실제 PROOF"로 만들고 재시작에도 유지(startup 재적용). 정책만으로 프로파일이
    # 갈리지 않도록(그동안 둘이 분리돼 Proof 정책인데 프로파일은 SAFE 로 도는 혼란이 있었음).
    "VALIDATION_PROFILE", "ALLOW_PROOF_MODE",
)

# 보고서 템플릿 옵션 → 보고서 env 매핑
TEMPLATE_OPTION_KEYS = ("org_name", "show_ai", "show_coverage", "show_attack_chain", "show_service_scan")

_BUILTIN_POLICIES = [
    ("Safe", "비파괴·저부하. SQLMap/심화 payload 끄고 최소 점검(rps 5).", {
        "PROBE_PAYLOAD_LEVEL": "safe", "ENABLE_SQLMAP": "false", "SQLMAP_ENUM_DBS": "false",
        "ENABLE_TIME_BASED_SQLI": "false", "ENABLE_ADVANCED_PAYLOADS": "false",
        "ENABLE_EXTENDED_XSS_PAYLOADS": "false", "ENABLE_SERVICE_SCAN": "false",
        "SERVICE_SCAN_USE_NMAP": "false", "USE_PROBE_ORCHESTRATOR": "false",
        "GLOBAL_ACTIVE_PROBE_RPS": "5",
    }, 0),
    ("Balance", "권장 기본값. balanced payload + SQLMap 검증 + 서비스/nmap 점검.", {
        "PROBE_PAYLOAD_LEVEL": "balanced", "ENABLE_SQLMAP": "true", "SQLMAP_ENUM_DBS": "false",
        "ENABLE_TIME_BASED_SQLI": "false", "ENABLE_ADVANCED_PAYLOADS": "false",
        "ENABLE_EXTENDED_XSS_PAYLOADS": "true", "ENABLE_SERVICE_SCAN": "true",
        "SERVICE_SCAN_USE_NMAP": "true", "USE_PROBE_ORCHESTRATOR": "false",
        "GLOBAL_ACTIVE_PROBE_RPS": "10",
    }, 1),  # 기본 활성
    ("Critical", "aggressive payload + SQLMap DB열람 + time-based SQLi. 권한 있는 대상만.", {
        "PROBE_PAYLOAD_LEVEL": "aggressive", "ENABLE_ADVANCED_PAYLOADS": "true",
        "ENABLE_SQLMAP": "true", "SQLMAP_ENUM_DBS": "true", "ENABLE_TIME_BASED_SQLI": "true",
        "ENABLE_EXTENDED_XSS_PAYLOADS": "true", "ENABLE_SERVICE_SCAN": "true",
        "SERVICE_SCAN_USE_NMAP": "true", "USE_PROBE_ORCHESTRATOR": "false",
        "GLOBAL_ACTIVE_PROBE_RPS": "10",
    }, 0),
    ("Proof (승인)", "실증 심화(승인 대상 전용). 로그인 우회/인젝션 특화 + RCE 무해 실증(echo 마커) + "
     "주입지점·크롤 대폭 확대. SQLMap BEU(time-based 제외, level 은 전역 설정 상속). 비파괴.", {
        "VALIDATION_PROFILE": "PROOF", "ALLOW_PROOF_MODE": "true",   # 정책 선택 = 실제 PROOF 프로파일(재시작 유지)
        "PROBE_PAYLOAD_LEVEL": "aggressive", "ENABLE_ADVANCED_PAYLOADS": "true",
        "ENABLE_EXTENDED_XSS_PAYLOADS": "true",
        "ENABLE_SQLMAP": "true", "SQLMAP_ENUM_DBS": "false",
        "ENABLE_TIME_BASED_SQLI": "false",          # time-based 제외(잠금·오탐 방지)
        "SQLMAP_RISK": "1", "SQLMAP_TECHNIQUE": "BEU",  # B/E/U만(T·S 제외), level 은 전역 env 상속
        "RCE_PROOF_MODE": "true",                   # OS 명령 무해 echo 마커 실증(승인 항목)
        "ENABLE_SERVICE_SCAN": "true", "SERVICE_SCAN_USE_NMAP": "true",
        "USE_PROBE_ORCHESTRATOR": "false", "GLOBAL_ACTIVE_PROBE_RPS": "10",
        "MAX_INJECTION_POINTS": "300",
        "MAX_CRAWL_PAGES": "1000", "MAX_CRAWL_DEPTH": "4",
        "AUTH_BYPASS_MAX_PER_POINT": "20",
        "FFUF_MAXTIME": "300",
    }, 0),
]

_BUILTIN_TEMPLATES = [
    ("표준 보고서 (KISA형)", "기관명 + AI 의견 + 커버리지 + 공격체인 + 서비스 점검 포함.", {
        "org_name": "Eoseureum Security", "show_ai": True, "show_coverage": True,
        "show_attack_chain": True, "show_service_scan": True,
    }, 1),  # 기본
    ("경영진 요약형", "핵심만. 커버리지·서비스 점검 섹션 생략, AI/공격체인 유지.", {
        "org_name": "Eoseureum Security", "show_ai": True, "show_coverage": False,
        "show_attack_chain": True, "show_service_scan": False,
    }, 0),
    ("OWASP 기술 상세형", "모든 기술 섹션 포함.", {
        "org_name": "Eoseureum Security", "show_ai": True, "show_coverage": True,
        "show_attack_chain": True, "show_service_scan": True,
    }, 0),
]


async def _seed_policies_and_templates(db) -> None:
    cur = await db.execute("SELECT COUNT(*) FROM scan_policies")
    if (await cur.fetchone())[0] == 0:
        for name, desc, cfg, active in _BUILTIN_POLICIES:
            await db.execute(
                "INSERT INTO scan_policies (name, description, config, is_active, builtin) VALUES (?,?,?,?,1)",
                (name, desc, json.dumps(cfg), active),
            )
    else:
        # D-b12: 이미 내장 정책이 존재하면 재시드하지 않는다(개명 시 구/신 이름이 중복 추가되던 문제 방지).
        # 내장 정책이 하나도 없을 때만(모두 삭제된 예외 상황) 재시드.
        cur = await db.execute("SELECT COUNT(*) FROM scan_policies WHERE builtin = 1")
        if (await cur.fetchone())[0] == 0:
            for name, desc, cfg, active in _BUILTIN_POLICIES:
                await db.execute(
                    "INSERT INTO scan_policies (name, description, config, is_active, builtin) "
                    "VALUES (?,?,?,0,1)",   # 재시드 시 비활성으로 추가
                    (name, desc, json.dumps(cfg)),
                )
    cur = await db.execute("SELECT COUNT(*) FROM report_templates")
    if (await cur.fetchone())[0] == 0:
        for name, desc, opts, default in _BUILTIN_TEMPLATES:
            await db.execute(
                "INSERT INTO report_templates (name, description, options, is_default, builtin) VALUES (?,?,?,?,1)",
                (name, desc, json.dumps(opts), default),
            )
    await db.commit()


def _row_to_dict(row, cursor) -> dict:
    cols = [d[0] for d in cursor.description]
    return dict(zip(cols, row))


async def get_user_by_username(username: str) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = await cursor.fetchone()
        return _row_to_dict(row, cursor) if row else None


async def get_user_by_id(user_id: int) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        return _row_to_dict(row, cursor) if row else None


async def get_all_users() -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT id, username, role, can_scan, scan_quota, max_concurrent_scans, allowed_ips, created_at "
            "FROM users ORDER BY id"
        )
        rows = await cursor.fetchall()
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, r)) for r in rows]


async def create_user(username: str, password: str, role: str, can_scan: bool,
                      scan_quota: int = 0, max_concurrent_scans: int = 0,
                      allowed_ips: str = "") -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "INSERT INTO users (username, password_hash, role, can_scan, scan_quota, "
            "max_concurrent_scans, allowed_ips) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, hash_password(password), role, int(can_scan),
             max(0, int(scan_quota or 0)), max(0, int(max_concurrent_scans or 0)),
             (allowed_ips or "").strip()),
        )
        await db.commit()
        user_id = cursor.lastrowid
    return await get_user_by_id(user_id)


async def update_user(user_id: int, role: str | None = None, can_scan: bool | None = None,
                      password: str | None = None, scan_quota: int | None = None,
                      max_concurrent_scans: int | None = None, allowed_ips: str | None = None):
    parts, params = [], []
    if allowed_ips is not None:
        parts.append("allowed_ips = ?")
        params.append((allowed_ips or "").strip())
    if role is not None:
        parts.append("role = ?")
        params.append(role)
    if can_scan is not None:
        parts.append("can_scan = ?")
        params.append(int(can_scan))
    if password is not None:
        parts.append("password_hash = ?")
        params.append(hash_password(password))
    if scan_quota is not None:
        parts.append("scan_quota = ?")
        params.append(max(0, int(scan_quota)))
    if max_concurrent_scans is not None:
        parts.append("max_concurrent_scans = ?")
        params.append(max(0, int(max_concurrent_scans)))
    if not parts:
        return await get_user_by_id(user_id)
    params.append(user_id)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(f"UPDATE users SET {', '.join(parts)} WHERE id = ?", params)
        await db.commit()
    return await get_user_by_id(user_id)


async def count_user_scans(user_id: int) -> int:
    """해당 사용자가 보유한 총 스캔 수(쿼터 계산용). 스캔 삭제 시 감소한다."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,))
        row = await cursor.fetchone()
        return int(row[0]) if row else 0


async def delete_user(user_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await db.commit()


async def create_scan_record(scan_id: str, user_id: int, domain: str, status: str = "running",
                             notes: str = ""):
    # OR IGNORE: 대기열 단계에서 미리 생성한 레코드가 있으면 run_scan 재호출이 중복 INSERT 하지 않도록.
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO scans (scan_id, user_id, domain, status, notes) VALUES (?, ?, ?, ?, ?)",
            (scan_id, user_id, domain, status, notes or ""),
        )
        await db.commit()


async def update_scan_record(scan_id: str, status: str, results=None, analysis=None):
    parts, params = ["status = ?"], [status]
    if results is not None:
        parts.append("results = ?")
        params.append(json.dumps(results, ensure_ascii=False))
    if analysis is not None:
        parts.append("analysis = ?")
        params.append(json.dumps(analysis, ensure_ascii=False))
    params.append(scan_id)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(f"UPDATE scans SET {', '.join(parts)} WHERE scan_id = ?", params)
        await db.commit()


async def reconcile_orphan_running_scans() -> list[str]:
    """서버 시작 시 호출. 프로세스가 방금 떴으므로 status='running' 인 스캔은 모두 고아
    (이전 프로세스가 진행 중이던 스캔이 재시작/크래시로 끊긴 것)이다. 이를 'interrupted'
    로 정리해 재개 버튼이 노출되도록 한다. 정리된 scan_id 목록을 반환."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT scan_id FROM scans WHERE status = 'running'")
        ids = [r[0] for r in await cursor.fetchall()]
        if ids:
            await db.execute("UPDATE scans SET status = 'interrupted' WHERE status = 'running'")
        # 대기열(queued)은 시작 전 고아 → 실패로 정리(재개할 체크포인트 없음)
        await db.execute("UPDATE scans SET status = 'failed' WHERE status = 'queued'")
        await db.commit()
    return ids


async def save_checkpoint(scan_id: str, checkpoint: dict):
    """스캔 재개용 체크포인트(스테이지/부분결과) 저장. 스테이지 완료마다 호출."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE scans SET checkpoint = ? WHERE scan_id = ?",
            (json.dumps(checkpoint, ensure_ascii=False), scan_id))
        await db.commit()


async def load_checkpoint(scan_id: str) -> dict | None:
    """저장된 체크포인트를 반환(없거나 파싱 실패 시 None)."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT checkpoint FROM scans WHERE scan_id = ?", (scan_id,))
        row = await cursor.fetchone()
    if not row or not row[0]:
        return None
    try:
        return json.loads(row[0])
    except Exception:
        return None


async def get_scan_record(scan_id: str) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT s.*, u.username FROM scans s JOIN users u ON s.user_id = u.id WHERE s.scan_id = ?",
            (scan_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        d = _row_to_dict(row, cursor)
        for field in ("results", "analysis", "checkpoint", "scan_config"):
            if d.get(field):
                try:
                    d[field] = json.loads(d[field])
                except Exception:
                    pass
        return d


async def set_scan_config(scan_id: str, config: dict):
    """대기 스캔의 제출 설정(JSON)을 저장 — 스캔 전 '설정 수정' 프리필용. 비밀번호는 저장하지 않음."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE scans SET scan_config = ? WHERE scan_id = ?",
            (json.dumps(config, ensure_ascii=False), scan_id),
        )
        await db.commit()


# ── Domain Watchlist ──────────────────────────────────────────────────────────

async def add_to_watchlist(domain: str, user_id: int, description: str, notes: str,
                           scan_day: int = 1, scan_months: int = 0,
                           scan_time: str = "03:00", enabled: bool = False,
                           exclude_urls: list | None = None, time_budget_minutes: int = 0,
                           login_url: str = "", login_username: str = "",
                           login_password: str | None = None,
                           update_schedule: bool = True) -> dict:
    """등록 대상 upsert — (domain, user_id) 중복이면 스캔 설정을 갱신.
    update_schedule=False(새 스캔에서의 등록)면 기존 정기 스캔 스케줄은 보존하고 설정만 갱신한다.
    login_password 가 비어있지 않으면 Fernet 로 암호화해 저장(at-rest). None/빈값이면 기존 비번 보존."""
    _enabled = bool(enabled) and int(scan_months or 0) > 0
    nxt = compute_next_run("", scan_time, scan_day=scan_day, scan_months=scan_months) if _enabled else None
    excl_json = json.dumps([str(u) for u in (exclude_urls or [])], ensure_ascii=False)
    # 비밀번호: 새 값이 주어졌을 때만 암호화·갱신(빈값이면 기존 유지 → conflict SET 에서 제외).
    _pw_enc = None
    if login_password:
        try:
            import secrets_store as _ss
            _pw_enc = _ss.encrypt(login_password)
        except Exception:
            _pw_enc = None
    _set_config = ("notes=excluded.notes, exclude_urls=excluded.exclude_urls, "
                   "time_budget_minutes=excluded.time_budget_minutes, "
                   "login_url=excluded.login_url, login_username=excluded.login_username"
                   + (", login_password_enc=excluded.login_password_enc" if _pw_enc else ""))
    _set_sched = (", scan_day=excluded.scan_day, scan_months=excluded.scan_months, "
                  "scan_time=excluded.scan_time, enabled=excluded.enabled, next_run=excluded.next_run")
    _conflict = _set_config + (_set_sched if update_schedule else "")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO domain_watchlist "
            "(domain, user_id, description, notes, scan_day, scan_months, scan_time, enabled, next_run, "
            " exclude_urls, time_budget_minutes, login_url, login_username, login_password_enc) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            f"ON CONFLICT(domain, user_id) DO UPDATE SET {_conflict}",
            (domain, user_id, description, notes, int(scan_day or 1), int(scan_months or 0),
             scan_time or "03:00", 1 if _enabled else 0, nxt,
             excl_json, int(time_budget_minutes or 0), login_url or "", login_username or "",
             _pw_enc or ""),
        )
        await db.commit()
        cur = await db.execute(
            "SELECT id FROM domain_watchlist WHERE domain = ? AND user_id = ?", (domain, user_id))
        row = await cur.fetchone()
    return await get_watchlist_item(row[0], user_id, "admin") if row else {}


def _sanitize_watchlist(d: dict) -> dict:
    """암호화 비번(login_password_enc)은 응답에서 제거하고 저장 여부 플래그만 남긴다(평문/암호문 미노출)."""
    enc = d.pop("login_password_enc", "")
    d["has_login_password"] = bool(enc)
    return d


async def get_watchlist(user_id: int, role: str) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        if role == "admin":
            cursor = await db.execute(
                "SELECT w.*, u.username FROM domain_watchlist w JOIN users u ON w.user_id = u.id ORDER BY w.created_at DESC"
            )
        else:
            cursor = await db.execute(
                "SELECT w.*, u.username FROM domain_watchlist w JOIN users u ON w.user_id = u.id WHERE w.user_id = ? ORDER BY w.created_at DESC",
                (user_id,),
            )
        rows = await cursor.fetchall()
        cols = [d[0] for d in cursor.description]
        return [_sanitize_watchlist(dict(zip(cols, r))) for r in rows]


async def get_watchlist_password(domain: str, user_id: int) -> str | None:
    """등록 대상의 저장된 로그인 비밀번호를 복호화해 반환(스캔 시작 시 메모리 사용 전용). 없으면 None."""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT login_password_enc FROM domain_watchlist WHERE domain = ? AND user_id = ?",
            (domain, user_id))
        row = await cur.fetchone()
    if not row or not row[0]:
        return None
    try:
        import secrets_store as _ss
        return _ss.decrypt(row[0])
    except Exception:
        return None


async def get_watchlist_item(item_id: int, user_id: int, role: str) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT w.*, u.username FROM domain_watchlist w JOIN users u ON w.user_id = u.id WHERE w.id = ?",
            (item_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        d = _row_to_dict(row, cursor)
        if role != "admin" and d["user_id"] != user_id:
            return None
        # exclude_urls 는 JSON 문자열 저장 → 항상 배열로 반환(응답 일관성)
        if isinstance(d.get("exclude_urls"), str):
            try:
                d["exclude_urls"] = json.loads(d["exclude_urls"] or "[]")
            except Exception:
                d["exclude_urls"] = []
        return _sanitize_watchlist(d)


async def update_watchlist_item(
    item_id: int,
    description: str | None = None,
    notes: str | None = None,
    scan_cycle: str | None = None,
    scan_time: str | None = None,
    enabled: bool | None = None,
    scan_day: int | None = None,
    scan_months: int | None = None,
) -> dict | None:
    """대상 메타/점검 스케줄 갱신. 스케줄(일자/개월주기/시간/활성) 변경 시 next_run 재계산."""
    cur = await get_watchlist_item(item_id, 0, "admin")
    if not cur:
        return None

    parts, params = [], []
    if description is not None:
        parts += ["description = ?"]; params.append(description)
    if notes is not None:
        parts += ["notes = ?"]; params.append(notes)

    sched_changed = any(v is not None for v in (scan_cycle, scan_time, enabled, scan_day, scan_months))
    if sched_changed:
        new_cycle = (scan_cycle if scan_cycle is not None else cur.get("scan_cycle")) or "manual"
        new_time = (scan_time if scan_time is not None else cur.get("scan_time")) or "03:00"
        new_enabled = enabled if enabled is not None else bool(cur.get("enabled"))
        new_day = scan_day if scan_day is not None else int(cur.get("scan_day") or 1)
        new_months = scan_months if scan_months is not None else int(cur.get("scan_months") or 0)
        parts += ["scan_cycle = ?", "scan_time = ?", "enabled = ?", "scan_day = ?", "scan_months = ?"]
        params += [new_cycle, new_time, 1 if new_enabled else 0, int(new_day), int(new_months)]
        # 활성 + (월간 개월주기 또는 기존 주기)면 다음 실행 예약, 아니면 해제
        nxt = compute_next_run(new_cycle, new_time, scan_day=new_day, scan_months=new_months) if new_enabled else None
        parts += ["next_run = ?"]; params.append(nxt)

    if not parts:
        return cur
    params.append(item_id)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(f"UPDATE domain_watchlist SET {', '.join(parts)} WHERE id = ?", params)
        await db.commit()
    return await get_watchlist_item(item_id, 0, "admin")


async def get_due_watchlist(now_str: str | None = None) -> list[dict]:
    """자동 점검 대상(enabled=1, next_run 도래) 목록을 반환한다."""
    now_str = now_str or _now_str()
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT * FROM domain_watchlist "
            "WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= ? "
            "ORDER BY next_run ASC",
            (now_str,),
        )
        rows = await cursor.fetchall()
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, r)) for r in rows]


async def mark_watchlist_ran(item_id: int, scan_cycle: str, scan_time: str,
                             scan_day: int | None = None, scan_months: int | None = None) -> None:
    """자동 점검 실행 후 last_run/next_run 을 갱신한다."""
    last = _now_str()
    nxt = compute_next_run(scan_cycle, scan_time, scan_day=scan_day, scan_months=scan_months)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE domain_watchlist SET last_run = ?, next_run = ? WHERE id = ?",
            (last, nxt, item_id),
        )
        await db.commit()


async def delete_watchlist_item(item_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM domain_watchlist WHERE id = ?", (item_id,))
        await db.commit()


async def count_domain_scans(domain: str, user_id: int, role: str) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        if role == "admin":
            cursor = await db.execute(
                "SELECT COUNT(*) FROM scans WHERE domain = ? AND status = 'complete'", (domain,)
            )
        else:
            cursor = await db.execute(
                "SELECT COUNT(*) FROM scans WHERE domain = ? AND user_id = ? AND status = 'complete'",
                (domain, user_id),
            )
        row = await cursor.fetchone()
        return row[0] if row else 0


async def get_domain_scan_history(domain: str, user_id: int, role: str, limit: int = 5,
                                  scheduled_only: bool = False) -> list[dict]:
    # scheduled_only=True 면 예약(정기) 스캔만(notes 가 '[예약 스캔]' 으로 시작). 새 스캔 이력 제외.
    _sched = " AND notes LIKE '[예약 스캔]%'" if scheduled_only else ""
    async with aiosqlite.connect(DB_PATH) as db:
        if role == "admin":
            cursor = await db.execute(
                f"SELECT * FROM scans WHERE domain = ? AND status = 'complete'{_sched} ORDER BY created_at DESC LIMIT ?",
                (domain, limit),
            )
        else:
            cursor = await db.execute(
                f"SELECT * FROM scans WHERE domain = ? AND user_id = ? AND status = 'complete'{_sched} ORDER BY created_at DESC LIMIT ?",
                (domain, user_id, limit),
            )
        rows = await cursor.fetchall()
        cols = [d[0] for d in cursor.description]
        results = []
        for row in rows:
            d = dict(zip(cols, row))
            for field in ("results", "analysis"):
                if d.get(field):
                    d[field] = json.loads(d[field])
            results.append(d)
        return results


async def delete_scan_record(scan_id: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        await db.commit()


async def get_scans_for_user(user_id: int, role: str) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        if role == "admin":
            cursor = await db.execute(
                "SELECT s.*, u.username FROM scans s JOIN users u ON s.user_id = u.id ORDER BY s.created_at DESC"
            )
        else:
            cursor = await db.execute(
                "SELECT s.*, u.username FROM scans s JOIN users u ON s.user_id = u.id WHERE s.user_id = ? ORDER BY s.created_at DESC",
                (user_id,),
            )
        rows = await cursor.fetchall()
        cols = [d[0] for d in cursor.description]
        results = []
        for row in rows:
            d = dict(zip(cols, row))
            for field in ("results", "analysis"):
                if d.get(field):
                    d[field] = json.loads(d[field])
            results.append(d)
        return results


# ── 스캔 정책 (Scan Policy) ─────────────────────────────────────────────────────

def _parse_json_field(d: dict, field: str) -> dict:
    raw = d.get(field)
    if isinstance(raw, str):
        try:
            d[field] = json.loads(raw)
        except Exception:
            d[field] = {}
    return d


async def list_policies() -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT * FROM scan_policies ORDER BY id ASC")
        rows = await cur.fetchall()
        cols = [c[0] for c in cur.description]
        return [_parse_json_field(dict(zip(cols, r)), "config") for r in rows]


async def get_policy(policy_id: int) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT * FROM scan_policies WHERE id = ?", (policy_id,))
        row = await cur.fetchone()
        if not row:
            return None
        return _parse_json_field(_row_to_dict(row, cur), "config")


async def get_active_policy() -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT * FROM scan_policies WHERE is_active = 1 LIMIT 1")
        row = await cur.fetchone()
        if not row:
            return None
        return _parse_json_field(_row_to_dict(row, cur), "config")


def _clean_policy_config(config: dict) -> dict:
    """허용된 env 키만, 문자열 값으로 정규화."""
    out = {}
    for k, v in (config or {}).items():
        if k in POLICY_ENV_KEYS:
            out[k] = str(v)
    return out


async def create_policy(name: str, description: str, config: dict) -> dict:
    cfg = json.dumps(_clean_policy_config(config))
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO scan_policies (name, description, config, is_active, builtin) VALUES (?,?,?,0,0)",
            (name, description or "", cfg),
        )
        await db.commit()
        new_id = cur.lastrowid
    return await get_policy(new_id)


async def update_policy(policy_id: int, name=None, description=None, config=None) -> dict | None:
    cur = await get_policy(policy_id)
    if not cur:
        return None
    parts, params = [], []
    if name is not None:
        parts.append("name = ?"); params.append(name)
    if description is not None:
        parts.append("description = ?"); params.append(description)
    if config is not None:
        parts.append("config = ?"); params.append(json.dumps(_clean_policy_config(config)))
    if parts:
        params.append(policy_id)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(f"UPDATE scan_policies SET {', '.join(parts)} WHERE id = ?", params)
            await db.commit()
    return await get_policy(policy_id)


async def delete_policy(policy_id: int) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT builtin, is_active FROM scan_policies WHERE id = ?", (policy_id,))
        row = await cur.fetchone()
        if not row:
            return False
        # D-b11: 내장 정책·활성 정책은 삭제 금지(활성 삭제 시 정책 없음 상태 방지)
        if row[0] == 1 or row[1] == 1:
            return False
        await db.execute("DELETE FROM scan_policies WHERE id = ?", (policy_id,))
        await db.commit()
        return True


async def set_active_policy(policy_id: int) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT id FROM scan_policies WHERE id = ?", (policy_id,))
        if not await cur.fetchone():
            return None
        await db.execute("UPDATE scan_policies SET is_active = 0")
        await db.execute("UPDATE scan_policies SET is_active = 1 WHERE id = ?", (policy_id,))
        await db.commit()
    return await get_policy(policy_id)


# ── 보고서 템플릿 (Report Template) ─────────────────────────────────────────────

def _clean_template_options(options: dict) -> dict:
    out = {}
    for k, v in (options or {}).items():
        if k in TEMPLATE_OPTION_KEYS:
            out[k] = v
    return out


async def list_templates() -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT * FROM report_templates ORDER BY id ASC")
        rows = await cur.fetchall()
        cols = [c[0] for c in cur.description]
        return [_parse_json_field(dict(zip(cols, r)), "options") for r in rows]


async def get_template(template_id: int) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT * FROM report_templates WHERE id = ?", (template_id,))
        row = await cur.fetchone()
        if not row:
            return None
        return _parse_json_field(_row_to_dict(row, cur), "options")


async def get_default_template() -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT * FROM report_templates WHERE is_default = 1 LIMIT 1")
        row = await cur.fetchone()
        if not row:
            return None
        return _parse_json_field(_row_to_dict(row, cur), "options")


async def create_template(name: str, description: str, options: dict) -> dict:
    opts = json.dumps(_clean_template_options(options))
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO report_templates (name, description, options, is_default, builtin) VALUES (?,?,?,0,0)",
            (name, description or "", opts),
        )
        await db.commit()
        new_id = cur.lastrowid
    return await get_template(new_id)


async def update_template(template_id: int, name=None, description=None, options=None) -> dict | None:
    cur = await get_template(template_id)
    if not cur:
        return None
    parts, params = [], []
    if name is not None:
        parts.append("name = ?"); params.append(name)
    if description is not None:
        parts.append("description = ?"); params.append(description)
    if options is not None:
        parts.append("options = ?"); params.append(json.dumps(_clean_template_options(options)))
    if parts:
        params.append(template_id)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(f"UPDATE report_templates SET {', '.join(parts)} WHERE id = ?", params)
            await db.commit()
    return await get_template(template_id)


async def delete_template(template_id: int) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT id FROM report_templates WHERE id = ?", (template_id,))
        if not await cur.fetchone():
            return False
        await db.execute("DELETE FROM report_templates WHERE id = ?", (template_id,))
        await db.commit()
        return True


async def set_default_template(template_id: int) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT id FROM report_templates WHERE id = ?", (template_id,))
        if not await cur.fetchone():
            return None
        await db.execute("UPDATE report_templates SET is_default = 0")
        await db.execute("UPDATE report_templates SET is_default = 1 WHERE id = ?", (template_id,))
        await db.commit()
    return await get_template(template_id)
