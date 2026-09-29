import { useEffect, useRef, useState } from "react";
import {
  Bell, ChevronDown, LogOut, User, Shield, Play, CheckCircle2, Trash2, X,
  PauseCircle, StopCircle,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

const ROLE_LABEL = { admin: "관리자", user: "일반" };

// 스캔 생명주기 알림(시작/재개/일시정지/완료/정지) — 정기·일반 스캔 모두. localStorage 에 저장.
const NOTIF_KEY = "scan_notifs_v1";
const STATUS_KEY = "scan_status_map_v1";
const SEEN_KEY = "scan_notif_seen_v1";

const RUNNING = new Set(["running", "pending", "queued", "in_progress", "scanning"]);  // paused 제외
const PAUSED = "paused";
const COMPLETE = new Set(["complete", "completed"]);
const STOPPED = new Set(["stopped", "interrupted", "cancelled", "failed", "error"]);   // 정지·실패 계열
const TERMINAL = new Set([...COMPLETE, ...STOPPED]);
// 알림 종류별 표시(아이콘/색). 라벨은 render 에서 상태에 따라 보정.
const KIND_META = {
  start:  { label: "스캔 시작",     Icon: Play,         color: "text-primary" },
  resume: { label: "스캔 재개",     Icon: Play,         color: "text-primary" },
  pause:  { label: "스캔 일시정지",  Icon: PauseCircle,  color: "text-amber-500" },
  end:    { label: "스캔 완료",     Icon: CheckCircle2, color: "text-green-600" },
  stop:   { label: "스캔 정지됨",    Icon: StopCircle,   color: "text-red-600" },
};
const FINAL_KINDS = new Set(["end", "stop"]);   // 결과(상세)로 이동하는 종류
function notifLabel(n) {
  if (n.kind === "stop") return (n.status === "failed" || n.status === "error") ? "스캔 실패" : "스캔 정지됨";
  return KIND_META[n.kind]?.label || "스캔 알림";
}

function loadJSON(key, fallback) {
  try { const v = localStorage.getItem(key); return v == null ? fallback : JSON.parse(v); }
  catch { return fallback; }
}
function saveJSON(key, val) {
  try { localStorage.setItem(key, JSON.stringify(val)); } catch { /* 무시 */ }
}
function truncate(v, n) { const s = String(v ?? ""); return s.length > n ? s.slice(0, n) + "…" : s; }
function fmtClock(ms) {
  try { const d = new Date(ms); const p = (n) => String(n).padStart(2, "0"); return `${p(d.getHours())}:${p(d.getMinutes())}`; }
  catch { return ""; }
}

/**
 * 상단바.
 * - 좌측: 현재 페이지 제목 + 설명
 * - 우측: 알림 종(스캔 시작/완료 알림, 클릭 시 해당 스캔으로 이동) + 사용자 프로필
 */
export default function TopBar({ title, description, onOpenScan, onViewChange }) {
  const { auth, logout, apiFetch } = useAuth();
  const user = auth?.user || {};
  const [menuOpen, setMenuOpen] = useState(false);
  const [bellOpen, setBellOpen] = useState(false);
  const [notifs, setNotifs] = useState(() => loadJSON(NOTIF_KEY, []));
  const [seenTs, setSeenTs] = useState(() => Number(loadJSON(SEEN_KEY, 0)) || 0);
  const menuRef = useRef(null);
  const bellRef = useRef(null);
  const statusMapRef = useRef(loadJSON(STATUS_KEY, null));   // null = 최초(baseline 미형성)

  useEffect(() => {
    const onClick = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) setMenuOpen(false);
      if (bellRef.current && !bellRef.current.contains(e.target)) setBellOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  // /api/scans 폴링 → 시작/완료 전이 감지 → 알림 생성(정기·일반 모두)
  useEffect(() => {
    let alive = true;
    const pull = async () => {
      try {
        const r = await apiFetch("/api/scans");
        if (!r.ok) return;
        const d = await r.json();
        const items = Array.isArray(d) ? d : (d.items || d.scans || []);
        const curMap = {}; const meta = {};
        for (const s of items) {
          if (!s || !s.scan_id) continue;
          curMap[s.scan_id] = String(s.status || "");
          meta[s.scan_id] = s.domain || s.target || s.scan_id;
        }
        const prev = statusMapRef.current;
        // 최초 baseline: 기존 스캔들은 무음(과거 스캔으로 알림 폭주 방지)
        if (prev == null) {
          statusMapRef.current = curMap; saveJSON(STATUS_KEY, curMap); return;
        }
        const fresh = [];
        for (const [sid, st] of Object.entries(curMap)) {
          const before = prev[sid];
          if (before === st) continue;
          const dom = meta[sid];
          const mk = (kind) => fresh.push({
            id: `${sid}:${kind}:${Date.now()}`, kind, scan_id: sid, domain: dom, status: st, ts: Date.now(),
          });
          if (before === undefined) {
            // 최초 관측: 현재 상태에 맞는 알림 1개
            if (RUNNING.has(st)) mk("start");
            else if (st === PAUSED) mk("pause");
            else if (COMPLETE.has(st)) mk("end");
            else if (STOPPED.has(st)) mk("stop");
          } else {
            // 상태 전이
            if (st === PAUSED && before !== PAUSED) mk("pause");
            else if (RUNNING.has(st) && before === PAUSED) mk("resume");
            else if (COMPLETE.has(st) && !TERMINAL.has(before)) mk("end");
            else if (STOPPED.has(st) && !TERMINAL.has(before)) mk("stop");
          }
        }
        statusMapRef.current = curMap; saveJSON(STATUS_KEY, curMap);
        if (fresh.length && alive) {
          setNotifs((prevN) => {
            const byId = new Map(prevN.map((n) => [n.id, n]));
            for (const n of fresh) if (!byId.has(n.id)) byId.set(n.id, n);
            const merged = Array.from(byId.values()).sort((a, b) => b.ts - a.ts).slice(0, 40);
            saveJSON(NOTIF_KEY, merged);
            return merged;
          });
        }
      } catch { /* 무시 */ }
    };
    pull();
    const t = setInterval(pull, 8000);
    return () => { alive = false; clearInterval(t); };
  }, [apiFetch]);

  const unread = notifs.filter((n) => n.ts > seenTs).length;

  function toggleBell() {
    setBellOpen((v) => {
      const next = !v;
      if (next) { const now = Date.now(); setSeenTs(now); saveJSON(SEEN_KEY, now); }
      return next;
    });
  }
  function openNotif(n) {
    setBellOpen(false);
    // 완료·정지(종료) 알림 → 해당 스캔 결과(상세)로. 시작·재개·일시정지(진행) 알림 → 진행 현황으로.
    if (FINAL_KINDS.has(n.kind)) {
      if (n.scan_id && onOpenScan) onOpenScan(n.scan_id);
    } else {
      if (onViewChange) onViewChange("progress");
    }
  }
  function deleteNotif(e, id) {
    e.stopPropagation();
    setNotifs((prevN) => {
      const next = prevN.filter((n) => n.id !== id);
      saveJSON(NOTIF_KEY, next);
      return next;
    });
  }
  function clearNotifs(e) {
    e.stopPropagation();
    setNotifs([]); saveJSON(NOTIF_KEY, []);
    const now = Date.now(); setSeenTs(now); saveJSON(SEEN_KEY, now);
  }

  return (
    <header className="sticky top-0 z-20 bg-surface/90 backdrop-blur border-b border-hairline">
      <div className="flex items-center justify-between px-8 py-3.5 min-h-[72px]">
        {/* 페이지 제목 */}
        <div className="min-w-0">
          <h1 className="text-lg font-bold text-ink truncate">{title}</h1>
          {description && <p className="text-xs text-muted truncate">{description}</p>}
        </div>

        {/* 우측 액션 */}
        <div className="flex items-center gap-1.5">
          {/* 알림 */}
          <div className="relative" ref={bellRef}>
            <button
              onClick={toggleBell}
              className="relative w-9 h-9 rounded-lg flex items-center justify-center text-muted hover:text-ink hover:bg-gray-50 transition-colors"
              aria-label="알림"
            >
              <Bell className="w-[18px] h-[18px]" />
              {unread > 0 && (
                <span className="absolute top-1 right-1 min-w-[16px] h-4 px-1 rounded-full bg-red-500 text-white text-[10px] font-semibold flex items-center justify-center">
                  {unread > 99 ? "99+" : unread}
                </span>
              )}
            </button>
            {bellOpen && (
              <div className="absolute right-0 mt-2 w-80 bg-white border border-hairline rounded-xl shadow-card-hover py-2 z-30">
                <div className="px-3.5 py-2 flex items-center justify-between border-b border-hairline">
                  <span className="text-xs font-semibold text-ink">스캔 알림</span>
                  {notifs.length > 0 && (
                    <button onClick={clearNotifs} className="text-[11px] text-muted hover:text-red-600 flex items-center gap-1">
                      <Trash2 className="w-3 h-3" />비우기
                    </button>
                  )}
                </div>
                {notifs.length === 0 ? (
                  <div className="px-3.5 py-6 text-center text-xs text-muted">새 알림 없음</div>
                ) : (
                  <div className="max-h-96 overflow-y-auto">
                    {notifs.map((n) => (
                      <div
                        key={n.id}
                        className="flex items-stretch border-b border-hairline last:border-0 hover:bg-gray-50 transition-colors"
                      >
                        <button
                          onClick={() => openNotif(n)}
                          className="flex-1 min-w-0 text-left px-3.5 py-2.5 flex items-start gap-2.5"
                        >
                          {(() => {
                            const M = KIND_META[n.kind] || KIND_META.end;
                            const Icon = M.Icon;
                            return <Icon className={`w-4 h-4 ${M.color} flex-shrink-0 mt-0.5`} />;
                          })()}
                          <div className="min-w-0 flex-1">
                            <div className="text-xs font-medium text-ink truncate">{notifLabel(n)}</div>
                            <div className="text-[11px] text-muted truncate font-mono">{truncate(n.domain, 42)}</div>
                          </div>
                          <span className="text-[10px] text-muted flex-shrink-0 mt-0.5">{fmtClock(n.ts)}</span>
                        </button>
                        <button
                          onClick={(e) => deleteNotif(e, n.id)}
                          title="이 알림 삭제"
                          className="px-2 flex items-center flex-shrink-0 text-muted hover:text-red-600 hover:bg-red-50 transition-colors"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* 프로필 */}
          <div className="relative" ref={menuRef}>
            <button
              onClick={() => setMenuOpen((v) => !v)}
              className="flex items-center gap-2 pl-1.5 pr-2 py-1.5 rounded-lg hover:bg-gray-50 transition-colors"
            >
              <div className="w-7 h-7 rounded-full flex items-center justify-center eoseureum-brand-gradient">
                <User className="w-3.5 h-3.5 text-white" />
              </div>
              <div className="hidden sm:flex flex-col items-start leading-tight">
                <span className="text-sm font-medium text-ink">{user.username || "사용자"}</span>
                <span className="text-[10px] text-muted">{ROLE_LABEL[user.role] || "일반"}</span>
              </div>
              <ChevronDown className="w-3.5 h-3.5 text-muted" />
            </button>
            {menuOpen && (
              <div className="absolute right-0 mt-2 w-52 bg-white border border-hairline rounded-xl shadow-card-hover py-1.5 z-30">
                <div className="px-3.5 py-2.5 border-b border-hairline">
                  <div className="flex items-center gap-2">
                    <Shield className="w-3.5 h-3.5 text-primary" />
                    <span className="text-sm font-medium text-ink">{user.username || "사용자"}</span>
                  </div>
                  <div className="text-[11px] text-muted mt-0.5 pl-5.5">
                    권한: {ROLE_LABEL[user.role] || "일반"}
                  </div>
                </div>
                <button
                  onClick={logout}
                  className="w-full flex items-center gap-2 px-3.5 py-2.5 text-sm text-ink hover:bg-gray-50 transition-colors"
                >
                  <LogOut className="w-4 h-4 text-muted" />
                  로그아웃
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}
