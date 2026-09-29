import { useEffect, useState, useCallback } from "react";
import {
  Activity, Loader2, RefreshCw, StopCircle, PauseCircle, PlayCircle,
  CalendarClock, Pencil, ChevronDown, ChevronRight,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { statusBadge, effectiveStatus } from "../utils/status";

// 진행 로그 창 높이 — 펼쳤을 때 "약 5cm"(1cm=96/2.54px → 5cm≈189px).
const LOG_BOX_PX = 189;
// 정기 스캔 예약이 이 일수 이내로 다가오면 '대기 중'에 미리 노출(그 전엔 '정기 스캔' 목록에서만 관리).
const IMMINENT_DAYS = 3;

const planSchedule = (p) => {
  const m = Number(p.scan_months) || 0;
  if (m <= 0) return "수동";
  const head = m === 1 ? "매월" : `${m}개월마다`;
  return `${head} ${p.scan_day || 1}일 ${p.scan_time || "03:00"}`;
};

// 진행 현황 전용 페이지.
//  - 진행 중 스캔: 상단. 평소 간략(1줄), 클릭 시 진행 로그를 펼쳐 확인. 정지/일시정지/재개 가능.
//    (정기 스캔이 실행되면 여기 '진행 중'에 자동으로 올라온다 — 출처 무관하게 running 이면 표시)
//  - 대기 중: 하단. 실행 대기(대기열) 스캔 + '3일 이내 예정'인 정기 스캔.
export default function ProgressPage({ onEditQueued }) {
  const { apiFetch } = useAuth();
  const [scans, setScans] = useState([]);
  const [plans, setPlans] = useState([]);       // 등록된 정기 스캔(watchlist)
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);
  const [expanded, setExpanded] = useState({}); // scan_id → 진행 로그 펼침 여부

  const fetchScans = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const r = await apiFetch("/api/scans");
      if (r.ok) { const d = await r.json(); setScans(Array.isArray(d) ? d : []); }
    } finally { if (!quiet) setLoading(false); }
  }, [apiFetch]);

  const fetchPlans = useCallback(async () => {
    try {
      const r = await apiFetch("/api/watchlist");
      if (r.ok) { const d = await r.json(); setPlans(Array.isArray(d) ? d : []); }
    } catch { /* 표시 전용 */ }
  }, [apiFetch]);

  useEffect(() => { fetchScans(); fetchPlans(); }, [fetchScans, fetchPlans]);
  useEffect(() => {
    const t = setInterval(() => { fetchScans(true); fetchPlans(); }, 3000);   // 항상 폴링
    return () => clearInterval(t);
  }, [fetchScans, fetchPlans]);

  // 정지/일시정지/재개 공통 액션
  const act = async (e, id, action, confirmMsg) => {
    e.stopPropagation();
    if (confirmMsg && !window.confirm(confirmMsg)) return;
    setBusyId(id);
    try { await apiFetch(`/api/scans/${id}/${action}`, { method: "POST" }); fetchScans(true); }
    finally { setBusyId(null); }
  };

  const handleEdit = async (e, s) => {
    e.stopPropagation();
    setBusyId(s.scan_id);
    try {
      let cfg = {};
      try {
        const r = await apiFetch(`/api/scans/${s.scan_id}`);
        if (r.ok) { const d = await r.json(); cfg = d?.config || {}; }
      } catch { /* config 없으면 도메인만 프리필 */ }
      onEditQueued?.({ scan_id: s.scan_id, domain: s.domain, ...cfg });
    } finally { setBusyId(null); }
  };

  const running = scans.filter((s) => s.status === "running");
  const queued = scans.filter((s) => s.status === "queued");
  // 정기 스캔 중 'next_run 이 3일 이내'로 다가온 것만 대기중에 노출(진행/대기중인 도메인은 제외).
  const activeDomains = new Set(
    scans.filter((s) => s.status === "running" || s.status === "queued").map((s) => s.domain));
  const imminentPlans = plans.filter((p) => {
    if (!p.next_run || Number(p.scan_months) <= 0 || activeDomains.has(p.domain)) return false;
    const d = new Date(String(p.next_run).replace(" ", "T"));
    return !Number.isNaN(d.getTime()) && (d.getTime() - Date.now()) <= IMMINENT_DAYS * 86400000;
  });
  const waitingCount = queued.length + imminentPlans.length;

  // 진행 중 스캔의 로그는 '기본 펼침'(접히지 않고 보이도록). 사용자가 접으면 false 로 기록되고,
  // 다시 누르면 펼쳐진다. expanded[id] 가 명시적으로 false 일 때만 접힌 상태.
  const toggle = (id) => setExpanded((m) => ({ ...m, [id]: m[id] === false }));

  return (
    <div className="il-card p-5 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-primary" />
          <h2 className="font-semibold text-ink">진행 현황</h2>
          <span className="text-xs text-muted">진행 중 {running.length}{waitingCount > 0 && ` · 대기 ${waitingCount}`}</span>
        </div>
        <button onClick={() => fetchScans()} className="text-muted hover:text-ink p-1.5 rounded-lg hover:bg-gray-50 transition-colors"><RefreshCw className="w-4 h-4" /></button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12"><Loader2 className="w-6 h-6 animate-spin" style={{ color: "#1E3A8A" }} /></div>
      ) : running.length === 0 && waitingCount === 0 ? (
        <div className="py-12 text-center text-muted">진행 중이거나 대기 중인 스캔이 없습니다.</div>
      ) : (
        <>
          {/* ── 진행 중 스캔: 상단. 평소 간략, 클릭 시 진행 로그 펼침 ───────────── */}
          {running.length > 0 && (
            <div className="space-y-2">
              {running.map((s) => {
                const p = s.progress || {};
                const log = Array.isArray(p.log) ? p.log : [];
                const paused = effectiveStatus(s) === "paused";
                const isOpen = expanded[s.scan_id] !== false;   // 기본 펼침(로그 노출)
                const badge = statusBadge(paused ? "paused" : "running");
                return (
                  <div key={s.scan_id} className="border border-hairline rounded-xl overflow-hidden">
                    {/* 간략 헤더(클릭 → 펼침) */}
                    <div className="flex items-center gap-2 px-4 py-2.5 cursor-pointer hover:bg-gray-50 transition-colors"
                         onClick={() => toggle(s.scan_id)} title="진행 로그 펼치기/접기">
                      {isOpen ? <ChevronDown className="w-4 h-4 text-muted flex-shrink-0" /> : <ChevronRight className="w-4 h-4 text-muted flex-shrink-0" />}
                      {paused
                        ? <PauseCircle className="w-4 h-4 text-amber-500 flex-shrink-0" />
                        : <Loader2 className="w-4 h-4 text-primary animate-spin flex-shrink-0" />}
                      {typeof s.seq === "number" && <span className="text-xs font-bold text-muted font-mono">#{s.seq}</span>}
                      <span className="font-medium text-ink font-mono flex-1 min-w-0 truncate">{s.domain}</span>
                      <span className={`text-[11px] px-2 py-0.5 rounded-full ${badge.cls}`}>{badge.label}</span>
                      <span className="text-xs text-muted hidden sm:inline">{p.stage_label || ""}</span>
                      {typeof p.percent === "number" && <span className="text-xs text-muted w-9 text-right">{p.percent}%</span>}
                      {/* 컨트롤: 일시정지/재개 · 정지 */}
                      {paused ? (
                        <button onClick={(e) => act(e, s.scan_id, "resume")} disabled={busyId === s.scan_id}
                          title="재개" className="p-1.5 rounded-lg text-muted hover:text-primary hover:bg-primary-50 transition-colors disabled:opacity-50">
                          <PlayCircle className="w-4 h-4" />
                        </button>
                      ) : (
                        <button onClick={(e) => act(e, s.scan_id, "pause")} disabled={busyId === s.scan_id}
                          title="일시정지" className="p-1.5 rounded-lg text-muted hover:text-amber-600 hover:bg-amber-50 transition-colors disabled:opacity-50">
                          <PauseCircle className="w-4 h-4" />
                        </button>
                      )}
                      <button onClick={(e) => act(e, s.scan_id, "stop", "이 스캔을 중지하시겠습니까? 그때까지의 부분 보고서가 생성됩니다.")} disabled={busyId === s.scan_id}
                        title="정지" className="p-1.5 rounded-lg text-muted hover:text-red-600 hover:bg-red-50 transition-colors disabled:opacity-50">
                        {busyId === s.scan_id ? <Loader2 className="w-4 h-4 animate-spin" /> : <StopCircle className="w-4 h-4" />}
                      </button>
                    </div>

                    {/* 펼침: 진행바 + 진행 로그(5cm, 최신이 위) */}
                    {isOpen && (
                      <div className="px-4 pb-3 pt-1 space-y-2 border-t border-hairline">
                        <div className="w-full h-1.5 rounded-full bg-gray-200 overflow-hidden">
                          <div className="h-full bg-primary rounded-full transition-all duration-700" style={{ width: `${p.percent ?? 5}%` }} />
                        </div>
                        {p.message && <div className="text-[11px] text-muted truncate">{p.message}</div>}
                        {(() => {
                          // B3: i7(외부도구 오프로드) 이벤트가 있으면 2칸(좌 Mac 능동점검 / 우 i7 외부도구)으로
                          // 분할, 없으면 단일칸(구 스캔은 source 없음 → 단일칸, 하위호환).
                          const renderEvents = (evs, emptyText) => (
                            evs.length === 0 ? (
                              <div className="text-muted flex items-center gap-1.5 h-full justify-center">
                                <Loader2 className="w-3 h-3 animate-spin" />{emptyText}
                              </div>
                            ) : (
                              [...evs].reverse().map((ev, i) => (
                                <div key={i} className="flex gap-2">
                                  <span className="text-muted flex-shrink-0">{(ev.t || "").slice(11, 19)}</span>
                                  {ev.stage && <span className="text-primary font-semibold flex-shrink-0">{ev.stage}</span>}
                                  <span className="text-ink min-w-0 break-words">{ev.message}</span>
                                </div>
                              ))
                            )
                          );
                          const hasI7 = log.some((ev) => ev.source === "i7");
                          if (!hasI7) {
                            return (
                              <div className="rounded-lg bg-gray-50 border border-hairline overflow-y-auto px-3 py-2 font-mono text-[11px] space-y-0.5"
                                style={{ height: LOG_BOX_PX }}>
                                {renderEvents(log, "진행 로그 대기 중…")}
                              </div>
                            );
                          }
                          const macEvents = log.filter((ev) => ev.source !== "i7");
                          const i7Events = log.filter((ev) => ev.source === "i7");
                          return (
                            <div className="flex gap-2" style={{ height: LOG_BOX_PX }}>
                              <div className="flex-1 min-w-0 flex flex-col">
                                <div className="text-[10px] font-semibold text-primary px-1 pb-0.5 flex items-center gap-1">
                                  <span className="w-1.5 h-1.5 rounded-full bg-primary inline-block" />CPU1 · Mac 능동점검
                                </div>
                                <div className="rounded-lg bg-gray-50 border border-hairline overflow-y-auto px-3 py-2 font-mono text-[11px] space-y-0.5 flex-1">
                                  {renderEvents(macEvents, "대기 중…")}
                                </div>
                              </div>
                              <div className="flex-1 min-w-0 flex flex-col">
                                <div className="text-[10px] font-semibold text-emerald-600 px-1 pb-0.5 flex items-center gap-1">
                                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block" />CPU2 · i7 외부도구
                                </div>
                                <div className="rounded-lg bg-emerald-50 border border-hairline overflow-y-auto px-3 py-2 font-mono text-[11px] space-y-0.5 flex-1">
                                  {renderEvents(i7Events, "i7 대기 중…")}
                                </div>
                              </div>
                            </div>
                          );
                        })()}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* ── 대기 중: 대기열 스캔 + 3일 이내 예정인 정기 스캔 ─────────────────── */}
          {waitingCount > 0 && (
            <div className="border border-hairline rounded-xl overflow-hidden">
              <div className="px-4 py-2.5 bg-indigo-50/60 border-b border-hairline text-xs font-semibold text-indigo-700 flex items-center gap-1.5">
                <CalendarClock className="w-3.5 h-3.5" />대기 중 ({waitingCount}) — 앞 스캔 종료·예약 시각({IMMINENT_DAYS}일 이내) 도래 시 자동 시작
              </div>
              <div className="divide-y divide-hairline">
                {queued.map((s, i) => (
                  <div key={s.scan_id} className="flex items-center gap-2 px-4 py-2.5 text-xs">
                    <span className="text-muted font-mono w-5">{i + 1}</span>
                    {typeof s.seq === "number" && <span className="font-bold text-muted font-mono">#{s.seq}</span>}
                    <span className="font-medium text-ink font-mono truncate flex-1">{s.domain}</span>
                    <span className={`px-2 py-0.5 rounded-full ${statusBadge("queued").cls}`}>대기열</span>
                    <button onClick={(e) => handleEdit(e, s)} disabled={busyId === s.scan_id}
                      title="스캔 전 설정 수정" className="p-1.5 rounded-lg text-muted hover:text-primary hover:bg-primary-50 transition-colors disabled:opacity-50">
                      {busyId === s.scan_id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Pencil className="w-3.5 h-3.5" />}
                    </button>
                    <button onClick={(e) => act(e, s.scan_id, "stop", "이 대기 스캔을 취소하시겠습니까?")} disabled={busyId === s.scan_id}
                      title="대기 취소" className="p-1.5 rounded-lg text-muted hover:text-red-600 hover:bg-red-50 transition-colors disabled:opacity-50">
                      <StopCircle className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
                {/* 3일 이내 예정인 정기 스캔(정보 표시 — 관리는 '정기 스캔'에서) */}
                {imminentPlans.map((p) => (
                  <div key={`plan-${p.domain}`} className="flex items-center gap-2 px-4 py-2.5 text-xs">
                    <CalendarClock className="w-3.5 h-3.5 text-indigo-400 flex-shrink-0" />
                    <span className="font-medium text-ink font-mono truncate flex-1">{p.domain}</span>
                    <span className="text-muted">{planSchedule(p)}</span>
                    <span className="text-muted hidden sm:inline">· 예정 {String(p.next_run).slice(0, 16).replace("T", " ")}</span>
                    <span className="px-2 py-0.5 rounded-full bg-indigo-50 text-indigo-700">예약(곧 실행)</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
