import { useCallback, useEffect, useState } from "react";
import {
  Activity, Cpu, Search, Database, Clock, Loader2, RefreshCw, CircleSlash,
  ScanLine, Target, FileText, ChevronRight,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { SCAN_STAGES } from "../utils/stages";

/**
 * 공통 우측 상태 패널 (로그인 후에만 렌더).
 * - 시스템 / AI 분석 엔진 / 스캔 엔진 / 데이터베이스 상태
 * - 마지막 업데이트 시간
 * - 진행 중인 스캔이 있으면 진행률 / 대상 / 현재 작업 / 시작 시간
 *
 * 상태는 /api/health, /api/ai/health 실데이터로만 채운다.
 * 데이터가 없거나 조회 실패 시 mock 고정값 대신 "-" / "확인 불가" 로 표시한다.
 */

// 단계 순서/라벨은 공용 SCAN_STAGES 단일 출처에서 온다(ScanProgress 와 동일 값).
const STAGES = SCAN_STAGES;

const DOT = {
  ok:      "bg-success",
  warn:    "bg-warning",
  error:   "bg-danger",
  idle:    "bg-gray-300",
  unknown: "bg-gray-300",
};

function StatusRow({ icon: Icon, label, state, text }) {
  return (
    <div className="flex items-center gap-2.5 py-1.5">
      <Icon className="w-4 h-4 text-muted flex-shrink-0" />
      <span className="text-sm text-ink flex-1">{label}</span>
      <span className="flex items-center gap-1.5">
        <span className={`w-2 h-2 rounded-full ${DOT[state] || DOT.unknown}`} />
        <span className="text-xs text-muted">{text}</span>
      </span>
    </div>
  );
}

function fmtTime(d) {
  if (!d) return "-";
  const date = typeof d === "string" ? new Date(d) : d;
  if (isNaN(date.getTime())) return "-";
  const p = (n) => String(n).padStart(2, "0");
  return `${p(date.getHours())}:${p(date.getMinutes())}:${p(date.getSeconds())}`;
}

export default function RightPanel({ scanState, scanTarget, currentStage, scanStartedAt, scanningHost, onViewChange, onOpenScan, canScan }) {
  const { apiFetch } = useAuth();
  const [health, setHealth] = useState({ loading: true, ok: null, error: null });
  const [ai, setAi] = useState({ loading: true, available: null, configured: null, provider: null, mode: null });
  const [lastUpdated, setLastUpdated] = useState(null);
  const [running, setRunning] = useState([]);   // 서버의 '모든' 진행중 스캔(동시 스캔 전부 표시)

  // 진행중 스캔 전부를 서버에서 폴링(5초). WS 는 시작한 탭의 1건만 보여주므로 목록은 서버가 authoritative.
  useEffect(() => {
    let alive = true;
    const pull = async () => {
      try {
        const r = await apiFetch("/api/scans");
        if (!r.ok) return;
        const d = await r.json();
        const items = Array.isArray(d) ? d : (d.items || d.scans || []);
        if (alive) setRunning(items.filter((s) => s.status === "running"));
      } catch { /* ignore */ }
    };
    pull();
    const t = setInterval(pull, 5000);
    return () => { alive = false; clearInterval(t); };
  }, [apiFetch]);

  const load = useCallback(async () => {
    setHealth((h) => ({ ...h, loading: true }));
    setAi((a) => ({ ...a, loading: true }));
    // 시스템 health
    try {
      const r = await apiFetch("/api/health");
      const ok = r.ok && (await r.json())?.status === "ok";
      setHealth({ loading: false, ok, error: ok ? null : `HTTP ${r.status}` });
    } catch (e) {
      setHealth({ loading: false, ok: false, error: e.message });
    }
    // AI provider health
    try {
      const r = await apiFetch("/api/ai/health");
      if (r.ok) {
        const d = await r.json();
        setAi({ loading: false, available: !!d.available, configured: !!d.configured, provider: d.provider || null, mode: d.mode || null });
      } else {
        setAi({ loading: false, available: false, configured: null, provider: null, mode: null });
      }
    } catch {
      setAi({ loading: false, available: null, configured: null, provider: null, mode: null });
    }
    setLastUpdated(new Date());
  }, [apiFetch]);

  useEffect(() => {
    load();
    const t = setInterval(load, 30000); // 30초마다 가볍게 갱신
    return () => clearInterval(t);
  }, [load]);

  // ── 상태 → 표시값 매핑 ──────────────────────────────────────────────
  const sysState = health.loading ? "unknown" : health.ok ? "ok" : "error";
  const sysText = health.loading ? "확인 중" : health.ok ? "정상" : "확인 불가";

  // 스캔 엔진 / DB 는 별도 엔드포인트가 없으므로 서버 가용성(health)에 연동한다.
  const depText = health.loading ? "확인 중" : health.ok ? "정상" : "확인 불가";
  const depState = sysState;

  let aiState = "unknown";
  let aiText = "확인 중";
  if (!ai.loading) {
    if (ai.available) { aiState = "ok"; const _m = ai.mode === "ensemble" ? "앙상블" : ai.mode === "solo" ? "솔로" : null; aiText = _m ? `정상 · ${_m}` : (ai.provider ? `정상 (${ai.provider})` : "정상"); }
    else if (ai.configured === false) { aiState = "idle"; aiText = "미사용"; }
    else if (ai.available === false) { aiState = "warn"; aiText = "연결 실패"; }
    else { aiState = "unknown"; aiText = "확인 불가"; }
  }

  const isScanning = scanState === "scanning";
  const stageIdx = STAGES.findIndex((s) => s.id === currentStage);
  const percent = isScanning ? (stageIdx >= 0 ? Math.round(((stageIdx + 1) / STAGES.length) * 100) : 5) : 0;
  const stageLabel = stageIdx >= 0 ? STAGES[stageIdx].label : "준비 중";

  const QUICK_ACTIONS = [
    { id: "scanner",   label: "새 스캔",   icon: ScanLine, disabled: !canScan },
    { id: "watchlist", label: "정기 스캔", icon: Target, register: true },
    { id: "history",   label: "스캔 목록", icon: FileText },
  ];

  return (
    <aside className="hidden xl:flex flex-col w-[300px] shrink-0 border-l border-hairline bg-surface">
      <div className="p-5 space-y-5 overflow-y-auto">
        {/* 시스템 상태 */}
        <section>
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-semibold tracking-wider text-muted uppercase">시스템 상태</h3>
            <button
              onClick={load}
              className="text-muted hover:text-ink transition-colors"
              aria-label="새로고침"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${health.loading || ai.loading ? "animate-spin" : ""}`} />
            </button>
          </div>
          <div className="il-card p-3.5">
            <StatusRow icon={Activity} label="시스템 상태"   state={sysState} text={sysText} />
            <StatusRow icon={Cpu}      label="AI 분석 엔진"  state={aiState}  text={aiText} />
            <StatusRow icon={Search}   label="스캔 엔진"     state={depState} text={depText} />
            <StatusRow icon={Database} label="데이터베이스"  state={depState} text={depText} />
            <div className="flex items-center gap-2 pt-2 mt-1 border-t border-hairline">
              <Clock className="w-3.5 h-3.5 text-muted flex-shrink-0" />
              <span className="text-xs text-muted flex-1">마지막 업데이트</span>
              <span className="text-xs text-ink font-mono">{fmtTime(lastUpdated)}</span>
            </div>
          </div>
        </section>

        {/* 진행 중인 스캔 — 서버의 동시 스캔 전부 표시(폴링). WS 로 도는 현재 탭 스캔은 실시간 값으로 보정. */}
        <section>
          <h3 className="text-xs font-semibold tracking-wider text-muted uppercase mb-2">
            진행 중인 스캔{running.length > 0 && <span className="ml-1 text-primary">({running.length})</span>}
          </h3>
          {running.length === 0 && !isScanning ? (
            <div className="il-card p-5 flex flex-col items-center justify-center text-center gap-2">
              <CircleSlash className="w-6 h-6 text-gray-300" />
              <span className="text-xs text-muted">진행 중인 스캔 없음</span>
            </div>
          ) : (
            <div className="space-y-2">
              {running.map((s) => {
                const p = s.progress || {};
                // 현재 탭이 WS 로 도는 그 스캔이면 실시간(props) 진행률/단계로 보정(폴링보다 최신)
                const isCurrent = isScanning && (s.domain === scanTarget);
                const pct = isCurrent ? percent : (typeof p.percent === "number" ? p.percent : 5);
                const stg = isCurrent ? (scanningHost ? `${stageLabel} · ${scanningHost}` : stageLabel)
                                      : (p.stage_label || p.message || "진행 중");
                return (
                  <button key={s.scan_id} onClick={() => onViewChange?.("progress")}
                    className="il-card p-3 w-full text-left hover:border-primary/40 transition-colors">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-ink font-medium break-all mr-2">{s.domain || "-"}</span>
                      <span className="text-xs font-semibold text-primary flex-shrink-0">{pct}%</span>
                    </div>
                    <div className="w-full h-1.5 bg-gray-100 rounded-full overflow-hidden mb-1.5">
                      <div className="h-full rounded-full bg-primary transition-all duration-500" style={{ width: `${pct}%` }} />
                    </div>
                    <span className="text-[11px] text-muted flex items-center gap-1.5">
                      <Loader2 className="w-3 h-3 animate-spin text-primary flex-shrink-0" />
                      <span className="truncate">{String(stg).slice(0, 60)}</span>
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </section>

        {/* 빠른 작업 */}
        <section>
          <h3 className="text-xs font-semibold tracking-wider text-muted uppercase mb-2">빠른 작업</h3>
          <div className="il-card p-2 space-y-0.5">
            {QUICK_ACTIONS.map((a) => {
              const Icon = a.icon;
              return (
                <button
                  key={a.id}
                  onClick={() => {
                    if (a.disabled) return;
                    // '정기 스캔' → 정기 스캔 페이지로 이동하면서 '새 정기 스캔 등록' 위저드 자동 오픈
                    if (a.register) { try { sessionStorage.setItem("open_watchlist_wizard", "1"); } catch { /* 무시 */ } }
                    onViewChange?.(a.id);
                  }}
                  disabled={a.disabled}
                  className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm text-ink
                             hover:bg-primary-50 hover:text-primary transition-colors
                             disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent disabled:hover:text-ink"
                >
                  <span className="w-7 h-7 rounded-lg bg-primary-50 flex items-center justify-center flex-shrink-0">
                    <Icon className="w-3.5 h-3.5 text-primary" />
                  </span>
                  <span className="flex-1 text-left font-medium">{a.label}</span>
                  <ChevronRight className="w-3.5 h-3.5 text-muted" />
                </button>
              );
            })}
          </div>
        </section>
      </div>
    </aside>
  );
}
