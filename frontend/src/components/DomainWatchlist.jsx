import { useEffect, useState, useMemo } from "react";
import {
  CalendarClock, Plus, X, Loader2, Search, Trash2, ScanSearch,
  ShieldAlert, ShieldCheck, Clock, ChevronRight, Pencil, ArrowLeft,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { RISK_COLOR } from "../utils/risk";
import { statusBadge } from "../utils/status";
import ScanWizard from "./ScanWizard";
import Toggle from "./Toggle";

const scheduleText = (it) => {
  const months = Number(it.scan_months || 0);
  if (months <= 0) return "수동";
  return `${months === 1 ? "매월" : `${months}개월마다`} ${it.scan_day || 1}일 ${it.scan_time || "03:00"}`;
};

// 과거 정기 스캔 이력
function DomainScans({ item, apiFetch, onOpenScan }) {
  const [scans, setScans] = useState(null);
  useEffect(() => {
    apiFetch(`/api/watchlist/${item.id}/history`).then((r) => (r.ok ? r.json() : []))
      .then((d) => setScans(Array.isArray(d) ? d : [])).catch(() => setScans([]));
  }, [item.id]);
  return (
    <div>
      <div className="text-[11px] font-semibold text-muted mb-1">과거 정기 스캔 이력</div>
      {scans === null ? (
        <div className="text-xs text-muted flex items-center gap-2"><Loader2 className="w-3.5 h-3.5 animate-spin" />불러오는 중…</div>
      ) : scans.length === 0 ? (
        <div className="text-xs text-muted">이 대상의 스캔 이력이 없습니다.</div>
      ) : (
        <div className="border border-hairline rounded bg-white divide-y divide-hairline max-h-40 overflow-y-auto">
          {scans.map((s) => {
            const risk = s.analysis?.overall_risk;
            return (
              <button key={s.scan_id} onClick={() => onOpenScan?.(s.scan_id)} className="w-full flex items-center gap-2 px-3 py-1.5 text-left hover:bg-gray-50 transition-colors">
                {risk ? (risk === "GOOD" || risk === "LOW" ? <ShieldCheck className="w-3.5 h-3.5 text-green-600" /> : <ShieldAlert className="w-3.5 h-3.5 text-red-600" />) : <Clock className="w-3.5 h-3.5 text-muted" />}
                <span className="text-[11px] text-muted flex-1">{s.created_at}</span>
                {s.status && <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${statusBadge(s.status).cls}`}>{statusBadge(s.status).label}</span>}
                {risk && <span className={`text-[11px] font-semibold ${RISK_COLOR[risk]}`}>{risk}</span>}
                <ChevronRight className="w-3 h-3 text-muted" />
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default function DomainWatchlist({ onScanDomain, onOpenScan }) {
  const { apiFetch } = useAuth();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);
  const [showWizard, setShowWizard] = useState(false);
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState(null);   // 펼친 대상(이력)
  const [editItem, setEditItem] = useState(null);   // 수정 중인 대상(위저드 프리필)

  const load = async () => {
    setLoading(true);
    try { const r = await apiFetch("/api/watchlist"); if (r.ok) setItems(await r.json()); }
    finally { setLoading(false); }
  };
  useEffect(() => {
    load();
    // 우측 '빠른 작업 → 정기 스캔'에서 넘어온 경우 등록 위저드 자동 오픈
    try {
      if (sessionStorage.getItem("open_watchlist_wizard")) {
        setShowWizard(true);
        sessionStorage.removeItem("open_watchlist_wizard");
      }
    } catch { /* 무시 */ }
  }, []);

  const scheduled = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter((it) => Number(it.scan_months) > 0 && (!q || (it.domain || "").toLowerCase().includes(q)))
      .sort((a, b) => String(a.next_run || "z").localeCompare(String(b.next_run || "z")));
  }, [items, search]);

  const startEdit = (e, it) => { e.stopPropagation(); setShowWizard(false); setEditItem(it); };

  // 등록/수정 공통: watchlist upsert(도메인 기준). 성공 true.
  const handleRegister = async ({ domain, notes, ...rest }) => {
    const d = (domain || "").trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase();
    if (!d) return false;
    try {
      const r = await apiFetch("/api/watchlist", { method: "POST", body: JSON.stringify({ domain: d, description: "", notes: notes || "", ...rest }) });
      if (!r.ok) { const e = await r.json().catch(() => ({})); alert(e.detail || "저장 실패"); return false; }
      setShowWizard(false); setEditItem(null); load(); return true;
    } catch { alert("저장 실패"); return false; }
  };

  const removeItem = async (e, id) => {
    e.stopPropagation();
    if (!window.confirm("이 정기 스캔을 삭제하시겠습니까?")) return;
    setBusyId(id);
    try { await apiFetch(`/api/watchlist/${id}`, { method: "DELETE" }); setItems((p) => p.filter((x) => x.id !== id)); }
    finally { setBusyId(null); }
  };

  // 수정 화면(별도 페이지) — editItem 이 있으면 목록 대신 전용 수정 화면을 보여준다.
  if (editItem) {
    return (
      <div className="il-card overflow-hidden">
        <div className="px-5 py-4 border-b border-hairline flex items-center gap-3 flex-wrap">
          <button onClick={() => setEditItem(null)} className="p-2 rounded-lg text-muted hover:text-ink hover:bg-gray-50 transition-colors"><ArrowLeft className="w-5 h-5" /></button>
          <CalendarClock className="w-5 h-5 text-muted" />
          <h2 className="font-semibold text-ink">정기 스캔 수정</h2>
          <span className="font-mono text-primary text-sm">{editItem.domain}</span>
          <span className="text-xs text-muted">타겟 URL은 그대로, 나머지 단계만 수정합니다</span>
        </div>
        <div className="p-5">
          <ScanWizard mode="register" editItem={editItem} onRegister={handleRegister} disabled={false} />
        </div>
      </div>
    );
  }

  return (
    <div className="il-card overflow-hidden">
      <div className="px-5 py-4 border-b border-hairline space-y-3">
        <div className="flex items-center gap-2">
          <CalendarClock className="w-5 h-5 text-muted" />
          <h2 className="font-semibold text-ink">정기 스캔</h2>
          <span className="text-xs text-muted">— 예약된 대상 {scheduled.length}건 (직접 등록)</span>
          <button onClick={() => setShowWizard((v) => !v)}
            className="ml-auto inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-white text-sm font-semibold" style={{ background: "#1E3A8A" }}>
            {showWizard ? <X className="w-4 h-4" /> : <Plus className="w-4 h-4" />}{showWizard ? "닫기" : "새 정기 스캔 등록"}
          </button>
        </div>
        {showWizard && (
          <div className="border border-hairline rounded-xl p-4"><ScanWizard mode="register" onRegister={handleRegister} disabled={false} /></div>
        )}
        <div className="relative">
          <Search className="w-4 h-4 text-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="도메인 검색" className="il-input h-9 text-sm pl-8 pr-3 w-52" />
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12"><Loader2 className="w-6 h-6 animate-spin" style={{ color: "#1E3A8A" }} /></div>
      ) : scheduled.length === 0 ? (
        <div className="py-12 text-center text-muted">등록된 정기 스캔이 없습니다. “새 정기 스캔 등록”으로 주기를 지정해 추가하세요.</div>
      ) : (
        <div className="divide-y divide-hairline">
          {scheduled.map((it) => (
            <div key={it.id}>
              <div className="flex items-center hover:bg-gray-50 transition-colors">
                <button onClick={() => { setExpanded(expanded === it.id ? null : it.id); if (editId && editId !== it.id) setEditId(null); }}
                  className="flex-1 text-left px-5 py-3.5 flex items-center gap-3 min-w-0">
                  <ChevronRight className={`w-4 h-4 text-muted flex-shrink-0 transition-transform ${expanded === it.id ? "rotate-90" : ""}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium text-ink font-mono truncate">{it.domain}</span>
                      {it.last_risk && <span className={`text-xs font-semibold ${RISK_COLOR[it.last_risk]}`}>{it.last_risk}</span>}
                      {!it.enabled && <span className="text-[10px] text-amber-700 bg-amber-50 px-1.5 py-0.5 rounded-full">비활성</span>}
                    </div>
                    <div className="text-xs text-muted mt-0.5 flex items-center gap-2 flex-wrap">
                      <span className="flex items-center gap-1"><CalendarClock className="w-3 h-3" />{scheduleText(it)}</span>
                      {it.enabled && it.next_run && <span>· 다음 {it.next_run}</span>}
                      <span>· 스캔 {it.scan_count ?? 0}회</span>
                    </div>
                  </div>
                </button>
                <div className="flex items-center gap-1 pr-4">
                  <button onClick={(e) => startEdit(e, it)} title="정기 스캔 설정 수정" className="p-1.5 rounded-lg text-muted hover:text-primary hover:bg-primary-50 transition-colors"><Pencil className="w-4 h-4" /></button>
                  <button onClick={(e) => { e.stopPropagation(); onScanDomain?.(it.domain, "", it.login_username ? { login_url: it.login_url || "", username: it.login_username } : undefined); }} title="지금 스캔" className="p-1.5 rounded-lg text-muted hover:text-primary hover:bg-primary-50 transition-colors"><ScanSearch className="w-4 h-4" /></button>
                  <button onClick={(e) => removeItem(e, it.id)} disabled={busyId === it.id} title="삭제" className="p-1.5 rounded-lg text-muted hover:text-red-600 hover:bg-red-50 transition-colors disabled:opacity-50">
                    {busyId === it.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* 펼친 상세: 과거 정기 스캔 이력 */}
              {expanded === it.id && (
                <div className="px-5 pb-4 pt-2 bg-gray-50 border-t border-hairline">
                  <DomainScans item={it} apiFetch={apiFetch} onOpenScan={onOpenScan} />
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
