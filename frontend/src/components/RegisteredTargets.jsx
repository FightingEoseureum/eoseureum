import { useEffect, useState, useMemo } from "react";
import {
  ListChecks, Loader2, RefreshCw, Search, Trash2, ScanSearch,
  ChevronRight, Ban, Clock, KeyRound, CalendarClock, ShieldAlert, ShieldCheck,
  Pencil, Save, X,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { RISK_COLOR } from "../utils/risk";
import { statusBadge } from "../utils/status";

const fmtDur = (min) => {
  if (!min) return "-";
  const h = Math.floor(min / 60), m = min % 60;
  return `${h > 0 ? `${h}시간 ` : ""}${m > 0 ? `${m}분` : h > 0 ? "" : "0분"}`.trim();
};
const scheduleText = (it) => {
  const months = Number(it.scan_months || 0);
  if (!it.enabled || months <= 0) return "수동";
  return `${months === 1 ? "매월" : `${months}개월마다`} ${it.scan_day || 1}일 ${it.scan_time || "03:00"}`;
};

// 대상 클릭 시: 스캔 시 설정한 정보(저장된 스캔 설정)를 보여준다.
function TargetConfig({ item }) {
  const rows = [
    ["점검 주기", scheduleText(item) + (item.enabled ? "" : " (자동 점검 비활성)")],
    ["최대 진행 시간", Number(item.time_budget_minutes) > 0 ? fmtDur(item.time_budget_minutes) : "미설정"],
    ["로그인 URL", item.login_url || "비인증"],
    ["로그인 아이디", item.login_username || "-"],
  ];
  const excl = Array.isArray(item.exclude_urls) ? item.exclude_urls : [];
  return (
    <div className="bg-gray-50 px-5 py-3 space-y-3">
      <div className="text-xs font-semibold text-muted">스캔 시 설정한 정보</div>
      <table className="w-full text-sm">
        <tbody className="divide-y divide-hairline">
          {rows.map(([k, v], i) => (
            <tr key={i}><td className="py-1.5 pr-4 text-muted whitespace-nowrap w-32">{k}</td><td className="py-1.5 text-ink font-mono break-all">{String(v)}</td></tr>
          ))}
        </tbody>
      </table>
      <div>
        <div className="text-xs text-muted mb-1">추가 차단(제외) URL — {excl.length}건</div>
        {excl.length === 0 ? <div className="text-xs text-muted">없음</div> : (
          <div className="border border-hairline rounded bg-white divide-y divide-hairline max-h-40 overflow-y-auto">
            {excl.map((u, i) => (
              <div key={i} className="px-2.5 py-1 text-[11px] font-mono text-ink break-all flex items-center gap-1.5"><Ban className="w-3 h-3 text-red-500 flex-shrink-0" />{u}</div>
            ))}
          </div>
        )}
      </div>
      <p className="text-[11px] text-muted">참고: 스캔 범위(허용 도메인)는 스캔할 때마다 “함께 확인되는 URL 조회”로 새로 정합니다.</p>
    </div>
  );
}

export default function RegisteredTargets({ onScanDomain, onOpenScan }) {
  const { apiFetch } = useAuth();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);
  const [busyId, setBusyId] = useState(null);
  const [search, setSearch] = useState("");
  const [editingId, setEditingId] = useState(null);
  const [form, setForm] = useState(null);
  const [saving, setSaving] = useState(false);

  const startEdit = (e, it) => {
    e.stopPropagation();
    setExpanded(null);
    setEditingId(it.id);
    setForm({
      notes: it.notes || "",
      enabled: !!it.enabled,
      scan_months: Number(it.scan_months || 0),
      scan_day: Number(it.scan_day || 1),
      scan_time: it.scan_time || "03:00",
    });
  };
  const cancelEdit = () => { setEditingId(null); setForm(null); };

  const saveEdit = async (it) => {
    if (!form) return;
    // 변경된 필드만 PATCH (부분 업데이트)
    const patch = {};
    if ((form.notes || "") !== (it.notes || "")) patch.notes = form.notes || "";
    if (!!form.enabled !== !!it.enabled) patch.enabled = !!form.enabled;
    const months = Math.max(0, Number(form.scan_months) || 0);
    if (months !== Number(it.scan_months || 0)) patch.scan_months = months;
    const day = Math.min(31, Math.max(1, Number(form.scan_day) || 1));
    if (day !== Number(it.scan_day || 1)) patch.scan_day = day;
    if ((form.scan_time || "03:00") !== (it.scan_time || "03:00")) patch.scan_time = form.scan_time || "03:00";
    if (Object.keys(patch).length === 0) { cancelEdit(); return; }
    setSaving(true);
    try {
      const r = await apiFetch(`/api/watchlist/${it.id}`, { method: "PATCH", body: JSON.stringify(patch) });
      if (!r.ok) {
        let msg = `HTTP ${r.status}`;
        try { const j = await r.json(); if (j?.detail) msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch { /* ignore */ }
        alert(`저장 실패: ${msg}`);
        return;
      }
      cancelEdit();
      await load();
    } catch (err) {
      alert(`저장 실패: ${err?.message || err}`);
    } finally {
      setSaving(false);
    }
  };

  const load = async () => {
    setLoading(true);
    try { const r = await apiFetch("/api/watchlist"); if (r.ok) setItems(await r.json()); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const removeItem = async (e, id) => {
    e.stopPropagation();
    if (!window.confirm("이 등록 대상을 삭제하시겠습니까?")) return;
    setBusyId(id);
    try { await apiFetch(`/api/watchlist/${id}`, { method: "DELETE" }); setItems((p) => p.filter((x) => x.id !== id)); }
    finally { setBusyId(null); }
  };

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter((it) => !q || (it.domain || "").toLowerCase().includes(q));
  }, [items, search]);

  return (
    <div className="il-card overflow-hidden">
      <div className="px-5 py-4 border-b border-hairline flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <ListChecks className="w-5 h-5 text-muted" />
          <h2 className="font-semibold text-ink">등록된 대상</h2>
          <span className="text-xs text-muted">— {items.length}건 · 새 스캔/정기 스캔에서 저장된 대상·설정</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-4 h-4 text-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="도메인 검색" className="il-input h-9 text-sm pl-8 pr-3 w-52" />
          </div>
          <button onClick={load} className="text-muted hover:text-ink p-2 rounded-lg hover:bg-gray-50 transition-colors"><RefreshCw className="w-4 h-4" /></button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12"><Loader2 className="w-6 h-6 animate-spin" style={{ color: "#1E3A8A" }} /></div>
      ) : filtered.length === 0 ? (
        <div className="py-12 text-center text-muted">{items.length === 0 ? "등록된 대상이 없습니다. 새 스캔을 실행하면 대상이 등록됩니다." : "조건에 맞는 대상이 없습니다."}</div>
      ) : (
        <div className="divide-y divide-hairline">
          {filtered.map((it) => (
            <div key={it.id}>
              <div className="flex items-center hover:bg-gray-50 transition-colors">
                <button onClick={() => setExpanded(expanded === it.id ? null : it.id)} className="flex-1 text-left px-5 py-4 flex items-center gap-3 min-w-0">
                  <ChevronRight className={`w-4 h-4 text-muted flex-shrink-0 transition-transform ${expanded === it.id ? "rotate-90" : ""}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium text-ink font-mono truncate">{it.domain}</span>
                      {it.last_risk && <span className={`text-xs font-semibold ${RISK_COLOR[it.last_risk]}`}>{it.last_risk}</span>}
                    </div>
                    {/* 저장된 스캔 설정 요약 */}
                    <div className="text-xs text-muted mt-0.5 flex items-center gap-3 flex-wrap">
                      <span className="flex items-center gap-1"><CalendarClock className="w-3 h-3" />{scheduleText(it)}</span>
                      {Number(it.time_budget_minutes) > 0 && <span className="flex items-center gap-1"><Clock className="w-3 h-3" />최대 {fmtDur(it.time_budget_minutes)}</span>}
                      {Array.isArray(it.exclude_urls) && it.exclude_urls.length > 0 && <span className="flex items-center gap-1"><Ban className="w-3 h-3" />제외 {it.exclude_urls.length}</span>}
                      {it.login_url && <span className="flex items-center gap-1"><KeyRound className="w-3 h-3" />로그인 {it.login_username ? `(${it.login_username})` : ""}</span>}
                      <span>· 스캔 {it.scan_count ?? 0}회{it.last_scan && ` · 최근 ${it.last_scan}`}</span>
                    </div>
                  </div>
                </button>
                <div className="flex items-center gap-1 pr-4">
                  <button onClick={(e) => startEdit(e, it)} title="편집"
                    className="p-1.5 rounded-lg text-muted hover:text-primary hover:bg-primary-50 transition-colors"><Pencil className="w-4 h-4" /></button>
                  <button onClick={(e) => { e.stopPropagation(); onScanDomain?.(it.domain, "", it.login_username ? { login_url: it.login_url || "", username: it.login_username } : undefined); }} title="지금 스캔"
                    className="p-1.5 rounded-lg text-muted hover:text-primary hover:bg-primary-50 transition-colors"><ScanSearch className="w-4 h-4" /></button>
                  <button onClick={(e) => removeItem(e, it.id)} disabled={busyId === it.id} title="삭제"
                    className="p-1.5 rounded-lg text-muted hover:text-red-600 hover:bg-red-50 transition-colors disabled:opacity-50">
                    {busyId === it.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                  </button>
                </div>
              </div>
              {expanded === it.id && editingId !== it.id && <TargetConfig item={it} />}
              {editingId === it.id && form && (
                <div className="bg-gray-50 px-5 py-4 space-y-3 border-t border-hairline">
                  <div className="text-xs font-semibold text-muted">대상 설정 편집</div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <label className="flex items-center gap-2 text-sm text-ink sm:col-span-2">
                      <input type="checkbox" checked={form.enabled} onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))} className="w-4 h-4" />
                      자동(정기) 점검 활성화
                    </label>
                    <div>
                      <div className="text-xs text-muted mb-1">점검 주기(개월) — 0이면 수동</div>
                      <input type="number" min="0" max="60" value={form.scan_months}
                        onChange={(e) => setForm((f) => ({ ...f, scan_months: e.target.value }))}
                        className="il-input h-9 text-sm px-3 w-full" />
                    </div>
                    <div>
                      <div className="text-xs text-muted mb-1">점검 일자(1~31)</div>
                      <input type="number" min="1" max="31" value={form.scan_day}
                        onChange={(e) => setForm((f) => ({ ...f, scan_day: e.target.value }))}
                        className="il-input h-9 text-sm px-3 w-full" />
                    </div>
                    <div>
                      <div className="text-xs text-muted mb-1">점검 시각(HH:MM)</div>
                      <input type="time" value={form.scan_time}
                        onChange={(e) => setForm((f) => ({ ...f, scan_time: e.target.value }))}
                        className="il-input h-9 text-sm px-3 w-full" />
                    </div>
                    <div className="sm:col-span-2">
                      <div className="text-xs text-muted mb-1">메모</div>
                      <textarea rows={2} value={form.notes}
                        onChange={(e) => setForm((f) => ({ ...f, notes: e.target.value }))}
                        className="il-input text-sm px-3 py-2 w-full" placeholder="대상 관련 메모" />
                    </div>
                  </div>
                  <div className="flex items-center gap-2 pt-1">
                    <button onClick={() => saveEdit(it)} disabled={saving}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm bg-primary text-white hover:bg-primary/90 transition-colors disabled:opacity-50">
                      {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}저장
                    </button>
                    <button onClick={cancelEdit} disabled={saving}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm text-muted hover:text-ink hover:bg-gray-100 transition-colors disabled:opacity-50">
                      <X className="w-4 h-4" />취소
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
