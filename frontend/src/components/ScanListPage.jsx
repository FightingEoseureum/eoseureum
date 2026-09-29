import { useEffect, useState, useMemo, useRef } from "react";
import {
  Clock, ChevronRight, ChevronDown, Loader2, RefreshCw, Search,
  ShieldAlert, ShieldCheck, Trash2, ScanSearch, FileDown, Check,
  PlayCircle, ArrowDownWideNarrow, ArrowUpWideNarrow, CheckSquare, Square,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { RISK_COLOR } from "../utils/risk";
import { statusBadge, effectiveStatus } from "../utils/status";
import { downloadBlob } from "../utils/download";

const SEVERITY_OPTS = [
  { id: "all", label: "전체" }, { id: "HIGH", label: "높음" },
  { id: "MEDIUM", label: "중간" }, { id: "LOW", label: "낮음" }, { id: "GOOD", label: "양호" },
];
const STATUS_OPTS = [
  { id: "all", label: "전체" }, { id: "complete", label: "완료" },
  { id: "running", label: "진행 중" }, { id: "failed", label: "실패·중단" },
];
const FAILED_SET = new Set(["failed", "stopped", "interrupted"]);
const RECOVER_SET = new Set(["failed", "stopped", "interrupted"]);
const PAGE_SIZE = 20;

function Dropdown({ label, value, options, onChange }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return;
    const onDoc = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);
  const cur = options.find((o) => o.id === value) || options[0];
  return (
    <div className="flex items-center gap-2">
      <span className="text-ink font-bold">{label}</span>
      <div className="relative" ref={ref}>
        <button onClick={() => setOpen((v) => !v)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-hairline bg-white hover:bg-gray-50 text-ink transition-colors min-w-[84px] justify-between">
          <span>{cur.label}</span>
          <ChevronDown className={`w-3.5 h-3.5 text-muted transition-transform ${open ? "rotate-180" : ""}`} />
        </button>
        {open && (
          <div className="absolute z-20 mt-1 left-0 min-w-[120px] bg-white border border-hairline rounded-lg shadow-lg py-1">
            {options.map((o) => (
              <button key={o.id} onClick={() => { onChange(o.id); setOpen(false); }}
                className={`w-full flex items-center justify-between gap-2 px-3 py-1.5 text-xs text-left hover:bg-gray-50 transition-colors ${o.id === value ? "text-primary-700 font-semibold" : "text-ink"}`}>
                {o.label}{o.id === value && <Check className="w-3.5 h-3.5 text-primary" />}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default function ScanListPage({ onScan, onBatchScan, onOpenScan, onViewChange }) {
  const { apiFetch, auth } = useAuth();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [pdfAvailable, setPdfAvailable] = useState(false);
  const [busy, setBusy] = useState(null);   // "delete" | "download" | "recover"

  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const [sort, setSort] = useState("new");
  const [visible, setVisible] = useState(PAGE_SIZE);

  const [picked, setPicked] = useState(() => new Set());
  const [batchFormat, setBatchFormat] = useState("docx");

  const fetchHistory = async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const res = await apiFetch("/api/scans");
      if (!res.ok) return;
      const data = await res.json();
      setScans(Array.isArray(data) ? data : []);
    } finally { if (!quiet) setLoading(false); }
  };

  useEffect(() => {
    fetchHistory();
    apiFetch("/api/report/pdf-available").then(async (r) => { if (r.ok) setPdfAvailable(!!(await r.json()).pdf_available); }).catch(() => {});
  }, []);

  const hasRunning = scans.some((s) => s.status === "running" || s.status === "queued");
  useEffect(() => {
    if (!hasRunning) return;
    const t = setInterval(() => fetchHistory(true), 3000);
    return () => clearInterval(t);
  }, [hasRunning]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    let list = scans.filter((s) => {
      if (q && !(s.domain || "").toLowerCase().includes(q)) return false;
      if (severity !== "all" && (s.overall_risk || "") !== severity) return false;
      if (status !== "all") {
        if (status === "failed") { if (!FAILED_SET.has(s.status)) return false; }
        else if (status === "running") { if (s.status !== "running" && s.status !== "queued") return false; }
        else if (s.status !== status) return false;
      }
      return true;
    });
    return [...list].sort((a, b) => {
      const c = String(a.created_at || "").localeCompare(String(b.created_at || ""));
      return sort === "new" ? -c : c;
    });
  }, [scans, search, severity, status, sort]);

  useEffect(() => { setVisible(PAGE_SIZE); }, [search, severity, status, sort]);

  // 필터·검색으로 목록에서 사라진 항목은 선택에서 제거(현재 필터 목록 기준으로 정리)
  useEffect(() => {
    setPicked((prev) => {
      if (prev.size === 0) return prev;
      const ids = new Set(filtered.map((s) => s.scan_id));
      const next = new Set();
      let changed = false;
      prev.forEach((id) => { if (ids.has(id)) next.add(id); else changed = true; });
      return changed ? next : prev;
    });
  }, [filtered]);

  const shown = filtered.slice(0, visible);
  const sentinelRef = useRef(null);
  useEffect(() => {
    if (visible >= filtered.length) return;
    const el = sentinelRef.current;
    if (!el) return;
    const io = new IntersectionObserver((entries) => {
      if (entries[0].isIntersecting) setVisible((v) => Math.min(v + PAGE_SIZE, filtered.length));
    }, { rootMargin: "200px" });
    io.observe(el);
    return () => io.disconnect();
  }, [visible, filtered.length]);

  const downloadable = (s) => (s.status === "complete" || s.status === "stopped") && s.overall_risk;
  const byId = useMemo(() => new Map(scans.map((s) => [s.scan_id, s])), [scans]);
  const pickedScans = [...picked].map((id) => byId.get(id)).filter(Boolean);

  const togglePick = (e, id) => {
    e.stopPropagation();
    setPicked((prev) => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  };
  const allShownPicked = shown.length > 0 && shown.every((s) => picked.has(s.scan_id));
  const toggleAllShown = () => {
    setPicked((prev) => {
      const n = new Set(prev);
      if (allShownPicked) shown.forEach((s) => n.delete(s.scan_id));
      else shown.forEach((s) => n.add(s.scan_id));
      return n;
    });
  };

  // ── 상단 일괄 액션 ──────────────────────────────────────────────────────────
  const bulkDelete = async () => {
    if (pickedScans.length === 0) return;
    if (!window.confirm(`${pickedScans.length}개 스캔 이력을 삭제하시겠습니까?`)) return;
    setBusy("delete");
    try {
      for (const s of pickedScans) await apiFetch(`/api/scans/${s.scan_id}`, { method: "DELETE" });
      setScans((prev) => prev.filter((s) => !picked.has(s.scan_id)));
      setPicked(new Set());
    } finally { setBusy(null); }
  };
  const bulkDownload = async () => {
    const targets = pickedScans.filter(downloadable);
    if (targets.length === 0) { alert("선택 항목 중 보고서를 받을 수 있는 완료 스캔이 없습니다."); return; }
    setBusy("download");
    try {
      for (const s of targets) {
        const params = new URLSearchParams();
        if (batchFormat !== "docx") params.set("format", batchFormat);
        const res = await apiFetch(`/api/scans/${s.scan_id}/export?${params.toString()}`);
        if (!res.ok) continue;
        const served = res.headers.get("X-Report-Format");
        const ext = (batchFormat === "pdf" && served === "docx-fallback") ? "docx" : batchFormat;
        const dom = (s.domain || "report").replace(/[^\w.-]/g, "_");
        downloadBlob(await res.blob(), `security_report_${dom}_${(s.created_at || "").slice(0, 10)}.${ext}`);
        await new Promise((r) => setTimeout(r, 300));
      }
    } finally { setBusy(null); }
  };
  const bulkRescan = () => {
    const doms = [...new Set(pickedScans.map((s) => s.domain).filter(Boolean))];
    if (doms.length === 0) return;
    setPicked(new Set());
    if (doms.length === 1) { onScan?.(doms[0]); onViewChange?.("scanner"); }
    else if (onBatchScan) { onBatchScan(doms); onViewChange?.("batch"); }
  };
  const bulkRecover = async () => {
    const targets = pickedScans.filter((s) => RECOVER_SET.has(s.status));
    if (targets.length === 0) { alert("선택 항목 중 재진행 가능한 중단 스캔이 없습니다."); return; }
    setBusy("recover");
    try {
      for (const s of targets) await apiFetch(`/api/scans/${s.scan_id}/recover`, { method: "POST" });
      setPicked(new Set());
      fetchHistory(true);
    } finally { setBusy(null); }
  };

  const nDownload = pickedScans.filter(downloadable).length;
  const nRecover = pickedScans.filter((s) => RECOVER_SET.has(s.status)).length;

  return (
    <div className="il-card overflow-hidden">
      <div className="px-5 py-4 border-b border-hairline space-y-3">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <Clock className="w-5 h-5 text-muted" />
            <h2 className="font-semibold text-ink">스캔 목록</h2>
            <span className="text-xs text-muted">({filtered.length}건{auth.user.role === "admin" ? " · 전체 이력" : ""})</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="w-4 h-4 text-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="이름·URL 검색" className="il-input h-9 text-sm pl-8 pr-3 w-56" />
            </div>
            <button onClick={() => fetchHistory()} className="text-muted hover:text-ink p-2 rounded-lg hover:bg-gray-50 transition-colors"><RefreshCw className="w-4 h-4" /></button>
          </div>
        </div>

        <div className="flex items-center gap-5 flex-wrap text-xs">
          <Dropdown label="심각도" value={severity} options={SEVERITY_OPTS} onChange={setSeverity} />
          <Dropdown label="상태" value={status} options={STATUS_OPTS} onChange={setStatus} />
          <div className="flex items-center gap-2 ml-auto">
            <button onClick={() => setSort("new")} className={`flex items-center gap-1 px-3 py-1.5 rounded-lg font-medium transition-colors ${sort === "new" ? "bg-primary-50 text-primary-700 border border-primary-200" : "text-muted hover:text-ink border border-transparent hover:bg-gray-50"}`}>
              <ArrowDownWideNarrow className="w-3.5 h-3.5" />최신순
            </button>
            <button onClick={() => setSort("old")} className={`flex items-center gap-1 px-3 py-1.5 rounded-lg font-medium transition-colors ${sort === "old" ? "bg-primary-50 text-primary-700 border border-primary-200" : "text-muted hover:text-ink border border-transparent hover:bg-gray-50"}`}>
              <ArrowUpWideNarrow className="w-3.5 h-3.5" />오래된순
            </button>
          </div>
        </div>

        {/* 선택 기반 상단 일괄 액션 툴바 */}
        {picked.size > 0 && (
          <div className="flex items-center gap-2 flex-wrap bg-primary-50 border border-primary-200 rounded-lg px-3 py-2">
            <span className="text-xs font-semibold text-primary-700 mr-1">{picked.size}개 선택됨</span>
            <button onClick={bulkRescan} disabled={!!busy}
              className="inline-flex items-center gap-1.5 text-xs text-ink bg-white hover:bg-gray-50 border border-hairline rounded-lg px-2.5 py-1.5 transition-colors disabled:opacity-50">
              <ScanSearch className="w-3.5 h-3.5" />재스캔
            </button>
            <button onClick={bulkRecover} disabled={!!busy || nRecover === 0} title={nRecover === 0 ? "재진행 가능한 중단 스캔 없음" : ""}
              className="inline-flex items-center gap-1.5 text-xs text-ink bg-white hover:bg-gray-50 border border-hairline rounded-lg px-2.5 py-1.5 transition-colors disabled:opacity-50">
              {busy === "recover" ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <PlayCircle className="w-3.5 h-3.5" />}재진행 {nRecover > 0 && `(${nRecover})`}
            </button>
            <div className="inline-flex items-center gap-1.5">
              <select value={batchFormat} onChange={(e) => setBatchFormat(e.target.value)} className="il-input h-7 text-xs py-0 pl-2 pr-6">
                <option value="docx">DOCX</option><option value="html">HTML</option>{pdfAvailable && <option value="pdf">PDF</option>}
              </select>
              <button onClick={bulkDownload} disabled={!!busy || nDownload === 0} title={nDownload === 0 ? "완료 스캔 없음" : ""}
                className="inline-flex items-center gap-1.5 text-xs text-green-700 bg-green-50 hover:bg-green-100 border border-green-200 rounded-lg px-2.5 py-1.5 transition-colors disabled:opacity-50">
                {busy === "download" ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileDown className="w-3.5 h-3.5" />}보고서 {nDownload > 0 && `(${nDownload})`}
              </button>
            </div>
            <button onClick={bulkDelete} disabled={!!busy}
              className="inline-flex items-center gap-1.5 text-xs text-red-600 bg-red-50 hover:bg-red-100 border border-red-200 rounded-lg px-2.5 py-1.5 transition-colors disabled:opacity-50">
              {busy === "delete" ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}삭제
            </button>
            <button onClick={() => setPicked(new Set())} className="text-xs text-muted hover:text-ink ml-auto">선택 해제</button>
          </div>
        )}
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12"><Loader2 className="w-6 h-6 animate-spin" style={{ color: "#1E3A8A" }} /></div>
      ) : filtered.length === 0 ? (
        <div className="py-12 text-center text-muted">{scans.length === 0 ? "스캔 이력이 없습니다." : "조건에 맞는 스캔이 없습니다."}</div>
      ) : (
        <>
          {/* 전체 선택 헤더 */}
          <div className="flex items-center gap-2 px-5 py-2 border-b border-hairline bg-gray-50">
            <button onClick={toggleAllShown} className="text-muted hover:text-primary">
              {allShownPicked ? <CheckSquare className="w-4 h-4 text-primary" /> : <Square className="w-4 h-4" />}
            </button>
            <span className="text-xs text-muted">현재 목록 전체 선택</span>
          </div>

          <div className="divide-y divide-hairline">
            {shown.map((scan) => (
              <div key={scan.scan_id}>
                <div className="flex items-center hover:bg-gray-50 transition-colors">
                  <button onClick={(e) => togglePick(e, scan.scan_id)} title="선택"
                    className="pl-5 pr-1 py-4 text-muted hover:text-primary">
                    {picked.has(scan.scan_id) ? <CheckSquare className="w-4 h-4 text-primary" /> : <Square className="w-4 h-4" />}
                  </button>
                  <button onClick={() => onOpenScan?.(scan.scan_id)} className="flex-1 text-left pl-1 pr-5 py-4 flex items-center gap-3 min-w-0">
                    {scan.overall_risk ? (
                      scan.overall_risk === "GOOD" || scan.overall_risk === "LOW"
                        ? <ShieldCheck className="w-5 h-5 text-green-600 flex-shrink-0" />
                        : <ShieldAlert className="w-5 h-5 text-red-600 flex-shrink-0" />
                    ) : <Clock className="w-5 h-5 text-muted flex-shrink-0" />}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        {typeof scan.seq === "number" && <span className="text-xs font-bold text-muted font-mono">#{scan.seq}</span>}
                        <span className="font-medium text-ink font-mono truncate">{scan.domain}</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full ${statusBadge(effectiveStatus(scan)).cls}`}>{statusBadge(effectiveStatus(scan)).label}</span>
                        {scan.overall_risk && <span className={`text-xs font-semibold ${RISK_COLOR[scan.overall_risk]}`}>{scan.overall_risk}</span>}
                      </div>
                      <div className="text-xs text-muted mt-0.5 flex items-center gap-2 flex-wrap">
                        <span>{scan.created_at}</span>
                        {auth.user.role === "admin" && scan.username && <span className="text-muted">· {scan.username}</span>}
                        {scan.status === "complete" && typeof scan.vulnerability_count === "number" && (
                          <span className="text-muted">· 취약점 <b className="text-red-600">{scan.vulnerability_count}</b>
                            {typeof scan.attack_surface_count === "number" && <> · 공격표면 <b className="text-primary">{scan.attack_surface_count}</b></>}
                          </span>
                        )}
                      </div>
                    </div>
                    <ChevronRight className="w-4 h-4 text-muted flex-shrink-0" />
                  </button>
                </div>

                {/* 진행도(단계·%)는 '진행 현황' 페이지에서 확인 → 목록에선 상태 배지만 표기 */}
              </div>
            ))}
          </div>
          {visible < filtered.length && (
            <div ref={sentinelRef} className="flex items-center justify-center py-4 text-xs text-muted">
              <Loader2 className="w-4 h-4 animate-spin mr-2" />더 불러오는 중… ({shown.length}/{filtered.length})
            </div>
          )}
        </>
      )}
    </div>
  );
}
