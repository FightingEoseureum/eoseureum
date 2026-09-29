import { useEffect, useState, useMemo } from "react";
import {
  ArrowLeft, Loader2, ShieldAlert, ShieldCheck, FileDown, Crosshair,
  LayoutDashboard, Bug, Link2, GitBranch, Info, ScanSearch, Terminal,
  Layers, Network, Eye, EyeOff, CheckSquare, Square, FileText, Download,
  GitCompare, Plus, Minus, Equal, Trash2,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { deriveContract } from "../utils/contract";
import { isVuln } from "../utils/findings";
import { RISK_COLOR, severityBadgeClass } from "../utils/risk";
import { downloadBlob } from "../utils/download";
import FindingCard from "./findings/FindingCard";
import AttackSurfaceCard from "./findings/AttackSurfaceCard";
import DiscoveryCard from "./findings/DiscoveryCard";
import OverallRisk from "./results/OverallRisk";
import AIAnalysisPanel from "./results/AIAnalysisPanel";
import ScanDiff from "./ScanDiff";

const DETAIL_TABS = [
  { id: "overview",  label: "개요",       icon: LayoutDashboard },
  { id: "vulns",     label: "취약점",     icon: Bug },
  { id: "endpoints", label: "엔드포인트", icon: Link2 },
  { id: "threats",   label: "위협 시나리오", icon: GitBranch },
  { id: "compare",   label: "이전 대비",  icon: GitCompare },
  { id: "info",      label: "스캔 정보",  icon: Info },
  { id: "report",    label: "보고서 다운로드", icon: FileDown },
];

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_LABEL = { CRITICAL: "심각", HIGH: "높음", MEDIUM: "중간", LOW: "낮음", INFO: "정보" };
const sevKey = (f) => String(f?.report_severity || f?.severity || "").toUpperCase() || "LOW";

// ── 엔드포인트 집계(메서드·파라미터·연결 취약점 포함) ────────────────────────────────
function collectEndpoints(analysis) {
  const seen = new Map();
  const norm = (u) => (typeof u === "string" ? u : "");
  const ensure = (url) => {
    if (!seen.has(url)) seen.set(url, { url, sources: new Set(), methods: new Set(), params: new Set(), vulns: new Set() });
    return seen.get(url);
  };
  (analysis?.attack_surface_items || []).forEach((it) => {
    const url = norm(it.url || it.endpoint || it.path);
    if (!url) return;
    const e = ensure(url); e.sources.add("공격표면");
    if (it.method) e.methods.add(it.method);
    (it.params ? Object.keys(it.params) : []).forEach((p) => e.params.add(p));
    if (it.param) e.params.add(it.param);
  });
  (analysis?.findings || []).forEach((f) => {
    const urls = [...(f.affected_endpoints || []), ...(f.url ? [f.url] : [])].map(norm).filter(Boolean);
    urls.forEach((url) => {
      const e = ensure(url); e.sources.add("취약점");
      if (f.method) e.methods.add(f.method);
      if (f.param) e.params.add(f.param);
      if (f.title) e.vulns.add(f.title);
    });
  });
  (analysis?.discovery_items || []).forEach((it) => {
    const url = norm(it.url || it.endpoint);
    if (url) ensure(url).sources.add("참고발견");
  });
  return [...seen.values()].map((e) => ({
    url: e.url, sources: [...e.sources], methods: [...e.methods], params: [...e.params], vulns: [...e.vulns],
  }));
}

function findingKey(f) {
  return `${(f.title || "").trim()}|${f.cwe || ""}|${(f.url || (f.affected_endpoints || [])[0] || "")}`;
}

export default function ScanDetailPage({ scanId, initialTab = "overview", onTabChange, onBack, onScan, onOpenScan, onViewChange }) {
  const { apiFetch } = useAuth();
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState(initialTab);
  const [showGood, setShowGood] = useState(false);

  const [templates, setTemplates] = useState([]);
  const [templateId, setTemplateId] = useState("");
  const [pdfAvailable, setPdfAvailable] = useState(false);
  const [selected, setSelected] = useState(null);   // Set<rawIndex> | null(=전체)
  const [downloading, setDownloading] = useState(null);
  const [filename, setFilename] = useState("");

  // 이전 스캔 비교
  const [cmp, setCmp] = useState(null);         // {prev, diff} | "none"
  const [cmpLoading, setCmpLoading] = useState(false);
  const [showDiff, setShowDiff] = useState(false);   // 상세 비교 모달

  useEffect(() => { setTab(initialTab); }, [initialTab, scanId]);
  const changeTab = (id) => { setTab(id); onTabChange?.(id); };

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    setCmp(null);
    apiFetch(`/api/scans/${scanId}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => setDetail(d))
      .catch(() => setDetail(null))
      .finally(() => setLoading(false));
    apiFetch("/api/templates").then(async (tr) => {
      if (!tr.ok) return;
      const t = (await tr.json()).items || [];
      setTemplates(t);
      const def = t.find((x) => x.is_default === 1);
      setTemplateId(def ? String(def.id) : "");
    }).catch(() => {});
    apiFetch("/api/report/pdf-available").then(async (pr) => {
      if (pr.ok) setPdfAvailable(!!(await pr.json()).pdf_available);
    }).catch(() => {});
  }, [scanId]);

  const analysis = detail?.analysis;
  const contract = useMemo(() => (analysis ? deriveContract(analysis) : null), [analysis]);
  // 삭제요청: 상태변경형 실증의 자동 원복 실패 산출물({경로,작성내용,방법}). 있을 때만 '스캔 정보'
  // 탭 오른쪽에 '삭제요청' 탭을 노출한다(info=index 5 뒤에 삽입).
  const deletionRequests = (analysis && analysis.deletion_requests) || [];
  const detailTabs = deletionRequests.length
    ? [...DETAIL_TABS.slice(0, 6), { id: "cleanup", label: "삭제요청", icon: Trash2 }, ...DETAIL_TABS.slice(6)]
    : DETAIL_TABS;
  const endpoints = useMemo(() => (analysis ? collectEndpoints(analysis) : []), [analysis]);
  const sevCounts = useMemo(() => {
    const m = {};
    (contract?.vulns || []).forEach((f) => { const k = sevKey(f); m[k] = (m[k] || 0) + 1; });
    return m;
  }, [contract]);
  const selectable = useMemo(() => {
    const raw = Array.isArray(analysis?.findings) ? analysis.findings : [];
    return raw.map((f, i) => ({ f, i })).filter(({ f }) => isVuln(f));
  }, [analysis]);
  const pocScripts = selectable.filter(({ f }) => typeof f.poc === "string" && f.poc.trim());

  // 기본 파일명 초기화
  useEffect(() => {
    if (!detail) return;
    const dom = (detail.domain || "report").replace(/[^\w.-]/g, "_");
    setFilename(`security_report_${dom}_${(detail.created_at || "").slice(0, 10)}`);
  }, [detail]);

  const isSel = (i) => (selected === null ? true : selected.has(i));
  const toggleSel = (i) => {
    setSelected((prev) => {
      const base = prev === null ? new Set(selectable.map((s) => s.i)) : new Set(prev);
      base.has(i) ? base.delete(i) : base.add(i);
      return base;
    });
  };
  const selCount = selected === null ? selectable.length : selected.size;

  const download = async (format) => {
    setDownloading(format);
    try {
      const params = new URLSearchParams();
      if (templateId) params.set("template_id", templateId);
      if (format !== "docx") params.set("format", format);
      if (selected !== null && selected.size < selectable.length) params.set("include", [...selected].join(","));
      const res = await apiFetch(`/api/scans/${scanId}/export?${params.toString()}`);
      if (!res.ok) { alert("내보내기 실패: 분석 결과가 없거나 권한이 없습니다."); return; }
      const served = res.headers.get("X-Report-Format");
      let ext = format;
      if (format === "pdf" && served === "docx-fallback") { ext = "docx"; alert("PDF 변환 도구가 없어 DOCX로 다운로드합니다."); }
      const base = (filename || "security_report").replace(/[^\w.-]/g, "_");
      downloadBlob(await res.blob(), `${base}.${ext}`);
    } finally { setDownloading(null); }
  };

  const downloadPocBundle = () => {
    const chosen = pocScripts.filter(({ i }) => isSel(i));
    if (chosen.length === 0) { alert("선택된 취약점 중 PoC 스크립트가 없습니다."); return; }
    const body = chosen.map(({ f }) => `# ── ${f.title || "finding"} ${f.cwe ? `(${f.cwe})` : ""} ──\n${f.poc}\n`).join("\n");
    const base = (filename || "poc").replace(/[^\w.-]/g, "_");
    downloadBlob(new Blob([body], { type: "text/x-python" }), `${base}_poc.py`);
  };

  // 이전 스캔(같은 도메인, 더 이른 시각) 비교
  const loadCompare = async () => {
    if (cmp || cmpLoading || !detail) return;
    setCmpLoading(true);
    try {
      const lr = await apiFetch("/api/scans");
      const list = lr.ok ? await lr.json() : [];
      const prevMeta = (Array.isArray(list) ? list : [])
        .filter((s) => s.domain === detail.domain && s.scan_id !== detail.scan_id
          && String(s.created_at || "") < String(detail.created_at || "") && s.overall_risk)
        .sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))[0];
      if (!prevMeta) { setCmp("none"); return; }
      const pr = await apiFetch(`/api/scans/${prevMeta.scan_id}`);
      const prev = pr.ok ? await pr.json() : null;
      if (!prev?.analysis) { setCmp("none"); return; }
      const curV = (contract?.vulns || []);
      const prevV = (deriveContract(prev.analysis).vulns || []);
      const curKeys = new Map(curV.map((f) => [findingKey(f), f]));
      const prevKeys = new Map(prevV.map((f) => [findingKey(f), f]));
      const added = curV.filter((f) => !prevKeys.has(findingKey(f)));
      const resolved = prevV.filter((f) => !curKeys.has(findingKey(f)));
      const persisting = curV.filter((f) => prevKeys.has(findingKey(f)));
      setCmp({ prev: { ...prevMeta, seq: prev.seq }, added, resolved, persisting });
    } catch { setCmp("none"); }
    finally { setCmpLoading(false); }
  };
  useEffect(() => { if (tab === "compare") loadCompare(); }, [tab, detail]);   // eslint-disable-line

  if (loading) return <div className="flex items-center justify-center py-24"><Loader2 className="w-8 h-8 animate-spin" style={{ color: "#1E3A8A" }} /></div>;
  if (!detail) {
    return (
      <div className="il-card p-8 text-center space-y-3">
        <p className="text-muted text-sm">스캔을 불러올 수 없습니다.</p>
        <button onClick={onBack} className="text-sm hover:underline" style={{ color: "#1E3A8A" }}>← 목록으로</button>
      </div>
    );
  }

  const risk = analysis?.overall_risk;

  return (
    <div className="space-y-4">
      {/* 헤더 (중립 톤) */}
      <div className="il-card border border-hairline rounded-xl p-4 flex items-center gap-3 flex-wrap">
        <button onClick={onBack} className="p-2 rounded-lg text-muted hover:text-ink hover:bg-gray-50 transition-colors"><ArrowLeft className="w-5 h-5" /></button>
        {risk && (risk === "GOOD" || risk === "LOW") ? <ShieldCheck className="w-5 h-5 text-muted" /> : <ShieldAlert className="w-5 h-5 text-muted" />}
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            {typeof detail.seq === "number" && <span className="text-sm font-bold text-muted font-mono">#{detail.seq}</span>}
            <span className="font-semibold text-ink font-mono truncate">{detail.domain}</span>
            {risk && <span className={`text-sm font-bold ${RISK_COLOR[risk]}`}>{risk}</span>}
          </div>
          <div className="text-xs text-muted mt-0.5">{detail.created_at} · {detail.status}</div>
        </div>
        <button onClick={() => { onScan?.(detail.domain); onViewChange?.("scanner"); }}
          className="ml-auto flex items-center gap-1.5 text-sm text-muted hover:text-primary border border-hairline hover:border-primary-200 bg-white rounded-lg px-3 py-1.5 transition-colors">
          <ScanSearch className="w-4 h-4" />재스캔
        </button>
      </div>

      <div className="bg-white border border-hairline rounded-xl overflow-hidden">
        <div className="flex border-b border-hairline overflow-x-auto">
          {detailTabs.map((t) => {
            const Icon = t.icon;
            return (
              <button key={t.id} onClick={() => changeTab(t.id)}
                className={`flex items-center gap-2 px-5 py-3 text-sm font-medium whitespace-nowrap transition-colors ${tab === t.id ? "text-brand-400 border-b-2 border-brand-500 bg-gray-50" : "text-muted hover:text-ink"}`}>
                <Icon className="w-4 h-4" />{t.label}
              </button>
            );
          })}
        </div>

        <div className="p-5">
          {!analysis ? (
            <p className="text-muted text-sm py-6 text-center">분석 결과가 없습니다.</p>
          ) : (
            <>
              {/* 개요 */}
              {tab === "overview" && (
                <div className="space-y-4">
                  <OverallRisk risk={analysis.overall_risk} summary={analysis.overall_summary}
                    exploitSummary={analysis.exploit_summary} attackChain={analysis.attack_chain} />

                  {/* 심각도별 개수 */}
                  {contract.vulnerabilityCount > 0 && (
                    <div className="border border-hairline rounded-lg p-3">
                      <div className="text-xs font-semibold text-muted mb-2">심각도별 취약점</div>
                      <div className="flex items-center gap-2 flex-wrap">
                        {SEV_ORDER.filter((k) => sevCounts[k]).map((k) => (
                          <span key={k} className={`text-xs px-2.5 py-1 font-semibold ${severityBadgeClass(k)}`}>
                            {SEV_LABEL[k]} {sevCounts[k]}
                          </span>
                        ))}
                        {SEV_ORDER.every((k) => !sevCounts[k]) && <span className="text-xs text-muted">등급 정보 없음</span>}
                      </div>
                    </div>
                  )}

                  {analysis.ai_analysis && <AIAnalysisPanel aiAnalysis={analysis.ai_analysis} />}
                  <div className="flex items-center gap-3 flex-wrap">
                    {[
                      { v: contract.vulnerabilityCount, l: "취약 항목" },
                      { v: contract.attackSurfaceCount, l: "공격 표면" },
                      { v: contract.goodCount, l: "양호 항목" },
                      { v: contract.discoveryCount, l: "참고 발견" },
                      ...(typeof contract.checkedPorts === "number" ? [{ v: contract.checkedPorts, l: "점검 포트" }] : []),
                    ].map((s, i) => (
                      <div key={i} className="border border-hairline rounded-lg px-4 py-2 text-center">
                        <div className="text-xl font-bold text-ink">{s.v}</div>
                        <div className="text-xs text-muted">{s.l}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* 취약점 */}
              {tab === "vulns" && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <span className="text-sm font-semibold text-ink">
                      취약점 <span className="text-[#DC2626]">{contract.vulnerabilityCount}</span>건
                      {contract.serviceVulns.length > 0 && <span className="text-xs text-muted font-normal ml-2">(웹 {contract.webVulnerabilityCount} · 서비스 {contract.serviceVulnerabilityCount})</span>}
                    </span>
                    {contract.goodCount > 0 && (
                      <button onClick={() => setShowGood((v) => !v)} className="flex items-center gap-1.5 text-xs text-muted hover:text-ink border border-hairline rounded-lg px-2.5 py-1.5 transition-colors">
                        {showGood ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}{showGood ? "양호 항목 숨기기" : `양호 항목 보기 (${contract.goodCount})`}
                      </button>
                    )}
                  </div>
                  {contract.webVulns.length > 0 ? contract.webVulns.map((f, i) => <FindingCard key={`w-${i}`} finding={f} scanId={scanId} />) : <p className="text-muted text-sm py-2">발견된 웹 취약점이 없습니다.</p>}
                  {contract.serviceVulns.length > 0 && (
                    <div className="pt-2 space-y-2">
                      <div className="flex items-center gap-2 text-sm font-semibold text-ink"><Network className="w-4 h-4 text-[#1E3A8A]" />서비스/포트 취약점 ({contract.serviceVulnerabilityCount})</div>
                      {contract.serviceVulns.map((f, i) => <FindingCard key={`s-${i}`} finding={f} scanId={scanId} />)}
                    </div>
                  )}
                  {showGood && contract.good.map((f, i) => <FindingCard key={`g-${i}`} finding={f} scanId={scanId} />)}
                  {contract.attackSurfaceCount > 0 && (
                    <div className="pt-2 space-y-2">
                      <div className="flex items-center gap-2 text-sm font-semibold text-ink"><Layers className="w-4 h-4 text-[#1E3A8A]" />공격 표면 ({contract.attackSurfaceCount})</div>
                      {contract.attackSurface.map((it, i) => <AttackSurfaceCard key={i} item={it} />)}
                    </div>
                  )}
                  {contract.discoveryCount > 0 && (
                    <div className="pt-2 space-y-2">
                      <div className="flex items-center gap-2 text-sm font-semibold text-ink"><Info className="w-4 h-4 text-muted" />참고 발견 ({contract.discoveryCount})</div>
                      {contract.discovery.map((it, i) => <DiscoveryCard key={i} item={it} />)}
                    </div>
                  )}
                </div>
              )}

              {/* 엔드포인트 */}
              {tab === "endpoints" && (
                endpoints.length === 0 ? <p className="text-muted text-sm py-6 text-center">수집된 엔드포인트가 없습니다.</p> : (
                  <div className="overflow-x-auto">
                    <div className="text-xs text-muted mb-2">공격 표면·취약점·참고 발견에서 집계한 엔드포인트 {endpoints.length}개</div>
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left text-xs text-muted border-b border-hairline">
                          <th className="py-2 pr-3 font-semibold">엔드포인트</th>
                          <th className="py-2 pr-3 font-semibold">메서드</th>
                          <th className="py-2 pr-3 font-semibold">파라미터</th>
                          <th className="py-2 pr-3 font-semibold">출처</th>
                          <th className="py-2 pr-3 font-semibold">연결 취약점</th>
                        </tr>
                      </thead>
                      <tbody>
                        {endpoints.map((e, i) => (
                          <tr key={i} className="border-b border-hairline last:border-0 hover:bg-gray-50 align-top">
                            <td className="py-2 pr-3 font-mono text-xs text-ink break-all">{e.url}</td>
                            <td className="py-2 pr-3 text-xs text-muted whitespace-nowrap">{e.methods.join(", ") || "-"}</td>
                            <td className="py-2 pr-3 text-xs text-muted font-mono break-all">{e.params.join(", ") || "-"}</td>
                            <td className="py-2 pr-3 text-xs text-muted whitespace-nowrap">{e.sources.join(", ")}</td>
                            <td className="py-2 pr-3 text-xs text-red-600">{e.vulns.join(", ") || "-"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )
              )}

              {/* 위협 시나리오 */}
              {tab === "threats" && (
                <div className="space-y-4">
                  {analysis.exploit_summary && (
                    <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                      <div className="flex items-center gap-1.5 mb-1"><Crosshair className="w-4 h-4 text-red-600" /><span className="text-xs font-semibold text-red-600 uppercase tracking-wide">공격 시나리오 개요</span></div>
                      <p className="text-sm text-red-700 whitespace-pre-line">{analysis.exploit_summary}</p>
                    </div>
                  )}
                  {Array.isArray(analysis.attack_chain) && analysis.attack_chain.length > 0 && (
                    <div className="border border-hairline rounded-lg p-4">
                      <div className="text-sm font-semibold text-ink mb-2 flex items-center gap-2"><GitBranch className="w-4 h-4 text-brand-400" />공격 체인</div>
                      <ol className="space-y-1.5">
                        {analysis.attack_chain.map((step, i) => (
                          <li key={i} className="flex gap-2 text-sm text-muted">
                            <span className="flex-shrink-0 w-5 h-5 rounded-full bg-primary-50 text-primary-700 text-xs font-bold flex items-center justify-center">{i + 1}</span>
                            <span>{typeof step === "string" ? step : (step.description || step.step || JSON.stringify(step))}</span>
                          </li>
                        ))}
                      </ol>
                    </div>
                  )}
                  <div className="space-y-2">
                    <div className="text-sm font-semibold text-ink">취약점별 공격 시나리오</div>
                    {contract.vulns.filter((f) => f.attack_scenario).length === 0 ? <p className="text-muted text-sm">개별 시나리오 정보가 없습니다.</p> :
                      contract.vulns.filter((f) => f.attack_scenario).map((f, i) => (
                        <div key={i} className="border border-hairline rounded-lg p-3">
                          <div className="text-sm font-medium text-ink mb-1">{f.title}</div>
                          <p className="text-xs text-muted whitespace-pre-line">{f.attack_scenario}</p>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* 이전 대비 */}
              {tab === "compare" && (
                cmpLoading ? <div className="flex items-center gap-2 py-6 text-muted text-sm"><Loader2 className="w-4 h-4 animate-spin" />이전 스캔과 비교 중…</div> :
                cmp === "none" || !cmp ? <p className="text-muted text-sm py-6 text-center">비교할 이전 스캔(같은 대상)이 없습니다.</p> : (
                  <div className="space-y-4">
                    <div className="text-sm text-muted">
                      이전 스캔 {typeof cmp.prev.seq === "number" ? `#${cmp.prev.seq}` : ""} ({cmp.prev.created_at}) 대비 변화
                    </div>
                    <div className="grid grid-cols-3 gap-3">
                      {[
                        { l: "신규", n: cmp.added.length, c: "text-red-600", Icon: Plus },
                        { l: "해소", n: cmp.resolved.length, c: "text-green-600", Icon: Minus },
                        { l: "지속", n: cmp.persisting.length, c: "text-muted", Icon: Equal },
                      ].map((s, i) => (
                        <div key={i} className="il-card border border-hairline rounded-lg p-3 text-center">
                          <s.Icon className={`w-4 h-4 mx-auto mb-1 ${s.c}`} />
                          <div className={`text-xl font-bold ${s.c}`}>{s.n}</div>
                          <div className="text-xs text-muted">{s.l}</div>
                        </div>
                      ))}
                    </div>
                    {[
                      { title: "신규 취약점", items: cmp.added, cls: "text-red-600", Icon: Plus },
                      { title: "해소된 취약점", items: cmp.resolved, cls: "text-green-600", Icon: Minus },
                    ].map((g, gi) => g.items.length > 0 && (
                      <div key={gi} className="space-y-1.5">
                        <div className={`text-sm font-semibold flex items-center gap-1.5 ${g.cls}`}><g.Icon className="w-4 h-4" />{g.title} ({g.items.length})</div>
                        {g.items.map((f, i) => (
                          <div key={i} className="flex items-center gap-2 border border-hairline rounded-lg px-3 py-2">
                            <span className={`text-xs px-2 py-0.5 font-semibold ${severityBadgeClass(sevKey(f))}`}>{SEV_LABEL[sevKey(f)]}</span>
                            <span className="text-sm text-ink truncate">{f.title}</span>
                          </div>
                        ))}
                      </div>
                    ))}
                    {cmp.prev.scan_id && (
                      <div className="flex items-center gap-3 flex-wrap">
                        <button onClick={() => setShowDiff(true)} className="inline-flex items-center gap-1.5 text-xs text-primary border border-hairline hover:border-primary-200 rounded-lg px-2.5 py-1.5 transition-colors">
                          <GitCompare className="w-3.5 h-3.5" />상세 비교
                        </button>
                        <button onClick={() => onOpenScan?.(cmp.prev.scan_id)} className="text-xs text-primary hover:underline">이전 스캔 열기 →</button>
                      </div>
                    )}
                  </div>
                )
              )}

              {/* 스캔 정보 */}
              {tab === "info" && (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm"><tbody className="divide-y divide-hairline">
                    {[
                      ["스캔 번호", typeof detail.seq === "number" ? `#${detail.seq}` : "-"],
                      ["대상", detail.domain], ["스캔 ID", detail.scan_id], ["상태", detail.status],
                      ["생성일", detail.created_at], ["종합 위험도", analysis.overall_risk || "-"],
                      ["취약점 수", contract.vulnerabilityCount],
                      ["심각도별", SEV_ORDER.filter((k) => sevCounts[k]).map((k) => `${SEV_LABEL[k]} ${sevCounts[k]}`).join(" · ") || "-"],
                      ["웹 / 서비스 취약점", `${contract.webVulnerabilityCount} / ${contract.serviceVulnerabilityCount}`],
                      ["공격 표면", contract.attackSurfaceCount], ["참고 발견", contract.discoveryCount], ["양호 항목", contract.goodCount],
                      ...(typeof contract.checkedPorts === "number" ? [["점검 포트", contract.checkedPorts]] : []),
                      ...(typeof analysis.stopped_at_percent === "number" ? [["중단 지점", `${analysis.stopped_at_percent}%`]] : []),
                    ].map(([k, v], i) => (
                      <tr key={i}><td className="py-2.5 pr-6 text-muted whitespace-nowrap w-40">{k}</td><td className="py-2.5 text-ink font-mono break-all">{String(v)}</td></tr>
                    ))}
                  </tbody></table>
                </div>
              )}

              {/* 삭제요청 — 상태변경형 실증의 자동 원복 실패 산출물 */}
              {tab === "cleanup" && (
                <div>
                  <div className="flex items-start gap-2 mb-3 p-3 rounded-lg bg-amber-50 border border-amber-200 text-amber-800 text-sm">
                    <Trash2 className="w-4 h-4 mt-0.5 shrink-0" />
                    <span>
                      상태변경형 취약점 실증(저장형 XSS·파일 업로드·쓰기 접근통제) 과정에서 생성·저장된
                      무해 테스트 데이터 중 <b>자동 원복에 실패</b>한 항목입니다. 대상에 흔적이 남지 않도록
                      아래 경로의 항목을 확인 후 삭제해 주세요.
                    </span>
                  </div>
                  {deletionRequests.length === 0 ? (
                    <p className="text-muted text-sm p-4">삭제 요청 항목이 없습니다(테스트 데이터 전량 자동 원복).</p>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="text-left text-muted border-b border-hairline">
                            <th className="py-2 pr-4 font-medium whitespace-nowrap">유형</th>
                            <th className="py-2 pr-4 font-medium">경로</th>
                            <th className="py-2 pr-4 font-medium">작성/생성 내용</th>
                            <th className="py-2 font-medium whitespace-nowrap">방법</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-hairline">
                          {deletionRequests.map((r, i) => (
                            <tr key={i} className="align-top">
                              <td className="py-2.5 pr-4 whitespace-nowrap text-ink">{r.kind || "-"}</td>
                              <td className="py-2.5 pr-4 font-mono break-all text-ink">{r.path || "-"}</td>
                              <td className="py-2.5 pr-4 break-words text-muted">
                                {r.content || "-"}
                                {r.note ? <span className="block text-xs text-amber-700 mt-0.5">{r.note}</span> : null}
                              </td>
                              <td className="py-2.5 whitespace-nowrap font-mono text-muted">{r.method || "-"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {/* 보고서 다운로드 */}
              {tab === "report" && (
                <div className="space-y-5">
                  <div className="flex items-end gap-3 flex-wrap">
                    {templates.length > 0 && (
                      <label className="flex flex-col gap-1 text-xs text-muted">
                        <span className="flex items-center gap-1.5"><FileText className="w-3.5 h-3.5" />버전(템플릿)</span>
                        <select value={templateId} onChange={(e) => setTemplateId(e.target.value)} className="il-input h-9 text-sm py-0 pl-2 pr-7">
                          {templates.map((t) => <option key={t.id} value={String(t.id)}>{t.name}{t.is_default === 1 ? " (기본)" : ""}</option>)}
                        </select>
                      </label>
                    )}
                    <label className="flex flex-col gap-1 text-xs text-muted flex-1 min-w-[220px]">
                      <span>파일명</span>
                      <input value={filename} onChange={(e) => setFilename(e.target.value)} className="il-input h-9 text-sm" placeholder="security_report" />
                    </label>
                  </div>

                  <div className="flex flex-col gap-1 text-xs text-muted">
                    <span>형식 · 선택 취약점 {selCount}/{selectable.length}건 포함</span>
                    <div className="flex items-center gap-2 flex-wrap">
                      <button onClick={() => download("docx")} disabled={downloading === "docx"} className="inline-flex items-center gap-1.5 text-sm text-green-700 bg-green-50 hover:bg-green-100 border border-green-200 rounded-lg px-3 py-1.5 transition-colors disabled:opacity-50">
                        {downloading === "docx" ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileDown className="w-4 h-4" />}Word (DOCX)
                      </button>
                      <button onClick={() => download("html")} disabled={downloading === "html"} className="inline-flex items-center gap-1.5 text-sm text-blue-700 bg-blue-50 hover:bg-blue-100 border border-blue-200 rounded-lg px-3 py-1.5 transition-colors disabled:opacity-50">
                        {downloading === "html" ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileDown className="w-4 h-4" />}HTML
                      </button>
                      {pdfAvailable && (
                        <button onClick={() => download("pdf")} disabled={downloading === "pdf"} className="inline-flex items-center gap-1.5 text-sm text-red-700 bg-red-50 hover:bg-red-100 border border-red-200 rounded-lg px-3 py-1.5 transition-colors disabled:opacity-50">
                          {downloading === "pdf" ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileDown className="w-4 h-4" />}PDF
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="border border-hairline rounded-lg overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-2.5 bg-gray-50 border-b border-hairline">
                      <span className="text-sm font-semibold text-ink">보고서에 포함할 취약점 선택</span>
                      <div className="flex items-center gap-2 text-xs">
                        <button onClick={() => setSelected(null)} className="text-muted hover:text-primary">전체 선택</button>
                        <span className="text-hairline">·</span>
                        <button onClick={() => setSelected(new Set())} className="text-muted hover:text-primary">전체 해제</button>
                      </div>
                    </div>
                    {selectable.length === 0 ? <p className="text-muted text-sm p-4">선택할 취약점이 없습니다(전체 보고서가 생성됩니다).</p> : (
                      <div className="divide-y divide-hairline max-h-72 overflow-y-auto">
                        {selectable.map(({ f, i }) => (
                          <button key={i} onClick={() => toggleSel(i)} className="w-full flex items-center gap-2.5 px-4 py-2.5 text-left hover:bg-gray-50 transition-colors">
                            {isSel(i) ? <CheckSquare className="w-4 h-4 text-primary flex-shrink-0" /> : <Square className="w-4 h-4 text-muted flex-shrink-0" />}
                            <span className="text-sm text-ink flex-1 truncate">{f.title || `취약점 #${i}`}</span>
                            {(f.report_severity || f.severity) && <span className="text-xs text-muted flex-shrink-0">{f.report_severity || f.severity}</span>}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>

                  {pocScripts.length > 0 && (
                    <div className="border border-hairline rounded-lg p-4 flex items-center justify-between gap-3 flex-wrap">
                      <div className="text-sm text-muted flex items-center gap-2"><Terminal className="w-4 h-4 text-brand-400" />선택 취약점의 PoC 스크립트 {pocScripts.filter(({ i }) => isSel(i)).length}개를 단일 .py 로 내려받기</div>
                      <button onClick={downloadPocBundle} className="inline-flex items-center gap-1.5 text-sm text-ink bg-white hover:bg-gray-50 border border-hairline rounded-lg px-3 py-1.5 transition-colors"><Download className="w-4 h-4" />PoC 스크립트(.py)</button>
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {showDiff && cmp && cmp !== "none" && cmp.prev?.scan_id && (
        <ScanDiff
          apiFetch={apiFetch}
          currentScanId={scanId}
          previousScanId={cmp.prev.scan_id}
          onClose={() => setShowDiff(false)}
        />
      )}
    </div>
  );
}
