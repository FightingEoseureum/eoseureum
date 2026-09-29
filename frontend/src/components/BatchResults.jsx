import { useState } from "react";
import {
  ShieldAlert, ShieldCheck, Loader2, ChevronRight,
  AlertTriangle, CheckCircle2, FileDown, Crosshair,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { RISK_COLOR, RISK_BG, severityBadgeClass } from "../utils/risk";
import { isVuln, countVuln, countGood } from "../utils/findings";
import { downloadBlob } from "../utils/download";

function FindingRow({ finding }) {
  const [open, setOpen] = useState(false);
  const vuln = isVuln(finding);
  return (
    <div className={`border rounded-lg overflow-hidden text-sm ${vuln ? "border-red-200 bg-red-50" : "border-green-200 bg-green-50"}`}>
      <button className="w-full text-left px-4 py-2.5 flex items-center gap-2" onClick={() => setOpen(v => !v)}>
        {vuln ? <AlertTriangle className="w-4 h-4 text-red-600 flex-shrink-0" /> : <CheckCircle2 className="w-4 h-4 text-green-600 flex-shrink-0" />}
        <span className="flex-1 font-medium text-ink">{finding.title}</span>
        {vuln && <span className={`text-xs px-1.5 py-0.5 ${severityBadgeClass(finding.severity)}`}>{finding.severity}</span>}
        <span className="text-xs text-muted font-mono">{finding.host}:{finding.port}</span>
        <ChevronRight className={`w-4 h-4 text-muted flex-shrink-0 transition-transform ${open ? "rotate-90" : ""}`} />
      </button>
      {open && (
        <div className="px-4 pb-3 pt-2 border-t border-hairline space-y-2">
          <p className="text-muted text-xs">{finding.description}</p>
          {vuln && finding.attack_vector && (
            <div className="bg-red-50 border border-red-200 rounded p-2">
              <div className="flex items-center gap-1 mb-1"><Crosshair className="w-3 h-3 text-red-600" /><span className="text-xs font-semibold text-red-600">공격 벡터</span></div>
              <p className="text-xs text-red-700">{finding.attack_vector}</p>
            </div>
          )}
          {vuln && finding.attack_scenario && (
            <div className="bg-orange-50 border border-orange-200 rounded p-2">
              <div className="flex items-center gap-1 mb-1"><Crosshair className="w-3 h-3 text-orange-600" /><span className="text-xs font-semibold text-orange-600">공격 시나리오</span></div>
              <p className="text-xs text-orange-700 whitespace-pre-line">{finding.attack_scenario}</p>
            </div>
          )}
          {finding.recommendation && (
            <div className="bg-primary-50 border border-primary-200 rounded p-2">
              <p className="text-xs text-primary"><span className="font-semibold">권고: </span>{finding.recommendation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function DomainCard({ result, onViewChange, onOpenScan }) {
  const { apiFetch } = useAuth();
  const [open, setOpen] = useState(false);
  const [exporting, setExporting] = useState(false);
  const { domain, status, analysis, scan_id } = result;
  const risk = analysis?.overall_risk;

  const handleExport = async (e) => {
    e.stopPropagation();
    if (!scan_id) return;
    setExporting(true);
    try {
      const res = await apiFetch(`/api/scans/${scan_id}/export`);
      if (!res.ok) { alert("내보내기 실패"); return; }
      const blob = await res.blob();
      downloadBlob(blob, `security_report_${domain}.docx`);
    } finally { setExporting(false); }
  };

  return (
    <div className="border border-hairline rounded-xl overflow-hidden">
      <div
        className="flex items-center gap-3 px-5 py-4 hover:bg-gray-50 cursor-pointer transition-colors"
        onClick={() => status === "complete" && setOpen(v => !v)}
      >
        {status === "scanning" ? (
          <Loader2 className="w-5 h-5 animate-spin flex-shrink-0" style={{ color: "#1E3A8A" }} />
        ) : status === "complete" && risk ? (
          risk === "GOOD" || risk === "LOW"
            ? <ShieldCheck className="w-5 h-5 text-green-600 flex-shrink-0" />
            : <ShieldAlert className="w-5 h-5 text-red-600 flex-shrink-0" />
        ) : (
          <div className="w-5 h-5 rounded-full bg-gray-200 flex-shrink-0" />
        )}

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-ink font-mono">{domain}</span>
            {status === "scanning" && <span className="text-xs text-primary animate-pulse">스캔 중...</span>}
            {status === "queued"   && <span className="text-xs text-muted">대기 중</span>}
            {status === "complete" && risk && (
              <span className={`text-xs font-semibold ${RISK_COLOR[risk]}`}>{risk}</span>
            )}
            {status === "failed"   && <span className="text-xs text-red-600">실패</span>}
          </div>
          {status === "complete" && analysis && (
            <p className="text-xs text-muted mt-0.5 truncate">{analysis.overall_summary}</p>
          )}
        </div>

        <div className="flex items-center gap-2">
          {status === "complete" && scan_id && (
            <button
              onClick={(e) => { e.stopPropagation(); onOpenScan ? onOpenScan(scan_id, "report") : onViewChange?.("history"); }}
              className="p-1.5 rounded text-muted hover:text-green-600 hover:bg-green-50 transition-colors"
              title="이 스캔의 보고서 다운로드(취약점·형식 선택)"
            >
              <FileDown className="w-4 h-4" />
            </button>
          )}
          {status === "complete" && (
            <ChevronRight className={`w-4 h-4 text-muted transition-transform ${open ? "rotate-90" : ""}`} />
          )}
        </div>
      </div>

      {open && analysis && (
        <div className="px-5 pb-5 bg-gray-50 border-t border-hairline">
          {/* 위험도 요약 */}
          <div className={`mt-3 rounded-lg p-3 border ${RISK_BG[risk] || "bg-white border-hairline"} mb-3`}>
            <p className="text-sm text-muted">{analysis.overall_summary}</p>
            {analysis.exploit_summary && (
              <div className="mt-2 flex items-start gap-2">
                <Crosshair className="w-3.5 h-3.5 text-red-600 mt-0.5 flex-shrink-0" />
                <p className="text-xs text-red-700">{analysis.exploit_summary}</p>
              </div>
            )}
          </div>

          {/* 통계 */}
          <div className="flex gap-3 mb-3">
            {[
              { label: "취약", count: countVuln(analysis.findings), color: "text-red-600" },
              { label: "양호", count: countGood(analysis), color: "text-green-600" },
            ].map(s => (
              <div key={s.label} className="bg-white border border-hairline rounded-lg px-3 py-1.5 text-center">
                <div className={`text-lg font-bold ${s.color}`}>{s.count}</div>
                <div className="text-xs text-muted">{s.label}</div>
              </div>
            ))}
          </div>

          <div className="space-y-2">
            {analysis.findings.map((f, i) => <FindingRow key={i} finding={f} />)}
          </div>
        </div>
      )}
    </div>
  );
}

export default function BatchResults({ results, totalCount, onViewChange, onOpenScan }) {
  const done    = results.filter(r => r.status === "complete").length;
  const failed  = results.filter(r => r.status === "failed").length;
  const highRisk = results.filter(r => r.analysis?.overall_risk === "HIGH").length;

  return (
    <div className="space-y-4">
      {/* 진행 상황 헤더 */}
      <div className="il-card p-5">
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-semibold text-ink">일괄 스캔 결과</h2>
          <span className="text-sm text-muted">{done} / {totalCount} 완료</span>
        </div>

        {/* 프로그레스 바 */}
        <div className="w-full bg-gray-100 rounded-full h-2 mb-4">
          <div
            className="h-2 rounded-full transition-all duration-500"
            style={{ background: "linear-gradient(90deg, #1E3A8A, #1D4ED8)", width: `${totalCount > 0 ? (done / totalCount) * 100 : 0}%` }}
          />
        </div>

        {/* 통계 */}
        <div className="flex gap-3">
          {[
            { label: "전체",    value: totalCount,  color: "text-ink" },
            { label: "완료",    value: done,         color: "text-green-600" },
            { label: "HIGH 위험", value: highRisk,  color: "text-red-600"   },
            { label: "실패",    value: failed,       color: "text-muted" },
          ].map(s => (
            <div key={s.label} className="bg-gray-50 border border-hairline rounded-lg px-4 py-2 text-center">
              <div className={`text-xl font-bold ${s.color}`}>{s.value}</div>
              <div className="text-xs text-muted">{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* 도메인 카드 목록 */}
      <div className="space-y-3">
        {results.map((r, i) => <DomainCard key={i} result={r} onViewChange={onViewChange} onOpenScan={onOpenScan} />)}
      </div>
    </div>
  );
}
