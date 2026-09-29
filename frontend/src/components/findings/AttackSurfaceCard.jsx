import { useState } from "react";
import { Target, ChevronDown, ChevronUp } from "lucide-react";
import { confidenceLabel } from "../../utils/contract";

// 공격 표면 항목 카드(정본: 옛 ResultsDashboard.AttackSurfaceCard). ScanHistory 공유.

export default function AttackSurfaceCard({ item }) {
  const [expanded, setExpanded] = useState(false);
  const detail = item.evidence_detail || item.description;
  const hasDetail = detail || item.recommendation;

  return (
    <div className="border border-[rgba(30,58,138,0.25)] bg-[rgba(30,58,138,0.04)] rounded-xl overflow-hidden">
      <button className="w-full text-left px-5 py-4 flex items-center gap-3" onClick={() => setExpanded(v => !v)}>
        <Target className="w-5 h-5 text-[#1E3A8A] flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-ink">{item.title}</span>
            <span className="text-xs px-2 py-0.5 rounded-full font-semibold bg-[rgba(30,58,138,0.1)] text-[#1E3A8A] border border-[rgba(30,58,138,0.25)]">
              공격 표면
            </span>
            {item.attack_surface_label && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-[rgba(234,179,8,0.12)] text-[#A16207] border border-[rgba(234,179,8,0.3)]">
                {item.attack_surface_label}
              </span>
            )}
            {confidenceLabel(item.confidence_score) && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-gray-50 text-text-muted border border-hairline font-mono">
                {confidenceLabel(item.confidence_score)}
              </span>
            )}
          </div>
          {(item.host || item.port) && (
            <div className="text-xs text-text-muted font-mono mt-0.5">
              {item.host}{item.port ? `:${item.port}` : ""}
            </div>
          )}
        </div>
        {hasDetail && (expanded
          ? <ChevronUp className="w-4 h-4 text-text-muted flex-shrink-0" />
          : <ChevronDown className="w-4 h-4 text-text-muted flex-shrink-0" />)}
      </button>

      {expanded && hasDetail && (
        <div className="px-5 pb-4 border-t border-hairline pt-3 space-y-3">
          {detail && <p className="text-sm text-ink whitespace-pre-line">{detail}</p>}
          {item.recommendation && (
            <div className="bg-primary-50 border border-primary-200 rounded-lg p-3">
              <span className="text-xs font-semibold text-primary uppercase tracking-wide block mb-1">권고 조치</span>
              <p className="text-sm text-ink">{item.recommendation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
