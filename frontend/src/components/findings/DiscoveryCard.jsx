import { useState } from "react";
import { Info, ChevronDown, ChevronUp } from "lucide-react";

// 참고 발견 항목 카드(정본: 옛 ResultsDashboard.DiscoveryCard). ScanHistory 공유.

export default function DiscoveryCard({ item }) {
  const [expanded, setExpanded] = useState(false);
  const hasDetail = item.description || item.evidence_detail || item.recommendation;

  return (
    <div className="border border-hairline bg-gray-50 rounded-xl overflow-hidden">
      <button className="w-full text-left px-5 py-3.5 flex items-center gap-3" onClick={() => setExpanded(v => !v)}>
        <Info className="w-4 h-4 text-text-muted flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-ink">{item.title}</span>
            {item.owasp && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-primary-50 text-primary border border-primary-200 font-mono">
                {item.owasp}
              </span>
            )}
          </div>
          {(item.host || item.port || item.service) && (
            <div className="text-xs text-text-muted font-mono mt-0.5">
              {item.host}{item.port ? `:${item.port}` : ""}{item.service ? ` (${item.service})` : ""}
            </div>
          )}
        </div>
        {hasDetail && (expanded
          ? <ChevronUp className="w-4 h-4 text-text-muted flex-shrink-0" />
          : <ChevronDown className="w-4 h-4 text-text-muted flex-shrink-0" />)}
      </button>

      {expanded && hasDetail && (
        <div className="px-5 pb-4 border-t border-hairline pt-3 space-y-3">
          {item.description && <p className="text-sm text-ink">{item.description}</p>}
          {item.evidence_detail && (
            <p className="text-sm text-text-muted whitespace-pre-line">{item.evidence_detail}</p>
          )}
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
