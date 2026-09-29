import { useState } from "react";
import { ChevronDown, ChevronUp, Wrench } from "lucide-react";

export default function AdditionalReconPanel({ technologies, adaptiveRecon }) {
  const [expanded, setExpanded] = useState(false);
  const techs = Array.isArray(technologies) ? technologies : [];
  const recon = Array.isArray(adaptiveRecon) ? adaptiveRecon : [];
  if (techs.length === 0 && recon.length === 0) return null;

  return (
    <div className="border border-hairline rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-center gap-3 px-5 py-3.5 text-left bg-gray-50"
      >
        <Wrench className="w-4 h-4 text-text-muted flex-shrink-0" />
        <span className="text-sm font-semibold text-ink flex-1">추가 점검 권고</span>
        {expanded
          ? <ChevronUp className="w-4 h-4 text-text-muted" />
          : <ChevronDown className="w-4 h-4 text-text-muted" />}
      </button>
      {expanded && (
        <div className="p-4 space-y-3 border-t border-hairline">
          {techs.length > 0 && (
            <div className="space-y-2">
              <span className="text-xs font-semibold text-text-muted uppercase tracking-wide">탐지 기술 스택</span>
              {techs.map((t, i) => (
                <div key={i} className="bg-gray-50 border border-hairline rounded-lg p-3">
                  <p className="text-sm font-medium text-ink">{t.name}</p>
                  {Array.isArray(t.recommended_probes) && t.recommended_probes.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-1.5">
                      {t.recommended_probes.map((p, j) => (
                        <span key={j} className="text-xs font-mono bg-white text-text-muted border border-hairline px-2 py-0.5 rounded">{p}</span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
          {recon.length > 0 && (
            <div className="space-y-2">
              <span className="text-xs font-semibold text-text-muted uppercase tracking-wide">적응형 정찰 경로</span>
              {recon.map((r, i) => (
                <div key={i} className="bg-gray-50 border border-hairline rounded-lg p-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    {r.risk && (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-[rgba(234,179,8,0.12)] text-[#A16207] border border-[rgba(234,179,8,0.3)]">
                        {r.risk}
                      </span>
                    )}
                    {r.reason && <span className="text-sm text-ink">{r.reason}</span>}
                  </div>
                  {Array.isArray(r.paths) && r.paths.length > 0 && (
                    <div className="space-y-1 mt-1.5">
                      {r.paths.slice(0, 8).map((p, j) => (
                        <p key={j} className="text-xs font-mono text-text-muted truncate">{p}</p>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
