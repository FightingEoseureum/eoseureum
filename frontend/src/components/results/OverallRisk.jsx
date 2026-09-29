import { useState } from "react";
import { ChevronDown, ChevronUp, Crosshair, GitBranch, Globe, ShieldAlert, ShieldCheck } from "lucide-react";

const RISK_CONFIG = {
  HIGH:   { color: "text-[#F97316]", bg: "bg-[rgba(249,115,22,0.1)]", border: "border-[rgba(249,115,22,0.3)]", label: "높음 (HIGH)"   },
  MEDIUM: { color: "text-[#EAB308]", bg: "bg-[rgba(234,179,8,0.12)]", border: "border-[rgba(234,179,8,0.3)]", label: "중간 (MEDIUM)" },
  LOW:    { color: "text-[#22C55E]", bg: "bg-[rgba(34,197,94,0.12)]", border: "border-[rgba(34,197,94,0.3)]", label: "낮음 (LOW)"    },
  GOOD:   { color: "text-[#22C55E]", bg: "bg-[rgba(34,197,94,0.12)]", border: "border-[rgba(34,197,94,0.3)]", label: "양호 (GOOD)"   },
};

export default function OverallRisk({ risk, summary, exploitSummary, attackChain }) {
  const [chainExpanded, setChainExpanded] = useState(false);
  const cfg = RISK_CONFIG[risk] || RISK_CONFIG.GOOD;
  const Icon = risk === "GOOD" || risk === "LOW" ? ShieldCheck : ShieldAlert;

  return (
    <div className="space-y-3">
      <div className={`rounded-xl p-5 border ${cfg.bg} ${cfg.border} flex items-start gap-4`}>
        <Icon className={`w-10 h-10 mt-0.5 flex-shrink-0 ${cfg.color}`} />
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-sm text-text-muted">전체 위험도</span>
            <span className={`text-sm font-bold ${cfg.color}`}>{cfg.label}</span>
          </div>
          <p className="text-ink text-sm leading-relaxed">{summary}</p>
        </div>
      </div>

      {exploitSummary && (
        <div className="rounded-xl p-4 border border-[rgba(220,38,38,0.2)] bg-[rgba(220,38,38,0.05)] flex items-start gap-3">
          <Crosshair className="w-5 h-5 text-[#DC2626] flex-shrink-0 mt-0.5" />
          <div>
            <span className="text-xs font-semibold text-[#DC2626] uppercase tracking-wide block mb-1">공격 시나리오 개요</span>
            <p className="text-sm text-ink leading-relaxed">{exploitSummary}</p>
          </div>
        </div>
      )}

      {attackChain && (
        <div className="rounded-xl border border-[rgba(249,115,22,0.2)] bg-[rgba(249,115,22,0.05)] overflow-hidden">
          <button
            className="w-full flex items-center gap-3 px-4 py-3 text-left"
            onClick={() => setChainExpanded(v => !v)}
          >
            <GitBranch className="w-4 h-4 text-[#F97316] flex-shrink-0" />
            <span className="text-xs font-semibold text-[#F97316] uppercase tracking-wide flex-1">공격 체인 (Attack Chain)</span>
            {chainExpanded
              ? <ChevronUp className="w-4 h-4 text-text-muted" />
              : <ChevronDown className="w-4 h-4 text-text-muted" />}
          </button>
          {chainExpanded && (
            <div className="px-4 pb-4 space-y-3">
              {typeof attackChain === "object" ? (
                <>
                  {attackChain.recon && (
                    <div className="flex gap-3">
                      <div className="flex flex-col items-center gap-1">
                        <div className="w-7 h-7 rounded-full bg-primary-100 border border-primary-200 flex items-center justify-center flex-shrink-0">
                          <Globe className="w-3.5 h-3.5 text-primary" />
                        </div>
                        <div className="w-px flex-1 bg-hairline" />
                      </div>
                      <div className="pb-3">
                        <p className="text-xs font-semibold text-primary mb-1">정보수집 (Reconnaissance)</p>
                        <p className="text-sm text-ink leading-relaxed">{attackChain.recon}</p>
                      </div>
                    </div>
                  )}
                  {attackChain.penetration && (
                    <div className="flex gap-3">
                      <div className="flex flex-col items-center gap-1">
                        <div className="w-7 h-7 rounded-full bg-[rgba(220,38,38,0.1)] border border-[rgba(220,38,38,0.25)] flex items-center justify-center flex-shrink-0">
                          <Crosshair className="w-3.5 h-3.5 text-[#DC2626]" />
                        </div>
                        <div className="w-px flex-1 bg-hairline" />
                      </div>
                      <div className="pb-3">
                        <p className="text-xs font-semibold text-[#DC2626] mb-1">시스템 침투 (Initial Penetration)</p>
                        <p className="text-sm text-ink leading-relaxed">{attackChain.penetration}</p>
                      </div>
                    </div>
                  )}
                  {attackChain.lateral_movement && (
                    <div className="flex gap-3">
                      <div className="w-7 h-7 rounded-full bg-[rgba(249,115,22,0.1)] border border-[rgba(249,115,22,0.25)] flex items-center justify-center flex-shrink-0">
                        <GitBranch className="w-3.5 h-3.5 text-[#F97316]" />
                      </div>
                      <div>
                        <p className="text-xs font-semibold text-[#F97316] mb-1">공격 횡이동 (Lateral Movement)</p>
                        <p className="text-sm text-ink leading-relaxed">{attackChain.lateral_movement}</p>
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <p className="text-sm text-ink leading-relaxed whitespace-pre-line">{attackChain}</p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
