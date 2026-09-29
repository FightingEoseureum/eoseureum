import { useState } from "react";
import { Bot, ChevronDown, ChevronUp, Crosshair, ListOrdered, Sparkles, FlaskConical } from "lucide-react";

const RANK_COLORS = ["text-[#DC2626]", "text-[#F97316]", "text-[#A16207]"];
const RANK_BG     = ["bg-[rgba(220,38,38,0.08)] border-[rgba(220,38,38,0.25)]", "bg-[rgba(249,115,22,0.08)] border-[rgba(249,115,22,0.25)]", "bg-[rgba(234,179,8,0.1)] border-[rgba(234,179,8,0.3)]"];

export default function AIAnalysisPanel({ aiAnalysis }) {
  const [expanded, setExpanded] = useState(false);
  if (!aiAnalysis || aiAnalysis.ai_provider === "none") return null;
  if (aiAnalysis.ai_error && !aiAnalysis.ai_executive_summary) return null;

  const hasSummary   = Boolean(aiAnalysis.ai_executive_summary);
  const hasChain     = Boolean(aiAnalysis.ai_top_attack_chain);
  const hasPriority  = aiAnalysis.ai_remediation_priority?.length > 0;
  const hasRisk      = Boolean(aiAnalysis.ai_risk_assessment);

  return (
    <div className="rounded-xl border overflow-hidden" style={{ borderColor: "rgba(30,58,138,0.2)", background: "rgba(30,58,138,0.03)" }}>
      <button
        className="w-full flex items-center gap-3 px-5 py-4 text-left"
        onClick={() => setExpanded(v => !v)}
      >
        <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: "linear-gradient(135deg,#1E3A8A,#1D4ED8)" }}>
          <Bot className="w-4 h-4 text-white" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-ink">AI 분석 보강</span>
            <span className="text-xs px-2 py-0.5 rounded-full font-mono"
              style={{ background: "rgba(30,58,138,0.1)", color: "#1E3A8A", border: "1px solid rgba(30,58,138,0.2)" }}>
              {aiAnalysis.ai_provider}
            </span>
            {aiAnalysis.ai_ensemble && (
              <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-medium"
                style={{ background: "rgba(30,58,138,0.08)", color: "#1E3A8A", border: "1px solid rgba(30,58,138,0.2)" }}>
                <FlaskConical className="w-3 h-3" />
                {aiAnalysis.ai_ensemble.mode === "ensemble"
                  ? `앙상블 · ${(aiAnalysis.ai_ensemble.panel || []).length}모델 교차검증`
                  : "솔로"}
                {aiAnalysis.ai_ensemble.flagged > 0 ? ` · 오탐의심 ${aiAnalysis.ai_ensemble.flagged}건` : ""}
              </span>
            )}
            {aiAnalysis.ai_error && (
              <span className="text-xs text-[#F97316]">일부 오류</span>
            )}
          </div>
          <p className="text-xs text-text-muted mt-0.5">경영진 요약 · 공격 체인 분석 · 조치 우선순위</p>
        </div>
        {expanded
          ? <ChevronUp className="w-4 h-4 text-text-muted flex-shrink-0" />
          : <ChevronDown className="w-4 h-4 text-text-muted flex-shrink-0" />}
      </button>

      {expanded && (
        <div className="px-5 pb-5 space-y-4 border-t border-hairline">
          {/* 경영진 요약 */}
          {hasSummary && (
            <div className="pt-4">
              <div className="flex items-center gap-2 mb-2">
                <Sparkles className="w-4 h-4" style={{ color: "#1E3A8A" }} />
                <span className="text-xs font-semibold text-text-muted uppercase tracking-wide">경영진 요약</span>
              </div>
              <p className="text-sm text-ink leading-relaxed">{aiAnalysis.ai_executive_summary}</p>
            </div>
          )}

          {/* 최상위 공격 체인 */}
          {hasChain && (
            <div className="rounded-lg p-4 border border-[rgba(220,38,38,0.2)] bg-[rgba(220,38,38,0.05)]">
              <div className="flex items-center gap-2 mb-2">
                <Crosshair className="w-4 h-4 text-[#DC2626]" />
                <span className="text-xs font-semibold text-[#DC2626] uppercase tracking-wide">AI 선정 최위험 공격 시나리오</span>
              </div>
              <p className="text-sm text-ink leading-relaxed">{aiAnalysis.ai_top_attack_chain}</p>
            </div>
          )}

          {/* 조치 우선순위 */}
          {hasPriority && (
            <div>
              <div className="flex items-center gap-2 mb-2">
                <ListOrdered className="w-4 h-4 text-text-muted" />
                <span className="text-xs font-semibold text-text-muted uppercase tracking-wide">AI 조치 우선순위</span>
              </div>
              <div className="space-y-2">
                {aiAnalysis.ai_remediation_priority.map((item, i) => (
                  <div key={i} className={`flex items-start gap-3 rounded-lg px-3 py-2.5 border ${RANK_BG[i] || "bg-gray-50 border-hairline"}`}>
                    <span className={`text-sm font-bold min-w-[20px] ${RANK_COLORS[i] || "text-text-muted"}`}>
                      {item.rank || i + 1}.
                    </span>
                    <div>
                      <p className="text-sm font-medium text-ink">{item.title}</p>
                      {item.reason && (
                        <p className="text-xs text-text-muted mt-0.5">{item.reason}</p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 전체 위험도 평가 */}
          {hasRisk && (
            <div className="rounded-lg p-3 bg-gray-50 border border-hairline">
              <span className="text-xs font-semibold text-text-muted uppercase tracking-wide block mb-1">AI 위험도 평가</span>
              <p className="text-sm text-ink leading-relaxed">{aiAnalysis.ai_risk_assessment}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
