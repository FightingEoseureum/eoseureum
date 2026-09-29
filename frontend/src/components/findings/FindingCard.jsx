import { useState } from "react";
import {
  AlertTriangle, CheckCircle2, Network, Crosshair, Wrench, Terminal,
  Link2, Trash2, ChevronUp, ChevronDown, FlaskConical,
  CircleDot, Ban, ShieldAlert,
} from "lucide-react";
import { isVuln as isVulnFinding } from "../../utils/findings";
import { isServiceCategory, confidenceLabel } from "../../utils/contract";
import { severityBadgeClass } from "../../utils/risk";
import { useAuth } from "../../context/AuthContext";

// 취약점/양호 finding 상세 카드(정본: 옛 ResultsDashboard.FindingCard). ScanHistory 도 이 컴포넌트를 공유.

function severityKey(finding) {
  const raw = finding?.report_severity || finding?.severity || "";
  return String(raw).toUpperCase();
}

const DIFFICULTY_BADGE = {
  Easy:   "rounded-full bg-[rgba(220,38,38,0.1)] text-[#DC2626] border border-[rgba(220,38,38,0.25)]",
  Medium: "rounded-full bg-[rgba(249,115,22,0.1)] text-[#F97316] border border-[rgba(249,115,22,0.25)]",
  Hard:   "rounded-full bg-gray-50 text-text-muted border border-hairline",
};
const CONFIDENCE_BADGE = {
  CONFIRMED:     "rounded-full bg-[rgba(34,197,94,0.12)] text-[#15803D] border border-[rgba(34,197,94,0.3)]",
  POSSIBLE:      "rounded-full bg-[rgba(234,179,8,0.12)] text-[#A16207] border border-[rgba(234,179,8,0.3)]",
  MANUAL_REVIEW: "rounded-full bg-gray-50 text-text-muted border border-hairline",
};
const CONFIDENCE_LABEL = {
  CONFIRMED: "확인됨",
  POSSIBLE: "가능성",
  MANUAL_REVIEW: "수동확인",
};

// 트리아지(오탐 판정) 3-상태 정의 — 서버 허용값과 일치.
const TRIAGE_STATES = [
  { key: "open",           label: "열림",     Icon: CircleDot,   active: "bg-gray-100 text-ink border-gray-300" },
  { key: "false_positive", label: "오탐",     Icon: Ban,         active: "bg-[rgba(148,163,184,0.18)] text-slate-600 border-slate-400" },
  { key: "accepted_risk",  label: "위험수용", Icon: ShieldAlert, active: "bg-[rgba(234,179,8,0.14)] text-[#A16207] border-[rgba(234,179,8,0.4)]" },
];

export default function FindingCard({ finding, scanId }) {
  const [expanded, setExpanded] = useState(false);
  const { apiFetch } = useAuth();
  const isVulnerable = isVulnFinding(finding);
  const isService    = isServiceCategory(finding);
  const sevKey       = severityKey(finding);
  const sevLabel     = finding.report_severity || finding.severity;
  const severityCls  = severityBadgeClass(sevKey);
  const diffCls      = DIFFICULTY_BADGE[finding.exploitation_difficulty] || "";

  // scanId: prop 우선, 없으면 finding 객체에서(현재 상위 컴포넌트는 prop 을 넘기지 않으므로
  // 대개 finding.scan_id 로만 해결됨). 둘 다 없으면 트리아지 컨트롤을 숨긴다(안전 처리).
  const sid = scanId || finding?.scan_id || finding?.scanId || null;
  const canTriage = isVulnerable && !!sid && !!finding?.finding_uid;

  const [triage, setTriage]   = useState(finding?.user_triage || "open");
  const [saving, setSaving]   = useState(false);
  const [triageErr, setTriageErr] = useState("");
  const isFP = triage === "false_positive";

  async function applyTriage(next) {
    if (!canTriage || next === triage || saving) return;
    const prev = triage;
    setSaving(true);
    setTriageErr("");
    setTriage(next); // 낙관적 반영
    try {
      const res = await apiFetch(
        `/api/scans/${encodeURIComponent(sid)}/findings/${encodeURIComponent(finding.finding_uid)}/triage`,
        { method: "PATCH", body: JSON.stringify({ status: next }) },
      );
      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try { const j = await res.json(); if (j?.detail) msg = j.detail; } catch { /* ignore */ }
        throw new Error(msg);
      }
    } catch (e) {
      setTriage(prev); // 롤백
      const m = `트리아지 저장 실패: ${e?.message || e}`;
      setTriageErr(m);
      alert(m);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className={`border rounded-xl overflow-hidden ${isFP ? "opacity-60 " : ""}${isVulnerable ? "border-[rgba(220,38,38,0.25)] bg-[rgba(220,38,38,0.04)]" : "border-[rgba(34,197,94,0.25)] bg-[rgba(34,197,94,0.05)]"}`}>
      <button className="w-full text-left px-5 py-4 flex items-center gap-3" onClick={() => setExpanded(v => !v)}>
        {isVulnerable
          ? <AlertTriangle className="w-5 h-5 text-[#DC2626] flex-shrink-0" />
          : <CheckCircle2 className="w-5 h-5 text-[#22C55E] flex-shrink-0" />}

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-ink">{finding.title}</span>
            <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${isVulnerable ? "bg-[rgba(220,38,38,0.1)] text-[#DC2626] border border-[rgba(220,38,38,0.25)]" : "bg-[rgba(34,197,94,0.12)] text-[#15803D] border border-[rgba(34,197,94,0.3)]"}`}>
              {finding.judgment || (isVulnerable ? "취약" : "양호")}
            </span>
            {isService && (
              <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-semibold bg-[rgba(30,58,138,0.1)] text-[#1E3A8A] border border-[rgba(30,58,138,0.25)]">
                <Network className="w-3 h-3" />
                Network Service
              </span>
            )}
            {isVulnerable && sevLabel && (
              <span className={`text-xs px-2 py-0.5 font-semibold ${severityCls}`}>{sevLabel}</span>
            )}
            {isVulnerable && finding.confidence && CONFIDENCE_BADGE[finding.confidence] && (
              <span className={`text-xs px-2 py-0.5 ${CONFIDENCE_BADGE[finding.confidence]}`}>
                {CONFIDENCE_LABEL[finding.confidence] || finding.confidence}
              </span>
            )}
            {confidenceLabel(finding.confidence_score) && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-gray-50 text-text-muted border border-hairline font-mono">
                {confidenceLabel(finding.confidence_score)}
              </span>
            )}
            {isVulnerable && finding.owasp && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-primary-50 text-primary border border-primary-200 font-mono">
                {finding.owasp}
              </span>
            )}
            {isVulnerable && finding.cvss_estimate && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-[rgba(220,38,38,0.1)] text-[#DC2626] border border-[rgba(220,38,38,0.25)] font-mono">
                CVSS {finding.cvss_estimate}
              </span>
            )}
            {isVulnerable && finding.exploitation_difficulty && (
              <span className={`text-xs px-2 py-0.5 ${diffCls}`}>
                난이도: {finding.exploitation_difficulty}
              </span>
            )}
            {finding.ai_fp_flag && (
              <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-semibold bg-[rgba(234,179,8,0.12)] text-[#A16207] border border-[rgba(234,179,8,0.35)]">
                <FlaskConical className="w-3 h-3" />
                AI 오탐의심{finding.ai_fp_votes ? ` ${finding.ai_fp_votes}표` : ""}
              </span>
            )}
            {isVulnerable && isFP && (
              <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-semibold bg-[rgba(148,163,184,0.18)] text-slate-600 border border-slate-400">
                <Ban className="w-3 h-3" />
                오탐
              </span>
            )}
            {isVulnerable && triage === "accepted_risk" && (
              <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-semibold bg-[rgba(234,179,8,0.14)] text-[#A16207] border border-[rgba(234,179,8,0.4)]">
                <ShieldAlert className="w-3 h-3" />
                위험수용
              </span>
            )}
          </div>
          <div className="text-xs text-text-muted font-mono mt-0.5">
            {finding.host}:{finding.port} ({finding.service})
            {isService && finding.protocol ? ` · ${finding.protocol}` : ""}
          </div>
        </div>

        {expanded
          ? <ChevronUp className="w-4 h-4 text-text-muted flex-shrink-0" />
          : <ChevronDown className="w-4 h-4 text-text-muted flex-shrink-0" />}
      </button>

      {canTriage && (
        <div className="px-5 pb-3 -mt-1 flex items-center gap-2 flex-wrap">
          <span className="text-xs text-text-muted">판정:</span>
          <div className="inline-flex rounded-lg border border-hairline overflow-hidden bg-white">
            {TRIAGE_STATES.map(({ key, label, Icon, active }) => (
              <button
                key={key}
                type="button"
                disabled={saving}
                onClick={() => applyTriage(key)}
                className={`inline-flex items-center gap-1 text-xs px-2.5 py-1 border-r border-hairline last:border-r-0 transition-colors disabled:opacity-50 ${
                  triage === key ? `font-semibold ${active}` : "text-text-muted hover:bg-gray-50"
                }`}
                aria-pressed={triage === key}
              >
                <Icon className="w-3 h-3" />
                {label}
              </button>
            ))}
          </div>
          {saving && <span className="text-xs text-text-muted">저장 중…</span>}
          {triageErr && <span className="text-xs text-[#DC2626]">{triageErr}</span>}
        </div>
      )}

      {expanded && (
        <div className="px-5 pb-4 border-t border-hairline pt-3 space-y-3">
          {finding.ai_fp_flag && (
            <div className="rounded-lg p-3 border" style={{ background: "#fffbeb", borderColor: "#fde68a", borderLeftWidth: "4px", borderLeftColor: "#F59E0B" }}>
              <div className="flex items-center gap-1.5 mb-1">
                <FlaskConical className="w-3.5 h-3.5 text-[#A16207]" />
                <span className="text-xs font-semibold text-[#A16207] uppercase tracking-wide">
                  AI 앙상블 오탐 의심{finding.ai_fp_votes ? ` (${finding.ai_fp_votes}표)` : ""}
                </span>
              </div>
              <p className="text-xs text-[#92400E] leading-relaxed">
                룰 엔진 판정은 그대로 유지되나, 다중 AI 교차판정에서 오탐 가능성이 제기되었습니다. <b>수동 확인</b>을 권장합니다.
              </p>
              {finding.ai_fp_reasons?.length > 0 && (
                <ul className="mt-1.5 space-y-0.5">
                  {finding.ai_fp_reasons.slice(0, 3).map((reason, i) => (
                    <li key={i} className="text-xs text-[#92400E] flex gap-1.5">
                      <span className="flex-shrink-0">·</span><span>{reason}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
          <p className="text-sm text-ink">{finding.description}</p>

          {isVulnerable && finding.attack_vector && (
            <div className="bg-[rgba(220,38,38,0.05)] border border-[rgba(220,38,38,0.2)] rounded-lg p-3">
              <div className="flex items-center gap-1.5 mb-1">
                <Crosshair className="w-3.5 h-3.5 text-[#DC2626]" />
                <span className="text-xs font-semibold text-[#DC2626] uppercase tracking-wide">공격 벡터</span>
              </div>
              <p className="text-sm text-ink">{finding.attack_vector}</p>
            </div>
          )}

          {isVulnerable && finding.attack_scenario && (
            <div className="bg-[rgba(249,115,22,0.05)] border border-[rgba(249,115,22,0.2)] rounded-lg p-3">
              <div className="flex items-center gap-1.5 mb-1">
                <Crosshair className="w-3.5 h-3.5 text-[#F97316]" />
                <span className="text-xs font-semibold text-[#F97316] uppercase tracking-wide">공격 시나리오</span>
              </div>
              <p className="text-sm text-ink whitespace-pre-line">{finding.attack_scenario}</p>
            </div>
          )}

          {isVulnerable && finding.tools?.length > 0 && (
            <div className="bg-gray-50 border border-hairline rounded-lg p-3">
              <div className="flex items-center gap-1.5 mb-2">
                <Wrench className="w-3.5 h-3.5 text-text-muted" />
                <span className="text-xs font-semibold text-text-muted uppercase tracking-wide">테스트 도구</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {finding.tools.map((tool, i) => (
                  <span key={i} className="text-xs font-mono bg-white text-text-muted border border-hairline px-2 py-0.5 rounded">{tool}</span>
                ))}
              </div>
            </div>
          )}

          {isVulnerable && finding.cve_references?.length > 0 && (
            <div className="bg-primary-50 border border-primary-200 rounded-lg p-3">
              <span className="text-xs font-semibold text-primary uppercase tracking-wide block mb-1">CVE 참조</span>
              <div className="flex flex-wrap gap-1.5">
                {finding.cve_references.map((cve, i) => (
                  <span key={i} className="text-xs font-mono bg-primary-100 text-primary border border-primary-200 px-2 py-0.5 rounded">{cve}</span>
                ))}
              </div>
            </div>
          )}

          {isVulnerable && finding.lab_guide && (
            <div className="bg-primary-50 border border-primary-200 rounded-lg p-3">
              <span className="text-xs font-semibold text-primary uppercase tracking-wide block mb-1">실습 환경 안내</span>
              <p className="text-sm text-ink">{finding.lab_guide}</p>
            </div>
          )}

          {isVulnerable && finding.reproduction_cmd && (
            <div className="rounded-lg overflow-hidden border border-slate-700">
              <div className="flex items-center gap-2 px-3 py-2 bg-slate-800">
                <Terminal className="w-3.5 h-3.5 text-green-400" />
                <span className="text-xs font-semibold text-green-400 uppercase tracking-wide">curl 재현 명령어</span>
              </div>
              <pre className="bg-slate-900 px-3 py-2.5 text-xs font-mono text-green-300 overflow-x-auto whitespace-pre-wrap break-all">
                {finding.reproduction_cmd}
              </pre>
            </div>
          )}

          {isVulnerable && finding.affected_endpoints?.length > 0 && (
            <div className="bg-gray-50 border border-hairline rounded-lg p-3">
              <div className="flex items-center gap-1.5 mb-2">
                <Link2 className="w-3.5 h-3.5 text-text-muted" />
                <span className="text-xs font-semibold text-text-muted uppercase tracking-wide">영향받는 엔드포인트</span>
              </div>
              <div className="space-y-1">
                {finding.affected_endpoints.slice(0, 5).map((ep, i) => (
                  <p key={i} className="text-xs font-mono text-text-muted truncate">{ep}</p>
                ))}
                {finding.affected_endpoints.length > 5 && (
                  <p className="text-xs text-text-muted">+{finding.affected_endpoints.length - 5}개 더...</p>
                )}
              </div>
            </div>
          )}

          {isVulnerable && finding.cleanup_status?.required && (
            <div className={`rounded-lg p-3 border ${
              finding.cleanup_status.cleanup_success
                ? "bg-[rgba(34,197,94,0.08)] border-[rgba(34,197,94,0.3)]"
                : finding.cleanup_status.cleanup_attempted
                ? "bg-[rgba(234,179,8,0.1)] border-[rgba(234,179,8,0.3)]"
                : "bg-gray-50 border-hairline"
            }`}>
              <div className="flex items-center gap-1.5 mb-1">
                <Trash2 className={`w-3.5 h-3.5 ${finding.cleanup_status.cleanup_success ? "text-[#15803D]" : "text-[#A16207]"}`} />
                <span className="text-xs font-semibold text-text-muted uppercase tracking-wide">테스트 데이터 정리</span>
              </div>
              <p className={`text-xs ${
                finding.cleanup_status.cleanup_success
                  ? "text-[#15803D]"
                  : finding.cleanup_status.cleanup_attempted
                  ? "text-[#A16207]"
                  : "text-text-muted"
              }`}>
                {finding.cleanup_status.cleanup_success
                  ? "✔ 정리 완료 — 테스트 데이터 삭제됨"
                  : finding.cleanup_status.cleanup_attempted
                  ? "⚠ 정리 실패 — 수동 삭제 필요"
                  : "△ 정리 미수행 — 수동 확인 권고"}
              </p>
            </div>
          )}

          {finding.recommendation && (
            <div className="bg-primary-50 border border-primary-200 rounded-lg p-3">
              <span className="text-xs font-semibold text-primary uppercase tracking-wide block mb-1">권고 조치</span>
              <p className="text-sm text-ink">{finding.recommendation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
