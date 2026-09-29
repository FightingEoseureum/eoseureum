import { useState, useEffect } from "react";
import {
  AlertTriangle, CheckCircle2, Server, Network,
  ShieldAlert, ShieldCheck, ChevronDown, ChevronUp,
  FileDown, Crosshair, Wrench, Camera, Globe, GitBranch,
  Sparkles, ListOrdered, Bot, Terminal, Link2, Trash2,
  Eye, EyeOff, Info, Layers, Target,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { deriveContract } from "../utils/contract";
import FindingCard from "./findings/FindingCard";
import AttackSurfaceCard from "./findings/AttackSurfaceCard";
import DiscoveryCard from "./findings/DiscoveryCard";
import OverallRisk from "./results/OverallRisk";
import AdditionalReconPanel from "./results/AdditionalReconPanel";
import AIAnalysisPanel from "./results/AIAnalysisPanel";
import ScreenshotGallery from "./results/ScreenshotGallery";
import { KnowledgeGraphPanel, DetectionCoveragePanel } from "./results/IntelPanels";

// ── 정규화 계약 헬퍼 (옛 데이터 호환) ──────────────────────────────
// ── 보안 지식 그래프 패널 ────────────────────────────────────────────────────
export default function ResultsDashboard({ subdomains, portFindings, analysis, scanId, onViewChange, onOpenReport }) {
  const { apiFetch } = useAuth();
  const [activeTab, setActiveTab]     = useState("findings");
  const [hostResults, setHostResults] = useState(null);
  const [showGood, setShowGood]       = useState(false);
  const [showDiscovery, setShowDiscovery] = useState(false);
  const [showAttackSurface, setShowAttackSurface] = useState(false);
  const [showServiceVulns, setShowServiceVulns] = useState(true);

  // Fetch full scan data (including screenshots) once scan ID is available
  useEffect(() => {
    if (!scanId) return;
    apiFetch(`/api/scans/${scanId}`)
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data?.results) setHostResults(data.results); })
      .catch(() => {});
  }, [scanId]);

  const screenshotCount = hostResults
    ? hostResults.flatMap(hr => hr.services || []).filter(
        svc => svc.http_info?.screenshot || (svc.sensitive_paths || []).some(sp => sp.screenshot)
      ).length
    : 0;

  // 정규화 계약 기준 목록/통계 (보고서 숫자와 일치, 옛 데이터 폴백 포함)
  const {
    vulns, webVulns, serviceVulns, attackSurface, good, discovery,
    vulnerabilityCount, attackSurfaceCount, goodCount, discoveryCount,
    webVulnerabilityCount, serviceVulnerabilityCount, checkedPorts,
  } = deriveContract(analysis);
  const vulnerableCount = vulnerabilityCount;
  const hasServiceVulns = serviceVulns.length > 0;

  const hasIntel = !!(analysis?.security_knowledge_graph?.summary?.node_count
    || (analysis?.detection_coverage?.matrix || []).some(
      r => r.tested || r.confirmed || r.possible || r.blocked_by_policy));
  const TABS = [
    { id: "findings",    label: "취약점 분석",  icon: ShieldAlert },
    ...(hasIntel ? [{ id: "intel", label: "지식 그래프·커버리지", icon: GitBranch }] : []),
    { id: "hosts",       label: "호스트",       icon: Server      },
    { id: "ports",       label: "오픈 포트",    icon: Network     },
    { id: "screenshots", label: `스크린샷${screenshotCount > 0 ? ` (${screenshotCount})` : ""}`, icon: Camera },
  ];

  return (
    <div className="space-y-4">
      <OverallRisk
        risk={analysis.overall_risk}
        summary={analysis.overall_summary}
        exploitSummary={analysis.exploit_summary}
        attackChain={analysis.attack_chain}
      />

      {analysis.ai_analysis && (
        <AIAnalysisPanel aiAnalysis={analysis.ai_analysis} />
      )}

      {/* 통계 + 내보내기 */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="il-card border border-hairline rounded-lg px-4 py-2 text-center">
          <div className="text-xl font-bold text-[#DC2626]">{vulnerableCount}</div>
          <div className="text-xs text-text-muted">취약 항목</div>
          <div className="text-[10px] text-text-muted mt-0.5">
            웹 {webVulnerabilityCount} · 서비스 {serviceVulnerabilityCount}
          </div>
        </div>
        <div className="il-card border border-hairline rounded-lg px-4 py-2 text-center">
          <div className="text-xl font-bold text-[#1E3A8A]">{attackSurfaceCount}</div>
          <div className="text-xs text-text-muted">공격 표면</div>
        </div>
        <div className="il-card border border-hairline rounded-lg px-4 py-2 text-center">
          <div className="text-xl font-bold text-[#15803D]">{goodCount}</div>
          <div className="text-xs text-text-muted">양호 항목</div>
        </div>
        <div className="il-card border border-hairline rounded-lg px-4 py-2 text-center">
          <div className="text-xl font-bold text-brand-400">{subdomains.length}</div>
          <div className="text-xs text-text-muted">서브도메인</div>
        </div>
        <div className="il-card border border-hairline rounded-lg px-4 py-2 text-center">
          <div className="text-xl font-bold text-brand-400">{portFindings.length}</div>
          <div className="text-xs text-text-muted">오픈 포트</div>
        </div>
        {typeof checkedPorts === "number" && (
          <div className="il-card border border-hairline rounded-lg px-4 py-2 text-center">
            <div className="text-xl font-bold text-[#1E3A8A]">{checkedPorts}</div>
            <div className="text-xs text-text-muted">점검 포트</div>
          </div>
        )}

        {scanId && (
          <button
            onClick={() => (onOpenReport ? onOpenReport(scanId) : onViewChange?.("history"))}
            title="이 스캔의 보고서 다운로드(취약점·형식 선택)"
            className="il-btn-primary ml-auto flex items-center gap-2"
          >
            <FileDown className="w-4 h-4" />
            보고서 받기 →
          </button>
        )}
      </div>

      {/* 탭 */}
      <div className="bg-white border border-hairline rounded-xl overflow-hidden">
        <div className="flex border-b border-hairline overflow-x-auto">
          {TABS.map(tab => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-5 py-3 text-sm font-medium transition-colors whitespace-nowrap ${
                  activeTab === tab.id
                    ? "text-brand-400 border-b-2 border-brand-500 bg-gray-50"
                    : "text-text-muted hover:text-ink"
                }`}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </div>

        <div className="p-5">
          {activeTab === "findings" && (
            <div className="space-y-4">
              {/* 웹 취약점 (기본 표시) */}
              <div className="space-y-3">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <span className="text-sm font-semibold text-ink">
                    {hasServiceVulns ? "웹 취약점 " : "취약점 "}
                    <span className="text-[#DC2626]">{hasServiceVulns ? webVulnerabilityCount : vulnerableCount}</span>건
                    {hasServiceVulns && (
                      <span className="text-xs text-text-muted font-normal ml-2">
                        (전체 {vulnerableCount} · 웹 {webVulnerabilityCount} · 서비스 {serviceVulnerabilityCount})
                      </span>
                    )}
                  </span>
                  {goodCount > 0 && (
                    <button
                      onClick={() => setShowGood(v => !v)}
                      className="flex items-center gap-1.5 text-xs text-text-muted hover:text-ink border border-hairline rounded-lg px-2.5 py-1.5 transition-colors"
                    >
                      {showGood
                        ? <EyeOff className="w-3.5 h-3.5" />
                        : <Eye className="w-3.5 h-3.5" />}
                      {showGood ? "양호 항목 숨기기" : `양호 항목 보기 (${goodCount})`}
                    </button>
                  )}
                </div>

                {webVulns.length === 0 ? (
                  <p className="text-text-muted text-sm">발견된 웹 취약점이 없습니다.</p>
                ) : (
                  webVulns.map((finding, i) => <FindingCard key={`web-${i}`} finding={finding} scanId={scanId} />)
                )}

                {/* 양호 항목 (토글 시에만 표시) */}
                {showGood && good.length > 0 && (
                  <div className="space-y-3 pt-1">
                    {good.map((finding, i) => <FindingCard key={`good-${i}`} finding={finding} scanId={scanId} />)}
                  </div>
                )}
              </div>

              {/* 서비스/포트 취약점 (별도 그룹, 기본 펼침) */}
              {hasServiceVulns && (
                <div className="border border-[rgba(30,58,138,0.25)] rounded-xl overflow-hidden">
                  <button
                    onClick={() => setShowServiceVulns(v => !v)}
                    className="w-full flex items-center gap-3 px-5 py-3.5 text-left bg-[rgba(30,58,138,0.05)]"
                  >
                    <Network className="w-4 h-4 text-[#1E3A8A] flex-shrink-0" />
                    <span className="text-sm font-semibold text-ink flex-1">
                      서비스/포트 취약점 <span className="text-[#1E3A8A]">({serviceVulnerabilityCount})</span>
                    </span>
                    {showServiceVulns
                      ? <ChevronUp className="w-4 h-4 text-text-muted" />
                      : <ChevronDown className="w-4 h-4 text-text-muted" />}
                  </button>
                  {showServiceVulns && (
                    <div className="p-4 space-y-3 border-t border-hairline">
                      {serviceVulns.map((finding, i) => <FindingCard key={`svc-${i}`} finding={finding} scanId={scanId} />)}
                    </div>
                  )}
                </div>
              )}

              {/* 공격 표면 (취약점 아님, 기본 접힘) */}
              {attackSurfaceCount > 0 && (
                <div className="border border-[rgba(30,58,138,0.25)] rounded-xl overflow-hidden">
                  <button
                    onClick={() => setShowAttackSurface(v => !v)}
                    className="w-full flex items-center gap-3 px-5 py-3.5 text-left bg-[rgba(30,58,138,0.05)]"
                  >
                    <Layers className="w-4 h-4 text-[#1E3A8A] flex-shrink-0" />
                    <span className="text-sm font-semibold text-ink flex-1">
                      공격 표면 <span className="text-[#1E3A8A]">({attackSurfaceCount})</span>
                    </span>
                    {showAttackSurface
                      ? <ChevronUp className="w-4 h-4 text-text-muted" />
                      : <ChevronDown className="w-4 h-4 text-text-muted" />}
                  </button>
                  {showAttackSurface && (
                    <div className="p-4 space-y-3 border-t border-hairline">
                      {attackSurface.map((item, i) => <AttackSurfaceCard key={i} item={item} />)}
                    </div>
                  )}
                </div>
              )}

              {/* 추가 점검 권고 (technologies / adaptive_recon, 옵셔널) */}
              <AdditionalReconPanel
                technologies={analysis?.technologies}
                adaptiveRecon={analysis?.adaptive_recon}
              />

              {/* 참고 발견 항목 (취약점 아님, 접기/펼치기) */}
              {discoveryCount > 0 && (
                <div className="border border-hairline rounded-xl overflow-hidden">
                  <button
                    onClick={() => setShowDiscovery(v => !v)}
                    className="w-full flex items-center gap-3 px-5 py-3.5 text-left bg-gray-50"
                  >
                    <Info className="w-4 h-4 text-text-muted flex-shrink-0" />
                    <span className="text-sm font-semibold text-ink flex-1">
                      참고 발견 항목 <span className="text-text-muted">({discoveryCount})</span>
                    </span>
                    {showDiscovery
                      ? <ChevronUp className="w-4 h-4 text-text-muted" />
                      : <ChevronDown className="w-4 h-4 text-text-muted" />}
                  </button>
                  {showDiscovery && (
                    <div className="p-4 space-y-3 border-t border-hairline">
                      {discovery.map((item, i) => <DiscoveryCard key={i} item={item} />)}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {activeTab === "hosts" && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-text-muted border-b border-hairline">
                    <th className="pb-3 pr-6 font-medium">서브도메인</th>
                    <th className="pb-3 font-medium">IP 주소</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-hairline">
                  {subdomains.map((s, i) => (
                    <tr key={i}>
                      <td className="py-3 pr-6 font-mono text-brand-300">{s.subdomain}</td>
                      <td className="py-3 font-mono text-ink">{s.ip}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === "ports" && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-text-muted border-b border-hairline">
                    <th className="pb-3 pr-6 font-medium">호스트</th>
                    <th className="pb-3 pr-4 font-medium">포트</th>
                    <th className="pb-3 font-medium">서비스</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-hairline">
                  {portFindings.map((p, i) => (
                    <tr key={i}>
                      <td className="py-3 pr-6 font-mono text-brand-300">{p.host}</td>
                      <td className="py-3 pr-4 font-mono text-ink">{p.port}</td>
                      <td className="py-3">
                        <span className="bg-gray-50 text-text-muted border border-hairline text-xs px-2 py-1 rounded font-mono">
                          {p.service}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === "screenshots" && (
            <ScreenshotGallery hostResults={hostResults} />
          )}

          {activeTab === "intel" && (
            <div className="space-y-6">
              <div>
                <h3 className="text-base font-semibold text-ink mb-3 flex items-center gap-2">
                  <GitBranch className="w-4 h-4 text-brand-400" /> 보안 지식 그래프
                </h3>
                <KnowledgeGraphPanel analysis={analysis} />
              </div>
              <div>
                <h3 className="text-base font-semibold text-ink mb-3 flex items-center gap-2">
                  <Target className="w-4 h-4 text-brand-400" /> 탐지 커버리지
                </h3>
                <DetectionCoveragePanel analysis={analysis} />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
