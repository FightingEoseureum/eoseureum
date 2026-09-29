// 지식 그래프·탐지 커버리지 패널(정본: 옛 ResultsDashboard).

const _NODE_KO = {
  Internet: "인터넷", Host: "호스트", Service: "서비스", Port: "포트", URL: "URL",
  Endpoint: "엔드포인트", API: "API", Parameter: "파라미터", Form: "폼",
  BusinessFunction: "비즈니스 기능", Finding: "취약점", Evidence: "증거", Proof: "증명",
  Fingerprint: "핑거프린트", AttackPath: "공격 경로", Remediation: "조치",
};
const _EDGE_KO = {
  HAS_HOST: "호스트 보유", EXPOSES_SERVICE: "서비스 노출", HAS_ENDPOINT: "엔드포인트",
  HAS_PARAMETER: "파라미터", HAS_FINDING: "취약점 발견", HAS_EVIDENCE: "증거 보유",
  HAS_PROOF: "증명 보유", HAS_FINGERPRINT: "핑거프린트", AFFECTS_BUSINESS_FUNCTION: "비즈니스 영향",
  MITIGATED_BY: "조치 연결",
};

export function KnowledgeGraphPanel({ analysis }) {
  const kg = analysis?.security_knowledge_graph || {};
  const ap = analysis?.attack_path_graph || {};
  const s = kg.summary || {};
  if (!s.node_count) {
    return <div className="text-sm text-text-muted py-6 text-center">보안 지식 그래프 데이터가 없습니다.</div>;
  }
  const nodesBy = s.nodes_by_type || {};
  const edgesBy = s.edges_by_type || {};
  const paths = (ap.paths || []).slice(0, 5);
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-muted">
        취약점을 목록이 아니라 <b>자산 → 입력점 → 취약점 → 증거 → 증명 → 공격 경로 → 비즈니스 → 조치</b>의
        관계 그래프로 연결했습니다.
      </p>
      <div className="flex gap-3 flex-wrap">
        <div className="il-card border border-hairline rounded-lg px-4 py-2 text-center">
          <div className="text-xl font-bold text-[#1E3A8A]">{s.node_count}</div>
          <div className="text-xs text-text-muted">그래프 노드</div>
        </div>
        <div className="il-card border border-hairline rounded-lg px-4 py-2 text-center">
          <div className="text-xl font-bold text-[#0E9488]">{s.edge_count}</div>
          <div className="text-xs text-text-muted">관계(엣지)</div>
        </div>
        <div className="il-card border border-hairline rounded-lg px-4 py-2 text-center">
          <div className="text-xl font-bold text-[#DC2626]">{(ap.summary || {}).attack_paths || 0}</div>
          <div className="text-xs text-text-muted">공격 경로</div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="il-card border border-hairline rounded-lg p-4">
          <div className="text-sm font-semibold text-ink mb-2">노드 유형</div>
          {Object.entries(nodesBy).sort((a, b) => b[1] - a[1]).map(([t, c]) => (
            <div key={t} className="flex justify-between text-xs py-0.5">
              <span className="text-text-muted">{_NODE_KO[t] || t}</span>
              <span className="font-semibold text-ink">{c}</span>
            </div>
          ))}
        </div>
        <div className="il-card border border-hairline rounded-lg p-4">
          <div className="text-sm font-semibold text-ink mb-2">관계 유형</div>
          {Object.entries(edgesBy).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([t, c]) => (
            <div key={t} className="flex justify-between text-xs py-0.5">
              <span className="text-text-muted">{_EDGE_KO[t] || t}</span>
              <span className="font-semibold text-ink">{c}</span>
            </div>
          ))}
        </div>
      </div>

      {paths.length > 0 && (
        <div className="il-card border border-hairline rounded-lg p-4">
          <div className="text-sm font-semibold text-ink mb-3">공격 경로 (상위 {paths.length}건)</div>
          <div className="space-y-3">
            {paths.map((p, i) => (
              <div key={i} className="border-b border-hairline last:border-0 pb-3 last:pb-0">
                <div className="text-xs font-semibold text-[#1E3A8A] mb-1">
                  #{i + 1} {p.title} <span className="text-text-muted">[{p.severity || "-"}]</span>
                </div>
                <div className="flex flex-wrap items-center gap-1">
                  {(p.steps || []).map((st, j) => (
                    <span key={j} className="inline-flex items-center gap-1">
                      {j > 0 && <span className="text-brand-400 text-xs">→</span>}
                      <span className="text-[11px] bg-gray-100 rounded px-1.5 py-0.5 text-ink">
                        {st.icon} {String(st.node).slice(0, 30)}
                      </span>
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function DetectionCoveragePanel({ analysis }) {
  const dc = analysis?.detection_coverage || {};
  const matrix = (dc.matrix || []).filter(
    r => r.tested || r.confirmed || r.possible || r.blocked_by_policy);
  if (!matrix.length) {
    return <div className="text-sm text-text-muted py-6 text-center">탐지 커버리지 데이터가 없습니다.</div>;
  }
  const cols = [
    ["technique", "기법"], ["tested", "검사"], ["confirmed", "확인"], ["possible", "가능성"],
    ["blocked_by_policy", "차단"], ["not_applicable", "해당 없음"], ["reason", "비고"],
  ];
  return (
    <div className="space-y-3">
      <p className="text-sm text-text-muted">
        기법별로 <b>무엇을 검사했고 어떤 결과가 나왔는지</b> 요약합니다.
        (검사=시도, 확인=실증, 가능성=추가 검토, 차단=SAFE 정책으로 미수행)
      </p>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-text-muted border-b border-hairline">
              {cols.map(([, ko]) => <th key={ko} className="py-2 pr-3 font-semibold">{ko}</th>)}
            </tr>
          </thead>
          <tbody>
            {matrix.map((r, i) => (
              <tr key={i} className="border-b border-hairline last:border-0 hover:bg-gray-50">
                <td className="py-2 pr-3 font-semibold text-ink">{r.technique}</td>
                <td className="py-2 pr-3">{r.tested}</td>
                <td className="py-2 pr-3 font-bold text-[#15803D]">{r.confirmed}</td>
                <td className="py-2 pr-3 text-[#CA8A04]">{r.possible}</td>
                <td className="py-2 pr-3 text-text-muted">{r.blocked_by_policy}</td>
                <td className="py-2 pr-3 text-text-muted">{r.not_applicable}</td>
                <td className="py-2 pr-3 text-xs text-text-muted">{r.reason || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
