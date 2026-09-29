import { useState } from "react";
import { Layers, Server, ShieldCheck, Search, Loader2, RefreshCw, ListChecks } from "lucide-react";
import { useApiResource } from "../hooks/useApiResource";
import StatCard from "./StatCard";
import DashboardCard from "./DashboardCard";

const CONF = {
  high:   { label: "높음", cls: "bg-primary-50 text-primary border-primary-100" },
  medium: { label: "보통", cls: "bg-amber-50 text-amber-700 border-amber-200" },
  low:    { label: "낮음", cls: "bg-gray-100 text-gray-600 border-gray-200" },
};

export default function TechStackPage() {
  const { data, loading, error, reload } = useApiResource("/api/techstack");
  const [query, setQuery] = useState("");

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 className="w-8 h-8 animate-spin" style={{ color: "#1E3A8A" }} />
      </div>
    );
  }
  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-24 gap-3">
        <p className="text-danger text-sm">기술 스택 로드 실패: {error}</p>
        <button onClick={reload} className="text-sm hover:underline" style={{ color: "#1E3A8A" }}>재시도</button>
      </div>
    );
  }

  const items = data?.items || [];
  const summary = data?.summary || {};
  const recommendedTotal = items.reduce((acc, it) => acc + (it.recommended_checks?.length || 0), 0);

  const q = query.trim().toLowerCase();
  const filtered = q
    ? items.filter(it =>
        String(it.host || "").toLowerCase().includes(q) ||
        String(it.technology || "").toLowerCase().includes(q))
    : items;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <button onClick={reload}
          className="flex items-center gap-1.5 text-xs text-muted hover:text-ink bg-white hover:bg-gray-50 border border-hairline px-3 py-1.5 rounded-lg transition-colors">
          <RefreshCw className="w-3.5 h-3.5" />새로고침
        </button>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={Layers}      label="탐지 기술 수"  value={summary.total_technologies ?? 0} tone="blue" />
        <StatCard icon={Server}      label="대상 호스트 수" value={summary.total_hosts ?? 0}        tone="indigo" />
        <StatCard icon={ShieldCheck} label="높은 신뢰도"   value={summary.high_confidence ?? 0}    tone="green" />
        <StatCard icon={ListChecks}  label="추천 점검 수"  value={recommendedTotal}                tone="orange" />
      </div>

      <DashboardCard icon={Layers} iconClass="text-primary" title="탐지된 기술 스택"
        action={
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input value={query} onChange={e => setQuery(e.target.value)}
              placeholder="호스트/기술명 검색"
              className="il-input h-8 pl-8 pr-3 text-xs w-48" />
          </div>
        }>
        {filtered.length === 0 ? (
          <div className="text-center text-muted text-sm py-10">
            {items.length === 0
              ? "탐지된 기술 스택 데이터가 없습니다. 스캔 완료 후 표시됩니다."
              : "검색 결과가 없습니다."}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-muted border-b border-hairline">
                  <th className="py-2 pr-3 font-semibold">호스트</th>
                  <th className="py-2 pr-3 font-semibold">포트</th>
                  <th className="py-2 pr-3 font-semibold">서비스</th>
                  <th className="py-2 pr-3 font-semibold">기술</th>
                  <th className="py-2 pr-3 font-semibold">버전</th>
                  <th className="py-2 pr-3 font-semibold">신뢰도</th>
                  <th className="py-2 pr-3 font-semibold">탐지 출처</th>
                  <th className="py-2 pr-3 font-semibold">추천 점검</th>
                  <th className="py-2 pr-3 font-semibold">마지막 확인</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((it, i) => {
                  const c = CONF[it.confidence] || CONF.medium;
                  const checks = it.recommended_checks || [];
                  return (
                    <tr key={i} className="border-b border-hairline last:border-0 hover:bg-gray-50">
                      <td className="py-2.5 pr-3 font-mono text-ink">{it.host || "-"}</td>
                      <td className="py-2.5 pr-3 text-muted">{it.port ?? "-"}</td>
                      <td className="py-2.5 pr-3 text-muted">{it.service || "-"}</td>
                      <td className="py-2.5 pr-3 font-medium text-ink">{it.technology || "-"}</td>
                      <td className="py-2.5 pr-3 font-mono text-muted">{it.version || "-"}</td>
                      <td className="py-2.5 pr-3">
                        <span className={`text-[11px] px-1.5 py-0.5 rounded-full border ${c.cls}`}>{c.label}</span>
                      </td>
                      <td className="py-2.5 pr-3 text-xs text-muted">{it.source || "-"}</td>
                      <td className="py-2.5 pr-3">
                        {checks.length === 0 ? <span className="text-muted">-</span> : (
                          <div className="flex flex-wrap gap-1">
                            {checks.slice(0, 3).map((p, j) => (
                              <code key={j} className="text-[10px] bg-gray-100 text-ink rounded px-1 py-0.5">{p}</code>
                            ))}
                            {checks.length > 3 && <span className="text-[10px] text-muted">+{checks.length - 3}</span>}
                          </div>
                        )}
                      </td>
                      <td className="py-2.5 pr-3 text-xs text-muted whitespace-nowrap">{it.last_seen || "-"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </DashboardCard>
    </div>
  );
}
