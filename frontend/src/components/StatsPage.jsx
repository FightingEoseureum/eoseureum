import { useEffect, useState } from "react";
import {
  BarChart2, ShieldAlert, Shield, Globe, Bug, Layers,
  TrendingUp, Loader2, RefreshCw, Server, Lock, Clock,
  ShieldCheck, ChevronRight,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import StatCard from "./StatCard";
import DashboardCard from "./DashboardCard";
import { RISK_TONE, RISK_COLOR } from "../utils/risk";
import { SCAN_STATUS } from "../utils/status";

const RISK_ORDER = ["HIGH", "MEDIUM", "LOW", "GOOD"];


function RecentScans({ scans }) {
  if (!scans || scans.length === 0) {
    return <div className="text-center text-muted text-sm py-8">최근 스캔 결과 없음</div>;
  }
  return (
    <div className="divide-y divide-hairline -mx-1">
      {scans.slice(0, 6).map((s) => {
        const st = SCAN_STATUS[s.status] || SCAN_STATUS.complete;
        const isSafe = s.overall_risk === "GOOD" || s.overall_risk === "LOW";
        return (
          <div key={s.scan_id} className="flex items-center gap-3 px-1 py-2.5">
            {s.overall_risk
              ? (isSafe
                  ? <ShieldCheck className="w-4 h-4 text-green-600 flex-shrink-0" />
                  : <ShieldAlert className="w-4 h-4 text-red-600 flex-shrink-0" />)
              : <Clock className="w-4 h-4 text-muted flex-shrink-0" />}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-ink font-mono truncate">{s.domain}</span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded-full flex-shrink-0 ${st.cls}`}>{st.label}</span>
              </div>
              <div className="text-xs text-muted truncate">{s.created_at}</div>
            </div>
            <div className="text-right flex-shrink-0">
              {typeof s.vulnerability_count === "number"
                ? <div className="text-sm font-semibold text-red-600">{s.vulnerability_count}<span className="text-xs text-muted font-normal">건</span></div>
                : <div className="text-sm text-muted">-</div>}
              {s.overall_risk && <div className={`text-[10px] font-semibold ${RISK_COLOR[s.overall_risk] || "text-muted"}`}>{s.overall_risk}</div>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── 도넛 차트 ──────────────────────────────────────────────────────────────────
function DonutChart({ data, total }) {
  const colors = { HIGH: "#EF4444", MEDIUM: "#F97316", LOW: "#EAB308", GOOD: "#22C55E" };
  const size = 160;
  const r = 60;
  const cx = size / 2;
  const cy = size / 2;
  const circ = 2 * Math.PI * r;

  if (total === 0) {
    return (
      <div className="flex items-center justify-center h-40 text-muted text-sm">
        스캔 데이터 없음
      </div>
    );
  }

  let offset = 0;
  const slices = RISK_ORDER.filter(k => data[k] > 0).map(k => {
    const pct = data[k] / total;
    const dash = pct * circ;
    const gap  = circ - dash;
    const slice = { key: k, dash, gap, offset, color: colors[k], pct };
    offset += dash;
    return slice;
  });

  return (
    <div className="flex items-center gap-6">
      <div className="relative flex-shrink-0">
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ transform: "rotate(-90deg)" }}>
          {slices.map(s => (
            <circle
              key={s.key}
              cx={cx} cy={cy} r={r}
              fill="none"
              stroke={s.color}
              strokeWidth={22}
              strokeDasharray={`${s.dash} ${s.gap}`}
              strokeDashoffset={-s.offset}
            />
          ))}
          <circle cx={cx} cy={cy} r={49} fill="#FFFFFF" />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div className="text-2xl font-bold text-ink">{total}</div>
          <div className="text-xs text-muted">총 스캔</div>
        </div>
      </div>

      <div className="space-y-2 flex-1">
        {RISK_ORDER.map(k => {
          const cnt = data[k] || 0;
          const pct = total > 0 ? Math.round((cnt / total) * 100) : 0;
          const cfg = RISK_TONE[k];
          return (
            <div key={k} className="flex items-center gap-2">
              <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${cfg.bg}`} />
              <span className={`text-xs font-semibold w-16 ${cfg.text}`}>{k}</span>
              <div className="flex-1 bg-gray-100 rounded-full h-1.5">
                <div className={`h-1.5 rounded-full ${cfg.bg}`} style={{ width: `${pct}%` }} />
              </div>
              <span className="text-xs text-muted w-10 text-right">{cnt}건</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── 타임라인 바 차트 ───────────────────────────────────────────────────────────
function TimelineChart({ data }) {
  const max = Math.max(...data.map(d => d.count), 1);
  const nonZero = data.filter(d => d.count > 0);

  return (
    <div>
      <div className="flex items-end gap-0.5 h-28">
        {data.map((d, i) => {
          const heightPct = (d.count / max) * 100;
          const isToday = i === data.length - 1;
          return (
            <div key={d.date} className="flex-1 flex flex-col items-center justify-end h-full group relative">
              <div
                className={`w-full rounded-t transition-all ${isToday ? "bg-brand-400" : "bg-brand-500/50 group-hover:bg-brand-400/80"}`}
                style={{ height: `${heightPct}%`, minHeight: d.count > 0 ? "3px" : "0" }}
              />
              {d.count > 0 && (
                <div className="absolute -top-6 left-1/2 -translate-x-1/2 bg-ink text-white text-xs px-1.5 py-0.5 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-10">
                  {d.date.slice(5)}: {d.count}건
                </div>
              )}
            </div>
          );
        })}
      </div>
      <div className="flex justify-between mt-1 text-xs text-muted">
        <span>{data[0]?.date.slice(5)}</span>
        <span>최근 30일</span>
        <span>{data[data.length - 1]?.date.slice(5)}</span>
      </div>
      {nonZero.length === 0 && (
        <div className="text-center text-muted text-sm mt-2">스캔 데이터 없음</div>
      )}
    </div>
  );
}

// ── 수평 바 리스트 ──────────────────────────────────────────────────────────────
function HorizontalBarList({ items, colorClass = "bg-blue-500", emptyMsg = "데이터 없음" }) {
  if (items.length === 0) {
    return <div className="text-center text-muted text-sm py-6">{emptyMsg}</div>;
  }
  const max = items[0]?.count || 1;
  return (
    <div className="space-y-2">
      {items.map((item, i) => (
        <div key={i} className="flex items-center gap-3">
          <div className="text-xs text-muted w-4 text-right flex-shrink-0">{i + 1}</div>
          <div className="flex-1 min-w-0">
            <div className="flex justify-between mb-0.5">
              <span className="text-xs text-ink truncate">{item.title || item.service || item.port}</span>
              <span className="text-xs text-muted ml-2 flex-shrink-0">{item.count}건</span>
            </div>
            <div className="bg-gray-100 rounded-full h-1.5">
              <div
                className={`h-1.5 rounded-full ${colorClass}`}
                style={{ width: `${(item.count / max) * 100}%` }}
              />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── 사용자 활동 테이블 ──────────────────────────────────────────────────────────
function UserActivityTable({ data }) {
  if (data.length === 0) {
    return <div className="text-center text-muted text-sm py-6">데이터 없음</div>;
  }
  const max = data[0]?.count || 1;
  return (
    <div className="space-y-2">
      {data.map((u, i) => (
        <div key={i} className="flex items-center gap-3">
          <div className="w-6 h-6 bg-primary-50 rounded-full flex items-center justify-center flex-shrink-0">
            <span className="text-xs text-primary">{i + 1}</span>
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex justify-between mb-0.5">
              <span className="text-xs font-medium text-ink">{u.username}</span>
              <span className="text-xs text-muted">{u.count}회</span>
            </div>
            <div className="bg-gray-100 rounded-full h-1.5">
              <div
                className="h-1.5 rounded-full bg-purple-500"
                style={{ width: `${(u.count / max) * 100}%` }}
              />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── 메인 컴포넌트 ───────────────────────────────────────────────────────────────
export default function StatsPage() {
  const { apiFetch, auth } = useAuth();
  const [stats, setStats] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch("/api/stats");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setStats(await res.json());
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
    // 최근 스캔 결과 (실데이터 — 실패해도 대시보드 전체를 막지 않음)
    try {
      const r = await apiFetch("/api/scans");
      if (r.ok) {
        const data = await r.json();
        setRecentScans(Array.isArray(data) ? data : []);
      }
    } catch {
      setRecentScans([]);
    }
  };

  useEffect(() => { load(); }, []);

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
        <p className="text-danger text-sm">통계 로드 실패: {error}</p>
        <button onClick={load} className="text-sm hover:underline" style={{ color: "#1E3A8A" }}>재시도</button>
      </div>
    );
  }

  const { summary, risk_distribution, timeline, top_vuln_titles, top_vuln_services, top_open_ports, user_activity } = stats;
  const totalRisk = Object.values(risk_distribution).reduce((a, b) => a + b, 0);
  const isAdmin = auth?.user?.role === "admin";

  // 실데이터 기반 요약값 (없으면 "-")
  const fmt = (v) => (typeof v === "number" ? v : "-");
  const highRatio = summary.total_scans > 0
    ? `${Math.round((summary.high_risk_count / summary.total_scans) * 100)}%`
    : "-";

  const refreshBtn = (
    <button
      onClick={load}
      className="flex items-center gap-1.5 text-xs text-muted hover:text-ink bg-white hover:bg-gray-50 border border-hairline px-3 py-1.5 rounded-lg transition-colors"
    >
      <RefreshCw className="w-3.5 h-3.5" />
      새로고침
    </button>
  );

  return (
    <div className="space-y-6">
      {/* 요약 카드 */}
      <div className="flex items-center justify-end">{refreshBtn}</div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={Layers}      label="전체 자산"      value={fmt(summary.unique_domains)}        tone="indigo" sub="고유 점검 도메인" />
        <StatCard icon={Shield}      label="총 스캔"        value={fmt(summary.total_scans)}           tone="blue" />
        <StatCard icon={Bug}         label="발견된 취약점"  value={fmt(summary.total_vulnerabilities)} tone="orange" />
        <StatCard icon={ShieldAlert} label="High 위험 비율" value={highRatio}                          tone="red"
          sub={typeof summary.high_risk_count === "number" ? `High 위험 스캔 ${summary.high_risk_count}건` : undefined} />
      </div>

      {/* 최근 스캔 결과 + 위험도 분포 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <DashboardCard icon={Clock} iconClass="text-primary" title="최근 스캔 결과">
          <RecentScans scans={recentScans} />
        </DashboardCard>
        <DashboardCard icon={TrendingUp} title="위험도 분포"
          action={<span className="text-xs text-muted">완료 스캔 기준</span>}>
          <DonutChart data={risk_distribution} total={totalRisk} />
        </DashboardCard>
      </div>

      {/* 취약점 추이 */}
      <DashboardCard icon={BarChart2} title="취약점 추이"
        action={<span className="text-xs text-muted">최근 30일</span>}>
        <TimelineChart data={timeline} />
      </DashboardCard>

      {/* 취약점 TOP 10 + 취약 서비스 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <DashboardCard icon={Bug} iconClass="text-danger" title="자주 발견되는 취약점 TOP 10">
          <HorizontalBarList items={top_vuln_titles} colorClass="bg-red-500/70" emptyMsg="취약점 데이터 없음" />
        </DashboardCard>
        <DashboardCard icon={Server} iconClass="text-warning" title="취약 서비스 TOP 10">
          <HorizontalBarList items={top_vuln_services} colorClass="bg-orange-500/70" emptyMsg="서비스 데이터 없음" />
        </DashboardCard>
      </div>

      {/* 오픈 포트 + 사용자 활동 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <DashboardCard icon={Lock} iconClass="text-primary" title="자주 발견되는 오픈 포트 TOP 10">
          <HorizontalBarList items={top_open_ports} colorClass="bg-brand-500/70" emptyMsg="포트 데이터 없음" />
        </DashboardCard>
        {isAdmin && (
          <DashboardCard icon={Shield} iconClass="text-purple-600" title="사용자별 스캔 활동"
            action={<span className="text-xs bg-purple-50 text-purple-700 border border-purple-200 px-1.5 py-0.5 rounded">admin</span>}>
            <UserActivityTable data={user_activity} />
          </DashboardCard>
        )}
      </div>
    </div>
  );
}
