import { useEffect, useState } from "react";
import { Loader2, X, Plus, Minus, Equal, GitCompare } from "lucide-react";
import { severityBadgeClass } from "../utils/risk";

const SEV_LABEL = { CRITICAL: "심각", HIGH: "높음", MEDIUM: "중간", LOW: "낮음", INFO: "정보" };
const sevKey = (f) => String(f?.report_severity || f?.severity || "").toUpperCase() || "LOW";

// finding 동일성 키 = 정규화된 title(공백 정리 + 소문자). finding_uid 는 스캔마다 달라 부적합.
const titleKey = (f) => String(f?.title || "").trim().replace(/\s+/g, " ").toLowerCase();

function extractFindings(detail) {
  const arr = detail?.analysis?.findings;
  return Array.isArray(arr) ? arr : [];
}

export default function ScanDiff({ apiFetch, currentScanId, previousScanId, onClose }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [diff, setDiff] = useState(null); // { added, fixed, persisting }

  useEffect(() => {
    let cancelled = false;
    if (!currentScanId || !previousScanId) {
      setError("비교할 스캔 정보가 부족합니다.");
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    Promise.all([
      apiFetch(`/api/scans/${currentScanId}`).then((r) => (r.ok ? r.json() : null)),
      apiFetch(`/api/scans/${previousScanId}`).then((r) => (r.ok ? r.json() : null)),
    ])
      .then(([cur, prev]) => {
        if (cancelled) return;
        if (!cur || !prev) { setError("스캔 상세를 불러오지 못했습니다."); return; }
        const curF = extractFindings(cur);
        const prevF = extractFindings(prev);
        const curMap = new Map();
        curF.forEach((f) => { const k = titleKey(f); if (k && !curMap.has(k)) curMap.set(k, f); });
        const prevMap = new Map();
        prevF.forEach((f) => { const k = titleKey(f); if (k && !prevMap.has(k)) prevMap.set(k, f); });
        const added = [];       // 현재에만 존재 (New)
        const persisting = [];  // 양쪽 다 존재
        curMap.forEach((f, k) => { (prevMap.has(k) ? persisting : added).push(f); });
        const fixed = [];       // 이전에만 존재 (Fixed)
        prevMap.forEach((f, k) => { if (!curMap.has(k)) fixed.push(f); });
        setDiff({ added, fixed, persisting });
      })
      .catch(() => { if (!cancelled) setError("비교 중 오류가 발생했습니다."); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [apiFetch, currentScanId, previousScanId]);

  const Section = ({ title, items, cls, Icon, empty }) => (
    <div className="space-y-1.5">
      <div className={`text-sm font-semibold flex items-center gap-1.5 ${cls}`}>
        <Icon className="w-4 h-4" />{title} ({items.length})
      </div>
      {items.length === 0 ? (
        <p className="text-xs text-muted pl-1">{empty}</p>
      ) : (
        items.map((f, i) => (
          <div key={i} className="flex items-center gap-2 border border-hairline rounded-lg px-3 py-2">
            <span className={`text-xs px-2 py-0.5 font-semibold ${severityBadgeClass(sevKey(f))}`}>{SEV_LABEL[sevKey(f)]}</span>
            <span className="text-sm text-ink truncate">{f.title || "(제목 없음)"}</span>
          </div>
        ))
      )}
    </div>
  );

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4"
      onClick={onClose}>
      <div className="il-card bg-white border border-hairline rounded-xl w-full max-w-2xl my-8 shadow-xl"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 px-5 py-3 border-b border-hairline">
          <GitCompare className="w-4 h-4 text-brand-400" />
          <span className="text-sm font-semibold text-ink">이전 스캔 상세 비교</span>
          <button onClick={onClose} className="ml-auto p-1.5 rounded-lg text-muted hover:text-ink hover:bg-gray-50 transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5">
          {loading ? (
            <div className="flex items-center gap-2 py-10 justify-center text-muted text-sm">
              <Loader2 className="w-4 h-4 animate-spin" />두 스캔을 비교하는 중…
            </div>
          ) : error ? (
            <p className="text-muted text-sm py-10 text-center">{error}</p>
          ) : diff ? (
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-3">
                {[
                  { l: "신규", n: diff.added.length, c: "text-red-600", Icon: Plus },
                  { l: "해결됨", n: diff.fixed.length, c: "text-green-600", Icon: Minus },
                  { l: "지속", n: diff.persisting.length, c: "text-muted", Icon: Equal },
                ].map((s, i) => (
                  <div key={i} className="il-card border border-hairline rounded-lg p-3 text-center">
                    <s.Icon className={`w-4 h-4 mx-auto mb-1 ${s.c}`} />
                    <div className={`text-xl font-bold ${s.c}`}>{s.n}</div>
                    <div className="text-xs text-muted">{s.l}</div>
                  </div>
                ))}
              </div>
              <Section title="신규(New)" items={diff.added} cls="text-red-600" Icon={Plus} empty="신규로 추가된 취약점이 없습니다." />
              <Section title="해결됨(Fixed)" items={diff.fixed} cls="text-green-600" Icon={Minus} empty="해결된 취약점이 없습니다." />
              <Section title="지속(Persisting)" items={diff.persisting} cls="text-muted" Icon={Equal} empty="양쪽에 공통으로 존재하는 취약점이 없습니다." />
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
