/**
 * 대시보드 상단 요약 카드.
 * 원형 아이콘 배경 + 큰 수치 + 라벨(+보조). 값이 없으면 "-" 를 그대로 전달해 표시한다.
 * mock 고정값을 만들지 않는다.
 */
export default function StatCard({ icon: Icon, label, value, sub, tone = "blue" }) {
  const TONE = {
    blue:   { ring: "bg-primary-50",  fg: "text-primary" },
    indigo: { ring: "bg-indigo-50",   fg: "text-indigo-600" },
    orange: { ring: "bg-orange-50",   fg: "text-orange-600" },
    red:    { ring: "bg-red-50",      fg: "text-red-600" },
    purple: { ring: "bg-purple-50",   fg: "text-purple-600" },
    green:  { ring: "bg-green-50",    fg: "text-green-600" },
  }[tone] || { ring: "bg-primary-50", fg: "text-primary" };

  return (
    <div className="il-card p-5 flex items-center gap-4 hover:shadow-card-hover transition-shadow">
      <div className={`w-12 h-12 rounded-full flex items-center justify-center flex-shrink-0 ${TONE.ring}`}>
        <Icon className={`w-6 h-6 ${TONE.fg}`} />
      </div>
      <div className="min-w-0">
        <div className="text-2xl font-bold text-ink leading-tight">{value}</div>
        <div className="text-sm text-muted truncate">{label}</div>
        {sub && <div className="text-xs text-muted mt-0.5 truncate">{sub}</div>}
      </div>
    </div>
  );
}
