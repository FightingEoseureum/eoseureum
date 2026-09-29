/**
 * 대시보드 콘텐츠 섹션 래퍼.
 * 제목 + 아이콘 + 우측 보조 영역(action) + 본문(children).
 * 카드 radius/shadow/여백을 통일한다.
 */
export default function DashboardCard({ icon: Icon, iconClass = "text-muted", title, action, children, className = "" }) {
  return (
    <div className={`il-card p-5 ${className}`}>
      <div className="flex items-center gap-2 mb-4">
        {Icon && <Icon className={`w-4 h-4 ${iconClass}`} />}
        <h2 className="text-sm font-semibold text-ink">{title}</h2>
        {action && <div className="ml-auto">{action}</div>}
      </div>
      {children}
    </div>
  );
}
