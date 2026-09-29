import { Shield } from "lucide-react";

/**
 * 좌측 고정 사이드바 — 로그인 Hero 와 동일 계열의 Blue Gradient.
 * - 상단: shield / Eoseureum / AI Security Assessment / AI badge
 * - 중앙: 그룹별 메뉴 (App 에서 navItems 주입 — 단일 출처)
 * - 하단: 버전 / 카피라이트
 *
 * 라우팅/상태는 App 이 소유하고 여기서는 표현과 onViewChange 만 담당한다.
 */
const GROUP_LABEL = {
  scan: "스캔 관리",
  asset: "자산 관리",
  report: "보고서",
  config: "설정",
};

const ACTIVE_STYLE = {
  background: "rgba(255,255,255,0.16)",
  border: "1px solid rgba(255,255,255,0.18)",
  boxShadow: "0 8px 22px rgba(0,0,0,0.12)",
};
const HOVER_STYLE = { background: "rgba(255,255,255,0.10)" };

export default function Sidebar({ navItems, activeView, onViewChange }) {
  // group 순서를 보존하면서 묶기 (group 이 없으면 standalone)
  const blocks = [];
  for (const item of navItems) {
    if (!item.group) {
      blocks.push({ standalone: item });
      continue;
    }
    let g = blocks.find((x) => x.key === item.group);
    if (!g) {
      g = { key: item.group, items: [] };
      blocks.push(g);
    }
    g.items.push(item);
  }

  const MenuButton = ({ item }) => {
    const Icon = item.icon;
    const isActive = activeView === item.id;
    return (
      <button
        onClick={() => onViewChange(item.id)}
        className="w-full flex items-center gap-2.5 px-3 py-2.5 text-sm transition-colors"
        style={{
          borderRadius: 12,
          fontWeight: isActive ? 600 : 500,
          color: isActive ? "#ffffff" : "rgba(255,255,255,0.78)",
          border: "1px solid transparent",
          ...(isActive ? ACTIVE_STYLE : {}),
        }}
        onMouseEnter={(e) => { if (!isActive) Object.assign(e.currentTarget.style, HOVER_STYLE, { color: "#ffffff" }); }}
        onMouseLeave={(e) => { if (!isActive) Object.assign(e.currentTarget.style, { background: "transparent", color: "rgba(255,255,255,0.78)" }); }}
      >
        <Icon className="w-4 h-4 flex-shrink-0"
          style={{ color: isActive ? "#ffffff" : "rgba(255,255,255,0.72)" }} />
        <span className="truncate">{item.label}</span>
        {item.placeholder && (
          <span className="ml-auto text-[9px] rounded px-1 py-px"
            style={{
              color: "rgba(255,255,255,0.65)",
              background: "rgba(255,255,255,0.12)",
              border: "1px solid rgba(255,255,255,0.16)",
            }}>
            준비 중
          </span>
        )}
      </button>
    );
  };

  return (
    <aside className="hidden lg:flex flex-col w-[280px] shrink-0 h-screen sticky top-0 relative overflow-hidden eoseureum-sidebar-gradient text-white">
      {/* 은은한 grid overlay */}
      <div className="absolute inset-0 pointer-events-none" aria-hidden="true"
        style={{
          opacity: 0.4,
          backgroundImage:
            "linear-gradient(rgba(255,255,255,0.05) 1px, transparent 1px),"
            + "linear-gradient(90deg, rgba(255,255,255,0.05) 1px, transparent 1px)",
          backgroundSize: "44px 44px",
        }} />

      {/* 브랜드 */}
      <div className="relative z-10 px-6 py-5" style={{ borderBottom: "1px solid rgba(255,255,255,0.14)" }}>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
            style={{ background: "rgba(255,255,255,0.18)", border: "1px solid rgba(255,255,255,0.28)" }}>
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="font-extrabold text-base tracking-tight" style={{ color: "#ffffff" }}>Eoseureum</span>
              <span className="text-[10px] font-bold px-1.5 py-0.5 rounded text-white"
                style={{ letterSpacing: "0.08em", background: "rgba(255,255,255,0.16)", border: "1px solid rgba(255,255,255,0.28)" }}>
                AI
              </span>
            </div>
            <div className="text-[11px] truncate" style={{ color: "rgba(255,255,255,0.82)" }}>AI Security Assessment</div>
          </div>
        </div>
      </div>

      {/* 메뉴 */}
      <nav className="relative z-10 flex-1 overflow-y-auto px-3.5 py-4 space-y-4">
        {blocks.map((b, i) =>
          b.standalone ? (
            <MenuButton key={`s-${b.standalone.id}`} item={b.standalone} />
          ) : (
            <div key={`g-${b.key}-${i}`}>
              {GROUP_LABEL[b.key] && (
                <div className="px-3 mb-1.5 uppercase"
                  style={{ color: "rgba(255,255,255,0.45)", fontSize: 12, fontWeight: 700, letterSpacing: "0.06em" }}>
                  {GROUP_LABEL[b.key]}
                </div>
              )}
              <div className="space-y-1">
                {b.items.map((item) => <MenuButton key={item.id} item={item} />)}
              </div>
            </div>
          )
        )}
      </nav>

      {/* 푸터 */}
      <div className="relative z-10 px-6 py-4" style={{ borderTop: "1px solid rgba(255,255,255,0.14)" }}>
        <div className="text-[11px] font-semibold" style={{ color: "rgba(255,255,255,0.85)" }}>Eoseureum v1.0.0</div>
        <div className="text-[11px]" style={{ color: "rgba(255,255,255,0.78)" }}>© 2026 Eoseureum</div>
      </div>
    </aside>
  );
}
