// 위험도(overall_risk) 등급별 표현 상수 — 여러 컴포넌트가 공유한다.
// 예전에는 파일마다 개별 정의해 값이 조금씩 달라질 위험이 있었으므로 단일 출처로 통합.

// 텍스트 색상 클래스 맵 (등급 → Tailwind text-* 클래스)
export const RISK_COLOR = {
  HIGH: "text-red-600",
  MEDIUM: "text-orange-600",
  LOW: "text-yellow-600",
  GOOD: "text-green-600",
};

// 카드/배지 배경+테두리 클래스 맵
export const RISK_BG = {
  HIGH: "bg-red-50 border-red-200",
  MEDIUM: "bg-orange-50 border-orange-200",
  LOW: "bg-yellow-50 border-yellow-200",
  GOOD: "bg-green-50 border-green-200",
};

// 차트/통계용 다중 톤 맵 (text/bg/light/border 세트)
// severity 등급별 뱃지 클래스(색+테두리+rounded). report_severity/severity 를 넘기면 대문자화해 조회.
// 예전엔 ResultsDashboard(rgba맵)·ScanHistory·BatchResults(각자 Tailwind 삼항)가 제각각이라
// 등급별 색이 달랐다 → RD 스타일을 정본으로 통합.
const _SEVERITY_BADGE = {
  CRITICAL: "rounded-full bg-[rgba(220,38,38,0.1)] text-[#DC2626] border border-[rgba(220,38,38,0.25)]",
  HIGH:     "rounded-full bg-[rgba(249,115,22,0.1)] text-[#F97316] border border-[rgba(249,115,22,0.25)]",
  MEDIUM:   "rounded-full bg-[rgba(234,179,8,0.12)] text-[#A16207] border border-[rgba(234,179,8,0.3)]",
  LOW:      "rounded-full bg-[rgba(34,197,94,0.12)] text-[#15803D] border border-[rgba(34,197,94,0.3)]",
  INFO:     "rounded-full bg-[rgba(100,116,139,0.1)] text-[#64748B] border border-[rgba(100,116,139,0.25)]",
};
export function severityBadgeClass(sev) {
  return _SEVERITY_BADGE[String(sev || "").toUpperCase()] || _SEVERITY_BADGE.LOW;
}

export const RISK_TONE = {
  HIGH:   { text: "text-red-600",    bg: "bg-red-500",    light: "bg-red-500/10",   border: "border-red-500/30"   },
  MEDIUM: { text: "text-orange-600", bg: "bg-orange-500", light: "bg-orange-500/10", border: "border-orange-500/30" },
  LOW:    { text: "text-yellow-600", bg: "bg-yellow-400", light: "bg-yellow-500/10", border: "border-yellow-500/30" },
  GOOD:   { text: "text-green-600",  bg: "bg-green-500",  light: "bg-green-500/10",  border: "border-green-500/30"  },
};
