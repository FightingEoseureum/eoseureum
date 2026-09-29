// 정규화 계약 헬퍼 — analysis 객체에서 취약점/양호/참고/공격표면 목록과 통계를 안전하게 추출한다.
// 신계약: findings = 취약점만, good_items/attack_surface_items/discovery_items 는 별도 버킷.
// 구 데이터: judgment 혼재 → isVuln/isGood 로 폴백. 예전엔 ResultsDashboard·ScanHistory 가
// 이 로직을 각자 복붙해 한쪽만 고쳐지는 드리프트 위험이 있어 단일 출처로 통합.
import { isVuln, isGood } from "./findings";

// scan_category 폴백: 없으면 "web" 취급. "service"만 서비스/포트 취약점.
export function isServiceCategory(item) {
  return item?.scan_category === "service";
}

// 취약점은 Critical→High→Medium→Low→Info 순으로 표시(뒤죽박죽 방지).
const _SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
function _sevRank(f) {
  const s = String(f?.report_severity || f?.severity || "").toUpperCase();
  return _SEV_RANK[s] ?? 9;
}
function _bySeverity(a, b) {
  return _sevRank(a) - _sevRank(b);
}

export function deriveContract(analysis) {
  const allFindings = Array.isArray(analysis?.findings) ? analysis.findings : [];
  // 새 계약: findings = 취약점만. 옛 데이터: judgment 혼재 → 폴백 필터.
  const vulns = allFindings.filter(isVuln).slice().sort(_bySeverity);
  // 웹/서비스 취약점 분리 (scan_category 없으면 전부 웹) — 각각 심각도순 유지
  const serviceVulns = vulns.filter(isServiceCategory);
  const webVulns = vulns.filter(v => !isServiceCategory(v));

  // 공격 표면(취약점 아님) — 새 계약 필드, 옛 데이터는 빈 배열 폴백
  const attackSurface = Array.isArray(analysis?.attack_surface_items)
    ? analysis.attack_surface_items
    : [];

  const discovery = Array.isArray(analysis?.discovery_items) ? analysis.discovery_items : [];

  // good_items 우선, 없으면 findings 중 isGood 폴백
  const good = Array.isArray(analysis?.good_items)
    ? analysis.good_items
    : allFindings.filter(isGood);

  const summary = analysis?.summary || {};
  const vulnerabilityCount =
    typeof summary.vulnerability_count === "number" ? summary.vulnerability_count : vulns.length;
  const attackSurfaceCount =
    typeof summary.attack_surface_count === "number" ? summary.attack_surface_count : attackSurface.length;
  const goodCount =
    typeof summary.good_count === "number" ? summary.good_count : good.length;
  const discoveryCount =
    typeof summary.discovery_count === "number" ? summary.discovery_count : discovery.length;

  // 웹/서비스 취약점 개수: summary 우선, 없으면 scan_category 폴백 계산
  const webVulnerabilityCount =
    typeof summary.web_vulnerability_count === "number"
      ? summary.web_vulnerability_count
      : webVulns.length;
  const serviceVulnerabilityCount =
    typeof summary.service_vulnerability_count === "number"
      ? summary.service_vulnerability_count
      : serviceVulns.length;
  const checkedPorts =
    typeof summary.checked_ports === "number" ? summary.checked_ports : null;

  return {
    vulns, webVulns, serviceVulns, attackSurface, good, discovery,
    vulnerabilityCount, attackSurfaceCount, goodCount, discoveryCount,
    webVulnerabilityCount, serviceVulnerabilityCount, checkedPorts,
  };
}

// confidence_score(0~100)를 "신뢰도 NN" 배지로 — 숫자일 때만 표시
export function confidenceLabel(score) {
  if (typeof score !== "number" || Number.isNaN(score)) return null;
  return `신뢰도 ${Math.round(score)}`;
}
