// finding 판정 헬퍼 — 여러 목록/대시보드 컴포넌트가 공유한다.
// 규칙: 서버가 finding_type 을 부여했으면 그것을 신뢰하고(정규화 결과),
// 없는 구형 데이터는 judgment 문자열로 폴백한다. 과거 파일마다 이 판정을
// 인라인으로 중복 구현해 한 곳만 고쳐지는 버그(F1)가 있어 단일 출처로 통합.

export function isVuln(finding) {
  if (finding?.finding_type) return finding.finding_type === "vulnerability";
  return finding?.judgment === "취약";
}

export function isGood(finding) {
  if (finding?.finding_type) return finding.finding_type === "good";
  return finding?.judgment === "양호";
}

// findings 배열에서 취약 항목 수
export function countVuln(findings) {
  return (findings || []).filter(isVuln).length;
}

// 양호 항목 수: 신계약은 good_items, 없으면 findings 중 isGood 로 폴백(구 데이터 호환).
// analysis 객체를 받는다(good_items 가 findings 와 별도 버킷이므로).
export function countGood(analysis) {
  if (Array.isArray(analysis?.good_items)) return analysis.good_items.length;
  return (analysis?.findings || []).filter(isGood).length;
}
