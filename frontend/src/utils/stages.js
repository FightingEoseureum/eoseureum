// 스캔 파이프라인 단계 정의 — 진행 표시 컴포넌트들이 공유한다.
// 아이콘은 컴포넌트마다 필요 여부가 달라(진행 트리는 사용, 사이드 패널은 미사용)
// 여기서는 순서·id·라벨만 단일 출처로 두고, 아이콘 매핑은 각 컴포넌트가 부여한다.
export const SCAN_STAGES = [
  { id: "recon",            label: "정보수집 & 포트스캔" },
  { id: "url_discovery",    label: "URL 탐색" },
  { id: "active_probing",   label: "능동 취약점 점검" },
  { id: "external_scan",    label: "외부 도구 심층 점검" },
  { id: "penetration",      label: "증거 수집" },
  { id: "lateral_movement", label: "분석 & 보고" },
];
