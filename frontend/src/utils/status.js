// 스캔 상태 뱃지 — 여러 목록/대시보드가 공유. 예전엔 파일마다 라벨/클래스를 개별 정의했다.
export const SCAN_STATUS = {
  running:  { label: "진행 중", cls: "bg-primary-50 text-primary-700" },
  paused:   { label: "일시정지", cls: "bg-amber-50 text-amber-700" },
  queued:   { label: "대기열",  cls: "bg-indigo-50 text-indigo-700" },
  complete: { label: "완료",    cls: "bg-green-50 text-green-700" },
  failed:   { label: "실패",    cls: "bg-red-50 text-red-600" },
  stopped:  { label: "중단됨",  cls: "bg-amber-50 text-amber-700" },
  interrupted: { label: "중단(재개 가능)", cls: "bg-orange-50 text-orange-700" },
};

// 알 수 없는 상태는 완료 스타일로 폴백(기존 동작 유지).
export function statusBadge(s) {
  return SCAN_STATUS[s] || SCAN_STATUS.complete;
}

// 실효 상태: running 인데 서버 progress.paused=true 면 '일시정지'로 본다(백엔드 status 는 running 유지).
export function effectiveStatus(scan) {
  if (scan?.status === "running" && scan?.progress?.paused) return "paused";
  return scan?.status;
}
