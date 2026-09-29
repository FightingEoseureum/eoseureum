// Blob 을 파일로 저장(브라우저 다운로드). createObjectURL→a.click→revoke 보일러플레이트를
// 여러 컴포넌트가 복붙하던 것을 단일 헬퍼로 통합.
export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
