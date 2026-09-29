import { useState } from "react";
import { Camera } from "lucide-react";

export default function ScreenshotGallery({ hostResults }) {
  const [selectedImg, setSelectedImg] = useState(null);

  const shots = [];
  for (const hr of (hostResults || [])) {
    for (const svc of (hr.services || [])) {
      const hi = svc.http_info;
      if (hi?.screenshot) {
        shots.push({ label: `${hr.host}:${svc.port}`, filename: hi.screenshot, url: hi.url });
      }
      for (const sp of (svc.sensitive_paths || [])) {
        if (sp.screenshot) {
          shots.push({
            label: `${hr.host}:${svc.port}${sp.path}`,
            filename: sp.screenshot,
            url: (hi?.url || "") + sp.path,
          });
        }
      }
    }
  }

  if (shots.length === 0) {
    return (
      <div className="flex flex-col items-center gap-3 py-12 text-text-muted">
        <Camera className="w-10 h-10 opacity-30" />
        <p className="text-sm">스크린샷이 없습니다. (HTTP 서비스가 발견된 경우 자동 캡처됩니다)</p>
      </div>
    );
  }

  return (
    <>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        {shots.map((s, i) => (
          <div
            key={i}
            className="bg-white border border-hairline rounded-lg overflow-hidden cursor-pointer hover:border-brand-500/50 transition-colors group"
            onClick={() => setSelectedImg(s)}
          >
            <div className="relative bg-gray-50 aspect-video flex items-center justify-center overflow-hidden">
              <img
                src={`/api/screenshots/${s.filename}`}
                alt={s.label}
                className="w-full h-full object-cover object-top group-hover:scale-105 transition-transform duration-300"
                onError={e => { e.target.style.display = "none"; e.target.nextSibling.style.display = "flex"; }}
              />
              <div className="hidden absolute inset-0 items-center justify-center text-text-muted text-xs">
                로드 실패
              </div>
            </div>
            <div className="p-2">
              <p className="text-xs font-mono text-text-muted truncate">{s.label}</p>
              <p className="text-xs text-text-muted truncate">{s.url}</p>
            </div>
          </div>
        ))}
      </div>

      {selectedImg && (
        <div
          className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4"
          onClick={() => setSelectedImg(null)}
        >
          <div className="max-w-5xl w-full" onClick={e => e.stopPropagation()}>
            <div className="bg-white border border-hairline rounded-xl overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-hairline">
                <div>
                  <p className="text-sm font-mono text-ink">{selectedImg.label}</p>
                  <p className="text-xs text-text-muted">{selectedImg.url}</p>
                </div>
                <button
                  onClick={() => setSelectedImg(null)}
                  className="text-text-muted hover:text-ink text-xl leading-none"
                >×</button>
              </div>
              <img
                src={`/api/screenshots/${selectedImg.filename}`}
                alt={selectedImg.label}
                className="w-full"
              />
            </div>
          </div>
        </div>
      )}
    </>
  );
}
