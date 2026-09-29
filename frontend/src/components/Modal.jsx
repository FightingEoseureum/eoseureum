import { X } from "lucide-react";

// 공용 모달 셸 — 제목 바 + 닫기 버튼 + 본문. 여러 페이지가 동일한 백드롭/카드
// 마크업을 중복 정의하던 것을 단일 컴포넌트로 통합.
// max-h/overflow 는 긴 폼(정책 편집 등)에서 스크롤되도록 상위집합으로 둔다.
export default function Modal({ title, onClose, children, maxWidth = "max-w-lg" }) {
  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 px-4">
      <div className={`bg-white border border-hairline rounded-2xl w-full ${maxWidth} max-h-[90vh] overflow-y-auto`}>
        <div className="flex items-center justify-between px-6 py-4 border-b border-hairline">
          <h3 className="font-semibold text-ink">{title}</h3>
          <button onClick={onClose} className="text-muted hover:text-ink p-1">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="px-6 py-5">{children}</div>
      </div>
    </div>
  );
}
