// 공용 토글(체크박스) — 라벨 + 선택적 힌트/비활성 지원.
// PoliciesPage/EnvSettingsPage 가 각각 정의하던 것을 상위집합으로 통합.
export default function Toggle({ label, checked, disabled, onChange, hint }) {
  return (
    <label className="flex items-start gap-2 text-sm text-ink cursor-pointer py-1.5">
      <input
        type="checkbox"
        disabled={disabled}
        checked={!!checked}
        onChange={e => onChange(e.target.checked)}
        className="w-4 h-4 mt-0.5"
      />
      <span>
        {label}
        {hint && <span className="block text-xs text-muted">{hint}</span>}
      </span>
    </label>
  );
}
