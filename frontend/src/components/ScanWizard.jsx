import { useState, useMemo, useEffect, useRef } from "react";
import {
  Search, Loader2, ChevronLeft, ChevronRight, Check, Globe, Filter,
  Clock, KeyRound, ClipboardCheck, Ban, CalendarClock, Plus, ListChecks,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

const SLOT_MIN = 30;
const MAX_SLOTS = 96;         // 2일 = 48시간 = 96 × 30분
const MIN_SLOTS = 4;          // 최소 2시간 (30분 × 4) — 너무 짧으면 심층 점검 불가
// 프로파일별 기본 시간 상한(30분 슬롯 단위). 상한이며 조기 종료 가능 — 느린 프로파일일수록 넉넉히.
// SAFE(5rps) 6h / STANDARD(10rps) 3h / ADVANCED(100rps)·PROOF 2h.
const PROFILE_DEFAULT_SLOTS = { SAFE: 12, STANDARD: 6, ADVANCED: 4, PROOF: 4 };
const profileDefaultSlots = (p) => PROFILE_DEFAULT_SLOTS[p] || MIN_SLOTS;
const fmtDur = (min) => {
  if (!min) return "제한 없음";
  const h = Math.floor(min / 60), m = min % 60;
  return `${h > 0 ? `${h}시간 ` : ""}${m > 0 ? `${m}분` : h > 0 ? "" : "0분"}`.trim();
};

// mode: "scan"(스캔 시작) | "register"(대상 등록 — 점검 주기 단계 추가)
// editItem: 기존 등록 대상 수정 — 프리필 + 타겟 URL 단계 제외 + 자동 조회(register 모드)
// prefill: 대기 스캔 설정 수정 — 새 스캔 프로세스 그대로(모든 단계) + 스캔 시 작성값 프리필 + 자동 조회
export default function ScanWizard({ onScan, onRegister, disabled, mode = "scan", editItem = null, prefill = null }) {
  const { apiFetch } = useAuth();
  const register = mode === "register" || !!editItem;

  const STEPS = useMemo(() => ([
    ...(editItem ? [] : [{ key: "target", label: "타겟 URL", icon: Globe }]),
    { key: "scope", label: "스캔 범위", icon: Filter },
    { key: "time", label: "허용 시간", icon: Clock },
    { key: "login", label: "로그인 정보", icon: KeyRound },
    ...(register ? [{ key: "schedule", label: "점검 주기", icon: CalendarClock }] : []),
    { key: "confirm", label: "최종 확인", icon: ClipboardCheck },
  ]), [register, editItem]);

  const [stepIdx, setStepIdx] = useState(0);
  const cur = STEPS[stepIdx].key;

  const [url, setUrl] = useState("");
  const [preview, setPreview] = useState(null);
  const [previewing, setPreviewing] = useState(false);
  const [excluded, setExcluded] = useState(() => new Set());
  const [manualExclude, setManualExclude] = useState("");
  const [slots, setSlots] = useState(MIN_SLOTS);   // 프로파일 로드 후 기본값 자동 설정(아래 useEffect)
  const [profile, setProfile] = useState(null);    // 현재 검증 프로파일(시간 기본/최소값 산정용)
  const budgetTouchedRef = useRef(false);           // 사용자가 직접 시간을 정했거나 저장된 예산이 있으면 true → 프로파일 기본값이 덮지 않음
  // 프로파일별 최소 시간 강제 — 그 아래로는 선택 불가(느린 프로파일에서 너무 짧게 잡아 조기 절단되는 것 방지).
  const minSlots = profile ? profileDefaultSlots(profile) : MIN_SLOTS;
  const effSlots = Math.max(slots, minSlots);       // 최소값 하한 적용(프리필/과거값이 낮아도 floor)
  const budgetMin = effSlots * SLOT_MIN;
  const [startLocal, setStartLocal] = useState("");   // 예약 시작(datetime-local). 비우면 즉시.
  const [auth, setAuth] = useState({ login_url: "", username: "", password: "", username_b: "", password_b: "",
    login_method: "auto", login_action: "", login_body_mode: "form", extra_fields_text: "",
    auth_method: "password", session_headers: "", session_cookies: "" });
  const [showAuthAdv, setShowAuthAdv] = useState(false);
  const [pwStored, setPwStored] = useState(false);   // 등록 대상에 저장된 비밀번호 존재(비우면 저장값 사용)
  const setA = (k, v) => setAuth((a) => ({ ...a, [k]: v }));
  // 점검 주기(register 모드)
  const [scanDay, setScanDay] = useState(1);
  const [scanMonths, setScanMonths] = useState(0);   // 0=수동
  const [scanTime, setScanTime] = useState("03:00");
  const [submitting, setSubmitting] = useState(false);

  // 등록된 대상(URL별 저장된 스캔 설정) — 타겟 단계에서 선택해 프리필
  const [registered, setRegistered] = useState([]);
  useEffect(() => {
    apiFetch("/api/watchlist").then((r) => (r.ok ? r.json() : []))
      .then((d) => setRegistered(Array.isArray(d) ? d : [])).catch(() => {});
  }, [apiFetch]);

  // 현재 프로파일 조회 → 시간 상한 기본값을 프로파일에 맞게 설정(느릴수록 넉넉히).
  // 사용자가 이미 시간을 바꿨거나 저장된 예산을 프리필했으면(budgetTouchedRef) 덮어쓰지 않는다.
  useEffect(() => {
    apiFetch("/api/validation/profile").then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        const prof = d?.profile || "SAFE";
        setProfile(prof);
        if (!budgetTouchedRef.current) setSlots(profileDefaultSlots(prof));
      }).catch(() => {});
  }, [apiFetch]);

  const domain = url.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase();

  // 등록 대상 선택 → 스캔 범위(프리뷰)를 제외한 각 단계 정보를 프리필(수정 가능). 프리뷰는 재수행 필수.
  const applyTarget = (t) => {
    setUrl(t.domain || "");
    setPreview(null); setExcluded(new Set());
    const budget = Number(t.time_budget_minutes) || 0;
    if (budget > 0) { budgetTouchedRef.current = true; setSlots(Math.max(MIN_SLOTS, Math.min(MAX_SLOTS, Math.round(budget / SLOT_MIN)))); }
    // 기존 auth 상태 보존(auth_method·세션 헤더/쿠키 유지) 후 저장된 로그인 필드만 프리필.
    setAuth((a) => ({ ...a, login_url: t.login_url || "", username: t.login_username || "", password: "" }));
    setPwStored(!!t.has_login_password);   // 저장된 비번 있으면 비워둬도 스캔 시 자동 사용
    setManualExclude(Array.isArray(t.exclude_urls) ? t.exclude_urls.join("\n") : "");
    if (register) { setScanDay(t.scan_day || 1); setScanMonths(t.scan_months || 0); setScanTime(t.scan_time || "03:00"); }
  };
  const targetMatches = useMemo(() => {
    const q = url.trim().toLowerCase().replace(/^https?:\/\//, "");
    return registered.filter((t) => !q || (t.domain || "").toLowerCase().includes(q)).slice(0, 8);
  }, [registered, url]);

  const previewFor = async (target) => {
    const t = (target || "").trim();
    if (!t) return;
    setPreviewing(true);
    try {
      const res = await apiFetch("/api/scan/preview", { method: "POST", body: JSON.stringify({ url: t }) });
      if (res.ok) {
        const pv = await res.json();
        setPreview(pv);
        const others = (pv.origins || []).map((o) => o.origin).filter((o) => o !== pv.base_origin);
        setExcluded(new Set(others));
      } else setPreview({ base_origin: t, origins: [], count: 0, error: "미리보기 실패" });
    } catch { setPreview({ base_origin: t, origins: [], count: 0, error: "미리보기 실패" }); }
    finally { setPreviewing(false); }
  };
  const runPreview = () => previewFor(url);

  // 수정 모드: 등록 정보 프리필 + 타겟 URL 단계 제외 + 자동 조회(스캔 범위 준비)
  useEffect(() => {
    if (!editItem) return;
    setUrl(editItem.domain || "");
    const budget = Number(editItem.time_budget_minutes) || 0;
    if (budget > 0) { budgetTouchedRef.current = true; setSlots(Math.max(MIN_SLOTS, Math.min(MAX_SLOTS, Math.round(budget / SLOT_MIN)))); }
    setAuth((a) => ({ ...a, login_url: editItem.login_url || "", username: editItem.login_username || "", password: "" }));
    setManualExclude(Array.isArray(editItem.exclude_urls) ? editItem.exclude_urls.join("\n") : "");
    setScanDay(editItem.scan_day || 1); setScanMonths(editItem.scan_months || 0); setScanTime(editItem.scan_time || "03:00");
    setStepIdx(0);
    previewFor(editItem.domain);
  }, [editItem]);   // eslint-disable-line

  // 대기 스캔 설정 수정: 새 스캔 프로세스 그대로(mode="scan", 타겟 단계 유지) + 스캔 시 작성값 프리필 + 자동 조회.
  useEffect(() => {
    if (!prefill) return;
    setUrl(prefill.domain || "");
    const budget = Number(prefill.time_budget_minutes) || 0;
    if (budget > 0) { budgetTouchedRef.current = true; setSlots(Math.max(MIN_SLOTS, Math.min(MAX_SLOTS, Math.round(budget / SLOT_MIN)))); }
    setAuth((a) => ({ ...a, login_url: prefill.login_url || "", username: prefill.login_username || "", password: "" }));
    setManualExclude(Array.isArray(prefill.exclude_urls) ? prefill.exclude_urls.join("\n") : "");
    if (prefill.start_ts) {
      const d = new Date(prefill.start_ts * 1000);
      if (d.getTime() > Date.now()) {
        const p2 = (n) => String(n).padStart(2, "0");
        setStartLocal(`${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}T${p2(d.getHours())}:${p2(d.getMinutes())}`);
      }
    }
    setStepIdx(0);
    previewFor(prefill.domain);
  }, [prefill]);   // eslint-disable-line
  const toggleExclude = (o) => setExcluded((prev) => { const n = new Set(prev); n.has(o) ? n.delete(o) : n.add(o); return n; });

  const authError = useMemo(() => {
    const { login_url, username, password, username_b, password_b } = auth;
    if (password && !(login_url && username)) return "계정 A 비밀번호를 넣으려면 로그인 URL과 아이디가 필요합니다.";
    if (username && !login_url) return "아이디를 넣으려면 로그인 URL이 필요합니다.";
    if (password_b && !(login_url && username_b)) return "계정 B 비밀번호를 넣으려면 로그인 URL과 계정 B 아이디가 필요합니다.";
    if (username_b && !login_url) return "계정 B 아이디를 넣으려면 로그인 URL이 필요합니다.";
    if (username_b && !username) return "계정 B를 쓰려면 계정 A를 먼저 입력하세요.";
    return null;
  }, [auth]);
  const authProvided = !!(auth.login_url || auth.username || auth.password
    || auth.session_headers || auth.session_cookies);

  const canNext = () => {
    // 앞 단계가 수행되어야 다음으로(참조 필요). 로그인은 선택이라 예외.
    // 타겟: 조회가 성공(오류 없음 + 오리진 1개 이상)해야만 진행 — 범위 미정 스캔 방지.
    if (cur === "target") return !!domain && !!preview && !preview.error && (preview.origins?.length > 0);
    if (cur === "time") return slots > 0;                        // 시간 제한 필수
    if (cur === "login") return !authError;                      // 미입력 OK, 규칙 위반만 차단
    return true;
  };

  const collect = () => {
    // 허용 오리진(allowlist) = 체크된 도메인. 그 오리진의 모든 하부 URL 점검, 다른 오리진은 제외.
    const allow = preview && Array.isArray(preview.origins)
      ? preview.origins.map((o) => o.origin).filter((o) => !excluded.has(o)) : [];
    // 추가 차단(blocklist) = 직접 입력한 하위 경로/URL → 허용 오리진 안이라도 차단(부분일치).
    const manual = manualExclude.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
    const options = {};
    if (allow.length) options.include_urls = allow;
    if (manual.length) options.exclude_urls = manual;
    if (budgetMin > 0) options.time_budget_minutes = budgetMin;
    if (startLocal) {
      const ts = Math.floor(new Date(startLocal).getTime() / 1000);
      if (ts > Date.now() / 1000 + 30) options.start_ts = ts;   // 30초 이상 미래일 때만 예약
    }
    const authObj = {};
    for (const [k, v] of Object.entries(auth)) {
      if (k === "extra_fields_text") continue;
      if (typeof v === "string" && v.trim()) authObj[k] = v.trim();
    }
    // 추가 본문 필드: "name=value" 줄 파싱 → dict(토큰 등)
    const ef = {};
    (auth.extra_fields_text || "").split("\n").forEach((ln) => {
      const i = ln.indexOf("=");
      if (i > 0) { const kk = ln.slice(0, i).trim(); if (kk) ef[kk] = ln.slice(i + 1).trim(); }
    });
    if (Object.keys(ef).length) authObj.extra_fields = ef;
    // 기본값은 전송 생략(백엔드 기본과 동일)
    if (authObj.login_method === "auto") delete authObj.login_method;
    if (authObj.login_body_mode === "form") delete authObj.login_body_mode;
    return { include_urls: allow, exclude_urls: manual, options, authObj };
  };

  const finish = async () => {
    if (!domain || disabled || submitting) return;
    const { exclude_urls, options, authObj } = collect();
    const cfg = {   // URL별 저장할 스캔 설정. 비밀번호는 서버에서 Fernet 암호화 저장(입력했을 때만).
      exclude_urls, time_budget_minutes: budgetMin,
      login_url: authObj.login_url || "", login_username: authObj.username || "",
      login_password: authObj.password || "",
    };
    if (register) {
      setSubmitting(true);
      try {
        const notes = [
          exclude_urls.length ? `제외 ${exclude_urls.length}건` : "",
          budgetMin ? `허용 ${fmtDur(budgetMin)}` : "",
          authObj.login_url ? "로그인 설정" : "",
        ].filter(Boolean).join(" · ");
        const ok = await onRegister?.({
          domain, scan_day: Number(scanDay) || 1, scan_months: Number(scanMonths) || 0,
          scan_time: scanTime || "03:00", enabled: Number(scanMonths) > 0, notes, ...cfg,
        });
        if (ok === false) return;
      } finally { setSubmitting(false); }
    } else {
      // 승인 시 등록 대상(설정만)으로 저장(upsert). update_schedule:false → 정기 스캔 스케줄은 건드리지 않음.
      apiFetch("/api/watchlist", { method: "POST", body: JSON.stringify({ domain, description: "스캔 등록", update_schedule: false, ...cfg }) }).catch(() => {});
      onScan(domain, "", Object.keys(authObj).length ? authObj : undefined, Object.keys(options).length ? options : undefined);
    }
  };

  const scheduleSummary = Number(scanMonths) > 0
    ? `${Number(scanMonths) === 1 ? "매월" : `${scanMonths}개월마다`} ${scanDay}일 ${scanTime}`
    : "수동(자동 점검 없음)";

  return (
    <div className="space-y-5">
      {/* 스텝 인디케이터 */}
      <div className="flex items-center gap-1 flex-wrap">
        {STEPS.map((s, i) => {
          const Icon = s.icon; const active = i === stepIdx, done = i < stepIdx;
          return (
            <div key={s.key} className="flex items-center gap-1">
              <button onClick={() => i <= stepIdx && setStepIdx(i)} disabled={i > stepIdx}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors ${active ? "bg-primary text-white" : done ? "text-primary-700 bg-primary-50" : "text-muted"} ${i > stepIdx ? "cursor-not-allowed" : ""}`}>
                {done ? <Check className="w-3.5 h-3.5" /> : <Icon className="w-3.5 h-3.5" />}{s.label}
              </button>
              {i < STEPS.length - 1 && <ChevronRight className="w-3.5 h-3.5 text-hairline" />}
            </div>
          );
        })}
      </div>

      <div className="min-h-[220px]">
        {cur === "target" && (
          <div className="space-y-3">
            <label className="text-sm font-semibold text-ink">타겟 URL</label>
            <p className="text-xs text-muted">본인이 소유하거나 점검 권한이 있는 대상만 입력하세요.</p>
            <div className="flex gap-2">
              <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="example.com 또는 https://example.com"
                className="il-input flex-1" onKeyDown={(e) => e.key === "Enter" && runPreview()} />
              <button onClick={runPreview} disabled={!url.trim() || previewing}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-white text-sm font-semibold disabled:opacity-50" style={{ background: "#1E3A8A" }}>
                {previewing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}함께 확인되는 URL 조회
              </button>
            </div>

            {/* 등록된 대상에서 선택 → 각 단계 정보 프리필(스캔 범위 제외, 조회는 필수) */}
            {targetMatches.length > 0 && (
              <div className="border border-hairline rounded-lg overflow-hidden">
                <div className="px-3 py-1.5 bg-gray-50 border-b border-hairline text-[11px] font-semibold text-muted flex items-center gap-1.5">
                  <ListChecks className="w-3.5 h-3.5" />등록된 대상에서 선택(설정 프리필)
                </div>
                <div className="max-h-40 overflow-y-auto divide-y divide-hairline">
                  {targetMatches.map((t) => (
                    <button key={t.id} onClick={() => applyTarget(t)}
                      className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-gray-50 transition-colors">
                      <span className="text-xs font-mono text-ink truncate flex-1">{t.domain}</span>
                      <span className="text-[10px] text-muted flex-shrink-0">
                        {Number(t.time_budget_minutes) > 0 && `최대 ${Math.floor(t.time_budget_minutes / 60)}h${t.time_budget_minutes % 60 ? (t.time_budget_minutes % 60) + "m" : ""} · `}
                        {Array.isArray(t.exclude_urls) && t.exclude_urls.length ? `제외 ${t.exclude_urls.length} · ` : ""}
                        {t.login_url ? "로그인" : "공개 영역"}
                      </span>
                    </button>
                  ))}
                </div>
                <div className="px-3 py-1.5 text-[10px] text-muted border-t border-hairline">선택해도 “함께 확인되는 URL 조회”는 반드시 다시 수행해야 다음 단계로 넘어갑니다.</div>
              </div>
            )}
            {previewing && (
              <div className="border border-hairline rounded-lg p-3 text-sm text-muted flex items-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin" />대상에서 함께 확인되는 URL을 조회하는 중…
              </div>
            )}
            {!previewing && preview && (
              <div className="border border-hairline rounded-lg p-3 text-sm space-y-2">
                {preview.error ? <span className="text-red-600">{preview.error} — 조회에 실패하면 스캔 범위를 정할 수 없어 다음 단계로 넘어갈 수 없습니다. URL을 확인하고 다시 조회하세요.</span> : (
                  <>
                    <div className="text-ink">함께 확인되는 URL <b className="text-primary">{preview.count}</b>개 · 도메인(오리진) <b className="text-primary">{preview.origins?.length || 0}</b>개를 확인했습니다. 다음 단계에서 스캔할 도메인을 고르고, 추가로 차단할 하위 경로/URL을 지정할 수 있습니다.</div>
                    {preview.origins?.length > 0 && (
                      <div className="max-h-40 overflow-y-auto border border-hairline rounded bg-gray-50 divide-y divide-hairline">
                        {preview.origins.slice(0, 30).map((o) => (
                          <div key={o.origin} className="px-2.5 py-1 text-[11px] font-mono text-muted truncate flex justify-between gap-2">
                            <span className="truncate">{o.origin}</span><span className="flex-shrink-0">{o.count}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
            {!preview && !previewing && <p className="text-[11px] text-muted">먼저 위 버튼으로 URL을 조회해야 다음 단계로 넘어갈 수 있습니다.</p>}
          </div>
        )}

        {cur === "scope" && (
          <div className="space-y-3">
            <label className="text-sm font-semibold text-ink">스캔 도메인(오리진) 선택</label>
            {!preview || !preview.origins || preview.origins.length === 0 ? (
              <p className="text-xs text-muted">조회된 도메인이 없습니다. 아래 추가 차단만 적용됩니다.</p>
            ) : (
              <>
                <p className="text-[11px] text-muted">대상 도메인은 기본 포함됩니다. 함께 발견된 다른 도메인은 필요할 때만 체크하세요. <b>선택한 도메인의 모든 하부 URL을 점검</b>하고, 그 외 오리진(도메인)은 스캔하지 않습니다.</p>
                <div className="border border-hairline rounded-lg max-h-56 overflow-y-auto divide-y divide-hairline">
                  {preview.origins.map((o) => {
                    const on = !excluded.has(o.origin);
                    const isBase = o.origin === preview.base_origin;
                    return (
                      <button key={o.origin} onClick={() => toggleExclude(o.origin)} className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-gray-50 transition-colors">
                        {on ? <Check className="w-4 h-4 text-green-600 flex-shrink-0" /> : <Ban className="w-4 h-4 text-red-500 flex-shrink-0" />}
                        <span className={`text-xs font-mono truncate flex-1 ${on ? "text-ink" : "text-muted line-through"}`}>{o.origin}</span>
                        {isBase && <span className="text-[10px] text-primary-700 bg-primary-50 px-1.5 py-0.5 rounded-full flex-shrink-0">대상</span>}
                        <span className="text-[11px] text-muted flex-shrink-0">URL {o.count}</span>
                      </button>
                    );
                  })}
                </div>
                <p className="text-[11px] text-muted">포함 도메인 {preview.origins.length - excluded.size} / 전체 {preview.origins.length} · 수집 URL {preview.count}개</p>
              </>
            )}
            <div className="pt-1">
              <label className="text-xs font-semibold text-ink">추가 차단 — 하위 경로/URL (선택)</label>
              <textarea value={manualExclude} onChange={(e) => setManualExclude(e.target.value)} rows={3}
                placeholder={"/admin\n/logout\nhttps://example.com/danger"} className="il-input w-full mt-1 text-xs font-mono" />
              <p className="text-[11px] text-muted mt-1">허용 목록 안이라도 여기 입력한 경로/URL은 차단합니다(줄바꿈/쉼표 구분, 부분일치).</p>
            </div>
          </div>
        )}

        {cur === "time" && (
          <div className="space-y-3">
            <label className="text-sm font-semibold text-ink">허용 시간 — 시작 예약 · 최대 진행 시간</label>
            <div className="flex items-end gap-3 flex-wrap">
              <div>
                <label className="text-xs text-muted">시작 시각 <span className="text-muted">(비우면 즉시)</span></label>
                <input type="datetime-local" value={startLocal} onChange={(e) => setStartLocal(e.target.value)} className="il-input mt-1 h-9 text-sm" />
              </div>
              {startLocal && <button onClick={() => setStartLocal("")} className="text-xs text-muted hover:text-ink underline pb-2">즉시 시작</button>}
            </div>
            <div className="flex items-center gap-2 pt-1">
              <span className="text-sm text-muted">최대 진행 시간 <span className="text-red-500">*</span></span>
              <select value={effSlots} onChange={(e) => { budgetTouchedRef.current = true; setSlots(Number(e.target.value)); }} className="il-input h-9 text-sm w-40">
                {Array.from({ length: MAX_SLOTS - minSlots + 1 }, (_, i) => i + minSlots).map((n) => (
                  <option key={n} value={n}>{fmtDur(n * SLOT_MIN)}</option>
                ))}
              </select>
              <span className="text-xs text-muted">(30분 단위, 최소 {fmtDur(minSlots * SLOT_MIN)} ~ 48시간 · 필수)</span>
            </div>
            {profile && (
              <p className="text-xs text-muted">현재 프로파일 <b className="text-ink">{profile}</b> — <b>최소 {fmtDur(minSlots * SLOT_MIN)}</b> (그 아래로는 선택 불가)
                {profile === "SAFE" && " · 초당 5개·순차라 넉넉히 필요 — 더 점검할 게 없으면 자동 조기 종료"}
                . 기본값으로 설정되며, 더 길게 조정 가능합니다.</p>
            )}
            <p className="text-xs text-muted">선택한 시간은 <b>최대 상한</b>입니다. 예약 시각부터 크롤링·취약점 점검을 심도 있게(반복) 수행하며, <b>더 점검할 대상이 없으면 상한 전에 자동으로 종료</b>합니다. 상한을 초과하면 그때까지의 부분 보고서를 생성합니다. 무제한은 위험하므로 반드시 상한을 지정해야 합니다.</p>
            {auth.auth_method === "session" && budgetMin > 60 && (
              <p className="text-[11px] text-amber-600">⚠️ 세션 주입 인증 스캔: 토큰이 보통 <b>~1시간</b>이면 만료돼요. 상한이 길면 후반부는 인증영역을 못 볼 수 있으니, 인증 점검이 핵심이면 <b>빠른 프로파일</b> 또는 <b>짧은 상한</b>을 권장합니다.</p>
            )}
          </div>
        )}

        {cur === "login" && (
          <div className="space-y-3">
            <label className="text-sm font-semibold text-ink">인증 정보 <span className="text-muted font-normal">(선택 — 없으면 공개 영역만 점검)</span></label>
            {/* 인증 방식 — 비밀번호 로그인 vs 세션 주입(캡챠·OTP·SSO 대상) */}
            <div className="flex gap-2 text-xs">
              {[["password", "비밀번호 로그인"], ["session", "세션 주입 (캡챠·OTP·SSO)"]].map(([k, label]) => (
                <button type="button" key={k} onClick={() => setA("auth_method", k)}
                  className={`px-3 py-1.5 rounded-lg border ${auth.auth_method === k ? "border-primary text-primary bg-primary/5 font-semibold" : "border-hairline text-muted"}`}>
                  {label}
                </button>
              ))}
            </div>
            {auth.auth_method === "session" && (
              <div className="space-y-2">
                <p className="text-xs text-muted">캡챠·OTP·SSO로 자동 로그인이 막힌 대상은, 브라우저로 <b>직접 로그인</b>한 뒤 <b>인증 헤더/쿠키</b>를 붙여 넣으세요. 스캐너가 로그인 폼을 건너뛰고 그 세션으로 점검합니다. <b>대상 호스트로만</b> 전송되며 저장되지 않습니다.</p>
                <textarea className="il-input w-full font-mono text-xs" rows={3}
                  placeholder={"인증 헤더 (한 줄에 하나)\n예: Authorization: JWT eyJ...\nX-Custom: value"}
                  value={auth.session_headers} onChange={(e) => setA("session_headers", e.target.value)} />
                <textarea className="il-input w-full font-mono text-xs" rows={2}
                  placeholder={"쿠키 (선택) — 예: sessionid=abc; csrftoken=xyz"}
                  value={auth.session_cookies} onChange={(e) => setA("session_cookies", e.target.value)} />
                <p className="text-[11px] text-muted">세션이 만료되면(토큰 exp 초과 등) 점검 도중 401이 날 수 있어, <b>유효시간 내에 끝나도록 시간 상한을 짧게</b> 잡는 걸 권장합니다.</p>
              </div>
            )}
            {auth.auth_method !== "session" && (<>
            <p className="text-xs text-muted">계정을 넣으면 로그인 후 영역까지 점검합니다. 아이디는 <b>최대 2개</b>까지 입력 가능하며, 2개를 넣으면 계정 간 접근통제(권한 분리·수평 권한상승/IDOR) 점검이 강화됩니다.</p>
            <input className="il-input" placeholder="로그인 URL (예: https://site/login)" value={auth.login_url} onChange={(e) => setA("login_url", e.target.value)} />
            <div>
              <div className="text-[11px] font-semibold text-muted mb-1">계정 A</div>
              <div className="grid grid-cols-2 gap-2">
                <input className="il-input" placeholder="아이디" value={auth.username} onChange={(e) => setA("username", e.target.value)} autoComplete="off" />
                <input className="il-input" type="password" placeholder={pwStored && !auth.password ? "저장된 비밀번호 사용" : "비밀번호"} value={auth.password} onChange={(e) => setA("password", e.target.value)} autoComplete="new-password" />
              </div>
              {pwStored && (
                <p className="text-[11px] text-green-700 mt-1">🔒 저장된 비밀번호가 있어요 — 비워두면 저장된 값으로 로그인합니다(새로 입력하면 교체·재저장).</p>
              )}
            </div>
            <div>
              <div className="text-[11px] font-semibold text-muted mb-1">계정 B <span className="font-normal">(선택 — 접근통제 점검용)</span></div>
              <div className="grid grid-cols-2 gap-2">
                <input className="il-input" placeholder="아이디 (두 번째 계정)" value={auth.username_b} onChange={(e) => setA("username_b", e.target.value)} autoComplete="off" />
                <input className="il-input" type="password" placeholder="비밀번호" value={auth.password_b} onChange={(e) => setA("password_b", e.target.value)} autoComplete="new-password" />
              </div>
            </div>
            <button type="button" onClick={() => setShowAuthAdv((s) => !s)}
              className="text-xs text-muted hover:text-ink">
              {showAuthAdv ? "▾" : "▸"} 로그인 고급 설정 (JS/SPA · 토큰 · 해시 비밀번호 대응)
            </button>
            {showAuthAdv && (
              <div className="space-y-2 pl-2 border-l-2 border-hairline">
                <div>
                  <label className="text-[11px] font-semibold text-muted">로그인 방식</label>
                  <select className="il-input w-full h-9 text-sm" value={auth.login_method} onChange={(e) => setA("login_method", e.target.value)}>
                    <option value="auto">자동 (브라우저 시도 → 실패 시 HTTP)</option>
                    <option value="browser">브라우저 강제 (JS/SPA · 해시PW · 토큰 자동 처리)</option>
                    <option value="http">HTTP 폼만</option>
                  </select>
                </div>
                <input className="il-input" placeholder="실제 로그인 요청 URL (선택 — 폼 action이 다를 때, 예: /api/auth/login)"
                  value={auth.login_action} onChange={(e) => setA("login_action", e.target.value)} />
                <div>
                  <label className="text-[11px] font-semibold text-muted">HTTP 본문 형식</label>
                  <select className="il-input w-full h-9 text-sm" value={auth.login_body_mode} onChange={(e) => setA("login_body_mode", e.target.value)}>
                    <option value="form">form (x-www-form-urlencoded)</option>
                    <option value="json">JSON (application/json)</option>
                  </select>
                </div>
                <textarea className="il-input w-full font-mono text-xs" rows={3}
                  placeholder={"추가 본문 필드 (선택, 한 줄에 name=value)\n예: csrf_token=abc\ndevice_id=xyz"}
                  value={auth.extra_fields_text} onChange={(e) => setA("extra_fields_text", e.target.value)} />
                <p className="text-[11px] text-muted">비밀번호가 클라이언트에서 해시/암호화되거나 토큰이 붙는 사이트는 <b>브라우저 방식</b>을 권장합니다(실제 JS 실행).</p>
              </div>
            )}
            </>)}
            {authError && <p className="text-xs text-red-600">{authError}</p>}
            <p className="text-[11px] text-muted">이 스캔에만 사용되며 서버에 저장되지 않습니다.</p>
          </div>
        )}

        {cur === "schedule" && (
          <div className="space-y-3">
            <label className="text-sm font-semibold text-ink">점검 주기</label>
            <p className="text-xs text-muted">얼마에 한 번씩 자동 점검할지 지정하세요. 주기를 0으로 두면 수동(자동 점검 없음)입니다.</p>
            <div className="flex items-end gap-3 flex-wrap">
              <div>
                <label className="text-xs text-muted">주기(개월, 0=수동)</label>
                <input type="number" min={0} max={24} value={scanMonths} onChange={(e) => setScanMonths(e.target.value)} className="il-input w-28 mt-1" />
              </div>
              <div>
                <label className="text-xs text-muted">월 중 일자</label>
                <input type="number" min={1} max={31} value={scanDay} onChange={(e) => setScanDay(e.target.value)} className="il-input w-20 mt-1" />
              </div>
              <div>
                <label className="text-xs text-muted">시각</label>
                <input type="time" value={scanTime} onChange={(e) => setScanTime(e.target.value)} className="il-input w-28 mt-1" />
              </div>
            </div>
            <div className="text-sm text-ink">→ <b className="text-primary">{scheduleSummary}</b></div>
          </div>
        )}

        {cur === "confirm" && (
          <div className="space-y-3">
            <label className="text-sm font-semibold text-ink">최종 확인</label>
            <table className="w-full text-sm">
              <tbody className="divide-y divide-hairline">
                {[
                  ["타겟", domain || "-"],
                  ["스캔 도메인", preview ? `${Math.max(0, (preview.origins?.length || 0) - excluded.size)} / ${preview.origins?.length || 0}개 오리진` : "미조회"],
                  ["추가 차단", `${manualExclude.split(/[\n,]+/).filter((s) => s.trim()).length}건`],
                  ["시작", startLocal ? new Date(startLocal).toLocaleString() : "즉시"],
                  ["최대 진행 시간", fmtDur(budgetMin)],
                  ["로그인", authProvided
                    ? (auth.username
                        ? `${auth.username}${auth.username_b ? ` · ${auth.username_b} (계정 2개)` : ""}@${auth.login_url}`
                        : auth.login_url)
                    : "공개 영역만(로그인 없음)"],
                  ...(register ? [["점검 주기", scheduleSummary]] : []),
                ].map(([k, v], i) => (
                  <tr key={i}><td className="py-2 pr-4 text-muted w-28">{k}</td><td className="py-2 text-ink font-mono break-all">{String(v)}</td></tr>
                ))}
              </tbody>
            </table>
            <p className="text-xs text-muted">{register ? "등록하면 대상 관리에 저장되고, 주기 설정 시 자동 점검됩니다." : "승인하면 스캔이 시작되고, 대상은 등록된 URL(대상 관리)에 저장됩니다."}</p>
          </div>
        )}
      </div>

      <div className="flex items-center justify-between pt-2 border-t border-hairline">
        <button onClick={() => setStepIdx((s) => Math.max(0, s - 1))} disabled={stepIdx === 0}
          className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink disabled:opacity-40"><ChevronLeft className="w-4 h-4" />이전</button>
        {stepIdx < STEPS.length - 1 ? (
          <button onClick={() => canNext() && setStepIdx((s) => s + 1)} disabled={!canNext()}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-white text-sm font-semibold disabled:opacity-50" style={{ background: "#1E3A8A" }}>다음<ChevronRight className="w-4 h-4" /></button>
        ) : (
          <button onClick={finish} disabled={disabled || submitting || !domain}
            className="inline-flex items-center gap-2 px-5 py-2 rounded-xl text-white text-sm font-semibold disabled:opacity-50" style={{ background: "#1E3A8A", boxShadow: "0 4px 14px rgba(30,58,138,0.18)" }}>
            {(disabled || submitting) ? <Loader2 className="w-4 h-4 animate-spin" /> : register ? <Plus className="w-4 h-4" /> : <Search className="w-4 h-4" />}
            {editItem ? "수정 저장" : register ? "대상 등록" : "승인하고 스캔 시작"}
          </button>
        )}
      </div>
    </div>
  );
}
