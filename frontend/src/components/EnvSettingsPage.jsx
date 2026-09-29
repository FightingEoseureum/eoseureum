import { useEffect, useState } from "react";
import { Settings2, Loader2, Save, ShieldCheck, FileText, Radar, Info, ChevronDown, ChevronRight } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import DashboardCard from "./DashboardCard";
import Toggle from "./Toggle";

/**
 * 환경 설정 — 플랫폼 런타임 설정(검증 프로파일·Browser Discovery·보고서 테마).
 * 백엔드 /api/config (GET 현황 / POST admin). 안전 부분집합만 런타임 반영(재시작 불필요).
 * 판정 로직/위험행위 정책은 변경하지 않는다.
 */
const PROFILES = ["SAFE", "STANDARD", "ADVANCED", "PROOF"];
const PROFILE_TONE = { SAFE: "text-green-700", STANDARD: "text-blue-700", ADVANCED: "text-amber-700", PROOF: "text-red-700" };

export default function EnvSettingsPage() {
  const { apiFetch, auth } = useAuth();
  const isAdmin = auth?.user?.role === "admin";
  const [cfg, setCfg] = useState(null);
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState(null);
  const [showIndividual, setShowIndividual] = useState(false);
  const [templates, setTemplates] = useState([]);   // 보고서 템플릿(비관리자 조회용)

  const load = async () => {
    try {
      const tr = await apiFetch("/api/templates");
      if (tr.ok) setTemplates((await tr.json()).items || []);
    } catch { /* 조회 전용 */ }
    try {
      const res = await apiFetch("/api/config");
      if (res.ok) {
        const d = await res.json();
        setCfg(d);
        setForm({
          validation_profile: d.validation?.requested_profile || d.validation?.profile || "SAFE",
          allow_proof_mode: !!d.validation?.allow_proof,
          browser_discovery: !!d.discovery?.browser_discovery,
          auth_browser_crawl: !!d.discovery?.auth_browser_crawl,
          graphql_discovery: !!d.discovery?.graphql_discovery,
          websocket_discovery: !!d.discovery?.websocket_discovery,
          auth_scan: !!d.advanced?.auth_scan,
          auth_crawl: !!d.advanced?.auth_crawl,
          known_credential_check: !!d.advanced?.known_credential_check,
          unauth_write_bac: !!d.detection?.unauth_write_bac,
          cve_intel: !!d.detection?.cve_intel,
          oob_collaborator: !!d.detection?.oob_collaborator,
          report_theme: d.report?.theme || "corporate_blue",
        });
      }
    } catch { /* ignore */ }
  };
  useEffect(() => { load(); }, []);

  const upd = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const save = async () => {
    setSaving(true); setMsg(null);
    try {
      // 관리자: 전체 설정 저장. 비관리자: 보고서 테마만 저장(테마는 표현 전용, 모두 허용).
      const res = isAdmin
        ? await apiFetch("/api/config", { method: "POST", body: JSON.stringify(form) })
        : await apiFetch("/api/config/report-theme", { method: "POST", body: JSON.stringify({ theme: form.report_theme }) });
      const d = await res.json();
      if (res.ok) {
        setMsg({ ok: true, text: isAdmin ? "저장되었습니다. 다음 스캔/보고서부터 적용됩니다." : "보고서 테마가 저장되었습니다." });
        load();
      } else setMsg({ ok: false, text: d.detail || "저장 실패" });
    } catch (e) { setMsg({ ok: false, text: String(e) }); }
    finally { setSaving(false); }
  };

  if (!cfg) return <div className="flex justify-center py-24"><Loader2 className="w-8 h-8 animate-spin" style={{ color: "#1E3A8A" }} /></div>;

  const v = cfg.validation || {}, r = cfg.report || {};
  const tog = (k) => ({ checked: !!form[k], disabled: !isAdmin, onChange: (val) => upd(k, val) });
  // 여러 설정 키를 하나의 마스터 토글로 묶음(모두 켜져야 on, 토글 시 일괄 적용).
  const mtog = (keys) => ({
    checked: keys.every((k) => !!form[k]),
    disabled: !isAdmin,
    onChange: (val) => setForm((f) => { const n = { ...f }; keys.forEach((k) => { n[k] = val; }); return n; }),
  });
  const DISCOVERY_KEYS = ["browser_discovery", "graphql_discovery", "websocket_discovery"];
  const AUTHSCAN_KEYS = ["auth_scan", "auth_crawl", "auth_browser_crawl"];

  return (
    <div className="space-y-4">
      <div className="il-card p-4 flex items-start gap-3 bg-blue-50/50 border-blue-100">
        <Info className="w-4 h-4 text-primary mt-0.5" />
        <p className="text-xs text-muted leading-relaxed">
          런타임 설정입니다. 변경 시 <b>다음 스캔/보고서부터 즉시 적용</b>(프로세스 재시작 불필요).
          판정(Rule Engine)·심각도·위험행위 금지 정책은 여기서 바꿀 수 없습니다.
          {!isAdmin && <span className="text-amber-600"> (일반 사용자는 보고서 테마만 변경할 수 있습니다)</span>}
        </p>
      </div>

      {/* 검증 프로파일 — 전체 노출(비관리자는 읽기 전용) */}
      <DashboardCard icon={ShieldCheck} iconClass="text-primary" title="검증 프로파일 (Validation)">
        <div className="flex items-center gap-3 mb-3 text-sm">
          <span className="text-muted">현재 실효 프로파일</span>
          <span className={`font-bold ${PROFILE_TONE[v.profile] || ""}`}>{v.profile}</span>
          {v.downgraded && <span className="text-xs text-amber-600">(요청 {v.requested_profile} → 안전 강등)</span>}
        </div>
        <label className="block max-w-xs">
          <span className="text-xs font-medium text-muted">요청 프로파일{!isAdmin && " (조회 전용)"}</span>
          <select disabled={!isAdmin} value={form.validation_profile} onChange={e => upd("validation_profile", e.target.value)}
            className="il-input w-full mt-1 h-9 text-sm disabled:opacity-70">
            {PROFILES.map(p => (
              <option key={p} value={p} disabled={p === "PROOF" && !form.allow_proof_mode}>
                {p}{p === "PROOF" && !form.allow_proof_mode ? " — 승인 필요(ALLOW_PROOF_MODE)" : ""}
              </option>
            ))}
          </select>
        </label>
        {isAdmin && (
          <div className="mt-2">
            <Toggle label="PROOF 모드 허용" hint="실증 확인(명시 승인). 위험 행위는 항상 차단. STANDARD·ADVANCED 는 승인 불필요" {...tog("allow_proof_mode")} />
          </div>
        )}
      </DashboardCard>

      {isAdmin && (
      <DashboardCard icon={Radar} iconClass="text-amber-600" title="고급 점검·탐색 (관리자 전용)">
        <p className="text-xs text-muted mb-2 leading-relaxed">
          권한 있는 대상에만 사용하세요. 인증 계열은 <b>스캔 시작 시 입력한 인증 정보</b>가 있어야 동작합니다.
        </p>
        <Toggle label="심층 공격표면 탐색" hint="브라우저·GraphQL·WebSocket 후보 수집" {...mtog(DISCOVERY_KEYS)} />
        <Toggle label="인증 후 점검" hint="로그인 후 크롤·재점검(자격증명 필요)" {...mtog(AUTHSCAN_KEYS)} />
        <Toggle label="알려진/기본 자격증명 점검" hint="기본 계정(admin/admin 등) 시도 — 계정 잠금 주의" {...tog("known_credential_check")} />
        <Toggle label="미인증 쓰기-BAC" hint="로그인 없이 글 작성·변조·삭제 가능 여부(비파괴)" {...tog("unauth_write_bac")} />
        <Toggle label="React2Shell·CVE 점검" hint="CVE-2025-55182 등 표면 탐지" {...tog("cve_intel")} />
        <Toggle label="OOB 컬래보레이터" hint="blind SSRF/XXE/명령주입 외부 콜백 실증(외부망은 미확증)" {...tog("oob_collaborator")} />

        {/* 개별 항목(세부 제어가 필요한 관리자용) */}
        <button type="button" onClick={() => setShowIndividual((s) => !s)}
          className="mt-2 flex items-center gap-1 text-xs text-muted hover:text-ink">
          {showIndividual ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}개별 항목 세부 설정
        </button>
        {showIndividual && (
          <div className="mt-1 pl-2 border-l-2 border-hairline">
            <Toggle label="Browser Discovery" hint="브라우저 기반 공격 표면 수집" {...tog("browser_discovery")} />
            <Toggle label="GraphQL 후보 수집" {...tog("graphql_discovery")} />
            <Toggle label="WebSocket 후보 수집" {...tog("websocket_discovery")} />
            <Toggle label="인증 스캔" hint="로그인 후 same-origin 크롤·점검" {...tog("auth_scan")} />
            <Toggle label="인증 후 크롤" hint="새로 열린 경로 추가 크롤·재점검" {...tog("auth_crawl")} />
            <Toggle label="인증 후 브라우저 크롤" {...tog("auth_browser_crawl")} />
          </div>
        )}
      </DashboardCard>
      )}

      <DashboardCard icon={FileText} iconClass="text-primary" title="보고서">
        <label className="block max-w-xs">
          <span className="text-xs font-medium text-muted">테마 <span className="text-muted">(모든 사용자 변경 가능)</span></span>
          <select value={form.report_theme} onChange={e => upd("report_theme", e.target.value)}
            className="il-input w-full mt-1 h-9 text-sm">
            {(r.themes || []).map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <div className="text-xs text-muted mt-2">
          글꼴 {r.font} · PDF {r.pdf_available ? "가능" : "불가"}
          {r.html_pdf ? " (HTML→PDF)" : r.docx_pdf ? " (DOCX→PDF)" : ""}
        </div>
      </DashboardCard>

      {/* 보고서 템플릿 — 비관리자 조회 전용(관리자는 정책·템플릿 탭에서 관리) */}
      {!isAdmin && (
        <DashboardCard icon={FileText} iconClass="text-primary" title="보고서 템플릿">
          <p className="text-xs text-muted mb-2">보고서 다운로드 시 선택할 수 있는 템플릿 목록입니다(관리자만 편집).</p>
          {templates.length === 0 ? (
            <p className="text-xs text-muted">등록된 템플릿이 없습니다.</p>
          ) : (
            <ul className="text-sm text-ink space-y-1">
              {templates.map((t) => (
                <li key={t.id} className="flex items-center gap-2">
                  <span className="font-medium">{t.name}</span>
                  {t.is_default === 1 && <span className="text-[11px] text-green-700 bg-green-50 px-1.5 py-0.5 rounded-full">기본</span>}
                  {t.description && <span className="text-xs text-muted">— {t.description}</span>}
                </li>
              ))}
            </ul>
          )}
        </DashboardCard>
      )}

      <div className="flex items-center gap-3">
        <button onClick={save} disabled={saving}
          className="inline-flex items-center gap-2 text-sm text-white rounded-lg px-4 py-2 disabled:opacity-50" style={{ backgroundColor: "#1E3A8A" }}>
          {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />} {isAdmin ? "설정 저장" : "테마 저장"}
        </button>
        {msg && <span className={`text-xs ${msg.ok ? "text-green-600" : "text-danger"}`}>{msg.text}</span>}
      </div>
    </div>
  );
}
