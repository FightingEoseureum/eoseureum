import { useEffect, useState } from "react";
import {
  ShieldCheck, FileText, CheckCircle2, Star, Plus, Pencil, Trash2, Loader2, RefreshCw,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import DashboardCard from "./DashboardCard";
import Modal from "./Modal";
import Toggle from "./Toggle";

// 정책 편집 필드 (env 키 → UI)
const PAYLOAD_LEVELS = ["safe", "balanced", "aggressive"];
const POLICY_TOGGLES = [
  ["ENABLE_SQLMAP", "SQLMap 최종 검증"],
  ["SQLMAP_ENUM_DBS", "SQLMap DB 목록 열람(--dbs)"],
  ["ENABLE_TIME_BASED_SQLI", "Time-based SQLi"],
  ["ENABLE_ADVANCED_PAYLOADS", "고위험(aggressive) payload"],
  ["ENABLE_EXTENDED_XSS_PAYLOADS", "검색창 XSS 확장"],
  ["ENABLE_SERVICE_SCAN", "서비스/포트 점검"],
  ["SERVICE_SCAN_USE_NMAP", "nmap -sV 버전 식별"],
];
// 고위험(이중용도) 토글 — 명시 승인 항목. 위험 행위는 여전히 항상 차단되며,
// RCE Proof Mode 는 '무해 고정 echo 마커(EOSEUREUM_RCE_*)의 반사'만 증거로 허용한다.
const POLICY_TOGGLES_HIGH_RISK = [
  ["RCE_PROOF_MODE", "RCE Proof Mode (무해 echo 마커만 · 고위험 승인 항목)"],
];
const TEMPLATE_TOGGLES = [
  ["show_ai", "AI 보안 분석가 의견"],
  ["show_coverage", "점검 커버리지 요약"],
  ["show_attack_chain", "AI 공격 체인 분석"],
  ["show_service_scan", "서비스/포트 점검 결과"],
];

export default function PoliciesPage() {
  const { apiFetch, auth } = useAuth();
  const isAdmin = auth?.user?.role === "admin";
  const [policies, setPolicies] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [polModal, setPolModal] = useState(null);   // {mode, data}
  const [tplModal, setTplModal] = useState(null);

  const load = async () => {
    setLoading(true);
    try {
      const [p, t] = await Promise.all([apiFetch("/api/policies"), apiFetch("/api/templates")]);
      setPolicies((await p.json()).items || []);
      setTemplates((await t.json()).items || []);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { load(); }, []);

  const activatePolicy = async (id) => { setBusy(true); try { await apiFetch(`/api/policies/${id}/activate`, { method: "POST" }); await load(); } finally { setBusy(false); } };
  const deletePolicy = async (id) => { if (!confirm("이 정책을 삭제할까요?")) return; const r = await apiFetch(`/api/policies/${id}`, { method: "DELETE" }); if (!r.ok && r.status !== 204) { alert((await r.json().catch(() => ({}))).detail || "삭제 실패"); return; } load(); };
  const setDefaultTpl = async (id) => { setBusy(true); try { await apiFetch(`/api/templates/${id}/default`, { method: "POST" }); await load(); } finally { setBusy(false); } };
  const deleteTpl = async (id) => { if (!confirm("이 템플릿을 삭제할까요?")) return; const r = await apiFetch(`/api/templates/${id}`, { method: "DELETE" }); if (!r.ok && r.status !== 204) { alert((await r.json().catch(() => ({}))).detail || "삭제 실패"); return; } load(); };

  const savePolicy = async (form) => {
    setBusy(true);
    try {
      const body = JSON.stringify({ name: form.name, description: form.description, config: form.config });
      const r = form.id
        ? await apiFetch(`/api/policies/${form.id}`, { method: "PATCH", body })
        : await apiFetch("/api/policies", { method: "POST", body });
      if (!r.ok) { alert("저장 실패"); return; }
      setPolModal(null); await load();
    } finally { setBusy(false); }
  };
  const saveTemplate = async (form) => {
    setBusy(true);
    try {
      const body = JSON.stringify({ name: form.name, description: form.description, options: form.options });
      const r = form.id
        ? await apiFetch(`/api/templates/${form.id}`, { method: "PATCH", body })
        : await apiFetch("/api/templates", { method: "POST", body });
      if (!r.ok) { alert("저장 실패"); return; }
      setTplModal(null); await load();
    } finally { setBusy(false); }
  };

  if (loading) return <div className="flex justify-center py-24"><Loader2 className="w-8 h-8 animate-spin" style={{ color: "#1E3A8A" }} /></div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <button onClick={load} className="flex items-center gap-1.5 text-xs text-muted hover:text-ink bg-white border border-hairline px-3 py-1.5 rounded-lg">
          <RefreshCw className="w-3.5 h-3.5" />새로고침
        </button>
      </div>

      {/* 스캔 정책 */}
      <DashboardCard icon={ShieldCheck} iconClass="text-primary" title="스캔 정책 (Scan Policy)"
        action={isAdmin && <button onClick={() => setPolModal({ mode: "new", data: { name: "", description: "", config: { PROBE_PAYLOAD_LEVEL: "balanced" } } })} className="il-btn-primary text-xs px-3 py-1.5 flex items-center gap-1"><Plus className="w-3.5 h-3.5" />새 정책</button>}>
        <p className="text-xs text-muted mb-3">활성 정책의 설정이 이후 시작되는 모든 스캔에 적용됩니다(서버 재시작 없이 즉시).</p>
        <div className="space-y-2">
          {policies.map(p => (
            <div key={p.id} className="border border-hairline rounded-lg px-4 py-3 flex items-start gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-semibold text-ink">{p.name}</span>
                  {p.is_active === 1 && <span className="text-[11px] bg-green-50 text-green-700 border border-green-200 rounded-full px-2 py-0.5 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" />활성</span>}
                  {p.builtin === 1 && <span className="text-[11px] text-muted bg-gray-100 rounded-full px-2 py-0.5">내장</span>}
                </div>
                <p className="text-xs text-muted mt-0.5">{p.description}</p>
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {Object.entries(p.config || {}).map(([k, v]) => (
                    <code key={k} className="text-[10px] bg-gray-100 text-ink rounded px-1 py-0.5">{k.replace(/^ENABLE_|^PROBE_/, "")}={v}</code>
                  ))}
                </div>
              </div>
              {isAdmin && (
                <div className="flex items-center gap-1 flex-shrink-0">
                  {p.is_active !== 1 && <button onClick={() => activatePolicy(p.id)} disabled={busy} className="text-xs text-primary border border-primary-200 bg-primary-50 rounded-lg px-2.5 py-1 hover:bg-primary-100">활성화</button>}
                  <button onClick={() => setPolModal({ mode: "edit", data: { id: p.id, name: p.name, description: p.description, config: { ...p.config } } })} className="p-1.5 text-muted hover:text-ink rounded"><Pencil className="w-3.5 h-3.5" /></button>
                  {p.builtin !== 1 && <button onClick={() => deletePolicy(p.id)} className="p-1.5 text-muted hover:text-red-600 rounded"><Trash2 className="w-3.5 h-3.5" /></button>}
                </div>
              )}
            </div>
          ))}
        </div>
      </DashboardCard>

      {/* 보고서 템플릿 */}
      <DashboardCard icon={FileText} iconClass="text-primary" title="보고서 템플릿 (Report Template)"
        action={isAdmin && <button onClick={() => setTplModal({ mode: "new", data: { name: "", description: "", options: { org_name: "Eoseureum Security", show_ai: true, show_coverage: true, show_attack_chain: true, show_service_scan: true } } })} className="il-btn-primary text-xs px-3 py-1.5 flex items-center gap-1"><Plus className="w-3.5 h-3.5" />새 템플릿</button>}>
        <p className="text-xs text-muted mb-3">기본 템플릿이 보고서 다운로드(DOCX) 시 적용됩니다 — 기관명/섹션 포함 여부.</p>
        <div className="space-y-2">
          {templates.map(t => (
            <div key={t.id} className="border border-hairline rounded-lg px-4 py-3 flex items-start gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-semibold text-ink">{t.name}</span>
                  {t.is_default === 1 && <span className="text-[11px] bg-amber-50 text-amber-700 border border-amber-200 rounded-full px-2 py-0.5 flex items-center gap-1"><Star className="w-3 h-3" />기본</span>}
                  {t.builtin === 1 && <span className="text-[11px] text-muted bg-gray-100 rounded-full px-2 py-0.5">내장</span>}
                </div>
                <p className="text-xs text-muted mt-0.5">{t.description}</p>
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {TEMPLATE_TOGGLES.map(([k, lbl]) => (
                    <span key={k} className={`text-[10px] rounded px-1 py-0.5 border ${t.options?.[k] ? "bg-primary-50 text-primary border-primary-100" : "bg-gray-100 text-muted border-gray-200 line-through"}`}>{lbl}</span>
                  ))}
                </div>
              </div>
              {isAdmin && (
                <div className="flex items-center gap-1 flex-shrink-0">
                  {t.is_default !== 1 && <button onClick={() => setDefaultTpl(t.id)} disabled={busy} className="text-xs text-amber-700 border border-amber-200 bg-amber-50 rounded-lg px-2.5 py-1 hover:bg-amber-100">기본 지정</button>}
                  <button onClick={() => setTplModal({ mode: "edit", data: { id: t.id, name: t.name, description: t.description, options: { ...t.options } } })} className="p-1.5 text-muted hover:text-ink rounded"><Pencil className="w-3.5 h-3.5" /></button>
                  {t.builtin !== 1 && <button onClick={() => deleteTpl(t.id)} className="p-1.5 text-muted hover:text-red-600 rounded"><Trash2 className="w-3.5 h-3.5" /></button>}
                </div>
              )}
            </div>
          ))}
        </div>
      </DashboardCard>

      {polModal && <PolicyModal initial={polModal.data} onSave={savePolicy} onClose={() => setPolModal(null)} busy={busy} />}
      {tplModal && <TemplateModal initial={tplModal.data} onSave={saveTemplate} onClose={() => setTplModal(null)} busy={busy} />}
    </div>
  );
}

function PolicyModal({ initial, onSave, onClose, busy }) {
  const [name, setName] = useState(initial.name || "");
  const [description, setDescription] = useState(initial.description || "");
  const [config, setConfig] = useState({ ...initial.config });
  const setC = (k, v) => setConfig(c => ({ ...c, [k]: v }));
  return (
    <Modal title={initial.id ? "정책 편집" : "새 스캔 정책"} onClose={onClose}>
      <div className="space-y-4">
        <div><label className="block text-sm font-medium text-ink mb-1.5">이름</label>
          <input className="il-input w-full" value={name} onChange={e => setName(e.target.value)} placeholder="예: 표준 점검(사내)" /></div>
        <div><label className="block text-sm font-medium text-ink mb-1.5">설명</label>
          <input className="il-input w-full" value={description} onChange={e => setDescription(e.target.value)} /></div>
        <div><label className="block text-sm font-medium text-ink mb-1.5">Payload Level</label>
          <select className="il-input w-full" value={config.PROBE_PAYLOAD_LEVEL || "balanced"} onChange={e => setC("PROBE_PAYLOAD_LEVEL", e.target.value)}>
            {PAYLOAD_LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
          </select></div>
        <div className="border-t border-hairline pt-3">
          {POLICY_TOGGLES.map(([k, lbl]) => (
            <Toggle key={k} label={lbl} checked={String(config[k]).toLowerCase() === "true"} onChange={v => setC(k, v ? "true" : "false")} />
          ))}
        </div>
        <div className="border-t border-red-200 pt-3">
          <p className="text-xs font-medium text-red-700 mb-1 flex items-center gap-1">
            <ShieldCheck className="w-3.5 h-3.5" />고위험 · 승인 필요
          </p>
          <p className="text-[11px] text-muted mb-1.5 leading-relaxed">
            OS 명령 실행 증거를 무해하게 실증합니다(고정 <code className="bg-gray-100 px-1 rounded">echo EOSEUREUM_RCE_*</code> 반사만).
            셸/파일/네트워크/권한 행위는 모드와 무관하게 항상 차단됩니다. 권한 있는 대상에만 사용하세요.
          </p>
          {POLICY_TOGGLES_HIGH_RISK.map(([k, lbl]) => (
            <label key={k} className="flex items-center gap-2 text-sm text-red-700 cursor-pointer py-1">
              <input type="checkbox" checked={String(config[k]).toLowerCase() === "true"}
                onChange={e => setC(k, e.target.checked ? "true" : "false")} className="w-4 h-4 accent-red-600" />
              {lbl}
            </label>
          ))}
        </div>
        <div><label className="block text-sm font-medium text-ink mb-1.5">전역 Rate Limit (rps, ≤1000)</label>
          <input className="il-input w-full" type="number" min="1" max="1000" value={config.GLOBAL_ACTIVE_PROBE_RPS || "10"} onChange={e => setC("GLOBAL_ACTIVE_PROBE_RPS", e.target.value)} />
          <p className="text-[11px] text-muted mt-1">높은 값은 대상 과부하·차단(WAF)·오탐을 유발할 수 있습니다. 권한 있는 대상에만 상향하세요.</p></div>
        <button onClick={() => onSave({ id: initial.id, name, description, config })} disabled={busy || !name} className="il-btn-primary w-full py-2.5 disabled:opacity-50">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : "저장"}
        </button>
      </div>
    </Modal>
  );
}

function TemplateModal({ initial, onSave, onClose, busy }) {
  const [name, setName] = useState(initial.name || "");
  const [description, setDescription] = useState(initial.description || "");
  const [options, setOptions] = useState({ ...initial.options });
  const setO = (k, v) => setOptions(o => ({ ...o, [k]: v }));
  return (
    <Modal title={initial.id ? "템플릿 편집" : "새 보고서 템플릿"} onClose={onClose}>
      <div className="space-y-4">
        <div><label className="block text-sm font-medium text-ink mb-1.5">이름</label>
          <input className="il-input w-full" value={name} onChange={e => setName(e.target.value)} /></div>
        <div><label className="block text-sm font-medium text-ink mb-1.5">설명</label>
          <input className="il-input w-full" value={description} onChange={e => setDescription(e.target.value)} /></div>
        <div><label className="block text-sm font-medium text-ink mb-1.5">작성 기관명</label>
          <input className="il-input w-full" value={options.org_name || ""} onChange={e => setO("org_name", e.target.value)} placeholder="Eoseureum Security" /></div>
        <div className="border-t border-hairline pt-3">
          <p className="text-xs text-muted mb-1">포함 섹션</p>
          {TEMPLATE_TOGGLES.map(([k, lbl]) => (
            <Toggle key={k} label={lbl} checked={!!options[k]} onChange={v => setO(k, v)} />
          ))}
        </div>
        <button onClick={() => onSave({ id: initial.id, name, description, options })} disabled={busy || !name} className="il-btn-primary w-full py-2.5 disabled:opacity-50">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : "저장"}
        </button>
      </div>
    </Modal>
  );
}
