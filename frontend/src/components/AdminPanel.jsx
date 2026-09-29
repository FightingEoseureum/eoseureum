import { useEffect, useState } from "react";
import { Users, Plus, Pencil, Trash2, Loader2, Check, Bot, CircleCheck, CircleX, Layers, Cpu, FlaskConical, Lock } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import Modal from "./Modal";

function UserForm({ initial, onSubmit, loading }) {
  const [form, setForm] = useState({
    username: initial?.username || "",
    password: "",
    role: initial?.role || "user",
    can_scan: initial?.can_scan ?? true,
    scan_quota: initial?.scan_quota ?? 0,
    max_concurrent_scans: initial?.max_concurrent_scans ?? 0,
    allowed_ips: initial?.allowed_ips ?? "",
  });

  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(form);
      }}
      className="space-y-4"
    >
      {!initial && (
        <div>
          <label className="block text-sm font-medium text-ink mb-1.5">아이디</label>
          <input
            type="text"
            value={form.username}
            onChange={(e) => set("username", e.target.value)}
            required
            className="il-input"
          />
        </div>
      )}
      <div>
        <label className="block text-sm font-medium text-ink mb-1.5">
          비밀번호 {initial && <span className="text-muted">(변경 시에만 입력)</span>}
        </label>
        <input
          type="password"
          value={form.password}
          onChange={(e) => set("password", e.target.value)}
          required={!initial}
          placeholder={initial ? "변경하지 않으면 비워두세요" : ""}
          className="il-input"
        />
      </div>
      <div>
        <label className="block text-sm font-medium text-ink mb-1.5">역할</label>
        <select
          value={form.role}
          onChange={(e) => set("role", e.target.value)}
          className="il-input"
        >
          <option value="user">user (일반)</option>
          <option value="admin">admin (관리자)</option>
        </select>
      </div>
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => set("can_scan", !form.can_scan)}
          className={`w-12 h-6 rounded-full transition-colors relative ${
            form.can_scan ? "bg-primary" : "bg-gray-300"
          }`}
        >
          <span
            className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${
              form.can_scan ? "translate-x-6" : "translate-x-0"
            }`}
          />
        </button>
        <span className="text-sm text-ink">스캔 실행 권한</span>
      </div>

      <div>
        <label className="block text-sm font-medium text-ink mb-1.5">
          총 스캔 쿼터 <span className="text-muted">(0 = 무제한)</span>
        </label>
        <input
          type="number"
          min="0"
          value={form.scan_quota}
          onChange={(e) => set("scan_quota", Math.max(0, parseInt(e.target.value || "0", 10)))}
          className="il-input"
        />
        <p className="text-xs text-muted mt-1">
          이 사용자가 보유할 수 있는 총 스캔 수. 초과 시 새 스캔이 거부됩니다(기존 스캔 삭제로 여유 확보).
        </p>
      </div>

      <div>
        <label className="block text-sm font-medium text-ink mb-1.5">
          동시 스캔 제한 <span className="text-muted">(0 = 기본값)</span>
        </label>
        <input
          type="number"
          min="0"
          value={form.max_concurrent_scans}
          onChange={(e) => set("max_concurrent_scans", Math.max(0, parseInt(e.target.value || "0", 10)))}
          disabled={form.role === "admin"}
          className="il-input disabled:opacity-50 disabled:cursor-not-allowed"
        />
        <p className="text-xs text-muted mt-1">
          {form.role === "admin"
            ? "관리자는 동시 스캔 수 제한이 없습니다(무제한)."
            : "이 사용자가 동시에 실행할 수 있는 스캔 수. 0 이면 서버 기본값을 사용합니다."}
        </p>
      </div>

      <div>
        <label className="block text-sm font-medium text-ink mb-1.5">
          접근 허용 IP <span className="text-danger">*필수</span>
        </label>
        <textarea
          rows={2}
          value={form.allowed_ips}
          onChange={(e) => set("allowed_ips", e.target.value)}
          placeholder="예: 10.25.2.16, 10.20.100.24 (콤마·줄바꿈 구분, 완전 일치)"
          className="il-input font-mono text-sm"
          required
        />
        <p className="text-xs text-muted mt-1">
          <b>정확히 일치하는 IP</b>에서만 이 사용자가 로그인·접근할 수 있습니다(대역/CIDR 아님).
          <b className="text-danger"> 비우면 이 계정은 아무 곳에서도 접근할 수 없습니다(전부 차단).</b>
          ⚠ 사용자의 실제 IP를 반드시 넣으세요.
        </p>
      </div>

      <button
        type="submit"
        disabled={loading}
        className="il-btn-primary w-full mt-2"
      >
        {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
        {initial ? "저장" : "생성"}
      </button>
    </form>
  );
}

const ROLE_LABELS = {
  analysis: "취약점 분석",
  poc: "PoC 코드",
  crawl: "크롤·발견",
  probe_priority: "프로브 우선순위",
  fp_judge: "오탐 판정",
};
const PROBE_LABELS = {
  sqlmap: "SQLMap 검증",
  oob: "OOB 컬래보레이터",
  unauth_write_bac: "미인증 쓰기-BAC",
  cve_intel: "React2Shell·CVE",
};

function AIProviderStatus({ apiFetch }) {
  const [status, setStatus] = useState(null);
  const [checking, setChecking] = useState(false);
  const [editable, setEditable] = useState(false);
  const [switching, setSwitching] = useState("");

  const checkHealth = async () => {
    setChecking(true);
    try {
      const res = await apiFetch("/api/ai/health");
      if (res.ok) setStatus(await res.json());
      try {
        const mr = await apiFetch("/api/ai/mode");
        if (mr.ok) setEditable(!!(await mr.json()).editable);
      } catch { /* 조회 전용 */ }
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => { checkHealth(); }, []);

  const switchMode = async (mode) => {
    if (switching) return;
    setSwitching(mode);
    try {
      const res = await apiFetch("/api/ai/mode", { method: "POST", body: JSON.stringify({ mode }) });
      if (res.ok) await checkHealth();
    } finally { setSwitching(""); }
  };

  if (!status) return null;

  const configured = status.configured;
  const available = status.available;
  const mode = status.mode || "solo";
  const isEnsemble = mode === "ensemble";
  const roles = status.roles || {};
  const panel = (status.fp_judge_ensemble && status.fp_judge_ensemble.panel) || [];
  const votes = (status.fp_judge_ensemble && status.fp_judge_ensemble.votes_to_downgrade) || 2;
  const probes = status.probes || {};
  const fallback = status.fallback_model;

  const providerLabel = status.provider === "none" ? "비활성 (AI 미설정)" : status.provider;
  const statusColor = !configured ? "text-muted" : available ? "text-success" : "text-danger";
  const StatusIcon = available ? CircleCheck : CircleX;

  return (
    <div className="il-card p-5 mb-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Bot className="w-5 h-5 text-muted" />
          <h2 className="font-semibold text-ink">AI 분석 엔진</h2>
        </div>
        <button onClick={checkHealth} disabled={checking}
          className="text-xs text-muted hover:text-ink flex items-center gap-1">
          {checking ? <Loader2 className="w-3 h-3 animate-spin" /> : "새로고침"}
        </button>
      </div>

      {/* 프로바이더 가용성 */}
      <div className="flex items-center gap-3">
        <StatusIcon className={`w-5 h-5 flex-shrink-0 ${statusColor}`} />
        <div>
          <p className="text-sm font-medium text-ink font-mono">{providerLabel}</p>
          {status.error && <p className="text-xs text-danger mt-0.5">{status.error}</p>}
          {available && !status.error && (
            <p className="text-xs text-success mt-0.5">연결 가능 — 스캔 후 AI 분석·오탐 판정이 자동 실행됩니다</p>
          )}
          {!configured && (
            <p className="text-xs text-muted mt-0.5">서버 .env 의 AI_PROVIDER=ollama 설정 시 활성화됩니다</p>
          )}
        </div>
      </div>

      {/* 모드: 앙상블(다중) vs 솔로(단일) */}
      <div className="mt-4 p-3 rounded-lg border" style={{ borderColor: isEnsemble ? "rgba(30,58,138,0.25)" : "rgba(120,120,120,0.25)", background: isEnsemble ? "rgba(30,58,138,0.04)" : "var(--gray-50, #f9fafb)" }}>
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <Layers className={`w-4 h-4 ${isEnsemble ? "text-primary" : "text-muted"}`} />
            <span className="text-sm font-semibold text-ink">
              {isEnsemble ? "앙상블 모드 (다중 판정)" : "솔로 모드 (단일 모델)"}
            </span>
          </div>
          {editable && (
            <div className="flex items-center gap-1">
              {["ensemble", "solo"].map((m) => (
                <button key={m} onClick={() => switchMode(m)} disabled={!!switching || m === mode}
                  className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${m === mode ? "bg-primary text-white border-primary" : "text-muted border-hairline hover:text-ink"}`}>
                  {switching === m ? <Loader2 className="w-3 h-3 animate-spin" /> : (m === "ensemble" ? "앙상블" : "솔로")}
                </button>
              ))}
            </div>
          )}
        </div>
        <p className="text-xs text-muted mt-1">
          {isEnsemble
            ? `오탐 판정을 ${panel.length}개 모델 다수결로 교차검증(${votes}표 이상이면 하향+검토표시).`
            : "단일 대형 모델이 모든 역할을 담당. 앙상블 다수결 미사용."}
        </p>
      </div>

      {/* 역할 → 모델 라우팅 */}
      {Object.keys(roles).length > 0 && (
        <div className="mt-3">
          <div className="flex items-center gap-1.5 mb-1.5">
            <Cpu className="w-3.5 h-3.5 text-muted" />
            <span className="text-xs font-semibold text-muted uppercase tracking-wide">역할별 모델</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
            {Object.entries(roles).map(([role, model]) => (
              <div key={role} className="flex items-center justify-between text-xs px-2.5 py-1.5 rounded-md bg-gray-50 border border-hairline">
                <span className="text-muted">{ROLE_LABELS[role] || role}</span>
                <span className="font-mono text-ink">{model || fallback || "-"}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 오탐 판정 패널(앙상블) */}
      {isEnsemble && panel.length > 0 && (
        <div className="mt-3">
          <div className="flex items-center gap-1.5 mb-1.5">
            <FlaskConical className="w-3.5 h-3.5 text-primary" />
            <span className="text-xs font-semibold text-muted uppercase tracking-wide">오탐 판정 패널</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {panel.map((m) => (
              <span key={m} className="text-xs font-mono px-2 py-0.5 rounded-full bg-primary-50 text-primary border border-primary-200">{m}</span>
            ))}
          </div>
        </div>
      )}

      {/* 신규 프로브 토글 상태 */}
      {Object.keys(probes).length > 0 && (
        <div className="mt-3">
          <span className="text-xs font-semibold text-muted uppercase tracking-wide block mb-1.5">스캔 프로브</span>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(probes).map(([k, on]) => (
              <span key={k} className={`text-xs px-2 py-0.5 rounded-full border ${on ? "bg-[rgba(34,197,94,0.12)] text-[#15803D] border-[rgba(34,197,94,0.3)]" : "bg-gray-50 text-muted border-hairline"}`}>
                {on ? "●" : "○"} {PROBE_LABELS[k] || k}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function AdminPanel() {
  const { apiFetch, auth } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [editTarget, setEditTarget] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const res = await apiFetch("/api/users");
      if (!res.ok) return;
      const data = await res.json();
      setUsers(Array.isArray(data) ? data : []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreate = async (form) => {
    setSubmitting(true);
    setError("");
    try {
      const res = await apiFetch("/api/users", {
        method: "POST",
        body: JSON.stringify(form),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail);
      }
      setShowCreate(false);
      fetchUsers();
    } catch (e) {
      setError(e.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleEdit = async (form) => {
    setSubmitting(true);
    setError("");
    try {
      const body = {
        role: form.role, can_scan: form.can_scan, scan_quota: form.scan_quota,
        max_concurrent_scans: form.max_concurrent_scans,
        allowed_ips: form.allowed_ips ?? "",
      };
      if (form.password) body.password = form.password;
      const res = await apiFetch(`/api/users/${editTarget.id}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error("수정 실패");
      setEditTarget(null);
      fetchUsers();
    } catch (e) {
      setError(e.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (user) => {
    if (!confirm(`"${user.username}" 계정을 삭제하시겠습니까?`)) return;
    await apiFetch(`/api/users/${user.id}`, { method: "DELETE" });
    fetchUsers();
  };

  const ROLE_BADGE = {
    admin: "bg-purple-50 text-purple-700 border border-purple-200",
    user: "bg-gray-100 text-muted border border-hairline",
  };

  return (
    <div className="space-y-4">
    <AIProviderStatus apiFetch={apiFetch} />
    <div className="il-card overflow-hidden">
      <div className="flex items-center justify-between px-5 py-4 border-b border-hairline">
        <div className="flex items-center gap-2">
          <Users className="w-5 h-5 text-muted" />
          <h2 className="font-semibold text-ink">사용자 관리</h2>
        </div>
        <button
          onClick={() => { setShowCreate(true); setError(""); }}
          className="il-btn-primary px-3 py-1.5 text-sm"
        >
          <Plus className="w-4 h-4" />
          새 사용자
        </button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin" style={{ color: "#1E3A8A" }} />
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-muted border-b border-hairline bg-gray-50">
                <th className="px-5 py-3 font-medium">아이디</th>
                <th className="px-5 py-3 font-medium">역할</th>
                <th className="px-5 py-3 font-medium">스캔 권한</th>
                <th className="px-5 py-3 font-medium">스캔 쿼터</th>
                <th className="px-5 py-3 font-medium">생성일</th>
                <th className="px-5 py-3 font-medium"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-gray-50">
                  <td className="px-5 py-3.5 font-medium text-ink">
                    {u.username}
                    {u.id === auth.user.id && (
                      <span className="ml-2 text-xs text-muted">(나)</span>
                    )}
                  </td>
                  <td className="px-5 py-3.5">
                    <span className={`text-xs px-2 py-0.5 rounded ${ROLE_BADGE[u.role] || ROLE_BADGE.user}`}>
                      {u.role}
                    </span>
                  </td>
                  <td className="px-5 py-3.5">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${u.can_scan ? "text-green-700 bg-green-50" : "text-red-700 bg-red-50"}`}>
                      {u.can_scan ? "허용" : "차단"}
                    </span>
                  </td>
                  <td className="px-5 py-3.5 text-xs">
                    {u.scan_quota > 0 ? (
                      <span className={(u.scans_used ?? 0) >= u.scan_quota ? "text-red-600 font-semibold" : "text-ink"}>
                        {(u.scans_used ?? 0)} / {u.scan_quota}
                      </span>
                    ) : (
                      <span className="text-muted">무제한{u.scans_used != null ? ` (${u.scans_used})` : ""}</span>
                    )}
                  </td>
                  <td className="px-5 py-3.5 text-muted text-xs">{u.created_at}</td>
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-1 justify-end">
                      {(u.username || "").toLowerCase() === "admin"
                        && (auth.user?.username || "").toLowerCase() !== "admin" ? (
                        <span className="text-xs text-muted flex items-center gap-1"
                          title="보호 계정 — 본인만 수정/삭제할 수 있습니다">
                          <Lock className="w-3.5 h-3.5" /> 보호됨
                        </span>
                      ) : (
                        <>
                          <button
                            onClick={() => { setEditTarget(u); setError(""); }}
                            className="p-1.5 text-muted hover:text-primary hover:bg-primary-50 rounded transition-colors"
                          >
                            <Pencil className="w-3.5 h-3.5" />
                          </button>
                          {u.id !== auth.user.id && (
                            <button
                              onClick={() => handleDelete(u)}
                              className="p-1.5 text-muted hover:text-danger hover:bg-red-50 rounded transition-colors"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <Modal title="새 사용자 생성" onClose={() => setShowCreate(false)} maxWidth="max-w-md">
          {error && <p className="text-danger text-sm mb-4">{error}</p>}
          <UserForm onSubmit={handleCreate} loading={submitting} />
        </Modal>
      )}

      {editTarget && (
        <Modal title={`사용자 수정 — ${editTarget.username}`} onClose={() => setEditTarget(null)} maxWidth="max-w-md">
          {error && <p className="text-danger text-sm mb-4">{error}</p>}
          <UserForm initial={editTarget} onSubmit={handleEdit} loading={submitting} />
        </Modal>
      )}
    </div>
    </div>
  );
}
