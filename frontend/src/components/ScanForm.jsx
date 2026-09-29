import { useState, useRef, useCallback, useEffect } from "react";
import { Search, FileText, X, Upload, ShieldCheck } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import ScanWizard from "./ScanWizard";

function parseDomains(text) {
  return text
    .split(/[\n,;]+/)
    .map(l => l.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase())
    .filter(l => l && !l.startsWith("#") && l.includes("."));
}

export default function ScanForm({ onScan, onBatchScan, disabled }) {
  const { apiFetch } = useAuth();
  const [domain, setDomain]       = useState("");
  const [domains, setDomains]     = useState([]);   // 배치 목록
  const [fileName, setFileName]   = useState("");
  const [dragging, setDragging]   = useState(false);
  const fileRef = useRef(null);

  // ── 스캔별 인증정보(선택) — 이 스캔에만 사용, 저장 안 함. 0/1/2 계정 모두 허용 ──
  const [showAuth, setShowAuth] = useState(false);
  const [auth, setAuth] = useState({
    login_url: "", username: "", password: "",
    username_b: "", password_b: "", role_a: "", role_b: "",
  });
  const setA = (k, v) => setAuth((a) => ({ ...a, [k]: v }));
  const buildAuth = () => {
    const a = {};
    for (const [k, v] of Object.entries(auth)) {
      if (typeof v === "string" && v.trim()) a[k] = v.trim();
    }
    return Object.keys(a).length ? a : undefined;
  };

  // ── Validation Profile 설정(표시 전용, 기본 SAFE) ──
  const [valProfile, setValProfile] = useState(null);
  useEffect(() => {
    (async () => {
      try {
        const res = await apiFetch("/api/validation/profile");
        if (res.ok) setValProfile(await res.json());
      } catch { /* 표시 전용 */ }
    })();
  }, [apiFetch]);

  const handleSubmit = (e) => {
    e.preventDefault();
    const d = domain.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (d) onScan(d, "", buildAuth());
  };

  const loadFile = useCallback((file) => {
    if (!file || !file.name.endsWith(".txt")) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (e) => {
      const parsed = parseDomains(e.target.result);
      setDomains(parsed);
    };
    reader.readAsText(file, "utf-8");
  }, []);

  const onDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    loadFile(file);
  }, [loadFile]);

  const onDragOver = (e) => { e.preventDefault(); setDragging(true); };
  const onDragLeave = () => setDragging(false);

  const clearBatch = () => { setDomains([]); setFileName(""); };

  const startBatch = () => {
    if (domains.length && onBatchScan) onBatchScan(domains);
  };

  const PROFILE_TONE = {
    SAFE: "bg-green-50 text-green-700 border-green-200",
    STANDARD: "bg-blue-50 text-blue-700 border-blue-200",
    ADVANCED: "bg-amber-50 text-amber-700 border-amber-200",
    PROOF: "bg-red-50 text-red-700 border-red-200",
  };

  return (
    <>
    {/* Validation Profile 배지 (기본 SAFE — 증거 기반 검증 설정) */}
    {valProfile && (
      <div className="il-card p-4 flex flex-wrap items-center gap-3">
        <ShieldCheck className="w-4 h-4 text-primary" />
        <span className="text-sm font-semibold text-ink">검증 프로파일</span>
        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${PROFILE_TONE[valProfile.profile] || PROFILE_TONE.SAFE}`}>
          {valProfile.profile}
          {valProfile.downgraded && ` (요청 ${valProfile.requested_profile} → 안전 강등)`}
        </span>
        <span className="text-xs text-muted">Proof 모드 {valProfile.allow_proof ? "허용" : "차단"}</span>
        <span className="text-xs text-muted">기본값 SAFE · 위험 행위(덤프·셸·추출·상태변경·brute·내부망)는 항상 차단</span>
      </div>
    )}
    <div className="il-card p-6 space-y-4">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 bg-primary">
          <Search className="w-4 h-4 text-white" />
        </div>
        <div>
          <h2 className="text-base font-semibold text-ink leading-tight">도메인 취약점 점검</h2>
          <p className="text-xs text-muted mt-0.5">본인이 소유하거나 점검 권한이 있는 도메인만 입력하세요.</p>
        </div>
      </div>

      {/* 단계별 새 스캔 마법사 */}
      <ScanWizard onScan={onScan} disabled={disabled} />
    </div>
    </>
  );
}
