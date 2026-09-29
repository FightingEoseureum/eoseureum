import { useState } from "react";
import {
  Loader2, Shield, ShieldCheck, Lock, Globe, Server, FileText, Activity, Search,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

const css = `
  @keyframes eoseureum-fade-up {
    from { opacity: 0; transform: translateY(14px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @keyframes eoseureum-float {
    0%, 100% { transform: translateY(0); }
    50%      { transform: translateY(-9px); }
  }
  @keyframes eoseureum-orbit { to { transform: rotate(360deg); } }
  @keyframes eoseureum-glow  { 0%,100% { opacity: .55; } 50% { opacity: .9; } }

  .eoseureum-fade   { animation: eoseureum-fade-up .6s ease both; }
  .eoseureum-fade-1 { animation: eoseureum-fade-up .6s .08s ease both; }
  .eoseureum-fade-2 { animation: eoseureum-fade-up .6s .16s ease both; }
  .eoseureum-fade-3 { animation: eoseureum-fade-up .6s .24s ease both; }
  .eoseureum-orbit  { animation: eoseureum-orbit 48s linear infinite; transform-origin: 50% 50%; }
  .eoseureum-glow   { animation: eoseureum-glow 4s ease-in-out infinite; }
  .eoseureum-chip   { animation: eoseureum-float 5s ease-in-out infinite; }

  /* 우측 로그인 폼 필드 (명세 색상) */
  .eoseureum-field {
    width: 100%; height: 56px; border-radius: 12px;
    border: 1px solid #d7e0ea; padding: 0 16px;
    font-size: 15px; color: #0f172a; background: #ffffff; outline: none;
    transition: border-color .15s, box-shadow .15s;
  }
  .eoseureum-field::placeholder { color: #94a3b8; }
  .eoseureum-field:focus { border-color: #1d5fd6; box-shadow: 0 0 0 3px rgba(29,95,214,0.15); }

  /* 로그인 버튼 (명세 그라디언트) */
  .eoseureum-submit {
    width: 100%; height: 58px; border-radius: 12px;
    background: linear-gradient(135deg, #0057c8 0%, #003c9e 100%);
    color: #ffffff; font-weight: 700; font-size: 15px;
    box-shadow: 0 10px 24px rgba(0,72,180,0.25);
    transition: filter .15s, transform .05s, box-shadow .15s;
  }
  .eoseureum-submit:hover:not(:disabled)  { filter: brightness(1.07); box-shadow: 0 12px 28px rgba(0,72,180,0.32); }
  .eoseureum-submit:active:not(:disabled) { transform: translateY(1px); }
  .eoseureum-submit:disabled { opacity: .55; cursor: not-allowed; }
`;

// 좌측 Shield 일러스트 주변 아이콘 (lock / globe / activity / server / document)
const CHIPS = [
  { icon: Lock,     top: "2%",  left: "20%", d: "0s"   },
  { icon: Globe,    top: "8%",  left: "74%", d: "1.1s" },
  { icon: Activity, top: "44%", left: "92%", d: "1.6s" },
  { icon: Server,   top: "66%", left: "2%",  d: "2s"   },
  { icon: FileText, top: "74%", left: "76%", d: "0.6s" },
];

function SecurityIllustration() {
  // 중앙 대형 rounded square + 점선 orbit 2개 + 주변 아이콘 5개
  return (
    <div className="relative w-[470px] h-[470px] select-none" aria-hidden="true">
      {/* glow */}
      <div className="absolute inset-0 flex items-center justify-center">
        <div className="w-72 h-72 rounded-full eoseureum-glow"
          style={{ background: "radial-gradient(circle, rgba(255,255,255,0.30) 0%, transparent 70%)" }} />
      </div>
      {/* 점선 orbit 2개 */}
      <svg className="absolute inset-0 m-auto eoseureum-orbit" width="470" height="470" viewBox="0 0 470 470">
        <circle cx="235" cy="235" r="212" fill="none" stroke="rgba(255,255,255,0.25)" strokeWidth="1" strokeDasharray="5 12" />
        <circle cx="235" cy="235" r="150" fill="none" stroke="rgba(255,255,255,0.25)" strokeWidth="1" strokeDasharray="4 11" />
      </svg>
      {/* 중앙 Shield box */}
      <div className="absolute inset-0 flex items-center justify-center">
        <div className="flex items-center justify-center"
          style={{
            width: 200, height: 200, borderRadius: 32,
            background: "linear-gradient(135deg, rgba(255,255,255,0.32), rgba(255,255,255,0.14))",
            border: "1px solid rgba(255,255,255,0.35)",
            boxShadow: "0 24px 60px rgba(0,0,0,0.22)",
            backdropFilter: "blur(4px)",
          }}>
          <ShieldCheck className="w-[104px] h-[104px] text-white" strokeWidth={1.5} />
        </div>
      </div>
      {/* 주변 아이콘 5개 */}
      {CHIPS.map((c, i) => {
        const Icon = c.icon;
        return (
          <div key={i} className="absolute eoseureum-chip" style={{ top: c.top, left: c.left, animationDelay: c.d }}>
            <div className="flex items-center justify-center"
              style={{
                width: 64, height: 64, borderRadius: 18,
                background: "rgba(255,255,255,0.16)",
                border: "1px solid rgba(255,255,255,0.28)",
                backdropFilter: "blur(8px)",
              }}>
              <Icon className="w-7 h-7 text-white" strokeWidth={1.6} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// 좌측 Hero — 세로 Feature List (가로/박스/glass 카드 아님: 아이콘 박스 + 텍스트)
const FEATURES = [
  { icon: Search,   label: "자동 취약점 탐지",   desc: "다양한 스캔 엔진을 통한 종합 보안 점검" },
  { icon: FileText, label: "정밀 분석 및 보고서", desc: "재현 가능한 증거 기반 취약점 분석 및 리포트" },
  { icon: Activity, label: "지속적인 보안 관리",  desc: "정기 점검을 통한 보안 위험 사전 식별" },
];

function FeatureList() {
  return (
    <div className="flex flex-col" style={{ gap: 36 }}>
      {FEATURES.map((f, i) => {
        const Icon = f.icon;
        return (
          <div key={i} className="flex items-start gap-5">
            <div className="flex items-center justify-center flex-shrink-0"
              style={{
                width: 78, height: 78, borderRadius: 18,
                background: "rgba(255,255,255,0.14)",
                border: "1px solid rgba(255,255,255,0.24)",
              }}>
              <Icon className="w-8 h-8 text-white" strokeWidth={1.7} />
            </div>
            <div className="pt-1">
              <div className="text-white font-bold" style={{ fontSize: 23, lineHeight: 1.25 }}>{f.label}</div>
              <div style={{ color: "rgba(255,255,255,0.82)", fontSize: 16.5, lineHeight: 1.5, marginTop: 4 }}>
                {f.desc}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function BrandMark({ compact = false }) {
  return (
    <div className="flex items-center gap-2.5">
      <div className="rounded-xl flex items-center justify-center flex-shrink-0"
        style={{ width: compact ? 32 : 42, height: compact ? 32 : 42,
                 background: "rgba(255,255,255,0.2)", border: "1px solid rgba(255,255,255,0.3)" }}>
        <Shield className={compact ? "w-4 h-4 text-white" : "w-5 h-5 text-white"} />
      </div>
      <div className="flex items-center gap-2.5">
        <span className={`font-extrabold text-white tracking-tight ${compact ? "text-lg" : "text-xl"}`}>Eoseureum</span>
        <span className="h-4 w-px bg-white/30" />
        <span className="text-sm font-medium" style={{ color: "rgba(255,255,255,0.82)" }}>AI Security Assessment</span>
        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded text-white"
          style={{ letterSpacing: "0.08em", background: "rgba(255,255,255,0.16)", border: "1px solid rgba(255,255,255,0.28)" }}>
          AI
        </span>
      </div>
    </div>
  );
}

export default function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError]       = useState("");
  const [loading, setLoading]   = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(username, password);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <style>{css}</style>
      <div className="h-screen flex overflow-hidden"
        style={{ fontFamily: "'Pretendard', 'Noto Sans KR', system-ui, sans-serif" }}>

        {/* ── 좌측 58% Hero 영역 (공통 Blue Gradient) ── */}
        <div className="hidden lg:block w-[58%] relative overflow-hidden eoseureum-hero-gradient">
          {/* 은은한 grid overlay */}
          <div className="absolute inset-0 pointer-events-none" aria-hidden="true"
            style={{
              opacity: 0.45,
              backgroundImage:
                "linear-gradient(rgba(255,255,255,0.05) 1px, transparent 1px),"
                + "linear-gradient(90deg, rgba(255,255,255,0.05) 1px, transparent 1px)",
              backgroundSize: "48px 48px",
            }} />
          {/* glow */}
          <div className="absolute -top-32 -right-24 w-[28rem] h-[28rem] rounded-full pointer-events-none" aria-hidden="true"
            style={{ background: "radial-gradient(circle, rgba(255,255,255,0.14) 0%, transparent 70%)" }} />

          {/* 상단 브랜드 (top 56px / left 52px) */}
          <div className="absolute z-20 eoseureum-fade" style={{ top: 56, left: 52 }}>
            <BrandMark />
          </div>

          {/* Shield 일러스트 — Hero 영역 중앙 오른쪽 (x≈66%, y≈57%) */}
          <div className="absolute z-10 eoseureum-fade-1" style={{ left: "66%", top: "57%", transform: "translate(-50%, -50%)" }}>
            <SecurityIllustration />
          </div>

          {/* 제목 → 설명 → Feature List (좌측, 제목은 상단 약 170px 지점) */}
          <div className="absolute z-20" style={{ top: 170, left: 52, maxWidth: 600 }}>
            <h1 className="eoseureum-fade" style={{ fontSize: 66, fontWeight: 800, lineHeight: 1.12, color: "#ffffff" }}>
              AI Security<br />Assessment Platform
            </h1>
            <p className="eoseureum-fade-1" style={{
              marginTop: 22, maxWidth: 560,
              fontSize: 19, lineHeight: 1.7, color: "rgba(255,255,255,0.9)",
            }}>
              보이지 않는 위험을 가장 먼저 발견합니다.<br />
              Eoseureum은 공격 표면을 발견하고 증거 기반으로 위험을 검증하는 AI 보안 진단 플랫폼입니다.
            </p>
            <div className="eoseureum-fade-2" style={{ marginTop: 52, maxWidth: 440 }}>
              <FeatureList />
            </div>
          </div>
        </div>

        {/* ── 우측 42% 로그인 영역 ── */}
        <div className="flex flex-col items-center justify-center w-full lg:w-[42%] px-6 sm:px-10 eoseureum-login-grid">
          {/* 모바일 전용 브랜드 바 */}
          <div className="lg:hidden w-full max-w-[448px] mb-8 rounded-2xl px-5 py-4 eoseureum-hero-gradient eoseureum-fade">
            <BrandMark compact />
          </div>

          <div className="w-full" style={{ maxWidth: 448 }}>
            {/* 제목 (카드와 동일 left alignment) */}
            <div className="mb-7 eoseureum-fade">
              <h2 style={{ color: "#0f172a", fontSize: 34, fontWeight: 800, lineHeight: 1.2 }}>로그인</h2>
              <p style={{ color: "#475569", fontSize: 16, marginTop: 8 }}>계정 자격증명을 입력하여 접속하세요.</p>
            </div>

            {/* 로그인 카드 */}
            <div className="eoseureum-fade-1 overflow-hidden"
              style={{
                background: "#ffffff", borderRadius: 20,
                border: "1px solid rgba(15,23,42,0.08)",
                boxShadow: "0 22px 50px rgba(15,23,42,0.14)",
              }}>
              <div style={{ padding: 40 }}>
                <form onSubmit={handleSubmit} className="flex flex-col gap-5">
                  <div>
                    <label htmlFor="eoseureum-username" className="block text-xs font-semibold mb-2" style={{ color: "#475569" }}>아이디</label>
                    <input id="eoseureum-username" className="eoseureum-field" type="text" value={username}
                      onChange={e => setUsername(e.target.value)}
                      placeholder="아이디를 입력하세요" required autoFocus
                      autoComplete="username" />
                  </div>

                  <div>
                    <label htmlFor="eoseureum-password" className="block text-xs font-semibold mb-2" style={{ color: "#475569" }}>비밀번호</label>
                    <input id="eoseureum-password" className="eoseureum-field" type="password" value={password}
                      onChange={e => setPassword(e.target.value)}
                      placeholder="비밀번호를 입력하세요" required
                      autoComplete="current-password" />
                  </div>

                  {error && (
                    <div role="alert" className="flex items-start gap-2 rounded-lg px-3.5 py-2.5"
                      style={{ background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.25)" }}>
                      <span className="text-danger text-sm leading-5">✕</span>
                      <span className="text-danger text-[13px]">{error}</span>
                    </div>
                  )}

                  <button type="submit" disabled={loading}
                    className="eoseureum-submit inline-flex items-center justify-center gap-2 mt-1">
                    {loading
                      ? <><Loader2 className="w-4 h-4 animate-spin" />로그인 중...</>
                      : "로그인"}
                  </button>
                </form>
              </div>

              {/* 하단 보안 안내 */}
              <div className="flex items-center gap-2 px-9"
                style={{ height: 64, background: "#eef5ff", borderTop: "1px solid #dbeafe" }}>
                <Shield className="w-4 h-4 flex-shrink-0" style={{ color: "#064fb8" }} />
                <span className="text-sm" style={{ color: "#064fb8" }}>권한이 있는 담당자만 접속 가능합니다.</span>
              </div>
            </div>

            {/* Footer */}
            <div className="eoseureum-fade-2 text-center" style={{ marginTop: 48 }}>
              <span style={{ fontSize: 13, color: "#64748b" }}>
                © 2026 Eoseureum. All Rights Reserved.
              </span>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
