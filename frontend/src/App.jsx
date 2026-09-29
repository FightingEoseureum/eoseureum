import { useState, useRef, useCallback, useEffect } from "react";
import {
  LayoutDashboard, ScanLine, ListChecks, Target, Activity, CalendarClock,
  Layers, FileText, ShieldCheck, Settings2, Server, Loader2,
} from "lucide-react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import LoginPage from "./components/LoginPage";
import Sidebar from "./components/Sidebar";
import TopBar from "./components/TopBar";
import RightPanel from "./components/RightPanel";
import ScanForm from "./components/ScanForm";
import ScanWizard from "./components/ScanWizard";
import ScanListPage from "./components/ScanListPage";
import ScanDetailPage from "./components/ScanDetailPage";
import ProgressPage from "./components/ProgressPage";
import RegisteredTargets from "./components/RegisteredTargets";
import AdminPanel from "./components/AdminPanel";
import DomainWatchlist from "./components/DomainWatchlist";
import BatchResults from "./components/BatchResults";
import StatsPage from "./components/StatsPage";
import TechStackPage from "./components/TechStackPage";
import SettingsPage from "./components/SettingsPage";

// ── 사이드바 메뉴 + 페이지 메타 (단일 출처) ─────────────────────────────────────
//   requireScan:  스캔 권한(admin || can_scan) 없으면 메뉴에서 숨김
//   requireAdmin: 관리자 전용 — 비관리자는 메뉴에서 숨기고, 직접 접근 시 대시보드로 리다이렉트
const NAV = [
  { id: "dashboard",   label: "대시보드",       icon: LayoutDashboard, group: null,     title: "대시보드",       desc: "보안 현황 및 스캔 요약" },
  { id: "scanner",     label: "새 스캔",         icon: ScanLine,        group: "scan",   requireScan: true, title: "새 스캔",   desc: "대상을 입력하고 취약점 점검을 시작합니다" },
  { id: "progress",    label: "진행 현황",       icon: Activity,        group: "scan",   title: "진행 현황",      desc: "진행 중·대기 중인 스캔의 실시간 현황" },
  { id: "history",     label: "스캔 목록",       icon: ListChecks,      group: "scan",   title: "스캔 목록",      desc: "지난 점검 이력·결과·보고서를 한곳에서 확인합니다" },
  { id: "watchlist",   label: "정기 스캔",       icon: CalendarClock,   group: "asset",  title: "정기 스캔",      desc: "대상 도메인의 정기 점검 예약(주기·일자)" },
  { id: "registered",  label: "등록된 대상",     icon: ListChecks,     group: "asset",  title: "등록된 대상", desc: "새 스캔·정기 스캔에서 등록된 대상과 저장된 스캔 설정" },
  { id: "techstack",   label: "기술 스택",       icon: Layers,          group: "asset",  requireAdmin: true, title: "기술 스택", desc: "대상 자산의 탐지된 기술 스택 정보" },
  { id: "settings",    label: "설정",           icon: Settings2,       group: "config", title: "설정", desc: "환경 설정·정책·보고서 템플릿" },
  { id: "system",      label: "시스템 설정",     icon: Server,          group: "config", requireAdmin: true, title: "시스템 설정",    desc: "사용자 및 시스템 관리" },
];

const VIEW_META = Object.fromEntries(NAV.map((n) => [n.id, { title: n.title, desc: n.desc }]));
VIEW_META.batch = { title: "일괄 스캔", desc: "여러 대상을 순차적으로 점검합니다" };
VIEW_META.scanDetail = { title: "스캔 상세", desc: "개요·취약점·엔드포인트·위협 시나리오·보고서" };

// ── 해시 기반 라우팅 (새로고침·뒤로가기·링크 공유 지원) ─────────────────────────────
//   #/dashboard, #/history, #/scan/<id>/<tab> …
function parseHash() {
  const h = (window.location.hash || "").replace(/^#\/?/, "");
  const parts = h.split("/").filter(Boolean);
  if (parts[0] === "scan" && parts[1]) {
    return { view: "scanDetail", scanId: decodeURIComponent(parts[1]), tab: parts[2] || "overview" };
  }
  return { view: parts[0] || "dashboard", scanId: null, tab: "overview" };
}
function buildHash(view, scanId, tab) {
  if (view === "scanDetail" && scanId) {
    return `#/scan/${encodeURIComponent(scanId)}/${tab || "overview"}`;
  }
  return `#/${view || "dashboard"}`;
}

function MainApp() {
  const { auth, loading, apiFetch, ipBlocked } = useAuth();
  const [view, setView] = useState(() => parseHash().view);
  const [editingQueued, setEditingQueued] = useState(null);   // 진행현황에서 대기 스캔 설정 수정 중

  // 스캔 상세 페이지(스캔 목록 클릭 → 해당 스캔만 보는 페이지로 이동)
  const [selectedScanId, setSelectedScanId] = useState(() => parseHash().scanId);
  const [detailTab, setDetailTab] = useState(() => parseHash().tab);
  const openScan = useCallback((scanId, tab = "overview") => {
    setSelectedScanId(scanId);
    setDetailTab(tab || "overview");
    setView("scanDetail");
  }, []);

  // 상태 → 해시 반영(변경 시에만 기록해 루프 방지)
  useEffect(() => {
    const target = buildHash(view, selectedScanId, detailTab);
    if (window.location.hash !== target) window.location.hash = target;
  }, [view, selectedScanId, detailTab]);

  // 해시 → 상태 반영(뒤로/앞으로, 주소 직접 수정, 새로고침)
  useEffect(() => {
    const onHash = () => {
      const p = parseHash();
      setView(p.view);
      setSelectedScanId(p.scanId);
      setDetailTab(p.tab);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // 단일 스캔 상태
  const [scanState, setScanState]       = useState("idle");
  const [events, setEvents]             = useState([]);
  const [subdomains, setSubdomains]     = useState([]);
  const [portFindings, setPortFindings] = useState([]);
  const [analysis, setAnalysis]         = useState(null);
  const [currentStage, setCurrentStage] = useState(null);
  const [scanningHost, setScanningHost] = useState(null);
  const [currentScanId, setCurrentScanId] = useState(null);
  const [scanTarget, setScanTarget]       = useState(null);   // RightPanel 표시용
  const [scanStartedAt, setScanStartedAt] = useState(null);   // RightPanel 표시용
  const [scanError, setScanError]         = useState(null);   // C2: 스캔 실패 표면화
  const wsRef = useRef(null);

  // 배치 스캔 상태
  const [batchQueue, setBatchQueue]     = useState([]);   // 남은 도메인 목록
  const [batchResults, setBatchResults] = useState([]);   // 완료된 결과
  const [batchTotal, setBatchTotal]     = useState(0);
  const batchQueueRef = useRef([]);

  // ── 단일 스캔 ──────────────────────────────────────────────────────────────
  const runSingleScan = useCallback((domain, domain_notes = "", onComplete = null, scan_auth = undefined, options = undefined) => {
    const token = auth.token;
    // 동시 스캔 지원: 이전 스캔의 WS 핸들러만 분리한다(닫지는 않음).
    //  - 핸들러 제거 → 이전 스캔의 이벤트가 새 스캔 UI 에 섞이거나 상태를 덮어쓰지 않음.
    //  - 닫지 않음 → WS 종료로 서버 task 가 취소되어 '부분 종료'되는 것을 방지. 이전 스캔은
    //    서버에서 온전히 완료되며 '진행 중 스캔' 목록에서 폴링으로 계속 확인/중지할 수 있다.
    const prev = wsRef.current;
    if (prev) {
      try { prev.onopen = prev.onmessage = prev.onerror = prev.onclose = null; } catch { /* ignore */ }
    }
    const wsProto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsHost  = import.meta.env.DEV ? "localhost:8000" : window.location.host;
    const ws = new WebSocket(`${wsProto}//${wsHost}/ws/scan?token=${token}`);
    wsRef.current = ws;

    let lastAnalysis = null;
    let lastScanId   = null;

    ws.onopen = () => ws.send(JSON.stringify({
      action: "start_scan", domain, domain_notes,
      ...(scan_auth ? { auth: scan_auth } : {}),
      ...(options ? { options } : {}),
    }));

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);

      if (!onComplete) {
        // 단일 모드: UI 업데이트 (C1: events 누산 → 라이브 로그로 소비)
        setEvents(prev => [...prev.slice(-400), msg]);   // 상한 유지(메모리 보호)
        switch (msg.type) {
          case "queued":           setCurrentStage("대기열 대기 중 — 동시 실행 한도 초과"); break;
          case "stage":            setCurrentStage(msg.stage); break;
          case "subdomain_found":  setSubdomains(prev => [...prev, { subdomain: msg.subdomain, ip: msg.ip }]); break;
          case "scanning_host":    setScanningHost(msg.host); break;
          case "port_open":        setPortFindings(prev => [...prev, { host: msg.host, port: msg.port, service: msg.service }]); break;
          case "analysis_complete": setAnalysis(msg.analysis); break;
          case "error":            // C2: 서버측 스캔 오류 → 사용자에게 표면화
            setScanError(msg.message || "스캔 중 오류가 발생했습니다.");
            setScanState("idle"); setScanningHost(null);
            break;
          case "scan_complete":
            setScanState("complete");
            setScanningHost(null);
            setCurrentScanId(msg.scan_id);
            break;
          default: break;
        }
      } else {
        // 배치 모드: 분석 결과와 scan_id만 수집
        if (msg.type === "analysis_complete") lastAnalysis = msg.analysis;
        if (msg.type === "scan_complete")     lastScanId   = msg.scan_id;
      }
    };

    ws.onerror = () => {
      if (!onComplete) {
        setEvents(prev => [...prev, { type: "error", message: "WebSocket 연결 오류." }]);
        setScanError("서버와의 연결이 끊겼습니다(WebSocket 오류). 네트워크·서버 상태를 확인하세요.");
        setScanState("idle");
      } else {
        onComplete(null, null);
      }
    };

    ws.onclose = () => {
      if (!onComplete) {
        setScanState(s => s === "scanning" ? "complete" : s);
      } else {
        onComplete(lastAnalysis, lastScanId);
      }
    };
  }, [auth]);

  const startScan = useCallback((domain, domain_notes = "", scan_auth = undefined, options = undefined) => {
    setEvents([]); setSubdomains([]); setPortFindings([]);
    setAnalysis(null); setCurrentStage(null);
    setScanningHost(null); setCurrentScanId(null);
    setScanError(null);
    setScanTarget(domain); setScanStartedAt(new Date());
    setScanState("scanning");
    setView("progress");   // 스캔 시작과 동시에 진행 현황 화면으로 전환
    runSingleScan(domain, domain_notes, null, scan_auth, options);
  }, [runSingleScan]);

  // 진행현황: 대기 스캔 설정 수정 저장 → 기존 대기 스캔 취소 후 수정된 설정으로 재시작(대기열 재등록).
  const submitEditedQueued = useCallback(async (domain, domain_notes = "", scan_auth = undefined, options = undefined) => {
    const old = editingQueued;
    setEditingQueued(null);
    if (old?.scan_id) {
      try { await apiFetch(`/api/scans/${old.scan_id}/stop`, { method: "POST" }); } catch { /* 이미 시작/종료됐을 수 있음 */ }
    }
    startScan(domain, domain_notes, scan_auth, options);
  }, [editingQueued, apiFetch, startScan]);

  // ── 배치 스캔 ──────────────────────────────────────────────────────────────
  const runNextBatch = useCallback((queue, results) => {
    if (queue.length === 0) {
      setScanState("idle");
      setScanTarget(null);
      return;
    }
    const [domain, ...rest] = queue;
    batchQueueRef.current = rest;
    setScanTarget(domain);

    // 현재 도메인 상태를 "scanning"으로 업데이트
    setBatchResults(prev =>
      prev.map(r => r.domain === domain ? { ...r, status: "scanning" } : r)
    );

    runSingleScan(domain, "", (analysis, scan_id) => {
      setBatchResults(prev =>
        prev.map(r => r.domain === domain
          ? { ...r, status: analysis ? "complete" : "failed", analysis, scan_id }
          : r
        )
      );
      runNextBatch(batchQueueRef.current, []);
    });
  }, [runSingleScan]);

  const startBatchScan = useCallback((domains) => {
    const initial = domains.map(d => ({ domain: d, status: "queued", analysis: null, scan_id: null }));
    setBatchResults(initial);
    setBatchTotal(domains.length);
    batchQueueRef.current = domains;
    setScanStartedAt(new Date());
    setScanState("scanning");
    setView("batch");
    runNextBatch(domains, []);
  }, [runNextBatch]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-canvas">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="w-8 h-8 animate-spin" style={{ color: "#1E3A8A" }} />
          <span className="text-sm text-muted">로딩 중...</span>
        </div>
      </div>
    );
  }

  // 허용되지 않은 IP → 로그인/앱 대신 전체화면 차단 오류(홈페이지 접근 불가)
  if (ipBlocked) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-canvas p-6">
        <div className="il-card max-w-md w-full p-8 text-center border-2" style={{ borderColor: "#DC2626" }}>
          <div className="w-14 h-14 rounded-full mx-auto mb-4 flex items-center justify-center"
               style={{ background: "#FEE2E2" }}>
            <span style={{ color: "#DC2626", fontSize: 28, fontWeight: 800 }}>⛔</span>
          </div>
          <h1 className="text-xl font-bold text-ink mb-2">접근이 차단되었습니다</h1>
          <p className="text-sm text-muted leading-relaxed">{ipBlocked}</p>
          <p className="text-xs text-muted mt-4">
            이 IP에서는 어스름에 접근할 수 없습니다. 접근이 필요하면 관리자에게 IP 등록을 요청하세요.
          </p>
        </div>
      </div>
    );
  }

  if (!auth) return <LoginPage />;

  const canScan = auth.user.role === "admin" || auth.user.can_scan;
  const isAdmin = auth.user.role === "admin";

  // 사이드바에 노출할 메뉴 (스캔 권한 없으면 새 스캔 숨김 · 관리자 전용 메뉴는 관리자만)
  const navItems = NAV.filter(n => !(n.requireScan && !canScan) && !(n.requireAdmin && !isAdmin));

  // 권한/존재하지 않는 view 보정
  let effectiveView = view;
  if (effectiveView === "scanner" && !canScan) effectiveView = "dashboard";
  // 관리자 전용 view 를 비관리자가 직접 열면 대시보드로 보정(env 는 테마용으로 모두 허용)
  const _navItem = NAV.find(n => n.id === effectiveView);
  if (_navItem && _navItem.requireAdmin && !isAdmin) effectiveView = "dashboard";

  const meta = VIEW_META[effectiveView] || { title: "Eoseureum", desc: "" };

  return (
    <div className="min-h-screen flex bg-canvas text-ink">
      <Sidebar navItems={navItems} activeView={effectiveView} onViewChange={setView} />

      <div className="flex-1 flex flex-col min-w-0">
        <TopBar title={meta.title} description={meta.desc} onOpenScan={openScan} onViewChange={setView} />

        <div className="flex-1 flex min-w-0" style={{ backgroundColor: "#F5F7FB" }}>
          <main className="flex-1 min-w-0 px-8 py-7 space-y-6">
            {/* C2: 스캔 실패/오류 전역 배너 — 조용히 삼키던 오류를 사용자에게 표면화 */}
            {scanError && (
              <div className="il-card border-2 px-4 py-3 flex items-start gap-3" style={{ borderColor: "#DC2626", background: "#FEF2F2" }}>
                <span style={{ color: "#DC2626", fontSize: 18 }}>⚠</span>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-semibold" style={{ color: "#B91C1C" }}>스캔 오류</div>
                  <div className="text-xs text-ink mt-0.5 break-words">{scanError}</div>
                </div>
                <button onClick={() => setScanError(null)} className="text-muted hover:text-ink text-xs px-2 py-1 rounded hover:bg-white/60">닫기</button>
              </div>
            )}
            {effectiveView === "dashboard" && <StatsPage />}

            {effectiveView === "scanner" && (
              /* 새 스캔 시작 화면 — 폼만 표시. 이전 스캔 결과/진행상황은 '진행 현황'·'스캔 이력'에서 확인
                 (시작하면 진행 현황으로 전환되므로 여기 아래엔 결과를 띄우지 않는다). */
              <ScanForm
                onScan={startScan}
                onBatchScan={startBatchScan}
                disabled={false}
              />
            )}

            {effectiveView === "batch" && (
              <>
                <ScanForm
                  onScan={startScan}
                  onBatchScan={startBatchScan}
                  disabled={scanState === "scanning"}
                />
                <BatchResults results={batchResults} totalCount={batchTotal} onViewChange={setView} onOpenScan={openScan} />
              </>
            )}

            {effectiveView === "progress" && (
              editingQueued ? (
                <div className="il-card p-5 space-y-4">
                  <div className="flex items-center gap-2">
                    <button onClick={() => setEditingQueued(null)}
                      className="text-sm text-muted hover:text-ink px-2 py-1 -ml-2 rounded-lg hover:bg-gray-50 transition-colors">← 뒤로</button>
                    <h2 className="font-semibold text-ink">대기 스캔 설정 수정</h2>
                    <span className="text-xs text-muted font-mono truncate">{editingQueued.domain}</span>
                  </div>
                  <p className="text-xs text-muted">
                    저장하면 기존 대기 스캔은 취소되고, 수정한 설정으로 다시 시작(대기열에 재등록)됩니다.
                    스캔 시 작성했던 값이 미리 채워져 있습니다.
                  </p>
                  <ScanWizard onScan={submitEditedQueued} prefill={editingQueued} disabled={false} />
                </div>
              ) : (
                <ProgressPage onEditQueued={setEditingQueued} />
              )
            )}

            {effectiveView === "history" && (
              <ScanListPage onScan={startScan} onBatchScan={startBatchScan} onOpenScan={openScan} onViewChange={setView} />
            )}

            {effectiveView === "scanDetail" && (
              <ScanDetailPage
                scanId={selectedScanId}
                initialTab={detailTab}
                onTabChange={setDetailTab}
                onBack={() => setView("history")}
                onOpenScan={openScan}
                onScan={startScan}
                onViewChange={setView}
              />
            )}

            {/* 보고서 목록은 스캔 목록에 병합됨 — 옛 경로는 목록으로 폴백 */}
            {effectiveView === "reports" && (
              <ScanListPage onScan={startScan} onBatchScan={startBatchScan} onOpenScan={openScan} onViewChange={setView} />
            )}

            {effectiveView === "watchlist" && (
              <DomainWatchlist onScanDomain={startScan} onOpenScan={openScan} />
            )}

            {effectiveView === "registered" && (
              <RegisteredTargets onScanDomain={startScan} onOpenScan={openScan} />
            )}

            {effectiveView === "techstack" && <TechStackPage />}

            {/* system 뷰는 requireAdmin 필터·리다이렉트로 admin 만 도달 → Placeholder 분기는 도달불가라 제거 */}
            {effectiveView === "system" && <AdminPanel />}

            {/* 설정(환경 + 정책·템플릿 병합). 옛 경로(env·policies)도 폴백 */}
            {(effectiveView === "settings" || effectiveView === "env" || effectiveView === "policies") && <SettingsPage />}
          </main>

          <RightPanel
            scanState={scanState}
            scanTarget={scanTarget}
            currentStage={currentStage}
            scanStartedAt={scanStartedAt}
            scanningHost={scanningHost}
            scanError={scanError}
            onDismissError={() => setScanError(null)}
            onViewChange={setView}
            onOpenScan={openScan}
            canScan={canScan}
          />
        </div>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <MainApp />
    </AuthProvider>
  );
}
