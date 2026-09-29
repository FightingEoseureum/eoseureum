import { useState } from "react";
import { Settings2, ShieldCheck } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import EnvSettingsPage from "./EnvSettingsPage";
import PoliciesPage from "./PoliciesPage";

// 환경 설정 + 정책·템플릿을 하나의 "설정" 페이지로 병합(탭 전환).
export default function SettingsPage() {
  const { auth } = useAuth();
  const isAdmin = auth?.user?.role === "admin";
  const TABS = [
    { id: "env", label: "환경 설정", icon: Settings2 },
    ...(isAdmin ? [{ id: "policies", label: "정책 · 템플릿", icon: ShieldCheck }] : []),
  ];
  const [tab, setTab] = useState("env");

  return (
    <div className="space-y-4">
      <div className="bg-white border border-hairline rounded-xl overflow-hidden">
        <div className="flex border-b border-hairline">
          {TABS.map((t) => {
            const Icon = t.icon;
            return (
              <button key={t.id} onClick={() => setTab(t.id)}
                className={`flex items-center gap-2 px-5 py-3 text-sm font-medium transition-colors ${
                  tab === t.id ? "text-brand-400 border-b-2 border-brand-500 bg-gray-50" : "text-muted hover:text-ink"
                }`}>
                <Icon className="w-4 h-4" />{t.label}
              </button>
            );
          })}
        </div>
        <div className="p-5">
          {tab === "env" && <EnvSettingsPage />}
          {tab === "policies" && isAdmin && <PoliciesPage />}
        </div>
      </div>
    </div>
  );
}
