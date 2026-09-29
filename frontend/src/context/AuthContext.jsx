import { createContext, useContext, useState, useEffect, useCallback } from "react";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [auth, setAuth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [ipBlocked, setIpBlocked] = useState(null);   // 허용되지 않은 IP → 전체화면 차단 메시지

  useEffect(() => {
    const token = localStorage.getItem("token");
    const user = localStorage.getItem("user");
    if (token && user) {
      fetch("/api/auth/me", {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then(async (r) => {
          if (r.status === 403) {           // IP 차단 → 앱 대신 전체화면 오류
            const e = await r.json().catch(() => ({}));
            setIpBlocked(e.detail || "허용되지 않은 IP에서의 접근입니다.");
            localStorage.clear();
            return null;
          }
          return r.ok ? r.json() : null;
        })
        .then((data) => {
          if (data) setAuth({ token, user: data });
          else localStorage.removeItem("token");
        })
        .catch(() => localStorage.clear())
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const login = useCallback(async (username, password) => {
    const form = new URLSearchParams({ username, password });
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      if (res.status === 403) {            // IP 차단 → 전체화면 오류로 전환
        setIpBlocked(err.detail || "허용되지 않은 IP에서의 접근입니다.");
      }
      throw new Error(err.detail || "로그인 실패");
    }
    const data = await res.json();
    localStorage.setItem("token", data.access_token);
    localStorage.setItem("user", JSON.stringify(data.user));
    setAuth({ token: data.access_token, user: data.user });
  }, []);

  const logout = useCallback(() => {
    localStorage.clear();
    setAuth(null);
  }, []);

  const apiFetch = useCallback(
    (path, opts = {}) => {
      const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
      if (auth?.token) headers["Authorization"] = `Bearer ${auth.token}`;
      return fetch(path, { ...opts, headers });
    },
    [auth]
  );

  return (
    <AuthContext.Provider value={{ auth, login, logout, loading, apiFetch, ipBlocked }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
