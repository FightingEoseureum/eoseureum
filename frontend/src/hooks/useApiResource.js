import { useState, useEffect, useCallback } from "react";
import { useAuth } from "../context/AuthContext";

// GET 리소스 fetch 공통 훅. 여러 페이지가 반복하던 loading/error/try-catch 패턴을 통합.
// { data, loading, error, reload } 반환. res.ok 아니면 error 로 처리(4xx/5xx JSON 을 데이터로 오인 방지).
export function useApiResource(path, { initial = null } = {}) {
  const { apiFetch } = useAuth();
  const [data, setData] = useState(initial);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch(path);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setData(await res.json());
    } catch (e) {
      setError(e.message || "로드 실패");
    } finally {
      setLoading(false);
    }
  }, [path, apiFetch]);

  useEffect(() => { reload(); }, [reload]);

  return { data, loading, error, reload };
}
