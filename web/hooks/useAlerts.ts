"use client";

import { useEffect, useRef, useState } from "react";
import { getAlerts, type AlertsQuery, type AlertsResponse } from "@/lib/api";

/** Fetch `/alerts` mỗi khi filter đổi (so sánh qua JSON.stringify(query)).
 * Dùng `requestId` (ref, không phải state) để bỏ qua response cũ tới sau khi
 * user đã đổi filter khác — tránh hiện nhầm kết quả của request trước. `loading`
 * chỉ phản ánh lần tải đầu tiên (giữ kết quả cũ hiển thị khi đang lọc lại, không
 * nhấp nháy); setState luôn nằm trong then/catch/finally, không gọi đồng bộ
 * trong thân effect. */
export function useAlerts(query: AlertsQuery) {
  const [alerts, setAlerts] = useState<AlertsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const requestIdRef = useRef(0);
  const key = JSON.stringify(query);

  useEffect(() => {
    let active = true;
    const requestId = ++requestIdRef.current;
    getAlerts(query)
      .then((a) => {
        if (!active || requestId !== requestIdRef.current) return;
        setAlerts(a);
        setError(null);
      })
      .catch((e: unknown) => {
        if (!active || requestId !== requestIdRef.current) return;
        setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (active && requestId === requestIdRef.current) setLoading(false);
      });
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `key` là serialize của `query`
  }, [key]);

  return { alerts, error, loading };
}
