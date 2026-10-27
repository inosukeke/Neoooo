"use client";

import { useEffect, useState } from "react";
import { getHealth, type HealthResponse } from "@/lib/api";

/** Fetch `/health` một lần khi mount. Không có nút "làm mới" trong UI hiện tại
 * (chưa cần) — thêm sau nếu cần, bằng cách tăng 1 state `nonce` làm dependency. */
export function useHealth() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    getHealth()
      .then((h) => {
        if (!active) return;
        setHealth(h);
        setError(null);
      })
      .catch((e: unknown) => {
        if (!active) return;
        setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  return { health, error, loading };
}
