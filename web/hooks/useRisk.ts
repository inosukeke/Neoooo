"use client";

import { useEffect, useState } from "react";
import { getRisk, type RiskResponse } from "@/lib/api";

/** Fetch `/risk` một lần khi mount — cùng pattern với `useHealth`/`useOverview`. */
export function useRisk() {
  const [risk, setRisk] = useState<RiskResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    getRisk()
      .then((r) => {
        if (!active) return;
        setRisk(r);
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

  return { risk, error, loading };
}
