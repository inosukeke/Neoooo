"use client";

import { useEffect, useState } from "react";
import { getOverview, type OverviewResponse } from "@/lib/api";

/** Fetch `/overview` một lần khi mount — cùng pattern với `useHealth`. */
export function useOverview() {
  const [overview, setOverview] = useState<OverviewResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    getOverview()
      .then((o) => {
        if (!active) return;
        setOverview(o);
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

  return { overview, error, loading };
}
