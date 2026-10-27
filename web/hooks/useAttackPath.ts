"use client";

import { useEffect, useState } from "react";
import { getAttackPath, type AttackPathResponse } from "@/lib/api";

/** Fetch `/attack-path` một lần khi mount — cùng pattern với `useHealth`/`useOverview`.
 * Không có filter đổi theo input người dùng (chế độ Dijkstra/BFS/Betweenness chỉ đổi
 * cách highlight trên canvas, tính tại client từ data đã có) nên không cần re-fetch. */
export function useAttackPath(minCriticality = 4) {
  const [data, setData] = useState<AttackPathResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    getAttackPath(minCriticality)
      .then((d) => {
        if (!active) return;
        setData(d);
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
  }, [minCriticality]);

  return { data, error, loading };
}
