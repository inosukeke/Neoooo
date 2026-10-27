export function KpiCard({
  label,
  value,
  sub,
  tone = "neutral",
}: {
  label: string;
  value: number | null;
  sub?: string;
  tone?: "neutral" | "danger";
}) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-border bg-card p-4">
      <span className="text-[11px] font-semibold text-text-muted">{label}</span>
      <span
        className={`font-mono text-[28px] font-semibold ${
          tone === "danger" ? "text-danger" : "text-text-primary"
        }`}
      >
        {value ?? "—"}
      </span>
      {sub && <span className="text-[11px] text-text-secondary">{sub}</span>}
    </div>
  );
}

export default KpiCard;
