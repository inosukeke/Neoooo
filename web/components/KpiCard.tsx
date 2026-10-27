type KpiTone = "neutral" | "danger" | "success" | "warning" | "accent";

const TONE_TEXT: Record<KpiTone, string> = {
  neutral: "text-text-primary",
  danger: "text-danger",
  success: "text-success",
  warning: "text-warning",
  accent: "text-accent",
};

export function KpiCard({
  label,
  value,
  sub,
  tone = "neutral",
}: {
  label: string;
  value: number | string | null;
  sub?: string;
  tone?: KpiTone;
}) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-border bg-card p-4">
      <span className="text-[11px] font-semibold text-text-muted">{label}</span>
      <span className={`font-mono text-[28px] font-semibold ${TONE_TEXT[tone]}`}>
        {value ?? "—"}
      </span>
      {sub && <span className="text-[11px] text-text-secondary">{sub}</span>}
    </div>
  );
}

export default KpiCard;
