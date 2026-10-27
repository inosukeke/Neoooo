import type { ReactNode } from "react";

type Tone = "neutral" | "accent" | "success" | "danger" | "warning";

const TONE_CLASSES: Record<Tone, string> = {
  neutral: "bg-chip text-text-secondary",
  accent: "bg-accent-bg text-accent",
  success: "bg-success-bg text-success",
  danger: "bg-danger-bg text-danger",
  warning: "bg-chip text-warning",
};

export function StatusBadge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: Tone;
}) {
  return (
    <span
      className={`inline-flex w-fit items-center rounded px-[7px] py-[2px] text-[11px] font-semibold ${TONE_CLASSES[tone]}`}
    >
      {children}
    </span>
  );
}

export default StatusBadge;
