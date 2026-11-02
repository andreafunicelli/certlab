import { cva, type VariantProps } from "class-variance-authority";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

const pill = cva(
  "inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 text-[11px] font-medium leading-4 whitespace-nowrap",
  {
    variants: {
      tone: {
        ok: "border-ok/30 bg-ok-soft text-ok",
        warn: "border-warn/30 bg-warn-soft text-warn",
        crit: "border-crit/30 bg-crit-soft text-crit",
        danger: "border-danger/30 bg-danger-soft text-danger",
        info: "border-info/30 bg-info-soft text-info",
        neutral: "border-border bg-neutral-soft text-muted-foreground",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export type Tone = NonNullable<VariantProps<typeof pill>["tone"]>;

export function Pill({
  tone,
  children,
  className,
  dot,
}: {
  tone?: Tone;
  children: ReactNode;
  className?: string;
  dot?: boolean;
}) {
  return (
    <span className={cn(pill({ tone }), className)}>
      {dot && <span className="size-1.5 rounded-full bg-current" />}
      {children}
    </span>
  );
}

const certToneMap: Record<string, { tone: Tone; label: string }> = {
  valid: { tone: "ok", label: "Valid" },
  expiring: { tone: "warn", label: "Expiring Soon" },
  critical: { tone: "crit", label: "Critical" },
  expired: { tone: "danger", label: "Expired" },
  error: { tone: "danger", label: "Deployment Error" },
};

export function CertStatusBadge({ status }: { status: string }) {
  const m = certToneMap[status] ?? { tone: "neutral" as Tone, label: status };
  return (
    <Pill tone={m.tone} dot>
      {m.label}
    </Pill>
  );
}

const envTone: Record<string, Tone> = {
  Production: "danger",
  Staging: "warn",
  Test: "info",
  Development: "neutral",
};

export function EnvBadge({ env }: { env: string }) {
  return <Pill tone={envTone[env] ?? "neutral"}>{env}</Pill>;
}

export function SshBadge({ status }: { status: string }) {
  const tone: Tone = status === "Connected" ? "ok" : status === "Offline" ? "danger" : "warn";
  return (
    <Pill tone={tone} dot>
      {status}
    </Pill>
  );
}

export function DaysLeft({ days }: { days: number }) {
  const tone: Tone = days < 0 ? "danger" : days <= 7 ? "crit" : days <= 30 ? "warn" : days <= 90 ? "info" : "ok";
  return (
    <span
      className={cn(
        "mono tabular-nums",
        tone === "danger" && "text-danger",
        tone === "crit" && "text-crit",
        tone === "warn" && "text-warn",
        tone === "info" && "text-muted-foreground",
        tone === "ok" && "text-muted-foreground",
      )}
    >
      {days < 0 ? `${Math.abs(days)}d ago` : `${days}d`}
    </span>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("mono text-muted-foreground", className)}>{children}</span>;
}
