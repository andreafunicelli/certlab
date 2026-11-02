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
  info: { tone: "info", label: "Renew Soon" },
  warning: { tone: "warn", label: "Expiring Soon" },
  expiring: { tone: "warn", label: "Expiring Soon" },
  high: { tone: "crit", label: "High" },
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
  const tone: Tone =
    days < 0 ? "danger" : days <= 7 ? "crit" : days <= 30 ? "warn" : days <= 90 ? "info" : "ok";
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

const connTone: Record<string, { tone: Tone; label: string }> = {
  connected: { tone: "ok", label: "Connected" },
  unknown: { tone: "neutral", label: "Not tested" },
  offline: { tone: "danger", label: "Offline" },
  auth_error: { tone: "danger", label: "Auth failed" },
  host_key_unknown: { tone: "warn", label: "Host key not enrolled" },
  host_key_mismatch: { tone: "crit", label: "Host key changed" },
  error: { tone: "danger", label: "Error" },
};

/** SSH connection status coming from the API (`connection_status`). */
export function ConnectionBadge({ status, enabled = true }: { status: string; enabled?: boolean }) {
  if (!enabled)
    return (
      <Pill tone="neutral" dot>
        Disabled
      </Pill>
    );
  const m = connTone[status] ?? { tone: "neutral" as Tone, label: status };
  return (
    <Pill tone={m.tone} dot>
      {m.label}
    </Pill>
  );
}

export function OutcomePill({ outcome }: { outcome: string }) {
  const tone: Tone = outcome === "success" ? "ok" : outcome === "denied" ? "warn" : "danger";
  return (
    <Pill tone={tone} dot>
      {outcome.toUpperCase()}
    </Pill>
  );
}

const classTone: Record<string, { tone: Tone; label: string }> = {
  managed: { tone: "ok", label: "Managed" },
  unmanaged: { tone: "neutral", label: "Unmanaged" },
  requires_mapping: { tone: "warn", label: "Needs mapping" },
  unsupported: { tone: "neutral", label: "Unsupported" },
  unreadable: { tone: "danger", label: "Unreadable" },
  error: { tone: "danger", label: "Error" },
};
export function ClassificationBadge({ value, certbot }: { value: string; certbot?: boolean }) {
  if (certbot)
    return (
      <Pill tone="neutral" dot>
        Certbot-managed
      </Pill>
    );
  const m = classTone[value] ?? { tone: "neutral" as Tone, label: value };
  return (
    <Pill tone={m.tone} dot>
      {m.label}
    </Pill>
  );
}

const driftTone: Record<string, { tone: Tone; label: string }> = {
  in_sync: { tone: "ok", label: "In sync" },
  drifted: { tone: "warn", label: "Drifted" },
  missing: { tone: "danger", label: "Missing" },
  unknown: { tone: "neutral", label: "Unknown" },
};
export function DriftBadge({ value }: { value: string }) {
  const m = driftTone[value] ?? { tone: "neutral" as Tone, label: value };
  return (
    <Pill tone={m.tone} dot>
      {m.label}
    </Pill>
  );
}

const jobTone: Record<string, { tone: Tone; label: string }> = {
  pending: { tone: "neutral", label: "Pending" },
  awaiting_approval: { tone: "warn", label: "Awaiting approval" },
  preflight: { tone: "info", label: "Pre-flight" },
  activating: { tone: "info", label: "Running" },
  completed: { tone: "ok", label: "Completed" },
  partially_failed: { tone: "warn", label: "Partially failed" },
  failed: { tone: "danger", label: "Failed" },
  rolled_back: { tone: "warn", label: "Rolled back" },
  manual_intervention_required: { tone: "danger", label: "Manual intervention" },
  cancelled: { tone: "neutral", label: "Cancelled" },
};
/** Deployment job / target status. Unknown in-flight target states (backing_up, staging, ...) render as "running". */
export function JobStatusBadge({ status }: { status: string }) {
  const m = jobTone[status] ?? {
    tone: "info" as Tone,
    label: status.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase()),
  };
  return (
    <Pill tone={m.tone} dot>
      {m.label}
    </Pill>
  );
}
export const FINAL_STATUSES = new Set([
  "completed",
  "failed",
  "rolled_back",
  "cancelled",
  "partially_failed",
  "manual_intervention_required",
]);
