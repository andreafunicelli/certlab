import { AlertTriangle, Inbox, Loader2 } from "lucide-react";
import type { ReactNode } from "react";
import { isApiError } from "@/lib/api/client";
import { cn } from "@/lib/utils";

/** Shared form/button class names (same look as the original prototype pages). */
export const inputCls =
  "h-8 w-full rounded-md border border-input bg-surface px-2 text-[12.5px] outline-none placeholder:text-muted-foreground focus:border-ring disabled:opacity-60";
export const selectCls =
  "h-7.5 rounded-md border border-input bg-surface px-2 text-[12.5px] outline-none focus:border-ring";
export const labelCls =
  "mb-1 block text-[11.5px] uppercase tracking-[0.05em] text-muted-foreground";
export const btnCls =
  "inline-flex h-7.5 items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 text-[12.5px] hover:border-primary hover:text-primary disabled:pointer-events-none disabled:opacity-50";
export const btnPrimaryCls =
  "inline-flex h-7.5 items-center gap-1.5 rounded-md bg-primary px-2.5 text-[12.5px] font-medium text-primary-foreground hover:opacity-90 disabled:pointer-events-none disabled:opacity-50";
export const btnDangerCls =
  "inline-flex h-7.5 items-center gap-1.5 rounded-md border border-danger/40 bg-danger-soft px-2.5 text-[12.5px] text-danger hover:border-danger disabled:pointer-events-none disabled:opacity-50";

export function errorMessage(e: unknown): string {
  if (isApiError(e)) {
    const fe = e.fieldErrors;
    if (fe.length)
      return fe.map((x) => `${x.loc.filter((l) => l !== "body").join(".")}: ${x.msg}`).join("; ");
    return e.message;
  }
  return e instanceof Error ? e.message : "Unexpected error";
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn("size-3.5 animate-spin", className)} />;
}

export function LoadingBlock({ label = "Loading…" }: { label?: string }) {
  return (
    <div
      className="flex items-center justify-center gap-2 p-8 text-[12.5px] text-muted-foreground"
      role="status"
    >
      <Spinner /> {label}
    </div>
  );
}

export function EmptyState({
  title,
  hint,
  action,
}: {
  title: string;
  hint?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-1.5 p-8 text-center">
      <Inbox className="size-5 text-muted-foreground" />
      <div className="text-[13px] font-medium">{title}</div>
      {hint && <div className="max-w-md text-[12px] text-muted-foreground">{hint}</div>}
      {action && <div className="mt-1.5">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const cid = isApiError(error) ? error.correlationId : null;
  return (
    <div className="flex flex-col items-center gap-1.5 p-8 text-center" role="alert">
      <AlertTriangle className="size-5 text-danger" />
      <div className="text-[13px] font-medium">Could not load data</div>
      <div className="max-w-md text-[12px] text-muted-foreground">{errorMessage(error)}</div>
      {cid && <div className="mono text-[11px] text-muted-foreground">correlation id: {cid}</div>}
      {onRetry && (
        <button onClick={onRetry} className={cn(btnCls, "mt-1.5")}>
          Retry
        </button>
      )}
    </div>
  );
}

export function FieldError({ children }: { children?: ReactNode }) {
  if (!children) return null;
  return <p className="mt-1 text-[11.5px] text-danger">{children}</p>;
}
