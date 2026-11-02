import { AlertTriangle, Info, ShieldAlert } from "lucide-react";
import type { Finding } from "@/lib/api/types";
import { cn } from "@/lib/utils";

/** Blocking findings that the backend lets the operator acknowledge instead of failing (planner `_downgrade_acknowledged`). */
export const ACKNOWLEDGEABLE_BLOCKING = new Set(["INVENTORY_STALE"]);

const GROUPS = [
  {
    sev: "blocking",
    title: "Blocking",
    icon: ShieldAlert,
    cls: "border-danger/40 bg-danger-soft text-danger",
  },
  {
    sev: "warning",
    title: "Warnings",
    icon: AlertTriangle,
    cls: "border-warn/40 bg-warn-soft text-warn",
  },
  { sev: "info", title: "Information", icon: Info, cls: "border-info/30 bg-info-soft text-info" },
] as const;

/**
 * Findings grouped by severity. Warning codes (and acknowledgeable blocking codes) get a checkbox; the set of
 * acknowledged codes is owned by the caller and sent to the API as `acknowledged_warnings`.
 */
export function FindingsList({
  findings,
  acked,
  onToggle,
  where,
  disabled,
}: {
  findings: Finding[];
  acked: ReadonlySet<string>;
  onToggle: (code: string) => void;
  /** Resolves a finding's installation_id to a label (server name). */
  where?: (installationId: string) => string | undefined;
  disabled?: boolean;
}) {
  if (findings.length === 0)
    return <p className="p-3 text-[12.5px] text-muted-foreground">No findings.</p>;
  return (
    <div className="space-y-3 p-3" data-testid="findings">
      {GROUPS.map((g) => {
        const rows = findings.filter((f) => f.severity === g.sev);
        if (rows.length === 0) return null;
        const codes = [...new Set(rows.map((r) => r.code))];
        return (
          <div key={g.sev} data-severity={g.sev}>
            <div className="mb-1 flex items-center gap-1.5 text-[11px] uppercase tracking-[0.06em] text-muted-foreground">
              <g.icon className="size-3.5" /> {g.title} ({rows.length})
            </div>
            <ul className="space-y-1.5">
              {rows.map((f, i) => (
                <li
                  key={`${f.code}-${i}`}
                  className={cn("rounded-md border p-2 text-[12.5px]", g.cls)}
                  data-code={f.code}
                >
                  <div className="flex flex-wrap items-baseline gap-x-2">
                    <span className="mono text-[11px] font-semibold">{f.code}</span>
                    {f.installation_id && where?.(f.installation_id) && (
                      <span className="mono text-[11px] opacity-80">
                        {where(f.installation_id)}
                      </span>
                    )}
                  </div>
                  <div className="text-foreground">{f.message}</div>
                </li>
              ))}
            </ul>
            {(g.sev === "warning" ||
              (g.sev === "blocking" && codes.some((c) => ACKNOWLEDGEABLE_BLOCKING.has(c)))) && (
              <div className="mt-1.5 space-y-1">
                {codes
                  .filter((c) => g.sev === "warning" || ACKNOWLEDGEABLE_BLOCKING.has(c))
                  .map((c) => (
                    <label key={c} className="flex items-center gap-2 text-[12px]">
                      <input
                        type="checkbox"
                        checked={acked.has(c)}
                        disabled={disabled}
                        onChange={() => onToggle(c)}
                        className="accent-[var(--color-primary)]"
                        data-testid={`ack-${c}`}
                      />
                      <span>
                        I acknowledge <span className="mono">{c}</span> and want to proceed
                      </span>
                    </label>
                  ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
