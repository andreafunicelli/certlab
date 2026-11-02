import { CheckCircle2, CircleSlash, XCircle } from "lucide-react";
import { Panel } from "@/components/layout/AppShell";
import { Pill } from "@/components/ui/status";
import type { ConnectionTestResult } from "@/lib/api/types";
import { cn } from "@/lib/utils";

function StepIcon({ status }: { status: string }) {
  if (status === "ok") return <CheckCircle2 className="size-3.5 text-ok" />;
  if (status === "skipped") return <CircleSlash className="size-3.5 text-muted-foreground" />;
  return <XCircle className="size-3.5 text-danger" />;
}

/** Renders the real step results of POST /servers/{id}/test-connection. */
export function ConnectionTestPanel({ result }: { result: ConnectionTestResult }) {
  return (
    <Panel
      title="Connection Result"
      actions={
        <Pill tone={result.ok ? "ok" : "danger"} dot>
          {result.ok ? "Connected" : "Failed"}
        </Pill>
      }
    >
      <ol className="space-y-1.5 p-3 text-[12.5px]" data-testid="connection-steps">
        {result.steps.map((s) => (
          <li key={s.name} className="flex items-start gap-2" data-status={s.status}>
            <span className="mt-0.5">
              <StepIcon status={s.status} />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline justify-between gap-2">
                <span className={cn(s.status === "skipped" && "text-muted-foreground")}>
                  {s.name}
                </span>
                {s.duration_ms != null && (
                  <span className="mono text-[11px] text-muted-foreground">{s.duration_ms} ms</span>
                )}
              </div>
              {s.detail && (
                <div className="mono break-words text-[11.5px] text-muted-foreground">
                  {s.detail}
                </div>
              )}
            </div>
          </li>
        ))}
        {!result.ok && result.error_message && (
          <li className="rounded-md border border-danger/30 bg-danger-soft p-2 text-[12px] text-danger">
            {result.error_code && <span className="mono mr-1.5">{result.error_code}</span>}
            {result.error_message}
          </li>
        )}
      </ol>
    </Panel>
  );
}
