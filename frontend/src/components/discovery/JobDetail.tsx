import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardCopy,
  Lightbulb,
  Loader2,
  Radio,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";
import { Pill, type Tone } from "@/components/ui/status";
import { btnCls, ErrorState, LoadingBlock, selectCls } from "@/components/ui/feedback";
import { clock, detailText, StepIcon } from "@/components/deployments/DeploymentLive";
import { api, invalidateInventory, qk } from "@/lib/api/queries";
import { useJobStream } from "@/lib/api/sse";
import type {
  DiscoveryJob,
  DiscoveryLogEntry,
  DiscoveryProgress,
  DiscoveryStep,
} from "@/lib/api/types";
import { fmtAgo, fmtDateTime } from "@/lib/format";
import { cn } from "@/lib/utils";

export const DISCOVERY_DONE = new Set(["completed", "partial", "failed", "cancelled"]);

export const discoveryTone = (s: string): Tone =>
  s === "completed"
    ? "ok"
    : s === "partial"
      ? "warn"
      : s === "failed"
        ? "danger"
        : s === "cancelled"
          ? "neutral"
          : "info";

export const fmtMs = (ms?: number | null): string => {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)}s`;
  return `${Math.floor(s / 60)}m ${String(Math.round(s % 60)).padStart(2, "0")}s`;
};

const clsTone = (c: string): Tone =>
  c === "managed"
    ? "ok"
    : c === "unmanaged" || c === "unsupported"
      ? "neutral"
      : c === "requires_mapping"
        ? "warn"
        : "danger";

const logLineText = (e: DiscoveryLogEntry) => {
  const d = e.details && Object.keys(e.details).length ? ` ${JSON.stringify(e.details)}` : "";
  return `${e.ts} ${e.level.toUpperCase().padEnd(7)} ${e.step ? `[${e.step}] ` : ""}${e.message}${d}`;
};

/**
 * Loads a discovery job and keeps it live: SSE `snapshot` merges job fields, `progress` frames of type `step` / `log`
 * upsert/append into the cached job, and the shared poller (3 s) takes over if the EventSource fails.
 */
export function useLiveDiscoveryJob(jobId: string, serverId?: string | null) {
  const qc = useQueryClient();
  const [progress, setProgress] = useState<DiscoveryProgress | null>(null);
  const q = useQuery({
    queryKey: qk.discoveryJobs.detail(jobId),
    queryFn: () => api.discoveryJobs.get(jobId),
  });
  const status = q.data?.status;
  const active = !!status && !DISCOVERY_DONE.has(status);

  const refreshAll = () => {
    void qc.invalidateQueries({ queryKey: qk.discoveryJobs.detail(jobId) });
    if (serverId) {
      void qc.invalidateQueries({ queryKey: qk.discoveryJobs.forServerAll(serverId) });
      void qc.invalidateQueries({ queryKey: qk.servers.installations(serverId) });
    }
    invalidateInventory(qc);
  };

  // The stream closes as soon as a snapshot shows a terminal status (possibly before `event: end`).
  const wasActive = useRef(false);
  useEffect(() => {
    if (wasActive.current && !active) refreshAll();
    wasActive.current = active;
  }, [active]); // eslint-disable-line react-hooks/exhaustive-deps

  const patchJob = (fn: (old: DiscoveryJob) => DiscoveryJob) =>
    qc.setQueryData<DiscoveryJob>(qk.discoveryJobs.detail(jobId), (old) => (old ? fn(old) : old));

  const mode = useJobStream<Record<string, unknown>>({
    url: active ? api.discoveryJobs.eventsUrl(jobId) : null,
    onSnapshot: (snap) =>
      patchJob((old) => ({
        ...old,
        status: String(snap["status"] ?? old.status),
        stats: (snap["stats"] as DiscoveryJob["stats"]) ?? old.stats,
        error: (snap["error"] as string | null) ?? old.error,
        error_code: (snap["error_code"] as string | null) ?? old.error_code,
        hint: (snap["hint"] as string | null) ?? old.hint,
        started_at: (snap["started_at"] as string | null) ?? old.started_at,
        finished_at: (snap["finished_at"] as string | null) ?? old.finished_at,
        steps: Array.isArray(snap["steps"]) ? (snap["steps"] as DiscoveryStep[]) : old.steps,
        log: Array.isArray(snap["log"]) ? (snap["log"] as DiscoveryLogEntry[]) : old.log,
      })),
    onProgress: (p) => {
      if (p["type"] === "step" && p["step"]) {
        const step = p["step"] as DiscoveryStep;
        patchJob((old) => {
          const steps = [...(old.steps ?? [])];
          const i = steps.findIndex((x) => x.name === step.name);
          if (i >= 0) steps[i] = step;
          else steps.push(step);
          return { ...old, steps };
        });
      } else if (p["type"] === "log" && p["entry"]) {
        const entry = p["entry"] as DiscoveryLogEntry;
        patchJob((old) => {
          const log = old.log ?? [];
          const dup = log.some(
            (l) => l.ts === entry.ts && l.message === entry.message && l.step === entry.step,
          );
          return dup ? old : { ...old, log: [...log, entry] };
        });
      } else {
        setProgress((prev) => ({ ...prev, ...(p as DiscoveryProgress) }));
      }
    },
    onEnd: refreshAll,
    poll: async () => {
      const j = await api.discoveryJobs.get(jobId);
      qc.setQueryData(qk.discoveryJobs.detail(jobId), j);
      if (DISCOVERY_DONE.has(j.status)) {
        refreshAll();
        return true;
      }
      return false;
    },
  });
  return { query: q, mode, active, progress };
}

export function FailureBanner({
  error,
  errorCode,
  hint,
  title = "Scan failed",
}: {
  error: string | null;
  errorCode: string | null;
  hint: string | null;
  title?: string;
}) {
  return (
    <div
      className="space-y-1.5 rounded-md border border-danger/40 bg-danger-soft p-3"
      role="alert"
      data-testid="discovery-failure"
    >
      <div className="flex flex-wrap items-center gap-2 text-[13px] font-semibold text-danger">
        <XCircle className="size-4" /> {title}
        {errorCode && (
          <span className="mono rounded-sm border border-danger/30 px-1.5 py-0.5 text-[11px] font-medium">
            {errorCode}
          </span>
        )}
      </div>
      {error && <p className="mono break-words text-[12px] text-danger">{error}</p>}
      {hint && (
        <p className="flex items-start gap-1.5 text-[12px] text-foreground">
          <Lightbulb className="mt-0.5 size-3.5 shrink-0 text-warn" />
          <span>{hint}</span>
        </p>
      )}
    </div>
  );
}

export function StepTimeline({ steps, running }: { steps: DiscoveryStep[]; running: boolean }) {
  if (steps.length === 0) return null;
  return (
    <ol className="space-y-1" data-testid="discovery-steps">
      {steps.map((s, i) => {
        const txt = detailText(s.detail);
        return (
          <li
            key={`${s.name}-${i}`}
            className="flex items-start gap-2 text-[12px]"
            data-status={s.status}
            data-step={s.name}
          >
            <span className="mt-0.5">
              <StepIcon state={s.status} />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-baseline gap-x-2">
                <span
                  className={cn(
                    s.status === "failed" && "text-danger",
                    s.status === "warning" && "text-warn",
                  )}
                >
                  {s.label || s.name}
                </span>
                <span className="mono text-[11px] text-muted-foreground">
                  {clock(s.started_at)}
                  {s.duration_ms !== null &&
                    s.duration_ms !== undefined &&
                    ` · ${fmtMs(s.duration_ms)}`}
                </span>
                {s.error_code && (
                  <span className="mono text-[11px] text-danger">{s.error_code}</span>
                )}
              </div>
              {txt && <div className="mono break-all text-[11px] text-muted-foreground">{txt}</div>}
            </div>
          </li>
        );
      })}
      {running && (
        <li className="flex items-center gap-2 text-[12px] text-muted-foreground">
          <Loader2 className="size-3.5 animate-spin text-info" /> Working…
        </li>
      )}
    </ol>
  );
}

const LEVEL_CLS: Record<string, string> = {
  info: "text-muted-foreground",
  warning: "text-warn",
  error: "text-danger",
};

export function LogViewer({ log, live }: { log: DiscoveryLogEntry[]; live: boolean }) {
  const [level, setLevel] = useState("all");
  const [onlyProblems, setOnlyProblems] = useState(false);
  const box = useRef<HTMLPreElement>(null);
  const shown = useMemo(
    () =>
      log.filter(
        (e) =>
          (level === "all" || e.level === level) &&
          (!onlyProblems || e.level === "warning" || e.level === "error"),
      ),
    [log, level, onlyProblems],
  );
  useEffect(() => {
    if (live && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [shown.length, live]);

  const copy = async () => {
    const text = shown.map(logLineText).join("\n");
    try {
      await navigator.clipboard.writeText(text);
      toast.success("Log copied to clipboard");
    } catch {
      toast.error("Could not copy", { description: "Clipboard access was denied by the browser." });
    }
  };

  return (
    <div className="space-y-1.5" data-testid="discovery-log">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11.5px] uppercase tracking-[0.05em] text-muted-foreground">
          Log ({shown.length}
          {shown.length !== log.length ? ` of ${log.length}` : ""})
        </span>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <label className="flex cursor-pointer items-center gap-1.5 text-[12px]">
            <input
              type="checkbox"
              checked={onlyProblems}
              onChange={(e) => setOnlyProblems(e.target.checked)}
            />
            Only warnings and errors
          </label>
          <select
            value={level}
            onChange={(e) => setLevel(e.target.value)}
            aria-label="Log level"
            className={selectCls}
          >
            <option value="all">All levels</option>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="error">Error</option>
          </select>
          <button className={btnCls} onClick={() => void copy()} disabled={shown.length === 0}>
            <ClipboardCopy className="size-3.5" /> Copy log
          </button>
        </div>
      </div>
      {shown.length === 0 ? (
        <p className="rounded-sm border border-border bg-surface-2/50 p-2 text-[12px] text-muted-foreground">
          {log.length === 0 ? "No log entries yet." : "No entries match the filter."}
        </p>
      ) : (
        <pre
          ref={box}
          tabIndex={0}
          className="mono max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-sm border border-border bg-surface-2/50 p-2 text-[11px] leading-5"
        >
          {shown.map((e, i) => (
            <div
              key={`${e.ts}-${i}`}
              className={cn(LEVEL_CLS[e.level] ?? "text-foreground")}
              data-level={e.level}
            >
              {logLineText(e)}
            </div>
          ))}
        </pre>
      )}
    </div>
  );
}

/** Full view of one discovery job: banner, progress, steps, stats, log, findings. Live while the job is active. */
export function JobDetail({
  jobId,
  serverId,
  withLog = true,
}: {
  jobId: string;
  serverId?: string | null;
  withLog?: boolean;
}) {
  const { query: q, mode, active, progress } = useLiveDiscoveryJob(jobId, serverId);

  if (q.isLoading) return <LoadingBlock label="Loading discovery job…" />;
  if (q.isError || !q.data) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const job = q.data;
  const done = DISCOVERY_DONE.has(job.status);
  const pct = done ? 100 : (progress?.percent ?? (job.status === "running" ? 2 : 0));
  const st = job.stats;
  const steps = job.steps ?? [];
  const log = job.log ?? [];

  return (
    <div className="space-y-3 p-3" data-testid="discovery-job" data-status={job.status}>
      <div className="flex flex-wrap items-center gap-2 text-[12px]">
        <Pill tone={discoveryTone(job.status)} dot>
          {job.status}
        </Pill>
        {active && mode === "live" && (
          <Pill tone="ok" className="gap-1">
            <Radio className="size-3" /> Live
          </Pill>
        )}
        {active && mode === "polling" && <Pill tone="warn">Polling every 3s</Pill>}
        {job.warnings_count > 0 && (
          <Pill tone="warn" className="gap-1">
            <AlertTriangle className="size-3" /> {job.warnings_count} warning
            {job.warnings_count === 1 ? "" : "s"}
          </Pill>
        )}
        <span className="mono text-muted-foreground">
          {job.duration_ms !== null && job.duration_ms !== undefined
            ? fmtMs(job.duration_ms)
            : job.started_at
              ? "running"
              : "queued"}
        </span>
        {job.scheduled && <Pill tone="neutral">scheduled</Pill>}
        <span className="text-muted-foreground">
          started {fmtDateTime(job.started_at ?? job.created_at)}
          {job.requested_by_name ? ` by ${job.requested_by_name}` : ""}
        </span>
      </div>

      {(job.status === "failed" || (job.error && done && job.status !== "completed")) && (
        <FailureBanner error={job.error} errorCode={job.error_code} hint={job.hint} />
      )}
      {job.status === "partial" && job.hint && (
        <p className="flex items-start gap-1.5 rounded-md border border-warn/40 bg-warn-soft p-2 text-[12px]">
          <Lightbulb className="mt-0.5 size-3.5 shrink-0 text-warn" />
          <span>{job.hint}</span>
        </p>
      )}

      {active && (
        <div>
          <div className="mb-1 flex items-center justify-between text-[12px] text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <Loader2 className="size-3.5 animate-spin" />
              {progress?.message ??
                (job.status === "pending" ? "Waiting for a worker…" : "Scanning…")}
            </span>
            <span className="mono tabular-nums">{pct}%</span>
          </div>
          <div className="h-1.5 w-full rounded-full bg-muted">
            <div
              className="h-1.5 rounded-full bg-primary transition-all"
              style={{ width: `${pct}%` }}
            />
          </div>
        </div>
      )}

      <StepTimeline steps={steps} running={active && steps.length > 0} />

      {st && done && (
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {(
            [
              ["Certificates found", st.certificates_created ?? 0],
              ["Installations new", st.installations_created ?? 0],
              ["Installations updated", st.installations_updated ?? 0],
              ["Marked missing", st.marked_missing ?? 0],
            ] as const
          ).map(([l, n]) => (
            <div key={l} className="rounded-md border border-border bg-surface-2/40 p-2">
              <div className="text-[10.5px] uppercase tracking-[0.06em] text-muted-foreground">
                {l}
              </div>
              <div className="mono text-lg tabular-nums">{n}</div>
            </div>
          ))}
        </div>
      )}
      {st?.failed_services && Object.keys(st.failed_services).length > 0 && (
        <div className="rounded-md border border-warn/40 bg-warn-soft p-2 text-[12px]">
          <div className="font-semibold text-warn">Some services could not be read</div>
          <ul className="mono mt-1 space-y-0.5 text-[11.5px]">
            {Object.entries(st.failed_services).map(([k, v]) => (
              <li key={k}>
                {k}: {v}
              </li>
            ))}
          </ul>
        </div>
      )}

      {withLog && <LogViewer log={log} live={active} />}

      {job.findings && job.findings.length > 0 && (
        <details
          open={
            job.status !== "completed" ||
            job.findings.some((f) => !["managed", "unmanaged"].includes(f.classification))
          }
        >
          <summary className="cursor-pointer text-[12px] text-muted-foreground">
            Findings ({job.findings.length})
            {st?.by_classification &&
              ` · ${Object.entries(st.by_classification)
                .map(([k, n]) => `${n} ${k}`)
                .join(", ")}`}
          </summary>
          <ul
            className="mt-1.5 divide-y divide-border/60 rounded-md border border-border"
            data-testid="discovery-findings"
          >
            {job.findings.map((f) => (
              <li
                key={f.id}
                className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 px-2 py-1.5 text-[12px]"
              >
                <Pill tone={clsTone(f.classification)}>{f.classification}</Pill>
                <span className="mono break-all">{f.path}</span>
                {f.message && <span className="text-muted-foreground">{f.message}</span>}
              </li>
            ))}
          </ul>
        </details>
      )}
      {done && job.status !== "failed" && (
        <div className="flex items-center gap-1.5 text-[12px] text-muted-foreground">
          <CheckCircle2 className="size-3.5 text-ok" /> Finished {fmtAgo(job.finished_at)}
        </div>
      )}
    </div>
  );
}
