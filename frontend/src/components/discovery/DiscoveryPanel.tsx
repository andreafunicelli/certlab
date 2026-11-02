import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Loader2, Radio, XCircle } from "lucide-react";
import { Panel } from "@/components/layout/AppShell";
import { Pill, type Tone } from "@/components/ui/status";
import { ErrorState, LoadingBlock } from "@/components/ui/feedback";
import { api, invalidateInventory, qk, useServerDiscoveryJobs } from "@/lib/api/queries";
import { useJobStream } from "@/lib/api/sse";
import type { DiscoveryJob, DiscoveryProgress } from "@/lib/api/types";
import { fmtAgo, fmtDuration } from "@/lib/format";

const DONE = new Set(["completed", "partial", "failed", "cancelled"]);
const jobTone = (s: string): Tone =>
  s === "completed"
    ? "ok"
    : s === "partial"
      ? "warn"
      : s === "failed"
        ? "danger"
        : s === "cancelled"
          ? "neutral"
          : "info";

const clsTone = (c: string): Tone =>
  c === "managed"
    ? "ok"
    : c === "unmanaged" || c === "unsupported"
      ? "neutral"
      : c === "requires_mapping"
        ? "warn"
        : "danger";

/** Live view of one discovery job: SSE progress, then stats + findings/errors from GET /discovery-jobs/{id}. */
function JobView({ jobId, serverId }: { jobId: string; serverId: string }) {
  const qc = useQueryClient();
  const [progress, setProgress] = useState<DiscoveryProgress | null>(null);
  const [lines, setLines] = useState<string[]>([]);
  const q = useQuery({
    queryKey: qk.discoveryJobs.detail(jobId),
    queryFn: () => api.discoveryJobs.get(jobId),
  });
  const status = q.data?.status;
  const active = !!status && !DONE.has(status);

  const refreshAll = () => {
    void qc.invalidateQueries({ queryKey: qk.discoveryJobs.detail(jobId) });
    void qc.invalidateQueries({ queryKey: qk.discoveryJobs.forServer(serverId) });
    void qc.invalidateQueries({ queryKey: qk.servers.installations(serverId) });
    invalidateInventory(qc);
  };

  // The stream closes as soon as a snapshot shows a terminal status (possibly before `event: end`).
  const wasActive = useRef(false);
  useEffect(() => {
    if (wasActive.current && !active) refreshAll();
    wasActive.current = active;
  }, [active]); // eslint-disable-line react-hooks/exhaustive-deps

  const mode = useJobStream<Record<string, unknown>>({
    url: active ? api.discoveryJobs.eventsUrl(jobId) : null,
    onSnapshot: (snap) => {
      qc.setQueryData<DiscoveryJob>(qk.discoveryJobs.detail(jobId), (old) =>
        old
          ? {
              ...old,
              status: String(snap["status"] ?? old.status),
              stats: (snap["stats"] as DiscoveryJob["stats"]) ?? old.stats,
              error: (snap["error"] as string | null) ?? old.error,
              started_at: (snap["started_at"] as string | null) ?? old.started_at,
              finished_at: (snap["finished_at"] as string | null) ?? old.finished_at,
            }
          : old,
      );
    },
    onProgress: (p) => {
      const d = p as DiscoveryProgress;
      setProgress((prev) => ({ ...prev, ...d }));
      if (d.message) setLines((l) => [...l.slice(-30), `${d.stage ?? d.type}: ${d.message}`]);
    },
    onEnd: refreshAll,
    poll: async () => {
      const j = await api.discoveryJobs.get(jobId);
      qc.setQueryData(qk.discoveryJobs.detail(jobId), j);
      if (DONE.has(j.status)) {
        refreshAll();
        return true;
      }
      return false;
    },
  });

  if (q.isLoading) return <LoadingBlock label="Loading discovery job…" />;
  if (q.isError || !q.data) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const job = q.data;
  const pct = DONE.has(job.status)
    ? 100
    : (progress?.percent ?? (job.status === "running" ? 2 : 0));
  const st = job.stats;

  return (
    <div className="space-y-3 p-3" data-testid="discovery-job" data-status={job.status}>
      <div className="flex flex-wrap items-center gap-2 text-[12px]">
        <Pill tone={jobTone(job.status)} dot>
          {job.status}
        </Pill>
        {active && mode === "live" && (
          <Pill tone="ok" className="gap-1">
            <Radio className="size-3" /> Live
          </Pill>
        )}
        {active && mode === "polling" && <Pill tone="warn">Polling every 3s</Pill>}
        <span className="mono text-muted-foreground">
          {job.started_at ? fmtDuration(job.started_at, job.finished_at) : "queued"}
        </span>
        {job.scheduled && <Pill tone="neutral">scheduled</Pill>}
      </div>

      {active && (
        <div>
          <div className="mb-1 flex items-center justify-between text-[12px] text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <Loader2 className="size-3.5 animate-spin" />
              {progress?.message ??
                (job.status === "pending" ? "Waiting for a worker…" : "Starting…")}
            </span>
            <span className="mono tabular-nums">{pct}%</span>
          </div>
          <div className="h-1.5 w-full rounded-full bg-muted">
            <div
              className="h-1.5 rounded-full bg-primary transition-all"
              style={{ width: `${pct}%` }}
            />
          </div>
          {lines.length > 0 && (
            <pre className="mono mt-2 max-h-28 overflow-auto rounded-sm border border-border bg-surface-2/50 p-2 text-[11px]">
              {lines.join("\n")}
            </pre>
          )}
        </div>
      )}

      {job.error && (
        <div
          className="rounded-md border border-danger/30 bg-danger-soft p-2 text-[12px] text-danger"
          role="alert"
        >
          {job.error}
        </div>
      )}

      {st && DONE.has(job.status) && (
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
      {DONE.has(job.status) && job.status !== "failed" && (
        <div className="flex items-center gap-1.5 text-[12px] text-muted-foreground">
          <CheckCircle2 className="size-3.5 text-ok" /> Finished {fmtAgo(job.finished_at)}
        </div>
      )}
      {job.status === "failed" && (
        <div className="flex items-center gap-1.5 text-[12px] text-danger">
          <XCircle className="size-3.5" /> Discovery failed {fmtAgo(job.finished_at)}
        </div>
      )}
    </div>
  );
}

export function DiscoveryPanel({
  serverId,
  jobId,
}: {
  serverId: string;
  /** Job just started from the page (null: show the latest job of this server, resuming it if still running). */
  jobId: string | null;
}) {
  const jobs = useServerDiscoveryJobs(serverId);
  const latest = jobs.data?.items[0];
  const show = jobId ?? latest?.id ?? null;
  if (!show) {
    if (jobs.isLoading) return null;
    return null;
  }
  return (
    <Panel
      title="Certificate discovery"
      actions={
        <span className="text-[11.5px] text-muted-foreground">
          {jobs.data && jobs.data.total > 1 ? `${jobs.data.total} runs · ` : ""}latest shown
        </span>
      }
    >
      <JobView key={show} jobId={show} serverId={serverId} />
    </Panel>
  );
}
