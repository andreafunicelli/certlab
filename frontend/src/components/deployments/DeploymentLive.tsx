import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  Clock,
  Loader2,
  MinusCircle,
  RotateCcw,
  Radio,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";
import { Panel } from "@/components/layout/AppShell";
import { Pill, JobStatusBadge, FINAL_STATUSES } from "@/components/ui/status";
import { ConfirmDialog } from "@/components/ui/confirm";
import {
  btnCls,
  btnDangerCls,
  btnPrimaryCls,
  EmptyState,
  ErrorState,
  errorMessage,
  LoadingBlock,
  Spinner,
} from "@/components/ui/feedback";
import { useReauthGate } from "@/components/auth/useReauthGate";
import {
  api,
  invalidateDeployments,
  qk,
  useDeployment,
  useDeploymentActions,
} from "@/lib/api/queries";
import { isApiError } from "@/lib/api/client";
import { useJobStream, type StreamMode } from "@/lib/api/sse";
import type { DeploymentJob, DeploymentTarget, TargetStep } from "@/lib/api/types";
import { useCan } from "@/lib/auth";
import { fmtDateTime, fmtDuration, fmtMode, shortFp } from "@/lib/format";
import { cn } from "@/lib/utils";

const STALE_AFTER_MS = 10 * 60 * 1000;

/**
 * Loads a deployment and keeps it live: SSE `snapshot` replaces the cached job, `progress` frames trigger a refetch,
 * and if the EventSource fails we poll every 3 s (see lib/api/sse.ts).
 */
export function useLiveDeployment(id: string) {
  const qc = useQueryClient();
  const q = useDeployment(id);
  const status = q.data?.status;
  const active = !!status && !FINAL_STATUSES.has(status);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );

  // The stream is closed as soon as a snapshot/refetch shows a terminal status (possibly before `event: end`
  // arrives), so refresh dependants on the active -> inactive transition as well.
  const wasActive = useRef(false);
  useEffect(() => {
    if (wasActive.current && !active) {
      void qc.invalidateQueries({ queryKey: qk.deployments.detail(id) });
      invalidateDeployments(qc);
    }
    wasActive.current = active;
  }, [active]); // eslint-disable-line react-hooks/exhaustive-deps

  const mode = useJobStream<Record<string, unknown>>({
    url: active ? api.deployments.eventsUrl(id) : null,
    onSnapshot: (snap) => {
      const { type: _t, kind: _k, job_id: _j, ...job } = snap as Record<string, unknown>;
      void _t;
      void _k;
      void _j;
      qc.setQueryData<DeploymentJob>(qk.deployments.detail(id), (old) => ({
        ...(old as DeploymentJob),
        ...(job as unknown as DeploymentJob),
      }));
    },
    onProgress: () => {
      if (timer.current) return;
      timer.current = setTimeout(() => {
        timer.current = null;
        void qc.invalidateQueries({ queryKey: qk.deployments.detail(id) });
      }, 300);
    },
    onEnd: () => {
      void qc.invalidateQueries({ queryKey: qk.deployments.detail(id) });
      invalidateDeployments(qc);
    },
    poll: async () => {
      const j = await api.deployments.get(id);
      qc.setQueryData(qk.deployments.detail(id), j);
      return FINAL_STATUSES.has(j.status);
    },
  });
  return { query: q, mode };
}

// ---------------------------------------------------------------------------------------------
function StepIcon({ state }: { state: string }) {
  if (state === "ok") return <CheckCircle2 className="size-3.5 text-ok" />;
  if (state === "failed") return <XCircle className="size-3.5 text-danger" />;
  if (state === "running") return <Loader2 className="size-3.5 animate-spin text-info" />;
  if (state === "skipped") return <MinusCircle className="size-3.5 text-muted-foreground" />;
  return <CircleDashed className="size-3.5 text-muted-foreground" />;
}

const STEP_LABELS: Record<string, string> = {
  connect: "SSH connection",
  lock: "Acquire deployment lock",
  recheck: "Re-check target state",
  backup: "Back up existing files",
  stage: "Stage new certificate files",
  validate: "Validate staged files",
  activate: "Activate (atomic replace)",
  config_test: "Service config test",
  reload: "Reload service",
  verify: "Verify served certificate",
  cleanup: "Clean up staging files",
  finalize: "Finalize",
  rollback: "Automatic rollback",
  reconcile: "Reconcile after interruption",
};
export const stepLabel = (n: string) =>
  STEP_LABELS[n] ?? n.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());

function detailText(d: TargetStep["detail"]): string | null {
  if (!d) return null;
  if (typeof d === "string") return d;
  const parts = Object.entries(d)
    .filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(([k, v]) => {
      const sv = typeof v === "object" ? JSON.stringify(v) : String(v);
      return `${k}: ${sv.length > 140 ? `${sv.slice(0, 140)}…` : sv}`;
    });
  return parts.length ? parts.join(" · ") : null;
}

const clock = (iso: string | null) => (iso ? fmtDateTime(iso).slice(11) : "");

function TargetPanel({
  job,
  t,
  onRollback,
  canRollback,
}: {
  job: DeploymentJob;
  t: DeploymentTarget;
  onRollback: (t: DeploymentTarget) => void;
  canRollback: boolean;
}) {
  const steps = t.steps ?? [];
  const v = t.verification;
  const running = !FINAL_STATUSES.has(t.status) && t.status !== "pending";
  const canManualRollback =
    canRollback &&
    !!t.backup_id &&
    ["completed", "failed", "manual_intervention_required"].includes(t.status);
  const fpOk =
    v && v.expected_fingerprint
      ? v.endpoints.length > 0 &&
        v.endpoints.every((e) => e.served_fingerprint === v.expected_fingerprint)
      : null;

  return (
    <div data-testid="deploy-target">
      <Panel
        title={
          <span className="flex flex-wrap items-center gap-2">
            <span className="mono">{t.server_name ?? t.server_id.slice(0, 8)}</span>
            {t.service_type && <Pill tone="neutral">{t.service_type}</Pill>}
            {t.vhost && <span className="mono text-muted-foreground">{t.vhost}</span>}
            {t.is_canary && <Pill tone="info">canary</Pill>}
          </span>
        }
        actions={<JobStatusBadge status={t.status} />}
      >
        <div className="space-y-3 p-3">
          {t.cert_path && (
            <div className="mono truncate text-[11.5px] text-muted-foreground">{t.cert_path}</div>
          )}

          {steps.length === 0 && t.status === "pending" && (
            <div className="flex items-center gap-2 text-[12px] text-muted-foreground">
              <CircleDashed className="size-3.5" /> Waiting to start
              {job.status === "awaiting_approval" && " (awaiting approval)"}
            </div>
          )}

          {steps.length > 0 && (
            <ol className="space-y-1" data-testid="deploy-steps">
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
                        <span className={cn(s.status === "failed" && "text-danger")}>
                          {stepLabel(s.name)}
                        </span>
                        <span className="mono text-[11px] text-muted-foreground">
                          {clock(s.started_at)}
                          {s.finished_at && ` · ${fmtDuration(s.started_at, s.finished_at)}`}
                        </span>
                        {s.error_code && (
                          <span className="mono text-[11px] text-danger">{s.error_code}</span>
                        )}
                      </div>
                      {txt && (
                        <div className="mono break-all text-[11px] text-muted-foreground">
                          {txt}
                        </div>
                      )}
                    </div>
                  </li>
                );
              })}
              {running && (
                <li className="flex items-center gap-2 text-[12px] text-muted-foreground">
                  <Loader2 className="size-3.5 animate-spin text-info" />
                  {t.current_step ? stepLabel(t.current_step) : t.status.replace(/_/g, " ")}…
                </li>
              )}
            </ol>
          )}

          {t.error_message && (
            <pre
              className="mono overflow-x-auto whitespace-pre-wrap rounded-sm border border-danger/40 bg-danger-soft p-2 text-[11px] text-danger"
              role="alert"
            >
              {t.error_code ? `${t.error_code}: ` : ""}
              {t.error_message}
            </pre>
          )}

          {(t.status === "rolled_back" || t.rollback_attempts > 0) && (
            <div className="flex items-start gap-1.5 text-[11.5px] text-warn">
              <RotateCcw className="mt-0.5 size-3.5 shrink-0" />
              <span>
                {t.status === "rolled_back"
                  ? "Automatic rollback performed: previous certificate files restored from backup."
                  : `Rollback attempted ${t.rollback_attempts}×.`}
                {t.backup_id && (
                  <>
                    {" "}
                    Backup <span className="mono">{t.backup_id.slice(0, 8)}</span>.
                  </>
                )}
              </span>
            </div>
          )}
          {t.status === "manual_intervention_required" && (
            <div className="flex items-start gap-1.5 rounded-md border border-danger/40 bg-danger-soft p-2 text-[12px] text-danger">
              <ShieldAlert className="mt-0.5 size-3.5 shrink-0" />
              Automatic rollback did not complete. Inspect the server and restore the backup
              manually.
            </div>
          )}

          {(t.previous_fingerprint || t.new_fingerprint) && (
            <div className="grid gap-1 text-[11.5px] sm:grid-cols-2">
              <div>
                <div className="text-muted-foreground">Previous fingerprint</div>
                <div className="mono break-all" title={t.previous_fingerprint ?? ""}>
                  {shortFp(t.previous_fingerprint)}
                </div>
              </div>
              <div>
                <div className="text-muted-foreground">New fingerprint</div>
                <div className="mono break-all" title={t.new_fingerprint ?? ""}>
                  {shortFp(t.new_fingerprint)}
                </div>
              </div>
            </div>
          )}

          {t.files && t.files.length > 0 && (
            <details className="text-[11.5px]">
              <summary className="cursor-pointer text-muted-foreground">
                Files ({t.files.length})
              </summary>
              <ul className="mono mt-1 space-y-0.5">
                {t.files.map((f) => (
                  <li key={f.dest_path} className="break-all">
                    <Pill tone={f.action === "keep" ? "neutral" : "info"} className="mr-1.5">
                      {f.action}
                    </Pill>
                    {f.dest_path}
                    {f.is_symlink && f.realpath && f.realpath !== f.dest_path && ` → ${f.realpath}`}
                  </li>
                ))}
              </ul>
            </details>
          )}

          {v && (
            <div
              className="rounded-md border border-border bg-surface-2/40 p-2"
              data-testid="verification"
            >
              <div className="mb-1.5 flex items-center justify-between">
                <span className="text-[11px] uppercase tracking-[0.06em] text-muted-foreground">
                  Verification
                </span>
                <span className="flex items-center gap-1.5">
                  <Pill tone={v.mode === "live" ? "ok" : "warn"}>
                    {v.mode === "live" ? "Live TLS probe" : "File content only"}
                  </Pill>
                  {fpOk === true && (
                    <Pill tone="ok" dot>
                      Fingerprint verified
                    </Pill>
                  )}
                  {fpOk === false && v.mode === "live" && (
                    <Pill tone="danger" dot>
                      Fingerprint mismatch
                    </Pill>
                  )}
                </span>
              </div>
              {v.endpoints.map((e) => (
                <div
                  key={`${e.host}:${e.port}`}
                  className="flex flex-wrap items-baseline gap-x-2 text-[11.5px]"
                >
                  <span className="mono">
                    {e.host}:{e.port}
                    {e.sni ? ` (SNI ${e.sni})` : ""}
                  </span>
                  {e.reachable === false ? (
                    <span className="text-warn">unreachable{e.error ? `: ${e.error}` : ""}</span>
                  ) : (
                    <>
                      <span
                        className={cn(
                          "mono",
                          e.served_fingerprint === v.expected_fingerprint
                            ? "text-ok"
                            : "text-danger",
                        )}
                        title={e.served_fingerprint ?? ""}
                        data-testid="served-fingerprint"
                      >
                        serves {shortFp(e.served_fingerprint)}
                      </span>
                      {e.chain_valid === false && (
                        <span className="text-warn">chain not trusted</span>
                      )}
                      {e.hostname_matches === false && (
                        <span className="text-danger">hostname mismatch</span>
                      )}
                    </>
                  )}
                </div>
              ))}
              {v.files.map((f) => (
                <div
                  key={f.path}
                  className="mono flex flex-wrap gap-x-2 text-[11px] text-muted-foreground"
                >
                  <CheckCircle2 className="size-3 self-center text-ok" />
                  <span className="break-all">{f.path}</span>
                  <span title={f.sha256}>sha256 {f.sha256.slice(0, 12)}…</span>
                  <span>
                    {fmtMode(f.mode)} {f.owner}
                  </span>
                </div>
              ))}
            </div>
          )}

          {t.log && t.log.length > 0 && (
            <details className="text-[11.5px]">
              <summary className="cursor-pointer text-muted-foreground">
                Log ({t.log.length} lines, sanitized)
              </summary>
              <pre className="mono mt-1 max-h-56 overflow-auto rounded-sm border border-border bg-surface-2/50 p-2 text-[11px]">
                {t.log
                  .map((l) => `${clock(l.ts)} ${l.level.toUpperCase().padEnd(5)} ${l.message}`)
                  .join("\n")}
              </pre>
            </details>
          )}

          {canManualRollback && (
            <div className="flex justify-end">
              <button className={btnDangerCls} onClick={() => onRollback(t)}>
                <RotateCcw className="size-3.5" /> Roll back this server
              </button>
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}

function ModeIndicator({ mode }: { mode: StreamMode }) {
  if (mode === "live")
    return (
      <Pill tone="ok" className="gap-1">
        <Radio className="size-3" /> Live
      </Pill>
    );
  if (mode === "polling")
    return (
      <Pill tone="warn" className="gap-1">
        <Clock className="size-3" /> Polling every 3s
      </Pill>
    );
  if (mode === "connecting")
    return (
      <Pill tone="neutral" className="gap-1">
        <Spinner className="size-3" /> Connecting
      </Pill>
    );
  return null;
}

/** Approve / Cancel / Retry buttons + banners. */
export function DeploymentActions({ job }: { job: DeploymentJob }) {
  const canApprove = useCan("deployments:approve");
  const canCancel = useCan("deployments:cancel");
  const canRetry = useCan("deployments:retry");
  const act = useDeploymentActions();
  const navigate = useNavigate();
  const gate = useReauthGate("Approving a deployment requires a recent re-authentication.");
  const [cancelOpen, setCancelOpen] = useState(false);
  const final = FINAL_STATUSES.has(job.status);
  const hasFailed =
    (job.target_counts["failed"] ?? 0) + (job.target_counts["rolled_back"] ?? 0) > 0;

  return (
    <>
      {job.status === "awaiting_approval" && canApprove && (
        <button
          className={btnPrimaryCls}
          disabled={act.approve.isPending}
          onClick={() =>
            void gate.attempt(
              () =>
                act.approve.mutateAsync(job.id).then(() => toast.success("Deployment approved")),
              (e) => toast.error("Could not approve", { description: errorMessage(e) }),
            )
          }
        >
          {act.approve.isPending ? <Spinner /> : <CheckCircle2 className="size-3.5" />} Approve
          deployment
        </button>
      )}
      {!final && canCancel && (
        <button
          className={btnCls}
          onClick={() => setCancelOpen(true)}
          disabled={job.cancel_requested}
        >
          <XCircle className="size-3.5" /> {job.cancel_requested ? "Cancelling…" : "Cancel"}
        </button>
      )}
      {final && hasFailed && canRetry && (
        <button
          className={btnCls}
          disabled={act.retry.isPending}
          onClick={() =>
            act.retry.mutate(job.id, {
              onSuccess: (n) => {
                toast.success("Retry deployment created");
                void navigate({ to: "/deployments/$id", params: { id: n.id } });
              },
              onError: (e) => toast.error("Retry failed", { description: errorMessage(e) }),
            })
          }
        >
          {act.retry.isPending ? <Spinner /> : <RotateCcw className="size-3.5" />} Retry failed
          targets
        </button>
      )}
      {gate.dialog}
      <ConfirmDialog
        open={cancelOpen}
        onOpenChange={(o) => {
          setCancelOpen(o);
          if (!o) act.cancel.reset();
        }}
        title="Cancel this deployment?"
        description="Targets that have not started are skipped. A target already being modified finishes its current step and is rolled back."
        confirmLabel="Cancel deployment"
        destructive
        pending={act.cancel.isPending}
        error={act.cancel.error}
        onConfirm={() =>
          act.cancel.mutate(job.id, {
            onSuccess: () => {
              toast.success("Cancellation requested");
              setCancelOpen(false);
            },
          })
        }
      />
    </>
  );
}

/** Banners + per-target panels for one deployment. Shared by the wizard (step 5) and the detail page. */
export function DeploymentLive({
  id,
  onJob,
}: {
  id: string;
  onJob?: (job: DeploymentJob, mode: StreamMode) => void;
}) {
  const { query: q, mode } = useLiveDeployment(id);
  const canRollback = useCan("deployments:rollback");
  const canApprove = useCan("deployments:approve");
  const act = useDeploymentActions();
  const gate = useReauthGate("Rolling back a server requires a recent re-authentication.");
  const [rb, setRb] = useState<DeploymentTarget | null>(null);
  const job = q.data;

  useEffect(() => {
    if (job) onJob?.(job, mode);
  }, [job, mode]); // eslint-disable-line react-hooks/exhaustive-deps

  if (q.isLoading) return <LoadingBlock label="Loading deployment…" />;
  if (q.isError || !job) {
    if (isApiError(q.error) && q.error.status === 404)
      return <EmptyState title="Deployment not found" />;
    return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  }

  const final = FINAL_STATUSES.has(job.status);
  const lastTouch = Math.max(
    ...[job.started_at, job.created_at, ...(job.targets ?? []).map((t) => t.updated_at)]
      .filter(Boolean)
      .map((x) => new Date(x as string).getTime()),
  );
  const stale =
    !final && job.status !== "awaiting_approval" && Date.now() - lastTouch > STALE_AFTER_MS;

  return (
    <div className="space-y-3">
      {job.status === "awaiting_approval" && (
        <div
          className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft p-2.5 text-[12.5px]"
          data-testid="approval-banner"
        >
          <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warn" />
          <div className="flex-1">
            <div className="font-semibold text-warn">Awaiting approval</div>
            <div className="text-[12px] text-muted-foreground">
              {canApprove
                ? "Targets include an environment that requires approval. Nothing has been changed on any server yet. A different administrator than the initiator must approve (unless self-approval is enabled in settings)."
                : "This deployment targets an environment that requires administrator approval. Nothing has been changed on any server yet; an administrator must approve it before it starts."}
            </div>
          </div>
          <DeploymentActions job={job} />
        </div>
      )}
      {stale && (
        <div className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft p-2.5 text-[12px]">
          <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warn" />
          <span>
            No progress was recorded for {Math.round((Date.now() - lastTouch) / 60000)} minutes. The
            worker may be down or the job interrupted; it is reconciled automatically when the
            worker returns.
          </span>
        </div>
      )}
      {job.cancel_requested && !final && (
        <div className="rounded-md border border-border bg-surface-2/50 p-2 text-[12px] text-muted-foreground">
          Cancellation requested. The deployment stops at the next safe checkpoint.
        </div>
      )}
      {job.error_summary && (
        <div
          className="rounded-md border border-danger/40 bg-danger-soft p-2 text-[12px] text-danger"
          role="alert"
        >
          {job.error_summary}
        </div>
      )}
      {job.rollback_status && (
        <div className="flex items-center gap-1.5 text-[12px] text-warn">
          <RotateCcw className="size-3.5" /> Rollback status:{" "}
          <span className="mono">{job.rollback_status}</span>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 text-[12px] text-muted-foreground">
        <JobStatusBadge status={job.status} />
        <ModeIndicator mode={mode} />
        {Object.entries(job.target_counts).map(([k, n]) => (
          <span key={k} className="mono">
            {n} {k.replace(/_/g, " ")}
          </span>
        ))}
        <span className="ml-auto flex items-center gap-1.5">
          {job.status !== "awaiting_approval" && <DeploymentActions job={job} />}
        </span>
      </div>

      <div className="grid gap-3 lg:grid-cols-2" data-testid="deploy-targets">
        {(job.targets ?? []).map((t) => (
          <TargetPanel key={t.id} job={job} t={t} canRollback={canRollback} onRollback={setRb} />
        ))}
      </div>
      {(job.targets ?? []).length === 0 && <EmptyState title="No targets" />}

      {job.retry_of && (
        <p className="text-[11.5px] text-muted-foreground">
          Retry of{" "}
          <Link
            to="/deployments/$id"
            params={{ id: job.retry_of }}
            className="mono text-primary hover:underline"
          >
            {job.retry_of.slice(0, 8)}
          </Link>
        </p>
      )}

      {gate.dialog}
      <ConfirmDialog
        open={!!rb}
        onOpenChange={(o) => {
          if (!o) {
            setRb(null);
            act.rollback.reset();
          }
        }}
        title={`Roll back ${rb?.server_name ?? "server"}?`}
        description="The files replaced by this deployment are restored from the verified backup, the service config is tested and reloaded. This changes the certificate served by that server."
        confirmLabel="Restore backup"
        destructive
        pending={act.rollback.isPending}
        error={act.rollback.error && !isApiError(act.rollback.error) ? act.rollback.error : null}
        onConfirm={() => {
          const t = rb;
          if (!t) return;
          void gate.attempt(
            () =>
              act.rollback.mutateAsync({ id: job.id, targetId: t.id }).then((r) => {
                if (r.accepted)
                  toast.info("Rollback queued", {
                    description: `${t.server_name ?? "Target"}: the status updates live when the worker finishes.`,
                  });
                else toast.error("Rollback was not accepted");
                setRb(null);
              }),
            (e) => toast.error("Rollback failed", { description: errorMessage(e) }),
          );
        }}
      />
    </div>
  );
}
