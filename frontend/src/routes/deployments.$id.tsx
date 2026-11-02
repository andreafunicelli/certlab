import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { JobStatusBadge } from "@/components/ui/status";
import { DeploymentLive } from "@/components/deployments/DeploymentLive";
import { useCertificate, useDeployment } from "@/lib/api/queries";
import { fmtDateTime, fmtDuration } from "@/lib/format";

export const Route = createFileRoute("/deployments/$id")({
  head: () => ({
    meta: [
      { title: "Deployment — Certificate Manager" },
      {
        name: "description",
        content:
          "Per-server steps, verification results, logs and rollback state for a deployment.",
      },
    ],
  }),
  component: DeploymentDetail,
});

function DeploymentDetail() {
  const { id } = Route.useParams();
  const job = useDeployment(id).data;
  const cert = useCertificate(job?.certificate_id).data;
  const name = cert?.common_name;
  const s = job?.strategy ?? {};

  return (
    <AppShell>
      <Link
        to="/deployments"
        className="mb-2 inline-flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3.5" /> Deployments
      </Link>

      <PageHeader
        title={
          <span>
            Deployment <span className="mono">{name ?? id.slice(0, 8)}</span>
          </span>
        }
        badge={job ? <JobStatusBadge status={job.status} /> : undefined}
        subtitle={
          job
            ? `${fmtDateTime(job.created_at)} · by ${job.initiated_by_name ?? "system"} · ${job.target_total} target${job.target_total === 1 ? "" : "s"} · ${job.started_at ? fmtDuration(job.started_at, job.finished_at) : "not started"}`
            : undefined
        }
        actions={
          job?.certificate_id ? (
            <Link
              to="/certificates/$id"
              params={{ id: job.certificate_id }}
              className="inline-flex h-7.5 items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 text-[12.5px] hover:border-primary hover:text-primary"
            >
              Open certificate
            </Link>
          ) : undefined
        }
      />

      <DeploymentLive id={id} />

      {job && (
        <div className="mt-3 grid gap-3 lg:grid-cols-2">
          <Panel title="Strategy">
            <div className="mono grid grid-cols-2 gap-x-3 gap-y-1 p-3 text-[12px]">
              <span className="text-muted-foreground">Mode</span>
              <span>{String(s.mode ?? "—")}</span>
              <span className="text-muted-foreground">Concurrency</span>
              <span>{String(s.concurrency ?? "—")}</span>
              <span className="text-muted-foreground">Failure threshold</span>
              <span>{String(s.failure_threshold ?? "—")}</span>
              <span className="text-muted-foreground">Continue on failure</span>
              <span>{s.continue_on_failure ? "yes" : "no"}</span>
              <span className="text-muted-foreground">Allow restart</span>
              <span>{s.allow_restart ? "yes" : "no"}</span>
              <span className="text-muted-foreground">File-only verification</span>
              <span>{s.allow_file_only_verification ? "allowed" : "not allowed"}</span>
              <span className="text-muted-foreground">Approval</span>
              <span>
                {job.approval_required
                  ? job.approved_at
                    ? `approved ${fmtDateTime(job.approved_at)}`
                    : "required"
                  : "not required"}
              </span>
              {job.acknowledged_warnings.length > 0 && (
                <>
                  <span className="text-muted-foreground">Acknowledged warnings</span>
                  <span>{job.acknowledged_warnings.join(", ")}</span>
                </>
              )}
            </div>
          </Panel>
        </div>
      )}
    </AppShell>
  );
}
