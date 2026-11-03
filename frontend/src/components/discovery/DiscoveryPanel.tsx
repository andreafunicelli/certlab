import { AlertTriangle } from "lucide-react";
import { Panel } from "@/components/layout/AppShell";
import { Pill } from "@/components/ui/status";
import { useServerDiscoveryJobs } from "@/lib/api/queries";
import { fmtAgo } from "@/lib/format";
import { discoveryTone, JobDetail } from "./JobDetail";

export function DiscoveryPanel({
  serverId,
  jobId,
  onOpenJob,
}: {
  serverId: string;
  /** Job just started from the page (null: show the latest job of this server, resuming it if still running). */
  jobId: string | null;
  /** Called to open a job's full detail (scan history). */
  onOpenJob?: (id: string) => void;
}) {
  const jobs = useServerDiscoveryJobs(serverId);
  const latest = jobs.data?.items[0];
  const show = jobId ?? latest?.id ?? null;
  if (!show) return null;
  const summary = jobs.data?.items.find((j) => j.id === show) ?? latest;
  const when = summary?.finished_at ?? summary?.started_at ?? summary?.created_at;
  return (
    <Panel
      title="Certificate discovery"
      actions={
        summary && (
          <button
            type="button"
            onClick={() => onOpenJob?.(summary.id)}
            className="flex items-center gap-1.5 text-[11.5px] text-muted-foreground hover:text-primary"
            data-testid="last-scan"
          >
            Last scan:
            <Pill tone={discoveryTone(summary.status)} dot>
              {summary.status}
            </Pill>
            {when ? fmtAgo(when) : ""}
            {summary.error_code && <span className="mono text-danger">— {summary.error_code}</span>}
            {summary.warnings_count > 0 && (
              <span className="flex items-center gap-1 text-warn">
                <AlertTriangle className="size-3" /> {summary.warnings_count}
              </span>
            )}
          </button>
        )
      }
    >
      <JobDetail key={show} jobId={show} serverId={serverId} withLog={false} />
    </Panel>
  );
}
