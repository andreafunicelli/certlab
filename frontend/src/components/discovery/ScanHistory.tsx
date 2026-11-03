import { Fragment, useEffect, useRef, useState } from "react";
import { AlertTriangle, ChevronDown, ChevronRight } from "lucide-react";
import { Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { Pill } from "@/components/ui/status";
import { btnCls, EmptyState, ErrorState, LoadingBlock } from "@/components/ui/feedback";
import { useServerDiscoveryJobs } from "@/lib/api/queries";
import { fmtAgo, fmtDateTime } from "@/lib/format";
import { discoveryTone, fmtMs, JobDetail } from "./JobDetail";

const PAGE_SIZE = 10;

/** Recent discovery runs of a server; clicking a row expands the job detail (steps, log, findings). */
export function ScanHistory({
  serverId,
  focusJobId,
}: {
  serverId: string;
  /** A job to expand and scroll to (set from the discovery panel header). */
  focusJobId?: string | null;
}) {
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState<string | null>(null);
  const root = useRef<HTMLDivElement>(null);
  const q = useServerDiscoveryJobs(serverId, { page, page_size: PAGE_SIZE });

  useEffect(() => {
    if (!focusJobId) return;
    setOpen(focusJobId);
    root.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [focusJobId]);

  const rows = q.data?.items ?? [];
  const total = q.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div ref={root} data-testid="scan-history">
      <Panel
        title="Scan history"
        actions={<span className="text-[11.5px] text-muted-foreground">{total} runs</span>}
      >
        {q.isLoading ? (
          <LoadingBlock />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            title="No scans yet"
            hint="Run “Scan Certificates” to create the first one."
          />
        ) : (
          <DTable>
            <THead>
              <TH>Started</TH>
              <TH>Status</TH>
              <TH>Duration</TH>
              <TH>Requested by</TH>
              <TH>Result</TH>
              <TH>Warnings</TH>
              <TH>Error</TH>
            </THead>
            <tbody>
              {rows.map((j) => {
                const isOpen = open === j.id;
                const st = j.stats;
                const inst = (st?.installations_created ?? 0) + (st?.installations_updated ?? 0);
                return (
                  <Fragment key={j.id}>
                    <TRow onClick={() => setOpen(isOpen ? null : j.id)}>
                      <TD className="mono">
                        <button
                          type="button"
                          aria-expanded={isOpen}
                          aria-label={`${isOpen ? "Collapse" : "Expand"} scan ${fmtDateTime(j.started_at ?? j.created_at)}`}
                          className="inline-flex items-center gap-1 hover:text-primary"
                          onClick={(e) => {
                            e.stopPropagation();
                            setOpen(isOpen ? null : j.id);
                          }}
                        >
                          {isOpen ? (
                            <ChevronDown className="size-3.5" />
                          ) : (
                            <ChevronRight className="size-3.5" />
                          )}
                          {fmtDateTime(j.started_at ?? j.created_at)}
                        </button>
                        <div className="pl-5 text-[11px] text-muted-foreground">
                          {fmtAgo(j.started_at ?? j.created_at)}
                        </div>
                      </TD>
                      <TD>
                        <Pill tone={discoveryTone(j.status)} dot>
                          {j.status}
                        </Pill>
                      </TD>
                      <TD className="mono">{fmtMs(j.duration_ms)}</TD>
                      <TD className="text-muted-foreground">{j.requested_by_name ?? "system"}</TD>
                      <TD className="mono text-[12px]">
                        {st ? `${st.certificates_created ?? 0} certs · ${inst} installations` : "—"}
                      </TD>
                      <TD>
                        {j.warnings_count > 0 ? (
                          <Pill tone="warn" className="gap-1">
                            <AlertTriangle className="size-3" /> {j.warnings_count}
                          </Pill>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TD>
                      <TD>
                        {j.error_code ? (
                          <span className="mono text-[11.5px] text-danger">{j.error_code}</span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TD>
                    </TRow>
                    {isOpen && (
                      <tr className="border-b border-border/70 bg-surface-2/30">
                        <td colSpan={7}>
                          <JobDetail jobId={j.id} serverId={serverId} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </DTable>
        )}
        {total > PAGE_SIZE && (
          <div className="flex items-center justify-between border-t border-border px-3 py-1.5 text-[12px] text-muted-foreground">
            <span>
              page {page} / {pages}
            </span>
            <div className="flex gap-1.5">
              <button className={btnCls} disabled={page <= 1} onClick={() => setPage(page - 1)}>
                Previous
              </button>
              <button className={btnCls} disabled={page >= pages} onClick={() => setPage(page + 1)}>
                Next
              </button>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}
