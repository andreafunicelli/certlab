import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Search } from "lucide-react";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { JobStatusBadge } from "@/components/ui/status";
import {
  btnCls,
  EmptyState,
  ErrorState,
  inputCls,
  LoadingBlock,
  selectCls,
} from "@/components/ui/feedback";
import { useCertificates, useDeployments } from "@/lib/api/queries";
import { fmtDateTime, fmtDuration, shortFp } from "@/lib/format";
import { useDebounced } from "@/lib/use-debounced";

export const Route = createFileRoute("/deployments/")({
  head: () => ({
    meta: [
      { title: "Deployments — Certificate Manager" },
      {
        name: "description",
        content:
          "History of certificate deployments to Nginx servers, with per-server results and logs.",
      },
      { property: "og:title", content: "Deployments — Certificate Manager" },
      {
        property: "og:description",
        content: "Certificate deployment history with success, failure and rollback outcomes.",
      },
    ],
  }),
  component: DeploymentsPage,
});

const PAGE_SIZE = 25;
const STATUSES: [string, string][] = [
  ["all", "All statuses"],
  ["pending,awaiting_approval,preflight,activating", "In progress / waiting"],
  ["awaiting_approval", "Awaiting approval"],
  ["completed", "Completed"],
  ["partially_failed", "Partially failed"],
  ["failed", "Failed"],
  ["rolled_back", "Rolled back"],
  ["manual_intervention_required", "Manual intervention"],
  ["cancelled", "Cancelled"],
];

const FAILED_KEYS = ["failed", "rolled_back", "manual_intervention_required"];

function DeploymentsPage() {
  const [status, setStatus] = useState("all");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [idq, setIdq] = useState("");
  const [page, setPage] = useState(1);
  const dq = useDebounced(idq.trim(), 300);

  const list = useDeployments({
    status: status === "all" ? undefined : status,
    since: since ? new Date(`${since}T00:00:00`).toISOString() : undefined,
    until: until ? new Date(`${until}T23:59:59`).toISOString() : undefined,
    q: dq || undefined,
    page,
    page_size: PAGE_SIZE,
  });
  const certs = useCertificates({ page_size: 200, include_ca: true });
  const names = useMemo(
    () => new Map((certs.data?.items ?? []).map((c) => [c.id, c.common_name])),
    [certs.data],
  );
  const rows = list.data?.items ?? [];
  const total = list.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const reset =
    <T,>(set: (v: T) => void) =>
    (v: T) => {
      set(v);
      setPage(1);
    };

  return (
    <AppShell>
      <PageHeader
        title="Deployments"
        subtitle="Every deployment is atomic per server: backup → stage → config test → reload → TLS verify"
      />
      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-2">
          <div className="relative min-w-44 flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              value={idq}
              onChange={(e) => reset(setIdq)(e.target.value)}
              placeholder="Deployment ID prefix…"
              aria-label="Deployment ID prefix"
              className={inputCls + " pl-8"}
            />
          </div>
          <select
            value={status}
            onChange={(e) => reset(setStatus)(e.target.value)}
            className={selectCls}
            aria-label="Status"
          >
            {STATUSES.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
          <label className="flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
            From
            <input
              type="date"
              value={since}
              onChange={(e) => reset(setSince)(e.target.value)}
              className={selectCls}
            />
          </label>
          <label className="flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
            To
            <input
              type="date"
              value={until}
              onChange={(e) => reset(setUntil)(e.target.value)}
              className={selectCls}
            />
          </label>
        </div>

        {list.isLoading ? (
          <LoadingBlock label="Loading deployments…" />
        ) : list.isError ? (
          <ErrorState error={list.error} onRetry={() => void list.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            title="No deployments"
            hint="Deployments appear here once a certificate is replaced from its Replace / Renew wizard."
          />
        ) : (
          <DTable>
            <THead>
              <TH>Date</TH>
              <TH>Certificate</TH>
              <TH>User</TH>
              <TH align="right">Targets</TH>
              <TH align="right">Success</TH>
              <TH align="right">Failed</TH>
              <TH align="right">Duration</TH>
              <TH>Status</TH>
            </THead>
            <tbody>
              {rows.map((d) => {
                const ok = d.target_counts["completed"] ?? 0;
                const bad = FAILED_KEYS.reduce((n, k) => n + (d.target_counts[k] ?? 0), 0);
                return (
                  <TRow key={d.id}>
                    <TD>
                      <Link
                        to="/deployments/$id"
                        params={{ id: d.id }}
                        className="mono text-foreground hover:text-primary hover:underline"
                      >
                        {fmtDateTime(d.created_at)}
                      </Link>
                    </TD>
                    <TD className="mono">
                      {d.certificate_id ? (
                        <Link
                          to="/certificates/$id"
                          params={{ id: d.certificate_id }}
                          className="hover:text-primary hover:underline"
                        >
                          {names.get(d.certificate_id) ?? shortFp(d.new_fingerprint)}
                        </Link>
                      ) : (
                        shortFp(d.new_fingerprint)
                      )}
                    </TD>
                    <TD className="text-muted-foreground">{d.initiated_by_name ?? "system"}</TD>
                    <TD align="right" className="mono tabular-nums">
                      {d.target_total}
                    </TD>
                    <TD align="right" className="mono tabular-nums text-ok">
                      {ok}
                    </TD>
                    <TD align="right" className="mono tabular-nums text-danger">
                      {bad}
                    </TD>
                    <TD align="right" className="mono">
                      {d.started_at ? fmtDuration(d.started_at, d.finished_at) : "—"}
                    </TD>
                    <TD>
                      <JobStatusBadge status={d.status} />
                    </TD>
                  </TRow>
                );
              })}
            </tbody>
          </DTable>
        )}

        {total > PAGE_SIZE && (
          <div className="flex items-center justify-between border-t border-border px-3 py-1.5 text-[12px] text-muted-foreground">
            <span>
              {total} deployments · page {page} / {pages}
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
      <p className="mt-2 text-[11.5px] text-muted-foreground">
        Select a deployment to open its complete per-server log and rollback timeline.
      </p>
    </AppShell>
  );
}
