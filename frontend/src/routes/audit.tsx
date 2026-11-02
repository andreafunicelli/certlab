import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Lock, Search } from "lucide-react";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { OutcomePill, Pill } from "@/components/ui/status";
import { btnCls, EmptyState, ErrorState, LoadingBlock, selectCls } from "@/components/ui/feedback";
import { useAuditEvents } from "@/lib/api/queries";
import { fmtDateTime } from "@/lib/format";
import { useDebounced } from "@/lib/use-debounced";

export const Route = createFileRoute("/audit")({
  head: () => ({
    meta: [
      { title: "Audit Log — Certificate Manager" },
      {
        name: "description",
        content:
          "Immutable audit trail of certificate uploads, deployments, rollbacks, Nginx reloads and server changes.",
      },
      { property: "og:title", content: "Audit Log — Certificate Manager" },
      {
        property: "og:description",
        content: "Immutable audit trail of every certificate and server operation.",
      },
    ],
  }),
  component: AuditPage,
});

const PAGE_SIZE = 50;
const RESOURCE_TYPES = [
  "server",
  "credential",
  "user",
  "environment",
  "settings",
  "certificate",
  "deployment",
  "session",
];

const dateInputCls =
  "h-7.5 rounded-md border border-input bg-surface px-2 text-[12.5px] outline-none focus:border-ring";
const textInputCls =
  "h-7.5 rounded-md border border-input bg-surface px-2 text-[12.5px] outline-none placeholder:text-muted-foreground focus:border-ring";

function AuditPage() {
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const [resourceType, setResourceType] = useState("all");
  const [outcome, setOutcome] = useState("all");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [page, setPage] = useState(1);
  const dActor = useDebounced(actor);
  const dAction = useDebounced(action);

  const q = useAuditEvents({
    actor: dActor.trim() || undefined,
    action: dAction.trim() || undefined,
    resource_type: resourceType === "all" ? undefined : resourceType,
    outcome: outcome === "all" ? undefined : outcome,
    from: from ? new Date(`${from}T00:00:00`).toISOString() : undefined,
    to: to ? new Date(`${to}T23:59:59`).toISOString() : undefined,
    page,
    page_size: PAGE_SIZE,
  });
  const rows = q.data?.items ?? [];
  const total = q.data?.total ?? 0;
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
        title="Audit Log"
        subtitle="Append-only record · entries cannot be edited or deleted from the interface"
        actions={
          <Pill tone="info">
            <Lock className="size-3" /> Immutable
          </Pill>
        }
      />

      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-2">
          <div className="relative min-w-40 flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              value={actor}
              onChange={(e) => reset(setActor)(e.target.value)}
              placeholder="User…"
              aria-label="Filter by user"
              className="h-7.5 w-full rounded-md border border-input bg-surface pl-8 pr-2 text-[12.5px] outline-none placeholder:text-muted-foreground focus:border-ring"
            />
          </div>
          <input
            value={action}
            onChange={(e) => reset(setAction)(e.target.value)}
            placeholder="Action (e.g. SERVER_CREATED)"
            aria-label="Filter by action"
            className={textInputCls + " w-56"}
          />
          <select
            value={resourceType}
            onChange={(e) => reset(setResourceType)(e.target.value)}
            aria-label="Resource type"
            className={selectCls}
          >
            <option value="all">All resources</option>
            {RESOURCE_TYPES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <select
            value={outcome}
            onChange={(e) => reset(setOutcome)(e.target.value)}
            aria-label="Outcome"
            className={selectCls}
          >
            <option value="all">Any result</option>
            <option value="success">Success</option>
            <option value="failure">Failure</option>
            <option value="denied">Denied</option>
          </select>
          <input
            type="date"
            value={from}
            onChange={(e) => reset(setFrom)(e.target.value)}
            aria-label="From"
            className={dateInputCls}
          />
          <input
            type="date"
            value={to}
            onChange={(e) => reset(setTo)(e.target.value)}
            aria-label="To"
            className={dateInputCls}
          />
        </div>

        {q.isLoading ? (
          <LoadingBlock label="Loading audit events…" />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState title="No audit events match the filters" />
        ) : (
          <DTable>
            <THead>
              <TH>Timestamp</TH>
              <TH>User</TH>
              <TH>Action</TH>
              <TH>Resource</TH>
              <TH>Source IP</TH>
              <TH>Correlation</TH>
              <TH>Result</TH>
            </THead>
            <tbody>
              {rows.map((a) => (
                <TRow key={a.id}>
                  <TD className="mono">{fmtDateTime(a.ts)}</TD>
                  <TD className="text-muted-foreground">{a.actor_name ?? "system"}</TD>
                  <TD className="mono font-medium">{a.action}</TD>
                  <TD className="mono">
                    <span title={a.error ?? undefined}>
                      {a.resource_type ?? "—"}
                      {a.resource_id ? `:${a.resource_id.slice(0, 8)}` : ""}
                    </span>
                  </TD>
                  <TD className="mono">{a.ip ?? "—"}</TD>
                  <TD className="mono text-muted-foreground">
                    {a.correlation_id?.slice(0, 8) ?? "—"}
                  </TD>
                  <TD>
                    <OutcomePill outcome={a.outcome} />
                  </TD>
                </TRow>
              ))}
            </tbody>
          </DTable>
        )}

        <div className="flex items-center justify-between border-t border-border px-3 py-1.5 text-[12px] text-muted-foreground">
          <span>
            {total} events · page {page} / {pages}
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
      </Panel>
    </AppShell>
  );
}
