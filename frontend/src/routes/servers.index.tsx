import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { Plus, Search, Radar } from "lucide-react";
import { toast } from "sonner";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { ConnectionBadge, EnvBadge } from "@/components/ui/status";
import {
  btnCls,
  btnPrimaryCls,
  EmptyState,
  ErrorState,
  LoadingBlock,
  selectCls,
} from "@/components/ui/feedback";
import { api, useEnvironments, useServers } from "@/lib/api/queries";
import { isApiError } from "@/lib/api/client";
import { useCan } from "@/lib/auth";
import { fmtAgo, servicesLabel } from "@/lib/format";

export const Route = createFileRoute("/servers/")({
  head: () => ({
    meta: [
      { title: "Servers — Certificate Manager" },
      {
        name: "description",
        content:
          "Inventory of Linux web servers running Nginx, their SSH reachability and installed certificates.",
      },
      { property: "og:title", content: "Servers — Certificate Manager" },
      {
        property: "og:description",
        content: "Linux/Nginx server inventory with SSH status and certificate counts.",
      },
    ],
  }),
  component: ServersPage,
});

const PAGE_SIZE = 25;

function ServersPage() {
  const [q, setQ] = useState("");
  const [env, setEnv] = useState("all");
  const [status, setStatus] = useState("all");
  const [page, setPage] = useState(1);
  const canWrite = useCan("servers:write");
  const canDiscover = useCan("discovery:run");
  const envs = useEnvironments();

  const servers = useServers({
    q: q.trim() || undefined,
    environment: env === "all" ? undefined : env,
    status: status === "all" ? undefined : status,
    page,
    page_size: PAGE_SIZE,
  });
  const rows = servers.data?.items ?? [];
  const total = servers.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const scanAll = async () => {
    try {
      await api.discoveryJobs.bulk(rows.filter((s) => s.enabled).map((s) => s.id));
      toast.success("Discovery started for all enabled servers");
    } catch (e) {
      if (isApiError(e) && [404, 405, 501].includes(e.status))
        toast.info("Discovery is not available yet", {
          description: "This API is not enabled in this build.",
        });
      else
        toast.error("Could not start discovery", {
          description: isApiError(e) ? e.message : undefined,
        });
    }
  };

  return (
    <AppShell>
      <PageHeader
        title="Servers"
        subtitle="Linux web servers managed over SSH · certificate deployment targets"
        actions={
          <>
            {canDiscover && (
              <button onClick={() => void scanAll()} className={btnCls} disabled={!rows.length}>
                <Radar className="size-3.5" /> Scan All
              </button>
            )}
            {canWrite && (
              <Link to="/servers/new" className={btnPrimaryCls}>
                <Plus className="size-3.5" /> Add Server
              </Link>
            )}
          </>
        }
      />

      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-2">
          <div className="relative min-w-52 flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setPage(1);
              }}
              placeholder="Filter by name, hostname, IP…"
              aria-label="Filter servers"
              className="h-7.5 w-full rounded-md border border-input bg-surface pl-8 pr-2 text-[12.5px] outline-none placeholder:text-muted-foreground focus:border-ring"
            />
          </div>
          <select
            value={env}
            onChange={(e) => {
              setEnv(e.target.value);
              setPage(1);
            }}
            aria-label="Environment"
            className={selectCls}
          >
            <option value="all">All environments</option>
            {envs.data?.map((e) => (
              <option key={e.id} value={e.name}>
                {e.name}
              </option>
            ))}
          </select>
          <select
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(1);
            }}
            aria-label="Connection status"
            className={selectCls}
          >
            <option value="all">Any status</option>
            <option value="connected">Connected</option>
            <option value="unknown">Not tested</option>
            <option value="offline">Offline</option>
            <option value="auth_error">Auth failed</option>
            <option value="host_key_unknown">Host key not enrolled</option>
            <option value="host_key_mismatch">Host key changed</option>
            <option value="error">Error</option>
          </select>
        </div>

        {servers.isLoading ? (
          <LoadingBlock label="Loading servers…" />
        ) : servers.isError ? (
          <ErrorState error={servers.error} onRetry={() => void servers.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            title={
              q || env !== "all" || status !== "all"
                ? "No servers match the filters"
                : "No servers registered yet"
            }
            hint="Deployment targets are Linux hosts reachable over SSH with a dedicated key."
            action={
              canWrite && (
                <Link to="/servers/new" className={btnPrimaryCls}>
                  <Plus className="size-3.5" /> Add Server
                </Link>
              )
            }
          />
        ) : (
          <DTable>
            <THead>
              <TH>Name</TH>
              <TH>Hostname</TH>
              <TH>IP Address</TH>
              <TH>Environment</TH>
              <TH>OS</TH>
              <TH>Web Servers</TH>
              <TH>SSH Status</TH>
              <TH align="right">Certificates</TH>
              <TH>Last Check</TH>
            </THead>
            <tbody>
              {rows.map((s) => (
                <TRow key={s.id}>
                  <TD>
                    <Link
                      to="/servers/$id"
                      params={{ id: s.id }}
                      className="mono font-medium text-foreground hover:text-primary hover:underline"
                    >
                      {s.name}
                    </Link>
                  </TD>
                  <TD className="mono">
                    {s.hostname}:{s.ssh_port}
                  </TD>
                  <TD className="mono">{s.address ?? "—"}</TD>
                  <TD>
                    <EnvBadge env={s.environment} />
                  </TD>
                  <TD className="text-muted-foreground">{s.os_pretty ?? "—"}</TD>
                  <TD className="mono">{servicesLabel(s.detected_services)}</TD>
                  <TD>
                    <ConnectionBadge status={s.connection_status} enabled={s.enabled} />
                  </TD>
                  <TD align="right" className="mono tabular-nums">
                    {s.certificate_count}
                  </TD>
                  <TD className="mono">{fmtAgo(s.last_connected_at)}</TD>
                </TRow>
              ))}
            </tbody>
          </DTable>
        )}

        {total > PAGE_SIZE && (
          <div className="flex items-center justify-between border-t border-border px-3 py-1.5 text-[12px] text-muted-foreground">
            <span>
              {total} servers · page {page} / {pages}
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
    </AppShell>
  );
}
