import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { AlertTriangle, ArrowLeft, Pencil, PlugZap, Power, Radar, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { ConnectionBadge, EnvBadge, Pill } from "@/components/ui/status";
import { ConfirmDialog } from "@/components/ui/confirm";
import {
  btnCls,
  btnPrimaryCls,
  EmptyState,
  ErrorState,
  errorMessage,
  inputCls,
  labelCls,
  LoadingBlock,
  Spinner,
} from "@/components/ui/feedback";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EditServerDialog } from "@/components/servers/EditServerDialog";
import { HostKeyPanel } from "@/components/servers/HostKeyPanel";
import { ConnectionTestPanel } from "@/components/servers/ConnectionTestPanel";
import { DiscoveryPanel } from "@/components/discovery/DiscoveryPanel";
import { ScanHistory } from "@/components/discovery/ScanHistory";
import { InstallationsTable } from "@/components/certificates/InstallationsTable";
import { JobStatusBadge } from "@/components/ui/status";
import {
  useDeleteServer,
  useDiscoverServer,
  useServer,
  useServerDeployments,
  useServerInstallations,
  useSettings,
  useSetServerEnabled,
  useTestConnection,
} from "@/lib/api/queries";
import { isApiError } from "@/lib/api/client";
import type { ConnectionTestResult, Server } from "@/lib/api/types";
import { useCan } from "@/lib/auth";
import { detectedServices, fmtAgo, fmtDateTime, fmtDuration, shortFp } from "@/lib/format";

export const Route = createFileRoute("/servers/$id")({
  head: () => ({
    meta: [
      { title: "Server — Certificate Manager" },
      {
        name: "description",
        content:
          "Server details: SSH status, host key, detected services and installed certificates.",
      },
    ],
  }),
  component: ServerDetail,
});

const str = (v: unknown): string => (typeof v === "string" ? v : v == null ? "—" : String(v));

function ServerDetail() {
  const { id } = Route.useParams();
  const navigate = useNavigate();
  const q = useServer(id);
  const server = q.data;
  const canWrite = useCan("servers:write");
  const canTest = useCan("servers:test");
  const canDiscover = useCan("discovery:run");

  const testConn = useTestConnection();
  const discover = useDiscoverServer();
  const setEnabled = useSetServerEnabled();
  const del = useDeleteServer();
  const [result, setResult] = useState<ConnectionTestResult | null>(null);
  const [editOpen, setEditOpen] = useState(false);
  const [delOpen, setDelOpen] = useState(false);
  const inst = useServerInstallations(id);
  const deps = useServerDeployments(id);
  const refreshMinutes = Number(useSettings().data?.general.data["inventory_refresh_minutes"] ?? 0);
  const [jobId, setJobId] = useState<string | null>(null);
  const [focusJobId, setFocusJobId] = useState<string | null>(null);
  const [hkHighlight, setHkHighlight] = useState(false);
  const hkRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!hkHighlight) return;
    const t = setTimeout(() => setHkHighlight(false), 6000);
    return () => clearTimeout(t);
  }, [hkHighlight]);

  const runTest = () =>
    testConn.mutate(id, {
      onSuccess: (r) => {
        setResult(r);
        if (r.ok)
          toast.success("SSH connection successful", {
            description: `${server?.hostname}:${server?.ssh_port}`,
          });
        else toast.error("SSH connection failed", { description: r.error_message ?? undefined });
      },
      onError: (e) => toast.error("Test failed", { description: errorMessage(e) }),
    });

  const runDiscover = () =>
    discover.mutate(id, {
      onSuccess: (job) => {
        setJobId(job.id);
        toast.success("Discovery started", { description: "Progress is shown below." });
      },
      onError: (e) => {
        const running = isApiError(e) && e.code === "DISCOVERY_ALREADY_RUNNING";
        const existing = running ? (e.details as { job_id?: string } | null)?.job_id : undefined;
        if (existing) {
          setJobId(existing);
          toast.info("Discovery is already running", { description: "Showing its progress." });
        } else toast.error("Could not start discovery", { description: errorMessage(e) });
      },
    });

  if (q.isLoading)
    return (
      <AppShell>
        <LoadingBlock label="Loading server…" />
      </AppShell>
    );
  if (q.isError || !server)
    return (
      <AppShell>
        <Link
          to="/servers"
          className="mb-2 inline-flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="size-3.5" /> Servers
        </Link>
        {isApiError(q.error) && q.error.status === 404 ? (
          <EmptyState title="Server not found" hint="It may have been deleted." />
        ) : (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        )}
      </AppShell>
    );

  const services = detectedServices(server.detected_services);
  const lastDisc = server.last_discovery_at ? new Date(server.last_discovery_at).getTime() : null;
  const staleInventory =
    server.enabled &&
    (lastDisc === null || (refreshMinutes > 0 && Date.now() - lastDisc > refreshMinutes * 60_000));
  const sub = [
    server.hostname,
    server.os_pretty,
    services.find((s) => s.service === "nginx" && s.installed)?.version &&
      `nginx ${services.find((s) => s.service === "nginx")?.version}`,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <AppShell>
      <Link
        to="/servers"
        className="mb-2 inline-flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3.5" /> Servers
      </Link>

      <PageHeader
        title={<span className="mono text-[17px]">{server.name}</span>}
        badge={<ConnectionBadge status={server.connection_status} enabled={server.enabled} />}
        subtitle={sub}
        actions={
          <>
            {canDiscover && (
              <button onClick={runDiscover} className={btnCls} disabled={discover.isPending}>
                {discover.isPending ? <Spinner /> : <Radar className="size-3.5" />}
                Scan Certificates
              </button>
            )}
            {canTest && (
              <button onClick={runTest} className={btnCls} disabled={testConn.isPending}>
                {testConn.isPending ? <Spinner /> : <PlugZap className="size-3.5" />} Test SSH
              </button>
            )}
            {canWrite && (
              <>
                <button onClick={() => setEditOpen(true)} className={btnCls}>
                  <Pencil className="size-3.5" /> Edit
                </button>
                <button
                  onClick={() =>
                    setEnabled.mutate(
                      { id, enabled: !server.enabled },
                      { onError: (e) => toast.error(errorMessage(e)) },
                    )
                  }
                  className={btnCls}
                  disabled={setEnabled.isPending}
                >
                  <Power className="size-3.5" /> {server.enabled ? "Disable" : "Enable"}
                </button>
                <button
                  onClick={() => setDelOpen(true)}
                  className={btnCls + " hover:!border-danger hover:!text-danger"}
                >
                  <Trash2 className="size-3.5" /> Delete
                </button>
              </>
            )}
          </>
        }
      />

      <div className="grid gap-3 xl:grid-cols-4">
        <div className="space-y-3 xl:col-span-1">
          <Panel title="Server Information">
            <div className="space-y-1.5 p-3 text-[12.5px]">
              {[
                ["Hostname", `${server.hostname}`],
                ["IP Address", str(server.address)],
                ["Operating System", str(server.os_pretty)],
                ["SSH", `${server.ssh_username}@${server.hostname}:${server.ssh_port}`],
                ["Credential", str(server.credential_name)],
                ["Privilege mode", server.privilege_mode],
                ["Last connection", fmtDateTime(server.last_connected_at)],
                [
                  "Last discovery",
                  server.last_discovery_at
                    ? `${fmtAgo(server.last_discovery_at)} (${str(server.last_discovery_status)})`
                    : "never",
                ],
              ].map(([k, v]) => (
                <div
                  key={k}
                  className="flex items-baseline justify-between gap-3 border-b border-border/60 pb-1.5 last:border-0"
                >
                  <span className="shrink-0 text-muted-foreground">{k}</span>
                  <span className="mono break-all text-right text-foreground">{v}</span>
                </div>
              ))}
              <div className="flex items-center justify-between pt-1">
                <span className="text-muted-foreground">Environment</span>
                <EnvBadge env={server.environment} />
              </div>
              {server.tags.length > 0 && (
                <div className="flex flex-wrap gap-1 pt-1">
                  {server.tags.map((t) => (
                    <Pill key={t}>{t}</Pill>
                  ))}
                </div>
              )}
              {server.description && (
                <p className="pt-1 text-[12px] text-muted-foreground">{server.description}</p>
              )}
            </div>
          </Panel>
          <div
            ref={hkRef}
            id="host-key-panel"
            data-testid="host-key-section"
            className={
              hkHighlight
                ? "rounded-md ring-2 ring-warn ring-offset-2 ring-offset-background transition-shadow"
                : "transition-shadow"
            }
          >
            <HostKeyPanel server={server} />
          </div>
        </div>

        <div className="space-y-3 xl:col-span-3">
          {result && <ConnectionTestPanel result={result} />}

          <Panel
            title="Detected services"
            actions={
              <span className="text-[11.5px] text-muted-foreground">
                from the last successful connection test
              </span>
            }
          >
            {services.length === 0 ? (
              <EmptyState
                title="No services detected yet"
                hint="Run a connection test to probe the host."
              />
            ) : (
              <DTable>
                <THead>
                  <TH>Service</TH>
                  <TH>Version</TH>
                  <TH>Binary</TH>
                  <TH>State</TH>
                </THead>
                <tbody>
                  {services.map((s) => (
                    <TRow key={s.service}>
                      <TD className="mono font-medium">{s.service}</TD>
                      <TD className="mono">{s.version ?? "—"}</TD>
                      <TD className="mono">{s.binary ?? "—"}</TD>
                      <TD>
                        {!s.installed ? (
                          <Pill tone="neutral">Not installed</Pill>
                        ) : s.running ? (
                          <Pill tone="ok" dot>
                            Running
                          </Pill>
                        ) : (
                          <Pill tone="warn" dot>
                            Stopped
                          </Pill>
                        )}
                      </TD>
                    </TRow>
                  ))}
                </tbody>
              </DTable>
            )}
            {server.discovery_error && (
              <div
                className="m-3 rounded-md border border-danger/30 bg-danger-soft p-2 text-[12px] text-danger"
                role="alert"
              >
                Last discovery failed: {server.discovery_error}
              </div>
            )}
          </Panel>

          {staleInventory && (
            <div
              className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft p-2.5 text-[12px]"
              data-testid="stale-inventory"
            >
              <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warn" />
              <span>
                {lastDisc === null
                  ? "This server has never been scanned, so its certificate inventory is empty."
                  : `Certificate inventory is stale: last scan ${fmtAgo(server.last_discovery_at)}${refreshMinutes ? ` (refresh interval ${refreshMinutes} min)` : ""}.`}{" "}
                {canDiscover && "Run “Scan Certificates” to refresh it before deploying."}
              </span>
            </div>
          )}

          <DiscoveryPanel serverId={id} jobId={jobId} onOpenJob={(j) => setFocusJobId(j)} />
          <ScanHistory serverId={id} focusJobId={focusJobId} />

          <Panel title="Certificates installed on this server">
            {inst.isLoading ? (
              <LoadingBlock />
            ) : inst.isError ? (
              <ErrorState error={inst.error} onRetry={() => void inst.refetch()} />
            ) : !inst.data || inst.data.length === 0 ? (
              <EmptyState
                title="No certificates found on this server"
                hint="Run “Scan Certificates” to discover certificate references in the web server configuration."
              />
            ) : (
              <InstallationsTable rows={inst.data} context="server" />
            )}
          </Panel>

          <Panel title="Recent deployments">
            {deps.isLoading ? (
              <LoadingBlock />
            ) : deps.isError ? (
              <ErrorState error={deps.error} onRetry={() => void deps.refetch()} />
            ) : (deps.data?.items.length ?? 0) === 0 ? (
              <EmptyState title="No deployments to this server yet" />
            ) : (
              <DTable>
                <THead>
                  <TH>Date</TH>
                  <TH>Certificate</TH>
                  <TH>User</TH>
                  <TH align="right">Duration</TH>
                  <TH>Status</TH>
                </THead>
                <tbody>
                  {deps.data?.items.map((d) => (
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
                            {shortFp(d.new_fingerprint)}
                          </Link>
                        ) : (
                          shortFp(d.new_fingerprint)
                        )}
                      </TD>
                      <TD className="text-muted-foreground">{d.initiated_by_name ?? "system"}</TD>
                      <TD align="right" className="mono">
                        {d.started_at ? fmtDuration(d.started_at, d.finished_at) : "—"}
                      </TD>
                      <TD>
                        <JobStatusBadge status={d.status} />
                      </TD>
                    </TRow>
                  ))}
                </tbody>
              </DTable>
            )}
          </Panel>
        </div>
      </div>

      {editOpen && (
        <EditServerDialog
          server={server}
          onClose={() => setEditOpen(false)}
          onSaved={(r) => {
            if (!r.host_key_reset) return;
            toast.warning("Host key cleared", {
              description: "The address or port changed. Verify and enroll the new host key.",
            });
            setHkHighlight(true);
            setTimeout(
              () => hkRef.current?.scrollIntoView({ behavior: "smooth", block: "center" }),
              150,
            );
          }}
        />
      )}

      <ConfirmDialog
        open={delOpen}
        onOpenChange={(o) => {
          setDelOpen(o);
          if (!o) del.reset();
        }}
        title={`Delete ${server.name}?`}
        description="The server is removed from the inventory. Servers with deployment history cannot be deleted; disable them instead."
        confirmLabel="Delete server"
        destructive
        pending={del.isPending}
        error={del.error}
        onConfirm={() =>
          del.mutate(id, {
            onSuccess: () => {
              toast.success("Server deleted");
              void navigate({ to: "/servers" });
            },
          })
        }
      />
    </AppShell>
  );
}
