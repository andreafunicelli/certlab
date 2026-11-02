import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
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
import { HostKeyPanel } from "@/components/servers/HostKeyPanel";
import { ConnectionTestPanel } from "@/components/servers/ConnectionTestPanel";
import { DiscoveryPanel } from "@/components/discovery/DiscoveryPanel";
import { InstallationsTable } from "@/components/certificates/InstallationsTable";
import { JobStatusBadge } from "@/components/ui/status";
import {
  useCredentials,
  useDeleteServer,
  useDiscoverServer,
  useEnvironments,
  useServer,
  useServerDeployments,
  useServerInstallations,
  useServers,
  useSettings,
  useSetServerEnabled,
  useTestConnection,
  useUpdateServer,
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
          <HostKeyPanel server={server} />
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

          <DiscoveryPanel serverId={id} jobId={jobId} />

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

      {editOpen && <EditServerDialog server={server} onClose={() => setEditOpen(false)} />}

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

function Field({ label, id, children }: { label: string; id: string; children: React.ReactNode }) {
  return (
    <div>
      <label className={labelCls} htmlFor={id}>
        {label}
      </label>
      {children}
    </div>
  );
}

function EditServerDialog({ server, onClose }: { server: Server; onClose: () => void }) {
  const update = useUpdateServer(server.id);
  const envs = useEnvironments();
  const creds = useCredentials(useCan("credentials:read"));
  const others = useServers({ page_size: 200 });
  const [f, setF] = useState({
    name: server.name,
    hostname: server.hostname,
    address: server.address ?? "",
    ssh_port: String(server.ssh_port),
    ssh_username: server.ssh_username,
    environment: server.environment,
    credential_id: server.credential_id ?? "",
    bastion_server_id: server.bastion_server_id ?? "",
    privilege_mode: server.privilege_mode as "helper-sudo" | "none",
    tags: server.tags.join(", "),
    description: server.description ?? "",
  });
  useEffect(() => update.reset(), []); // eslint-disable-line react-hooks/exhaustive-deps
  const set =
    (k: keyof typeof f) =>
    (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) =>
      setF((s) => ({ ...s, [k]: e.target.value }));

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    update.mutate(
      {
        name: f.name.trim(),
        hostname: f.hostname.trim(),
        address: f.address.trim() || null,
        ssh_port: Number(f.ssh_port) || 22,
        ssh_username: f.ssh_username.trim(),
        environment: f.environment,
        credential_id: f.credential_id || null,
        bastion_server_id: f.bastion_server_id || null,
        privilege_mode: f.privilege_mode,
        tags: f.tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
        description: f.description.trim() || null,
      },
      {
        onSuccess: () => {
          toast.success("Server updated");
          onClose();
        },
      },
    );
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Edit server</DialogTitle>
          <DialogDescription>
            Changing the address or port may invalidate the enrolled host key.
          </DialogDescription>
        </DialogHeader>
        <form method="post" onSubmit={submit} className="grid gap-3 sm:grid-cols-2">
          <Field label="Name" id="e-name">
            <input id="e-name" className={inputCls} value={f.name} onChange={set("name")} />
          </Field>
          <Field label="Hostname" id="e-host">
            <input id="e-host" className={inputCls} value={f.hostname} onChange={set("hostname")} />
          </Field>
          <Field label="IP address" id="e-addr">
            <input id="e-addr" className={inputCls} value={f.address} onChange={set("address")} />
          </Field>
          <Field label="SSH port" id="e-port">
            <input id="e-port" className={inputCls} value={f.ssh_port} onChange={set("ssh_port")} />
          </Field>
          <Field label="SSH username" id="e-user">
            <input
              id="e-user"
              className={inputCls}
              value={f.ssh_username}
              onChange={set("ssh_username")}
            />
          </Field>
          <Field label="Environment" id="e-env">
            <select
              id="e-env"
              className={inputCls}
              value={f.environment}
              onChange={set("environment")}
            >
              {envs.data?.map((e) => (
                <option key={e.id} value={e.name}>
                  {e.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Credential" id="e-cred">
            <select
              id="e-cred"
              className={inputCls}
              value={f.credential_id}
              onChange={set("credential_id")}
            >
              <option value="">None</option>
              {creds.data?.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Bastion" id="e-bastion">
            <select
              id="e-bastion"
              className={inputCls}
              value={f.bastion_server_id}
              onChange={set("bastion_server_id")}
            >
              <option value="">None (direct)</option>
              {others.data?.items
                .filter((b) => b.id !== server.id)
                .map((b) => (
                  <option key={b.id} value={b.id}>
                    {b.name}
                  </option>
                ))}
            </select>
          </Field>
          <Field label="Privilege mode" id="e-priv">
            <select
              id="e-priv"
              className={inputCls}
              value={f.privilege_mode}
              onChange={set("privilege_mode")}
            >
              <option value="helper-sudo">helper-sudo</option>
              <option value="none">none</option>
            </select>
          </Field>
          <Field label="Tags" id="e-tags">
            <input id="e-tags" className={inputCls} value={f.tags} onChange={set("tags")} />
          </Field>
          <div className="sm:col-span-2">
            <Field label="Description" id="e-desc">
              <textarea
                id="e-desc"
                rows={2}
                className="w-full rounded-md border border-input bg-surface p-2 text-[12.5px] outline-none focus:border-ring"
                value={f.description}
                onChange={set("description")}
              />
            </Field>
          </div>
          {update.error && (
            <p
              className="rounded-md border border-danger/30 bg-danger-soft p-2 text-[12px] text-danger sm:col-span-2"
              role="alert"
            >
              {errorMessage(update.error)}
            </p>
          )}
          <div className="flex justify-end gap-2 sm:col-span-2">
            <button type="button" className={btnCls} onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className={btnPrimaryCls} disabled={update.isPending}>
              {update.isPending && <Spinner />} Save changes
            </button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
