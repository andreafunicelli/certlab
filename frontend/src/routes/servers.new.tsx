import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { ArrowLeft, KeyRound, Lock, PlugZap, Plus, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { Pill } from "@/components/ui/status";
import {
  btnCls,
  btnPrimaryCls,
  errorMessage,
  FieldError,
  inputCls,
  labelCls,
  LoadingBlock,
  Spinner,
} from "@/components/ui/feedback";
import { HostKeyPanel } from "@/components/servers/HostKeyPanel";
import { ConnectionTestPanel } from "@/components/servers/ConnectionTestPanel";
import { KeyMaterialFields, useKeyMaterial } from "@/components/servers/KeyMaterialFields";
import { ReauthDialog } from "@/components/auth/ReauthDialog";
import {
  useCreateCredential,
  useCreateServer,
  useCredentials,
  useEnvironments,
  useServer,
  useServers,
  useTestConnection,
} from "@/lib/api/queries";
import { ApiError, isReauthRequired } from "@/lib/api/client";
import type { ConnectionTestResult, ServerCreate } from "@/lib/api/types";
import { useCan, useSession } from "@/lib/auth";

export const Route = createFileRoute("/servers/new")({
  head: () => ({
    meta: [
      { title: "Add Server — Certificate Manager" },
      {
        name: "description",
        content:
          "Register a Linux/Nginx server with SSH key authentication as a deployment target.",
      },
      { property: "og:title", content: "Add Server — Certificate Manager" },
      {
        property: "og:description",
        content: "Register an Nginx server with SSH key authentication.",
      },
    ],
  }),
  component: AddServer,
});

function Row({
  label,
  htmlFor,
  error,
  children,
}: {
  label: string;
  htmlFor?: string;
  error?: string | undefined;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className={labelCls} htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      <FieldError>{error}</FieldError>
    </div>
  );
}

function AddServer() {
  const navigate = useNavigate();
  const { me } = useSession();
  const canWrite = useCan("servers:write");
  const canCred = useCan("credentials:write");
  const envs = useEnvironments();
  const creds = useCredentials(useCan("credentials:read"));
  const bastions = useServers({ page_size: 200 });
  const createServer = useCreateServer();
  const createCred = useCreateCredential();
  const testConn = useTestConnection();
  const km = useKeyMaterial();

  const [f, setF] = useState({
    name: "",
    hostname: "",
    address: "",
    ssh_port: "22",
    ssh_username: "",
    environment: "",
    credential_id: "",
    bastion_server_id: "",
    privilege_mode: "helper-sudo" as "helper-sudo" | "none",
    tags: "",
    description: "",
  });
  const set =
    (k: keyof typeof f) =>
    (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) =>
      setF((s) => ({ ...s, [k]: e.target.value }));

  const [newCred, setNewCred] = useState(false);
  const [credName, setCredName] = useState("");
  const [reauth, setReauth] = useState(false);
  const [createdId, setCreatedId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);
  const created = useServer(createdId ?? "");
  const server = createdId ? created.data : undefined;

  const fieldErr = (name: string) => {
    const e = createServer.error;
    if (e instanceof ApiError) return e.fieldErrors.find((x) => x.loc.includes(name))?.msg;
    return undefined;
  };

  const effectiveEnv = f.environment || envs.data?.[0]?.name || "";

  const doCreateCredential = (): Promise<string | null> =>
    new Promise((resolve) => {
      const { private_key, passphrase } = km.read();
      createCred.mutate(
        { name: credName.trim(), private_key, passphrase },
        {
          onSuccess: (c) => {
            km.clear(); // drop the secret from the DOM as soon as it is accepted
            setNewCred(false);
            setCredName("");
            setF((s) => ({ ...s, credential_id: c.id }));
            toast.success("Credential stored", { description: c.fingerprint });
            resolve(c.id);
          },
          onError: (e) => {
            if (isReauthRequired(e)) setReauth(true);
            resolve(null);
          },
        },
      );
    });

  const save = async () => {
    let credentialId = f.credential_id;
    if (newCred) {
      const id = await doCreateCredential();
      if (!id) return;
      credentialId = id;
    }
    const body: ServerCreate = {
      name: f.name.trim(),
      hostname: f.hostname.trim(),
      ssh_port: Number(f.ssh_port) || 22,
      ssh_username: f.ssh_username.trim(),
      environment: effectiveEnv,
      enabled: true,
      privilege_mode: f.privilege_mode,
      tags: f.tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
      ...(f.address.trim() ? { address: f.address.trim() } : {}),
      ...(credentialId ? { credential_id: credentialId } : {}),
      ...(f.bastion_server_id ? { bastion_server_id: f.bastion_server_id } : {}),
      ...(f.description.trim() ? { description: f.description.trim() } : {}),
    };
    createServer.mutate(body, {
      onSuccess: (s) => {
        setCreatedId(s.id);
        toast.success("Server registered", {
          description: "Next: verify and enroll its SSH host key.",
        });
      },
    });
  };

  const runTest = () => {
    if (!createdId) return;
    testConn.mutate(createdId, {
      onSuccess: (r) => {
        setTestResult(r);
        if (r.ok) toast.success("SSH connection successful");
        else toast.error("SSH connection failed", { description: r.error_message ?? undefined });
      },
    });
  };

  const locked = !!createdId;
  const needKeyFields = newCred;

  if (me && !canWrite)
    return (
      <AppShell>
        <PageHeader title="Add Server" />
        <Panel>
          <div className="p-4 text-[12.5px] text-muted-foreground">
            <Lock className="mr-1.5 inline size-3.5" /> Your role does not allow registering
            servers.{" "}
            <Link to="/servers" className="text-primary hover:underline">
              Back to servers
            </Link>
          </div>
        </Panel>
      </AppShell>
    );

  return (
    <AppShell>
      <Link
        to="/servers"
        className="mb-2 inline-flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3.5" /> Servers
      </Link>
      <PageHeader
        title="Add Server"
        subtitle="Deployment targets authenticate with SSH keys only"
      />

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel title="Server" className="lg:col-span-2">
          <fieldset disabled={locked} className="grid gap-3 p-3 sm:grid-cols-2">
            <Row label="Server Name" htmlFor="s-name" error={fieldErr("name")}>
              <input
                id="s-name"
                className={inputCls}
                placeholder="WEB-PROD-03"
                value={f.name}
                onChange={set("name")}
              />
            </Row>
            <Row label="Hostname / IP" htmlFor="s-host" error={fieldErr("hostname")}>
              <input
                id="s-host"
                className={inputCls}
                placeholder="web03.youco.local"
                value={f.hostname}
                onChange={set("hostname")}
              />
            </Row>
            <Row label="SSH Port" htmlFor="s-port" error={fieldErr("ssh_port")}>
              <input
                id="s-port"
                className={inputCls}
                inputMode="numeric"
                value={f.ssh_port}
                onChange={set("ssh_port")}
              />
            </Row>
            <Row label="SSH Username" htmlFor="s-user" error={fieldErr("ssh_username")}>
              <input
                id="s-user"
                className={inputCls}
                placeholder="cdpdeploy"
                value={f.ssh_username}
                onChange={set("ssh_username")}
              />
            </Row>
            <Row label="Environment" htmlFor="s-env" error={fieldErr("environment")}>
              <select
                id="s-env"
                className={inputCls}
                value={effectiveEnv}
                onChange={set("environment")}
              >
                {envs.data?.map((e) => (
                  <option key={e.id} value={e.name}>
                    {e.name}
                  </option>
                ))}
              </select>
            </Row>
            <Row label="IP Address (optional)" htmlFor="s-addr" error={fieldErr("address")}>
              <input
                id="s-addr"
                className={inputCls}
                placeholder="10.20.30.11"
                value={f.address}
                onChange={set("address")}
              />
            </Row>
            <Row label="Privilege mode" htmlFor="s-priv">
              <select
                id="s-priv"
                className={inputCls}
                value={f.privilege_mode}
                onChange={set("privilege_mode")}
              >
                <option value="helper-sudo">helper-sudo (cdp-helper via sudo)</option>
                <option value="none">none (read-only, no deployment)</option>
              </select>
            </Row>
            <Row label="Bastion / jump host" htmlFor="s-bastion">
              <select
                id="s-bastion"
                className={inputCls}
                value={f.bastion_server_id}
                onChange={set("bastion_server_id")}
              >
                <option value="">None (direct)</option>
                {bastions.data?.items.map((b) => (
                  <option key={b.id} value={b.id}>
                    {b.name}
                  </option>
                ))}
              </select>
            </Row>
            <Row label="Tags (comma separated)" htmlFor="s-tags" error={fieldErr("tags")}>
              <input
                id="s-tags"
                className={inputCls}
                placeholder="web, dmz"
                value={f.tags}
                onChange={set("tags")}
              />
            </Row>
            <Row label="Authentication">
              <div className="flex h-8 items-center gap-2 rounded-md border border-input bg-surface-2/50 px-2 text-[12.5px]">
                <KeyRound className="size-3.5 text-muted-foreground" /> SSH Key
                <Pill tone="info" className="ml-auto">
                  Password auth disabled
                </Pill>
              </div>
            </Row>
            <div className="sm:col-span-2">
              <Row label="SSH credential" htmlFor="s-cred" error={fieldErr("credential_id")}>
                <div className="flex gap-2">
                  <select
                    id="s-cred"
                    className={inputCls}
                    value={newCred ? "" : f.credential_id}
                    disabled={newCred}
                    onChange={set("credential_id")}
                  >
                    <option value="">Select a stored credential…</option>
                    {creds.data?.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.name} · {c.key_algorithm ?? c.type} · {c.fingerprint.slice(0, 20)}…
                      </option>
                    ))}
                  </select>
                  {canCred && (
                    <button
                      type="button"
                      className={btnCls + " shrink-0"}
                      onClick={() => setNewCred((v) => !v)}
                    >
                      <Plus className="size-3.5" /> {newCred ? "Use existing" : "New credential"}
                    </button>
                  )}
                </div>
              </Row>
            </div>
            {needKeyFields && !locked && (
              <div className="rounded-md border border-border bg-surface-2/40 p-3 sm:col-span-2">
                <div className="mb-2.5">
                  <label className={labelCls} htmlFor="c-name">
                    Credential name
                  </label>
                  <input
                    id="c-name"
                    className={inputCls}
                    placeholder="prod-web-deploy-key"
                    value={credName}
                    onChange={(e) => setCredName(e.target.value)}
                  />
                </div>
                <KeyMaterialFields km={km} idPrefix="newcred" />
                {createCred.error && !isReauthRequired(createCred.error) && (
                  <p className="mt-2 text-[12px] text-danger" role="alert">
                    {errorMessage(createCred.error)}
                  </p>
                )}
              </div>
            )}
          </fieldset>

          {createServer.error && (
            <p
              className="mx-3 mb-2 rounded-md border border-danger/30 bg-danger-soft p-2 text-[12px] text-danger"
              role="alert"
            >
              {errorMessage(createServer.error)}
            </p>
          )}

          <div className="flex flex-wrap items-center gap-2 border-t border-border px-3 py-2">
            {!locked ? (
              <button
                onClick={() => void save()}
                disabled={
                  createServer.isPending ||
                  createCred.isPending ||
                  !f.name.trim() ||
                  !f.hostname.trim() ||
                  !f.ssh_username.trim() ||
                  !effectiveEnv ||
                  (newCred ? !credName.trim() : false)
                }
                className="inline-flex h-8 items-center gap-1.5 rounded-md bg-primary px-3 text-[12.5px] font-medium text-primary-foreground hover:opacity-90 disabled:pointer-events-none disabled:opacity-50"
              >
                {(createServer.isPending || createCred.isPending) && <Spinner />}
                Save Server
              </button>
            ) : (
              <>
                <button
                  onClick={runTest}
                  disabled={testConn.isPending || !server?.host_key_fingerprint}
                  title={server?.host_key_fingerprint ? undefined : "Enroll the host key first"}
                  className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-surface px-3 text-[12.5px] hover:border-primary hover:text-primary disabled:pointer-events-none disabled:opacity-50"
                >
                  {testConn.isPending ? <Spinner /> : <PlugZap className="size-3.5" />}
                  Test SSH Connection
                </button>
                <button
                  onClick={() => void navigate({ to: "/servers/$id", params: { id: createdId! } })}
                  className="inline-flex h-8 items-center gap-1.5 rounded-md bg-primary px-3 text-[12.5px] font-medium text-primary-foreground hover:opacity-90"
                >
                  Open server
                </button>
              </>
            )}
            <span className="text-[11.5px] text-muted-foreground">
              Root password authentication is never requested or stored.
            </span>
          </div>
          {testConn.error && (
            <p className="mx-3 mb-2 text-[12px] text-danger" role="alert">
              {errorMessage(testConn.error)}
            </p>
          )}
        </Panel>

        <div className="space-y-3">
          {!locked && (
            <Panel title="SSH Key">
              <div className="space-y-2 p-3 text-[12.5px]">
                <div className="flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
                  <ShieldCheck className="size-3.5 shrink-0" /> Select an existing credential or add
                  a new one (administrators). Only the public key and fingerprint are ever
                  displayed.
                </div>
                {f.credential_id && creds.data && (
                  <div className="mono break-all rounded-md border border-border bg-surface-2/50 p-2 text-[11px] text-muted-foreground">
                    {creds.data.find((c) => c.id === f.credential_id)?.fingerprint}
                  </div>
                )}
                {creds.isLoading && <LoadingBlock />}
              </div>
            </Panel>
          )}

          {locked && !server && <LoadingBlock label="Loading server…" />}
          {server && <HostKeyPanel server={server} />}
          {testResult && <ConnectionTestPanel result={testResult} />}
          {locked && (
            <p className="text-[11.5px] text-muted-foreground">
              Steps: 1. server saved · 2. verify and enroll the host key · 3. test the connection.
            </p>
          )}
        </div>
      </div>

      <ReauthDialog
        open={reauth}
        onOpenChange={setReauth}
        reason="Storing an SSH credential requires a recent re-authentication."
        onSuccess={() => void save()}
      />
    </AppShell>
  );
}
