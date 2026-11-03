import { useEffect, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import {
  btnCls,
  btnPrimaryCls,
  errorMessage,
  inputCls,
  labelCls,
  Spinner,
} from "@/components/ui/feedback";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useCredentials, useEnvironments, useServers, useUpdateServer } from "@/lib/api/queries";
import type { Server, ServerUpdateResult } from "@/lib/api/types";
import { useCan } from "@/lib/auth";

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

export function EditServerDialog({
  server,
  onClose,
  onSaved,
}: {
  server: Server;
  onClose: () => void;
  /** Called after a successful save (before the dialog closes). */
  onSaved?: (result: ServerUpdateResult) => void;
}) {
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
        onSuccess: (r) => {
          toast.success("Server updated");
          onSaved?.(r);
          onClose();
        },
      },
    );
  };

  const endpointChanged =
    f.hostname.trim() !== server.hostname ||
    f.address.trim() !== (server.address ?? "") ||
    (Number(f.ssh_port) || 22) !== server.ssh_port;

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
          {endpointChanged && (
            <div
              className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft p-2.5 text-[12px] sm:col-span-2"
              role="status"
              data-testid="hostkey-reset-warning"
            >
              <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warn" />
              <span>
                Changing the address or port clears the enrolled host key. You will need to verify
                and enroll the new key before the server can be used.
              </span>
            </div>
          )}
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
