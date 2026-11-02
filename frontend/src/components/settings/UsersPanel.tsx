import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { Pill } from "@/components/ui/status";
import { ConfirmDialog } from "@/components/ui/confirm";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  btnCls,
  btnPrimaryCls,
  EmptyState,
  ErrorState,
  errorMessage,
  inputCls,
  labelCls,
  LoadingBlock,
  selectCls,
  Spinner,
} from "@/components/ui/feedback";
import { useUserMutations, useUsers } from "@/lib/api/queries";
import type { User } from "@/lib/api/types";
import { useSession } from "@/lib/auth";
import { fmtAgo } from "@/lib/format";
import { Toggle } from "./SectionForm";

const ROLES = ["admin", "operator", "viewer"] as const;
const roleTone = { admin: "danger", operator: "warn", viewer: "info" } as const;

function CreateUserDialog({ onClose }: { onClose: () => void }) {
  const { create } = useUserMutations();
  const [f, setF] = useState({
    username: "",
    email: "",
    display_name: "",
    password: "",
    role: "viewer",
  });
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setF((s) => ({ ...s, [k]: e.target.value }));
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>New local user</DialogTitle>
          <DialogDescription>Password must be at least 12 characters.</DialogDescription>
        </DialogHeader>
        <form
          method="post"
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate(
              {
                username: f.username.trim(),
                email: f.email.trim(),
                display_name: f.display_name.trim(),
                password: f.password,
                roles: [f.role],
              },
              {
                onSuccess: () => {
                  toast.success("User created");
                  onClose();
                },
              },
            );
          }}
        >
          {(
            [
              ["username", "Username"],
              ["email", "Email"],
              ["display_name", "Display name"],
            ] as const
          ).map(([k, l]) => (
            <div key={k}>
              <label className={labelCls} htmlFor={`u-${k}`}>
                {l}
              </label>
              <input id={`u-${k}`} className={inputCls} value={f[k]} onChange={set(k)} required />
            </div>
          ))}
          <div>
            <label className={labelCls} htmlFor="u-password">
              Initial password
            </label>
            <input
              id="u-password"
              type="password"
              autoComplete="new-password"
              className={inputCls}
              value={f.password}
              onChange={set("password")}
              required
              minLength={12}
            />
          </div>
          <div>
            <label className={labelCls} htmlFor="u-role">
              Role
            </label>
            <select id="u-role" className={inputCls} value={f.role} onChange={set("role")}>
              {ROLES.map((r) => (
                <option key={r}>{r}</option>
              ))}
            </select>
          </div>
          {create.error && (
            <p className="text-[12px] text-danger" role="alert">
              {errorMessage(create.error)}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <button type="button" className={btnCls} onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className={btnPrimaryCls} disabled={create.isPending}>
              {create.isPending && <Spinner />} Create
            </button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function UsersPanel() {
  const q = useUsers({ page_size: 200 });
  const { me } = useSession();
  const m = useUserMutations();
  const [creating, setCreating] = useState(false);
  const [del, setDel] = useState<User | null>(null);

  const changeRole = (u: User, role: string) =>
    m.setRoles.mutate(
      { id: u.id, roles: [role] },
      {
        onSuccess: () => toast.success(`${u.username} is now ${role}`),
        onError: (e) => toast.error(errorMessage(e)),
      },
    );

  return (
    <Panel
      title="Users & roles"
      className="lg:col-span-2"
      actions={
        <button className={btnCls} onClick={() => setCreating(true)}>
          <Plus className="size-3.5" /> Add user
        </button>
      }
    >
      {q.isLoading ? (
        <LoadingBlock />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : q.data!.items.length === 0 ? (
        <EmptyState title="No users" />
      ) : (
        <DTable>
          <THead>
            <TH>User</TH>
            <TH>Email</TH>
            <TH>Source</TH>
            <TH>Role</TH>
            <TH>MFA</TH>
            <TH>Last login</TH>
            <TH>Enabled</TH>
            <TH align="right">Actions</TH>
          </THead>
          <tbody>
            {q.data!.items.map((u) => {
              const self = u.id === me?.user.id;
              const role = u.roles[0] ?? "viewer";
              return (
                <TRow key={u.id}>
                  <TD>
                    <div className="mono font-medium">{u.username}</div>
                    <div className="text-[11px] text-muted-foreground">{u.display_name}</div>
                  </TD>
                  <TD className="text-muted-foreground">{u.email}</TD>
                  <TD>
                    <Pill>{u.auth_provider}</Pill>
                  </TD>
                  <TD>
                    <select
                      aria-label={`Role of ${u.username}`}
                      className={selectCls}
                      value={role}
                      disabled={self || m.setRoles.isPending}
                      onChange={(e) => changeRole(u, e.target.value)}
                    >
                      {ROLES.map((r) => (
                        <option key={r}>{r}</option>
                      ))}
                    </select>
                    {u.roles.length > 1 && (
                      <span className="ml-1.5">
                        {u.roles.map((r) => (
                          <Pill key={r} tone={roleTone[r as keyof typeof roleTone] ?? "neutral"}>
                            {r}
                          </Pill>
                        ))}
                      </span>
                    )}
                  </TD>
                  <TD>{u.mfa_enabled ? <Pill tone="ok">On</Pill> : <Pill>Off</Pill>}</TD>
                  <TD className="mono">{u.last_login_at ? fmtAgo(u.last_login_at) : "never"}</TD>
                  <TD>
                    <Toggle
                      on={u.enabled}
                      disabled={self}
                      label={`Enable ${u.username}`}
                      onChange={(v) =>
                        m.update.mutate(
                          { id: u.id, enabled: v },
                          { onError: (e) => toast.error(errorMessage(e)) },
                        )
                      }
                    />
                  </TD>
                  <TD align="right">
                    <button
                      aria-label={`Delete ${u.username}`}
                      disabled={self}
                      className={btnCls + " !px-1.5 hover:!border-danger hover:!text-danger"}
                      onClick={() => setDel(u)}
                    >
                      <Trash2 className="size-3" />
                    </button>
                  </TD>
                </TRow>
              );
            })}
          </tbody>
        </DTable>
      )}
      {creating && <CreateUserDialog onClose={() => setCreating(false)} />}
      <ConfirmDialog
        open={!!del}
        onOpenChange={(o) => {
          if (!o) {
            setDel(null);
            m.remove.reset();
          }
        }}
        title={`Delete user ${del?.username}?`}
        description="Their audit history is retained."
        confirmLabel="Delete user"
        destructive
        pending={m.remove.isPending}
        error={m.remove.error}
        onConfirm={() =>
          del &&
          m.remove.mutate(del.id, {
            onSuccess: () => {
              toast.success("User deleted");
              setDel(null);
            },
          })
        }
      />
    </Panel>
  );
}
