import { useState } from "react";
import { KeyRound, Plus, RefreshCw, Trash2 } from "lucide-react";
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
import { KeyMaterialFields, useKeyMaterial } from "@/components/servers/KeyMaterialFields";
import { ReauthDialog } from "@/components/auth/ReauthDialog";
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
  useCreateCredential,
  useCredentials,
  useDeleteCredential,
  useRotateCredential,
} from "@/lib/api/queries";
import { isReauthRequired } from "@/lib/api/client";
import type { Credential } from "@/lib/api/types";
import { useCan } from "@/lib/auth";
import { fmtDateTime } from "@/lib/format";

/** Create (cred === null) or rotate (cred set) a credential. Key material stays in uncontrolled inputs. */
function KeyDialog({ cred, onClose }: { cred: Credential | null; onClose: () => void }) {
  const km = useKeyMaterial();
  const create = useCreateCredential();
  const rotate = useRotateCredential();
  const m = cred ? rotate : create;
  const [name, setName] = useState("");
  const [reauth, setReauth] = useState(false);

  const submit = () => {
    const { private_key, passphrase } = km.read();
    const opts = {
      onSuccess: () => {
        km.clear();
        toast.success(cred ? "Credential rotated" : "Credential stored");
        onClose();
      },
      onError: (e: unknown) => isReauthRequired(e) && setReauth(true),
    };
    if (cred) rotate.mutate({ id: cred.id, private_key, passphrase }, opts);
    else create.mutate({ name: name.trim(), private_key, passphrase }, opts);
  };

  return (
    <>
      <Dialog open onOpenChange={(o) => !o && onClose()}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{cred ? `Rotate ${cred.name}` : "New SSH credential"}</DialogTitle>
            <DialogDescription>
              {cred
                ? "Servers using this credential switch to the new key immediately. Install the new public key first."
                : "Requires a recent re-authentication."}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            {!cred && (
              <div>
                <label className={labelCls} htmlFor="cred-name">
                  Name
                </label>
                <input
                  id="cred-name"
                  className={inputCls}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
            )}
            <KeyMaterialFields km={km} idPrefix="cred" />
            {m.error && !isReauthRequired(m.error) && (
              <p className="text-[12px] text-danger" role="alert">
                {errorMessage(m.error)}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <button className={btnCls} onClick={onClose}>
                Cancel
              </button>
              <button
                className={btnPrimaryCls}
                onClick={submit}
                disabled={m.isPending || (!cred && !name.trim())}
              >
                {m.isPending && <Spinner />} {cred ? "Rotate key" : "Store credential"}
              </button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
      <ReauthDialog
        open={reauth}
        onOpenChange={setReauth}
        onSuccess={submit}
        reason="Changing SSH credentials requires a recent re-authentication."
      />
    </>
  );
}

export function CredentialsPanel() {
  const q = useCredentials();
  const canWrite = useCan("credentials:write");
  const del = useDeleteCredential();
  const [dialog, setDialog] = useState<Credential | "new" | null>(null);
  const [confirmDel, setConfirmDel] = useState<Credential | null>(null);

  return (
    <Panel
      title="SSH credentials"
      className="lg:col-span-2"
      actions={
        canWrite && (
          <button className={btnCls} onClick={() => setDialog("new")}>
            <Plus className="size-3.5" /> Add credential
          </button>
        )
      }
    >
      {q.isLoading ? (
        <LoadingBlock />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : q.data!.length === 0 ? (
        <EmptyState title="No credentials stored" hint="Add a private key to register servers." />
      ) : (
        <DTable>
          <THead>
            <TH>Name</TH>
            <TH>Algorithm</TH>
            <TH>Fingerprint</TH>
            <TH>Passphrase</TH>
            <TH align="right">Servers</TH>
            <TH>Created</TH>
            <TH>Rotated</TH>
            {canWrite && <TH align="right">Actions</TH>}
          </THead>
          <tbody>
            {q.data!.map((c) => (
              <TRow key={c.id}>
                <TD className="mono font-medium">
                  <KeyRound className="mr-1.5 inline size-3 text-muted-foreground" />
                  {c.name}
                </TD>
                <TD className="mono">{c.key_algorithm ?? c.type}</TD>
                <TD className="mono text-muted-foreground">{c.fingerprint}</TD>
                <TD>{c.has_passphrase ? <Pill tone="ok">Protected</Pill> : <Pill>None</Pill>}</TD>
                <TD align="right" className="mono tabular-nums">
                  {c.server_count}
                </TD>
                <TD className="mono">{fmtDateTime(c.created_at)}</TD>
                <TD className="mono">{c.rotated_at ? fmtDateTime(c.rotated_at) : "—"}</TD>
                {canWrite && (
                  <TD align="right">
                    <div className="flex justify-end gap-1">
                      <button
                        aria-label={`Rotate ${c.name}`}
                        className={btnCls + " !px-1.5"}
                        onClick={() => setDialog(c)}
                      >
                        <RefreshCw className="size-3" />
                      </button>
                      <button
                        aria-label={`Delete ${c.name}`}
                        className={btnCls + " !px-1.5 hover:!border-danger hover:!text-danger"}
                        onClick={() => setConfirmDel(c)}
                      >
                        <Trash2 className="size-3" />
                      </button>
                    </div>
                  </TD>
                )}
              </TRow>
            ))}
          </tbody>
        </DTable>
      )}
      {dialog && (
        <KeyDialog cred={dialog === "new" ? null : dialog} onClose={() => setDialog(null)} />
      )}
      <ConfirmDialog
        open={!!confirmDel}
        onOpenChange={(o) => {
          if (!o) {
            setConfirmDel(null);
            del.reset();
          }
        }}
        title={`Delete credential ${confirmDel?.name}?`}
        description="Credentials still used by servers cannot be deleted."
        confirmLabel="Delete credential"
        destructive
        pending={del.isPending}
        error={del.error}
        onConfirm={() =>
          confirmDel &&
          del.mutate(confirmDel.id, {
            onSuccess: () => {
              toast.success("Credential deleted");
              setConfirmDel(null);
            },
          })
        }
      />
    </Panel>
  );
}
