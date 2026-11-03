import { useState } from "react";
import { Pencil, Plus, Trash2 } from "lucide-react";
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
  Spinner,
} from "@/components/ui/feedback";
import { useEnvironmentMutations, useEnvironments } from "@/lib/api/queries";
import type { Environment } from "@/lib/api/types";
import { useCan } from "@/lib/auth";
import { Toggle } from "./SectionForm";

function EnvDialog({ env, onClose }: { env: Environment | null; onClose: () => void }) {
  const { create, update } = useEnvironmentMutations();
  const m = env ? update : create;
  const [name, setName] = useState(env?.name ?? "");
  const [description, setDescription] = useState(env?.description ?? "");
  const [isProd, setIsProd] = useState(env?.is_production ?? false);
  const [approval, setApproval] = useState(env?.requires_approval ?? false);
  const [trustedChain, setTrustedChain] = useState(env?.require_trusted_chain ?? false);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const body = {
      name: name.trim(),
      description: description.trim() || null,
      is_production: isProd,
      requires_approval: approval,
      require_trusted_chain: trustedChain,
    };
    const done = {
      onSuccess: () => {
        toast.success(env ? "Environment updated" : "Environment created");
        onClose();
      },
    };
    if (env) update.mutate({ id: env.id, ...body }, done);
    else create.mutate(body, done);
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{env ? `Edit ${env.name}` : "New environment"}</DialogTitle>
          <DialogDescription>
            Environments group servers and drive deployment approval rules.
          </DialogDescription>
        </DialogHeader>
        <form method="post" onSubmit={submit} className="space-y-3">
          <div>
            <label className={labelCls} htmlFor="env-name">
              Name
            </label>
            <input
              id="env-name"
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>
          <div>
            <label className={labelCls} htmlFor="env-desc">
              Description
            </label>
            <input
              id="env-desc"
              className={inputCls}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          <div className="flex items-center justify-between text-[12.5px]">
            Production environment{" "}
            <Toggle on={isProd} onChange={setIsProd} label="Production environment" />
          </div>
          <div className="flex items-center justify-between text-[12.5px]">
            Deployments require approval{" "}
            <Toggle on={approval} onChange={setApproval} label="Requires approval" />
          </div>
          <div className="flex items-center justify-between gap-3 text-[12.5px]">
            <span>
              Require a trusted certificate chain
              <span className="block text-[11.5px] text-muted-foreground">
                Blocks deployments whose chain does not validate against the trust anchors, and
                fails verification if the served chain is untrusted.
              </span>
            </span>
            <Toggle
              on={trustedChain}
              onChange={setTrustedChain}
              label="Require a trusted certificate chain"
            />
          </div>
          {m.error && (
            <p className="text-[12px] text-danger" role="alert">
              {errorMessage(m.error)}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <button type="button" className={btnCls} onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className={btnPrimaryCls} disabled={m.isPending || !name.trim()}>
              {m.isPending && <Spinner />} Save
            </button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function EnvironmentsPanel() {
  const q = useEnvironments();
  const canWrite = useCan("environments:write");
  const { remove } = useEnvironmentMutations();
  const [edit, setEdit] = useState<Environment | "new" | null>(null);
  const [del, setDel] = useState<Environment | null>(null);

  return (
    <Panel
      title="Environments"
      className="lg:col-span-2"
      actions={
        canWrite && (
          <button className={btnCls} onClick={() => setEdit("new")}>
            <Plus className="size-3.5" /> Add environment
          </button>
        )
      }
    >
      {q.isLoading ? (
        <LoadingBlock />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : q.data!.length === 0 ? (
        <EmptyState title="No environments defined" />
      ) : (
        <DTable>
          <THead>
            <TH>Name</TH>
            <TH>Description</TH>
            <TH>Type</TH>
            <TH>Approval</TH>
            <TH>Chain</TH>
            <TH align="right">Servers</TH>
            {canWrite && <TH align="right">Actions</TH>}
          </THead>
          <tbody>
            {q.data!.map((e) => (
              <TRow key={e.id}>
                <TD className="mono font-medium">{e.name}</TD>
                <TD className="text-muted-foreground">{e.description ?? "—"}</TD>
                <TD>
                  {e.is_production ? (
                    <Pill tone="danger">Production</Pill>
                  ) : (
                    <Pill>Non-production</Pill>
                  )}
                </TD>
                <TD>
                  {e.requires_approval ? (
                    <Pill tone="warn">Required</Pill>
                  ) : (
                    <Pill>Not required</Pill>
                  )}
                </TD>
                <TD>
                  {e.require_trusted_chain ? (
                    <Pill tone="warn">Trusted only</Pill>
                  ) : (
                    <Pill>Any</Pill>
                  )}
                </TD>
                <TD align="right" className="mono tabular-nums">
                  {e.server_count}
                </TD>
                {canWrite && (
                  <TD align="right">
                    <div className="flex justify-end gap-1">
                      <button
                        aria-label={`Edit ${e.name}`}
                        className={btnCls + " !px-1.5"}
                        onClick={() => setEdit(e)}
                      >
                        <Pencil className="size-3" />
                      </button>
                      <button
                        aria-label={`Delete ${e.name}`}
                        className={btnCls + " !px-1.5 hover:!border-danger hover:!text-danger"}
                        onClick={() => setDel(e)}
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
      {edit && <EnvDialog env={edit === "new" ? null : edit} onClose={() => setEdit(null)} />}
      <ConfirmDialog
        open={!!del}
        onOpenChange={(o) => {
          if (!o) {
            setDel(null);
            remove.reset();
          }
        }}
        title={`Delete environment ${del?.name}?`}
        description="Environments that still contain servers cannot be deleted."
        confirmLabel="Delete"
        destructive
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() =>
          del &&
          remove.mutate(del.id, {
            onSuccess: () => {
              toast.success("Environment deleted");
              setDel(null);
            },
          })
        }
      />
    </Panel>
  );
}
