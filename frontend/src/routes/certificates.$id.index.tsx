import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { ArrowLeft, Download, RefreshCw, RotateCcw, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { CertStatusBadge, DaysLeft, JobStatusBadge, Pill } from "@/components/ui/status";
import { ConfirmDialog } from "@/components/ui/confirm";
import {
  btnCls,
  btnDangerCls,
  EmptyState,
  ErrorState,
  errorMessage,
  LoadingBlock,
  Spinner,
} from "@/components/ui/feedback";
import { InstallationsTable } from "@/components/certificates/InstallationsTable";
import { useReauthGate } from "@/components/auth/useReauthGate";
import { useCertificate, useRestoreBackup, useVerifyCertificate } from "@/lib/api/queries";
import { isApiError } from "@/lib/api/client";
import type { CertificateDetail as Cert } from "@/lib/api/types";
import { useCan } from "@/lib/auth";
import { fmtAgo, fmtDate, fmtDateTime, shortFp } from "@/lib/format";

export const Route = createFileRoute("/certificates/$id/")({
  head: () => ({
    meta: [
      { title: "Certificate — Certificate Manager" },
      {
        name: "description",
        content: "Certificate details, installations, versions, deployments and backups.",
      },
    ],
  }),
  component: CertificateDetail,
});

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5 border-b border-border/60 py-1.5 last:border-0 sm:flex-row sm:items-baseline sm:gap-3">
      <div className="w-52 shrink-0 text-[11.5px] uppercase tracking-[0.05em] text-muted-foreground">
        {label}
      </div>
      <div className={mono ? "mono break-all text-foreground" : "text-[12.5px] text-foreground"}>
        {value}
      </div>
    </div>
  );
}

function downloadPem(c: Cert) {
  const blob = new Blob([c.pem], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${c.common_name.replace(/[^a-zA-Z0-9.*_-]/g, "_")}.pem`;
  a.click();
  URL.revokeObjectURL(url);
}

function CertificateDetail() {
  const { id } = Route.useParams();
  const q = useCertificate(id);
  const verify = useVerifyCertificate();
  const restore = useRestoreBackup();
  const gate = useReauthGate("Restoring a backup requires a recent re-authentication.");
  const canVerify = useCan("certificates:verify");
  const canUpload = useCan("versions:upload");
  const canRestore = useCan("backups:restore");
  const [restoreId, setRestoreId] = useState<string | null>(null);
  const cert = q.data;

  if (q.isLoading)
    return (
      <AppShell>
        <LoadingBlock label="Loading certificate…" />
      </AppShell>
    );
  if (q.isError || !cert)
    return (
      <AppShell>
        <Link
          to="/certificates"
          className="mb-2 inline-flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="size-3.5" /> Certificates
        </Link>
        {isApiError(q.error) && q.error.status === 404 ? (
          <EmptyState
            title="Certificate not found"
            hint="It may have been removed from the inventory."
          />
        ) : (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        )}
      </AppShell>
    );

  const serverName = new Map(
    cert.installations.map((i) => [i.server_id, i.server_name ?? i.server_id.slice(0, 8)]),
  );
  const active = cert.installations.filter((i) => !i.missing_since);
  const deployable = active.filter((i) => i.classification === "managed" && !i.managed_by_certbot);

  const runVerify = () =>
    verify.mutate(id, {
      onSuccess: (r) => {
        const s = r.summary;
        if (s.total === 0)
          toast.info("Nothing to verify", { description: "No verifiable installations." });
        else if (s.mismatching || s.failed)
          toast.warning("Verification found problems", {
            description: `${s.matching} matching, ${s.mismatching} mismatching, ${s.failed} failed`,
          });
        else
          toast.success("All endpoints serve the installed certificate", {
            description: `${s.matching}/${s.total}`,
          });
      },
      onError: (e) => toast.error("Verification failed", { description: errorMessage(e) }),
    });

  return (
    <AppShell>
      <Link
        to="/certificates"
        className="mb-2 inline-flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3.5" /> Certificates
      </Link>

      <PageHeader
        title={<span className="mono text-[17px]">{cert.common_name}</span>}
        badge={<CertStatusBadge status={cert.expiry_status} />}
        subtitle={`${cert.issuer} · installed on ${cert.installation_count} location${cert.installation_count === 1 ? "" : "s"} across ${cert.server_count} server${cert.server_count === 1 ? "" : "s"}`}
        actions={
          <>
            {canVerify && (
              <button
                className={btnCls}
                onClick={runVerify}
                disabled={verify.isPending || active.length === 0}
              >
                {verify.isPending ? <Spinner /> : <ShieldCheck className="size-3.5" />} Verify
                endpoints
              </button>
            )}
            <button className={btnCls} onClick={() => downloadPem(cert)}>
              <Download className="size-3.5" /> Public certificate
            </button>
            {canUpload && (
              <Link
                to="/certificates/$id/renew"
                params={{ id: cert.id }}
                className="inline-flex h-7.5 items-center gap-1.5 rounded-md bg-primary px-2.5 text-[12.5px] font-medium text-primary-foreground hover:opacity-90"
              >
                <RefreshCw className="size-3.5" /> Upload / Replace
              </Link>
            )}
          </>
        }
      />

      <div className="grid gap-3 xl:grid-cols-3">
        <Panel title="Certificate Information" className="xl:col-span-2">
          <div className="px-3 py-1.5">
            <Field label="Common Name" value={cert.common_name} mono />
            <Field label="Subject Alternative Names" value={cert.sans.join(", ") || "—"} mono />
            <Field label="Subject" value={cert.subject} />
            <Field label="Issuer" value={cert.issuer} />
            <Field label="Serial Number" value={cert.serial_number} mono />
            <Field label="SHA-256 Fingerprint" value={cert.fingerprint_sha256} mono />
            <Field label="Signature Algorithm" value={cert.signature_algorithm} />
            <Field
              label="Public Key"
              value={`${cert.public_key_algorithm} ${cert.public_key_size ?? ""}`.trim()}
              mono
            />
            <Field label="Valid From" value={fmtDateTime(cert.not_before)} mono />
            <Field label="Valid Until" value={fmtDateTime(cert.not_after)} mono />
            <div className="flex items-baseline gap-3 py-1.5">
              <div className="w-52 shrink-0 text-[11.5px] uppercase tracking-[0.05em] text-muted-foreground">
                Days Remaining
              </div>
              <DaysLeft days={cert.days_remaining} />
            </div>
          </div>
        </Panel>

        <div className="space-y-3">
          <Panel title="Deployability">
            <div className="space-y-1.5 p-3 text-[12.5px]">
              {(
                [
                  ["In sync", cert.drift.in_sync, "ok"],
                  ["Drifted", cert.drift.drifted, "warn"],
                  ["Missing", cert.drift.missing, "danger"],
                  ["Unknown", cert.drift.unknown, "neutral"],
                ] as const
              ).map(([l, n, tone]) => (
                <div
                  key={l}
                  className="flex items-center justify-between border-b border-border/60 pb-1.5 last:border-0"
                >
                  <span className="text-muted-foreground">{l}</span>
                  <Pill tone={n > 0 ? tone : "neutral"}>{n}</Pill>
                </div>
              ))}
              <p className="pt-1 text-[11.5px] text-muted-foreground">
                {deployable.length} of {active.length} installation{active.length === 1 ? "" : "s"}{" "}
                eligible for automated deployment.
              </p>
            </div>
          </Panel>
        </div>
      </div>

      <div className="mt-3 space-y-3">
        <Panel title="Installed On">
          {cert.installations.length === 0 ? (
            <EmptyState
              title="Not installed anywhere"
              hint="Discovery has not found this certificate on a server."
            />
          ) : (
            <InstallationsTable rows={cert.installations} context="certificate" />
          )}
        </Panel>

        <div className="grid gap-3 xl:grid-cols-2">
          <Panel title="Versions">
            {cert.versions.length === 0 ? (
              <EmptyState
                title="No uploaded versions"
                hint="Use Upload / Replace to add a renewed certificate."
              />
            ) : (
              <DTable>
                <THead>
                  <TH>Uploaded</TH>
                  <TH>Fingerprint</TH>
                  <TH>Expires</TH>
                  <TH>Validation</TH>
                  <TH>Key</TH>
                </THead>
                <tbody>
                  {cert.versions.map((v) => (
                    <TRow key={v.id}>
                      <TD className="mono">{fmtAgo(v.created_at)}</TD>
                      <TD className="mono">{shortFp(v.fingerprint_sha256)}</TD>
                      <TD className="mono">{fmtDate(v.not_after)}</TD>
                      <TD>
                        <Pill
                          tone={
                            v.validation_status === "valid"
                              ? "ok"
                              : v.validation_status === "invalid"
                                ? "danger"
                                : "warn"
                          }
                        >
                          {v.validation_status}
                        </Pill>
                      </TD>
                      <TD className="text-muted-foreground">
                        {v.reuses_existing_key ? "reuses existing" : "uploaded"}
                      </TD>
                    </TRow>
                  ))}
                </tbody>
              </DTable>
            )}
          </Panel>

          <Panel title="Deployment History">
            {cert.deployments.length === 0 ? (
              <EmptyState title="Never deployed from this tool" />
            ) : (
              <DTable>
                <THead>
                  <TH>Date</TH>
                  <TH>Server</TH>
                  <TH>Previous → New</TH>
                  <TH>Status</TH>
                </THead>
                <tbody>
                  {cert.deployments.map((d) => (
                    <TRow key={d.target_id}>
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
                        {serverName.get(d.server_id) ?? d.server_id.slice(0, 8)}
                      </TD>
                      <TD className="mono text-muted-foreground">
                        {shortFp(d.previous_fingerprint).slice(0, 8)} →{" "}
                        {shortFp(d.new_fingerprint).slice(0, 8)}
                      </TD>
                      <TD>
                        <JobStatusBadge status={d.target_status} />
                      </TD>
                    </TRow>
                  ))}
                </tbody>
              </DTable>
            )}
          </Panel>
        </div>

        <Panel title="Backups">
          {cert.backups.length === 0 ? (
            <EmptyState
              title="No backups"
              hint="A verified backup of the replaced files is created before every deployment."
            />
          ) : (
            <DTable>
              <THead>
                <TH>Created</TH>
                <TH>Server</TH>
                <TH>Verified</TH>
                <TH>Restore</TH>
                <TH>Retention until</TH>
                {canRestore && <TH align="right">Action</TH>}
              </THead>
              <tbody>
                {cert.backups.map((b) => (
                  <TRow key={b.id}>
                    <TD className="mono">{fmtDateTime(b.created_at)}</TD>
                    <TD className="mono">
                      {serverName.get(b.server_id) ?? b.server_id.slice(0, 8)}
                    </TD>
                    <TD>
                      <Pill tone={b.verified ? "ok" : "danger"} dot>
                        {b.verified ? "Verified" : "Unverified"}
                      </Pill>
                    </TD>
                    <TD className="text-muted-foreground">
                      {b.restore_status ?? "never restored"}
                    </TD>
                    <TD className="mono">{fmtDate(b.retention_until)}</TD>
                    {canRestore && (
                      <TD align="right">
                        <button
                          className={btnDangerCls}
                          disabled={!b.verified}
                          onClick={() => setRestoreId(b.id)}
                        >
                          <RotateCcw className="size-3.5" /> Restore
                        </button>
                      </TD>
                    )}
                  </TRow>
                ))}
              </tbody>
            </DTable>
          )}
        </Panel>
      </div>

      {gate.dialog}
      <ConfirmDialog
        open={!!restoreId}
        onOpenChange={(o) => {
          if (!o) {
            setRestoreId(null);
            restore.reset();
          }
        }}
        title="Restore this backup?"
        description="The backed-up certificate files are written back to the server, the service configuration is tested and the service is reloaded. The certificate currently served will change."
        confirmLabel="Restore backup"
        destructive
        pending={restore.isPending}
        onConfirm={() => {
          const bid = restoreId;
          if (!bid) return;
          void gate.attempt(
            () =>
              restore.mutateAsync(bid).then((r) => {
                if (r.accepted)
                  toast.info("Restore queued", {
                    description: "Follow the backup's restore status; it updates when the worker finishes.",
                  });
                else toast.error("Restore was not accepted");
                setRestoreId(null);
              }),
            (e) => toast.error("Restore failed", { description: errorMessage(e) }),
          );
        }}
      />
    </AppShell>
  );
}
