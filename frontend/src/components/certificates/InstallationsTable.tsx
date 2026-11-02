import { Link } from "@tanstack/react-router";
import { ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { ClassificationBadge, DriftBadge, EnvBadge, Pill } from "@/components/ui/status";
import { btnCls, errorMessage, Spinner } from "@/components/ui/feedback";
import { useVerifyInstallation } from "@/lib/api/queries";
import type { Installation, VerificationRecord } from "@/lib/api/types";
import { useCan } from "@/lib/auth";
import { fmtAgo } from "@/lib/format";

export function VerificationCell({ v }: { v: VerificationRecord | null }) {
  if (!v) return <span className="text-muted-foreground">never</span>;
  const when = <span className="text-[11px] text-muted-foreground">{fmtAgo(v.checked_at)}</span>;
  if (!v.ok)
    return (
      <span className="flex flex-col gap-0.5">
        <Pill tone="danger" dot>
          Failed
        </Pill>
        <span className="max-w-48 truncate text-[11px] text-danger" title={v.error ?? ""}>
          {v.error}
        </span>
        {when}
      </span>
    );
  return (
    <span className="flex flex-col gap-0.5">
      {v.matches_file === false ? (
        <Pill tone="warn" dot>
          Serves different cert
        </Pill>
      ) : (
        <Pill tone="ok" dot>
          {v.matches_file ? "Matches file" : "Reachable"}
        </Pill>
      )}
      {when}
    </span>
  );
}

/** Why an installation cannot be selected for deployment (null = deployable). */
export function notDeployableReason(i: Installation): string | null {
  if (i.missing_since) return "File no longer found on the server";
  if (i.managed_by_certbot)
    return "Managed by certbot: renewals must go through certbot, not this tool";
  switch (i.classification) {
    case "managed":
      return null;
    case "requires_mapping":
      return "Requires mapping: the certificate/key locations could not be determined automatically";
    case "unsupported":
      return "Unsupported service or certificate container";
    case "unreadable":
      return "The certificate file is not readable by the service account";
    case "error":
      return "Discovery could not parse this installation";
    case "unmanaged":
      return "Marked unmanaged: not eligible for automated deployment";
    default:
      return `Not eligible (${i.classification})`;
  }
}

export function InstallationsTable({
  rows,
  context,
}: {
  rows: Installation[];
  /** "certificate": show the server column; "server": show the certificate column. */
  context: "certificate" | "server";
}) {
  const canVerify = useCan("installations:verify");
  const verify = useVerifyInstallation();
  const run = (i: Installation) =>
    verify.mutate(i.id, {
      onSuccess: (r) => {
        if (!r.ok) toast.error("Endpoint check failed", { description: r.error ?? undefined });
        else if (r.matches_file === false)
          toast.warning("Endpoint serves a different certificate than the file on disk");
        else toast.success("Endpoint verified");
      },
      onError: (e) => toast.error("Verification failed", { description: errorMessage(e) }),
    });

  return (
    <DTable>
      <THead>
        {context === "certificate" ? <TH>Server</TH> : <TH>Certificate</TH>}
        {context === "certificate" && <TH>Environment</TH>}
        <TH>Service</TH>
        <TH>Certificate Path</TH>
        <TH>Key Path</TH>
        <TH>Classification</TH>
        <TH>Drift</TH>
        <TH>Last verification</TH>
        {canVerify && <TH align="right">Action</TH>}
      </THead>
      <tbody>
        {rows.map((i) => (
          <TRow key={i.id} className={i.missing_since ? "opacity-60" : undefined}>
            <TD>
              {context === "certificate" ? (
                <Link
                  to="/servers/$id"
                  params={{ id: i.server_id }}
                  className="mono font-medium text-foreground hover:text-primary hover:underline"
                >
                  {i.server_name ?? i.server_id.slice(0, 8)}
                </Link>
              ) : i.certificate ? (
                <Link
                  to="/certificates/$id"
                  params={{ id: i.certificate.id }}
                  className="mono font-medium text-foreground hover:text-primary hover:underline"
                >
                  {i.certificate.common_name}
                </Link>
              ) : (
                <span className="text-muted-foreground">—</span>
              )}
            </TD>
            {context === "certificate" && (
              <TD>{i.environment ? <EnvBadge env={i.environment} /> : "—"}</TD>
            )}
            <TD className="mono">
              {i.service_type}
              {i.listen_port ? (
                <span className="text-muted-foreground">:{i.listen_port}</span>
              ) : null}
              {i.vhost && <div className="text-[11px] text-muted-foreground">{i.vhost}</div>}
            </TD>
            <TD className="mono">{i.cert_path ?? "—"}</TD>
            <TD className="mono">{i.is_combined_pem ? "(combined PEM)" : (i.key_path ?? "—")}</TD>
            <TD>
              <ClassificationBadge value={i.classification} certbot={i.managed_by_certbot} />
              {i.missing_since && (
                <div className="text-[11px] text-danger">
                  missing since {fmtAgo(i.missing_since)}
                </div>
              )}
            </TD>
            <TD>
              <DriftBadge value={i.drift_status} />
            </TD>
            <TD>
              <VerificationCell v={i.last_verification} />
            </TD>
            {canVerify && (
              <TD align="right">
                <button
                  className={btnCls}
                  onClick={() => run(i)}
                  disabled={verify.isPending || !!i.missing_since}
                  aria-label={`Verify ${i.cert_path ?? i.id}`}
                >
                  {verify.isPending && verify.variables === i.id ? (
                    <Spinner />
                  ) : (
                    <ShieldCheck className="size-3.5" />
                  )}
                  Verify
                </button>
              </TD>
            )}
          </TRow>
        ))}
      </tbody>
    </DTable>
  );
}
