import { useState } from "react";
import { Fingerprint, ShieldAlert, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { Panel } from "@/components/layout/AppShell";
import { Pill } from "@/components/ui/status";
import { btnCls, btnPrimaryCls, errorMessage, Spinner } from "@/components/ui/feedback";
import { useEnrollHostKey, useScanHostKey } from "@/lib/api/queries";
import type { HostKeyScan, Server } from "@/lib/api/types";
import { fmtDateTime } from "@/lib/format";
import { useCan } from "@/lib/auth";

/** Scan -> show fingerprint -> explicit confirmation -> enroll. Trust is never implicit. */
export function HostKeyPanel({
  server,
  onEnrolled,
}: {
  server: Server;
  onEnrolled?: (s: Server) => void;
}) {
  const canEnroll = useCan("servers:hostkey");
  const scan = useScanHostKey();
  const enroll = useEnrollHostKey();
  const [found, setFound] = useState<HostKeyScan | null>(null);
  const [confirmed, setConfirmed] = useState(false);

  const enrolled = !!server.host_key_fingerprint;
  const changed = !!found && enrolled && found.fingerprint_sha256 !== server.host_key_fingerprint;
  const same = !!found && enrolled && !changed;

  const doScan = () => {
    setConfirmed(false);
    scan.mutate(server.id, { onSuccess: setFound });
  };
  const doEnroll = () => {
    if (!found) return;
    enroll.mutate(
      {
        id: server.id,
        public_key: found.public_key,
        fingerprint_sha256: found.fingerprint_sha256,
        replace: enrolled,
      },
      {
        onSuccess: (s) => {
          toast.success("Host key enrolled", { description: found.fingerprint_sha256 });
          setFound(null);
          setConfirmed(false);
          onEnrolled?.(s);
        },
      },
    );
  };

  return (
    <Panel
      title="SSH Host Key"
      actions={
        enrolled ? (
          <Pill tone="ok" dot>
            Enrolled
          </Pill>
        ) : (
          <Pill tone="warn" dot>
            Not enrolled
          </Pill>
        )
      }
    >
      <div className="space-y-2 p-3 text-[12.5px]">
        {enrolled ? (
          <div className="space-y-1">
            <div className="flex justify-between gap-3">
              <span className="text-muted-foreground">Type</span>
              <span className="mono">{server.host_key_type}</span>
            </div>
            <div className="mono break-all rounded-md border border-border bg-surface-2/50 p-2 text-[11px]">
              {server.host_key_fingerprint}
            </div>
            <div className="text-[11.5px] text-muted-foreground">
              Enrolled {fmtDateTime(server.host_key_enrolled_at)} · connections to a different key
              are refused.
            </div>
          </div>
        ) : (
          <p className="text-[12px] text-muted-foreground">
            Unknown host keys are never trusted automatically. Fetch the key presented by the
            server, compare the fingerprint with the one shown on the host (
            <span className="mono">ssh-keygen -lf /etc/ssh/ssh_host_*.pub</span>) and confirm.
          </p>
        )}

        {scan.error && (
          <p className="text-[12px] text-danger" role="alert">
            {errorMessage(scan.error)}
          </p>
        )}

        {found && (
          <div
            className={
              changed
                ? "space-y-2 rounded-md border border-crit/40 bg-crit-soft p-2.5"
                : "space-y-2 rounded-md border border-info/30 bg-info-soft p-2.5"
            }
            data-testid="hostkey-found"
          >
            <div className="flex items-center gap-1.5 text-[12px] font-medium">
              {changed ? (
                <ShieldAlert className="size-3.5 text-crit" />
              ) : (
                <Fingerprint className="size-3.5 text-info" />
              )}
              {changed
                ? "The host presents a DIFFERENT key than the enrolled one"
                : same
                  ? "Matches the enrolled key"
                  : "Key presented by the server"}
            </div>
            <div className="flex justify-between gap-3 text-[12px]">
              <span className="text-muted-foreground">Type</span>
              <span className="mono">{found.key_type}</span>
            </div>
            <div
              className="mono break-all rounded-md border border-border bg-background/60 p-2 text-[11.5px]"
              data-testid="hostkey-fingerprint"
            >
              {found.fingerprint_sha256}
            </div>
            {!same && canEnroll && (
              <>
                <label className="flex cursor-pointer items-start gap-2 text-[12px]">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={confirmed}
                    onChange={(e) => setConfirmed(e.target.checked)}
                  />
                  <span>
                    I verified this fingerprint through a trusted channel
                    {changed ? " and I expect the host key to have changed" : ""}.
                  </span>
                </label>
                {enroll.error && (
                  <p className="text-[12px] text-danger" role="alert">
                    {errorMessage(enroll.error)}
                  </p>
                )}
                <button
                  className={btnPrimaryCls}
                  disabled={!confirmed || enroll.isPending}
                  onClick={doEnroll}
                >
                  {enroll.isPending ? <Spinner /> : <ShieldCheck className="size-3.5" />}
                  {enrolled ? "Replace enrolled key" : "Trust and enroll key"}
                </button>
              </>
            )}
          </div>
        )}

        <div>
          <button className={btnCls} onClick={doScan} disabled={scan.isPending}>
            {scan.isPending ? <Spinner /> : <Fingerprint className="size-3.5" />}
            {enrolled ? "Re-scan host key" : "Scan host key"}
          </button>
        </div>
      </div>
    </Panel>
  );
}
