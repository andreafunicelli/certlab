import { CheckCircle2, FileText, Link2, Lock, RotateCcw, ShieldAlert, XCircle } from "lucide-react";
import { Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { EnvBadge, Pill } from "@/components/ui/status";
import type { DeploymentPlan, PlanTarget } from "@/lib/api/types";
import { fmtMode, shortFp } from "@/lib/format";

function bytes(n: number): string {
  if (n > 1e9) return `${(n / 1e9).toFixed(1)} GB`;
  if (n > 1e6) return `${(n / 1e6).toFixed(0)} MB`;
  return `${Math.round(n / 1e3)} kB`;
}

function Label({ children }: { children: React.ReactNode }) {
  return (
    <div className="mb-1 text-[11px] uppercase tracking-[0.06em] text-muted-foreground">
      {children}
    </div>
  );
}

function TargetPlan({ t }: { t: PlanTarget }) {
  const replaced = t.files.filter((f) => f.action === "replace");
  const kept = t.files.filter((f) => f.action === "keep");
  return (
    <div data-testid="plan-target">
      <Panel
        title={
          <span className="flex flex-wrap items-center gap-2">
            <span className="mono">{t.server_name}</span>
            <EnvBadge env={t.environment} />
            <Pill tone="neutral">{t.service_type}</Pill>
            {t.vhost && <span className="mono text-muted-foreground">{t.vhost}</span>}
            {t.is_canary && <Pill tone="info">canary</Pill>}
            <span className="text-[11px] text-muted-foreground">batch {t.batch_index + 1}</span>
          </span>
        }
      >
        <div className="space-y-3 p-3">
          <div>
            <Label>
              Files ({replaced.length} replaced{kept.length ? `, ${kept.length} kept` : ""})
            </Label>
            <DTable>
              <THead>
                <TH>Path</TH>
                <TH>Action</TH>
                <TH>Content</TH>
                <TH>Mode / owner</TH>
                <TH>Notes</TH>
              </THead>
              <tbody>
                {t.files.map((f) => (
                  <TRow
                    key={f.dest_path}
                    className={f.action === "keep" ? "opacity-80" : undefined}
                  >
                    <TD className="mono">{f.dest_path}</TD>
                    <TD>
                      <Pill tone={f.action === "replace" ? "info" : "neutral"}>{f.action}</Pill>
                    </TD>
                    <TD className="mono text-muted-foreground">
                      {f.artifact}
                      {f.contains_private_key && (
                        <Lock
                          className="ml-1 inline size-3 text-warn"
                          aria-label="contains private key"
                        />
                      )}
                      {f.new_sha256 && f.action === "replace" && (
                        <div className="text-[11px]">sha256 {f.new_sha256.slice(0, 12)}…</div>
                      )}
                    </TD>
                    <TD className="mono">
                      {f.action === "replace"
                        ? `${fmtMode(f.mode)} ${f.owner ?? "?"}:${f.group ?? "?"} (preserved)`
                        : "unchanged"}
                    </TD>
                    <TD className="text-[11.5px] text-muted-foreground">
                      {f.is_symlink && (
                        <span className="flex items-center gap-1">
                          <Link2 className="size-3" /> symlink kept, target {f.realpath} replaced
                        </span>
                      )}
                      {f.action === "keep" && "existing private key is reused"}
                    </TD>
                  </TRow>
                ))}
              </tbody>
            </DTable>
          </div>

          {t.shared_with.length > 0 && (
            <div className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft p-2 text-[12px]">
              <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warn" />
              <span>
                These files are shared with other installations on this server:{" "}
                <span className="mono">{JSON.stringify(t.shared_with)}</span>. They are updated
                together.
              </span>
            </div>
          )}

          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <Label>Backups created first</Label>
              <ul className="mono space-y-0.5 rounded-md border border-border bg-surface-2/50 p-2 text-warn">
                {t.backups.map((b) => (
                  <li key={b} className="break-all">
                    {b}
                  </li>
                ))}
              </ul>
              <p className="mt-1 text-[11px] text-muted-foreground">
                Stored encrypted and integrity-verified before anything is modified.
              </p>
            </div>
            <div className="space-y-2">
              <div>
                <Label>Config test &amp; reload</Label>
                <div className="space-y-0.5 text-[12.5px]">
                  <div className="flex items-center gap-1.5">
                    {t.config_test?.current_ok ? (
                      <CheckCircle2 className="size-3.5 text-ok" />
                    ) : (
                      <XCircle className="size-3.5 text-danger" />
                    )}
                    <span>
                      Current {t.service_type} configuration{" "}
                      {t.config_test?.current_ok ? "passes" : "FAILS"} its config test
                    </span>
                  </div>
                  <div className="text-muted-foreground">
                    After replacing the files the config test runs again; then{" "}
                    <span className="mono text-foreground">
                      {t.reload ? `${t.reload.mode} of ${t.reload.service}` : "reload"}
                    </span>
                    .
                  </div>
                </div>
              </div>
              <div>
                <Label>Verification</Label>
                {t.verify_endpoints.length === 0 ? (
                  <p className="text-[12px] text-warn">
                    No TLS endpoint configured: file-content verification only.
                  </p>
                ) : (
                  <ul className="space-y-0.5 text-[12px]">
                    {t.verify_endpoints.map((e) => (
                      <li key={`${e.host}:${e.port}`} className="flex flex-wrap gap-x-2">
                        <span className="mono">
                          {e.host}:{e.port}
                          {e.sni ? ` (SNI ${e.sni})` : ""}
                        </span>
                        {e.reachable === false ? (
                          <span className="text-warn">
                            unreachable now{e.error ? `: ${e.error}` : ""}
                          </span>
                        ) : (
                          <span className="mono text-muted-foreground">
                            currently serves {shortFp(e.served_fingerprint)}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
                <p className="text-[11px] text-muted-foreground">
                  Mode:{" "}
                  {t.verification_mode === "live"
                    ? "live TLS probe must serve the new fingerprint"
                    : "file contents only"}
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-start gap-1.5 text-[11.5px] text-warn">
            <RotateCcw className="mt-0.5 size-3.5 shrink-0" />
            <span>{t.rollback}</span>
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-[11.5px] text-muted-foreground">
            <span>
              Current fingerprint <span className="mono">{shortFp(t.current_fingerprint)}</span>
            </span>
            <span>
              New fingerprint <span className="mono">{shortFp(t.new_fingerprint)}</span>
            </span>
            {t.disk && (
              <span>
                Disk free {bytes(t.disk.free_bytes)} (need {bytes(t.disk.required_bytes)})
              </span>
            )}
            {t.privilege && (
              <span>
                Privilege <span className="mono">{t.privilege.mode}</span>
                {t.privilege.helper_version ? ` · helper ${t.privilege.helper_version}` : ""}
              </span>
            )}
          </div>
        </div>
      </Panel>
    </div>
  );
}

/** Truthful dry-run: exactly what the backend planner computed (nothing was changed on any server). */
export function PlanView({ plan }: { plan: DeploymentPlan }) {
  const files = plan.targets.reduce(
    (n, t) => n + t.files.filter((f) => f.action === "replace").length,
    0,
  );
  return (
    <div className="space-y-3" data-testid="plan">
      <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-surface p-2 text-[12.5px]">
        <Pill tone="info">Dry run: nothing has been changed</Pill>
        <span>
          <b>{plan.summary.targets}</b> server installation{plan.summary.targets === 1 ? "" : "s"}{" "}
          would be modified
        </span>
        <span>
          <b>{files}</b> file{files === 1 ? "" : "s"} replaced
        </span>
        <span className="text-muted-foreground">
          strategy {plan.strategy.mode}, concurrency {plan.strategy.concurrency}, stop after{" "}
          {plan.strategy.failure_threshold || "∞"} failure
          {plan.strategy.failure_threshold === 1 ? "" : "s"}
        </span>
        <span className="ml-auto">
          {plan.summary.can_proceed ? (
            <Pill tone="ok" dot>
              Ready to deploy
            </Pill>
          ) : (
            <Pill tone="danger" dot>
              Cannot proceed
            </Pill>
          )}
        </span>
      </div>
      {plan.targets.map((t) => (
        <TargetPlan key={t.installation_id} t={t} />
      ))}
    </div>
  );
}
