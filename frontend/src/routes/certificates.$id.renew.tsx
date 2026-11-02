import { createFileRoute, Link, notFound } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  CircleDashed,
  FileKey2,
  FileText,
  Layers,
  Loader2,
  Lock,
  RotateCcw,
  ShieldAlert,
  Upload,
  X,
  XCircle,
} from "lucide-react";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { EnvBadge, Pill } from "@/components/ui/status";
import { getCertificate, type Installation } from "@/lib/mock-data";
import { cn } from "@/lib/utils";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export const Route = createFileRoute("/certificates/$id/renew")({
  loader: ({ params }) => {
    const cert = getCertificate(params.id);
    if (!cert) throw notFound();
    return { cert };
  },
  head: ({ loaderData }) => {
    if (!loaderData) {
      return {
        meta: [
          { title: "Renewal unavailable — Certificate Manager" },
          { name: "robots", content: "noindex" },
        ],
      };
    }
    const t = `Replace ${loaderData.cert.commonName} — Certificate Manager`;
    const d = `Upload, validate and deploy the renewed certificate for ${loaderData.cert.commonName} to its Nginx servers.`;
    return {
      meta: [
        { title: t },
        { name: "description", content: d },
        { property: "og:title", content: t },
        { property: "og:description", content: d },
      ],
    };
  },
  component: RenewWizard,
});

const steps = ["Upload", "Validation", "Target Servers", "Deployment Plan", "Deployment"];

const stamp = "20260910-143000";

function Dropzone({
  icon: Icon,
  label,
  formats,
  file,
  onPick,
}: {
  icon: typeof FileText;
  label: string;
  formats: string;
  file: string | null;
  onPick: () => void;
}) {
  const [over, setOver] = useState(false);
  return (
    <button
      type="button"
      onClick={onPick}
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        onPick();
      }}
      className={cn(
        "flex w-full flex-col items-center gap-1.5 rounded-md border border-dashed p-5 text-center transition-colors",
        over ? "border-primary bg-primary/5" : "border-border bg-surface-2/40 hover:border-primary/60",
        file && "border-ok/50 bg-ok-soft/40",
      )}
    >
      <Icon className={cn("size-5", file ? "text-ok" : "text-muted-foreground")} />
      <div className="text-[12.5px] font-medium">{label}</div>
      {file ? (
        <span className="mono text-ok">{file}</span>
      ) : (
        <>
          <span className="text-[11.5px] text-muted-foreground">
            Drag &amp; drop or click to select
          </span>
          <span className="mono text-[10.5px] text-muted-foreground">{formats}</span>
        </>
      )}
    </button>
  );
}

function StepIcon({ state }: { state: string }) {
  if (state === "ok") return <CheckCircle2 className="size-3.5 text-ok" />;
  if (state === "failed") return <XCircle className="size-3.5 text-danger" />;
  if (state === "running") return <Loader2 className="size-3.5 animate-spin text-info" />;
  return <CircleDashed className="size-3.5 text-muted-foreground" />;
}

type RunState = "pending" | "running" | "ok" | "failed" | "skipped";

const stepLabels = [
  "SSH Connection",
  "Backup Existing Certificate",
  "Backup Existing Private Key",
  "Upload Certificate",
  "Upload Private Key",
  "File Permissions",
  "nginx -t",
  "Reload Nginx",
  "TLS Verification (:443)",
];

function RenewWizard() {
  const { cert } = Route.useLoaderData();
  const [step, setStep] = useState(0);
  const [files, setFiles] = useState<{ cert: string | null; key: string | null; chain: string | null }>({
    cert: null,
    key: null,
    chain: null,
  });
  const [keyMismatch, setKeyMismatch] = useState(false);
  const [selected, setSelected] = useState<string[]>(
    cert.installations.filter((i) => i.environment === "Production").map((i) => i.serverId),
  );
  const [confirmed, setConfirmed] = useState(false);
  const [modal, setModal] = useState(false);
  const [progress, setProgress] = useState<Record<string, RunState[]>>({});
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const targets: Installation[] = cert.installations.filter((i) => selected.includes(i.serverId));
  const hasProduction = targets.some((t) => t.environment === "Production");

  useEffect(() => () => {
    if (timer.current) clearInterval(timer.current);
  }, []);

  const startDeployment = () => {
    setModal(false);
    setStep(4);
    const init: Record<string, RunState[]> = {};
    targets.forEach((t) => (init[t.serverId] = stepLabels.map(() => "pending")));
    setProgress(init);

    let tick = 0;
    timer.current = setInterval(() => {
      tick += 1;
      setProgress((prev) => {
        const next = { ...prev };
        targets.forEach((t, ti) => {
          const arr = [...(next[t.serverId] ?? [])];
          const idx = tick - 1 - ti;
          // second server fails at nginx -t and rolls back
          const failsAt = ti === 1 ? 6 : -1;
          if (idx >= 0 && idx < arr.length) {
            if (failsAt >= 0 && idx > failsAt) {
              arr[idx] = "skipped";
            } else {
              arr[idx] = idx === failsAt ? "failed" : "ok";
            }
            if (idx + 1 < arr.length && !(failsAt >= 0 && idx >= failsAt)) arr[idx + 1] = "running";
          }
          next[t.serverId] = arr;
        });
        return next;
      });
      if (tick > stepLabels.length + targets.length + 1 && timer.current) clearInterval(timer.current);
    }, 550);
  };

  const canNext =
    (step === 0 && files.cert && files.key && files.chain) ||
    (step === 1 && !keyMismatch) ||
    (step === 2 && selected.length > 0);

  return (
    <AppShell>
      <Link
        to="/certificates/$id"
        params={{ id: cert.id }}
        className="mb-2 inline-flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3.5" /> {cert.commonName}
      </Link>

      <PageHeader
        title="Replace / Renew Certificate"
        subtitle={
          <>
            Replacing <span className="mono text-foreground">{cert.commonName}</span> · filenames and
            filesystem paths are preserved so no Nginx configuration change is required
          </>
        }
      />

      {/* Stepper */}
      <ol className="mb-3 flex flex-wrap items-center gap-1 rounded-md border border-border bg-surface p-1.5">
        {steps.map((s, i) => (
          <li key={s} className="flex items-center gap-1">
            <span
              className={cn(
                "flex items-center gap-1.5 rounded-sm px-2 py-1 text-[12px]",
                i === step
                  ? "bg-primary/12 font-medium text-primary ring-1 ring-primary/25"
                  : i < step
                    ? "text-ok"
                    : "text-muted-foreground",
              )}
            >
              <span
                className={cn(
                  "flex size-4 items-center justify-center rounded-full text-[10px]",
                  i < step ? "bg-ok text-background" : i === step ? "bg-primary text-primary-foreground" : "bg-muted",
                )}
              >
                {i < step ? <Check className="size-2.5" /> : i + 1}
              </span>
              {s}
            </span>
            {i < steps.length - 1 && <ArrowRight className="size-3 text-muted-foreground" />}
          </li>
        ))}
      </ol>

      {step === 0 && (
        <Panel title="Step 1 — Upload New Certificate">
          <div className="grid gap-3 p-3 md:grid-cols-3">
            <Dropzone
              icon={FileText}
              label="Certificate"
              formats="PEM · CER · CRT · P7B"
              file={files.cert}
              onPick={() => setFiles((f) => ({ ...f, cert: cert.files.cert }))}
            />
            <Dropzone
              icon={FileKey2}
              label="Private Key"
              formats="PEM · KEY"
              file={files.key}
              onPick={() => setFiles((f) => ({ ...f, key: cert.files.key }))}
            />
            <Dropzone
              icon={Layers}
              label="Intermediate Certificate / Chain"
              formats="PEM · CER · CRT · P7B / PKCS#7"
              file={files.chain}
              onPick={() => setFiles((f) => ({ ...f, chain: cert.files.chain }))}
            />
          </div>
          <div className="flex items-center gap-2 border-t border-border px-3 py-2 text-[11.5px] text-muted-foreground">
            <Lock className="size-3.5" /> The private key is encrypted on upload and never displayed or
            downloadable.
          </div>
        </Panel>
      )}

      {step === 1 && (
        <div className="grid gap-3 lg:grid-cols-2">
          <Panel title="Parsed Certificate">
            <div className="px-3 py-1.5">
              {[
                ["Common Name", cert.commonName],
                ["SANs", cert.sans.join(", ")],
                ["Issuer", cert.issuer],
                ["Expiration", "07 Mar 2028"],
                ["Key Algorithm", cert.publicKeyAlgorithm],
                ["Key Size", String(cert.keySize)],
                ["Fingerprint", cert.fingerprint],
              ].map(([k, v]) => (
                <div key={k} className="flex flex-col gap-0.5 border-b border-border/60 py-1.5 last:border-0 sm:flex-row sm:gap-3">
                  <div className="w-40 shrink-0 text-[11.5px] uppercase tracking-[0.05em] text-muted-foreground">
                    {k}
                  </div>
                  <div className="mono break-all text-foreground">{v}</div>
                </div>
              ))}
            </div>
          </Panel>

          <Panel
            title="Validation Checks"
            actions={
              <label className="flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
                <input
                  type="checkbox"
                  checked={keyMismatch}
                  onChange={(e) => setKeyMismatch(e.target.checked)}
                  className="accent-[var(--color-primary)]"
                />
                Simulate key mismatch
              </label>
            }
          >
            <div className="p-3">
              {[
                { label: "Certificate is valid", failed: false },
                { label: "Private key matches certificate", failed: keyMismatch },
                { label: "Certificate chain valid", failed: false },
                { label: "Certificate not expired", failed: false },
                { label: "CN/SAN compatible with existing certificate", failed: false },
              ].map((c) => (
                <div
                  key={c.label}
                  className="flex items-center justify-between border-b border-border/60 py-1.5 last:border-0"
                >
                  <span className="flex items-center gap-2 text-[12.5px]">
                    {c.failed ? (
                      <XCircle className="size-3.5 text-danger" />
                    ) : (
                      <CheckCircle2 className="size-3.5 text-ok" />
                    )}
                    {c.label}
                  </span>
                  <Pill tone={c.failed ? "danger" : "ok"}>{c.failed ? "Failed" : "Passed"}</Pill>
                </div>
              ))}

              {keyMismatch && (
                <div className="mt-3 flex items-start gap-2 rounded-md border border-danger/40 bg-danger-soft p-2.5">
                  <ShieldAlert className="mt-0.5 size-4 shrink-0 text-danger" />
                  <div>
                    <div className="text-[12.5px] font-semibold text-danger">
                      Private key does not match the selected certificate. Deployment cannot continue.
                    </div>
                    <div className="mt-0.5 text-[11.5px] text-muted-foreground">
                      Modulus comparison failed. Upload the key generated with the CSR used for this
                      certificate.
                    </div>
                  </div>
                </div>
              )}
            </div>
          </Panel>
        </div>
      )}

      {step === 2 && (
        <Panel
          title="Step 3 — Select Target Servers"
          actions={
            <span className="text-[11.5px] text-muted-foreground">
              Servers currently running the previous certificate
            </span>
          }
        >
          <DTable>
            <THead>
              <TH className="w-8" />
              <TH>Server</TH>
              <TH>IP</TH>
              <TH>Environment</TH>
              <TH>Web Server</TH>
              <TH>Certificate Path</TH>
              <TH>Key Path</TH>
              <TH>Last Deployment</TH>
            </THead>
            <tbody>
              {cert.installations.map((i) => {
                const on = selected.includes(i.serverId);
                return (
                  <TRow
                    key={i.serverId}
                    onClick={() =>
                      setSelected((s) =>
                        s.includes(i.serverId) ? s.filter((x) => x !== i.serverId) : [...s, i.serverId],
                      )
                    }
                    className={on ? "bg-primary/5" : undefined}
                  >
                    <TD>
                      <input
                        type="checkbox"
                        readOnly
                        checked={on}
                        className="accent-[var(--color-primary)]"
                      />
                    </TD>
                    <TD className="mono font-medium">{i.serverName}</TD>
                    <TD className="mono">{i.ip}</TD>
                    <TD>
                      <EnvBadge env={i.environment} />
                    </TD>
                    <TD className="text-muted-foreground">{i.webServer}</TD>
                    <TD className="mono">{i.certPath}</TD>
                    <TD className="mono">{i.keyPath}</TD>
                    <TD className="mono">{i.lastDeployment}</TD>
                  </TRow>
                );
              })}
            </tbody>
          </DTable>
          <div className="border-t border-border px-3 py-2 text-[11.5px] text-muted-foreground">
            {selected.length} of {cert.installations.length} servers selected · paths are per-server and
            will not be modified
          </div>
        </Panel>
      )}

      {step === 3 && (
        <div className="space-y-3">
          {targets.map((t) => (
            <Panel
              key={t.serverId}
              title={
                <span className="flex items-center gap-2">
                  <span className="mono">{t.serverName}</span>
                  <EnvBadge env={t.environment} />
                  <span className="mono text-muted-foreground">{t.ip}</span>
                </span>
              }
            >
              <div className="grid gap-3 p-3 md:grid-cols-2">
                <div>
                  <div className="mb-1 text-[11px] uppercase tracking-[0.06em] text-muted-foreground">
                    Current files
                  </div>
                  <div className="mono space-y-0.5 rounded-md border border-border bg-surface-2/50 p-2">
                    <div>{t.certPath}</div>
                    <div>{t.keyPath}</div>
                  </div>
                  <div className="mb-1 mt-2.5 text-[11px] uppercase tracking-[0.06em] text-muted-foreground">
                    Backups that will be created
                  </div>
                  <div className="mono space-y-0.5 rounded-md border border-border bg-surface-2/50 p-2 text-warn">
                    <div>{`${t.certPath}.bak-${stamp}`}</div>
                    <div>{`${t.keyPath}.bak-${stamp}`}</div>
                  </div>
                </div>
                <div>
                  <div className="mb-1 text-[11px] uppercase tracking-[0.06em] text-muted-foreground">
                    Actions
                  </div>
                  <ol className="space-y-1">
                    {[
                      "Backup existing certificate",
                      "Backup existing private key",
                      "Copy new certificate (same filename)",
                      "Copy new private key (same filename)",
                      "Set filesystem permissions (0644 / 0600)",
                      "Run nginx -t",
                      "Reload Nginx (systemctl reload nginx)",
                      "Verify exposed certificate on TCP/443",
                    ].map((a, n) => (
                      <li key={a} className="flex items-center gap-2 text-[12.5px]">
                        <span className="mono w-4 text-muted-foreground">{n + 1}.</span>
                        {a}
                      </li>
                    ))}
                  </ol>
                </div>
              </div>
            </Panel>
          ))}

          <Panel>
            <div className="space-y-2.5 p-3">
              <div className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft p-2.5 text-[12px]">
                <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warn" />
                <span>
                  Every step is recorded in the audit log. If <span className="mono">nginx -t</span> or
                  TLS verification fails, the previous certificate and key are restored automatically.
                </span>
              </div>
              <label className="flex items-center gap-2 text-[12.5px]">
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(e) => setConfirmed(e.target.checked)}
                  className="accent-[var(--color-primary)]"
                />
                I confirm the deployment on the selected production servers
              </label>
              <button
                disabled={!confirmed}
                onClick={() => (hasProduction ? setModal(true) : startDeployment())}
                className="inline-flex h-8 items-center gap-1.5 rounded-md bg-primary px-3 text-[12.5px] font-medium text-primary-foreground disabled:cursor-not-allowed disabled:opacity-40 hover:opacity-90"
              >
                Deploy Certificate
              </button>
            </div>
          </Panel>
        </div>
      )}

      {step === 4 && (
        <div className="space-y-3">
          <Panel
            title={
              <span>
                Deploying <span className="mono">{cert.commonName}</span> · {targets.length} target
                servers
              </span>
            }
          >
            <div className="grid gap-3 p-3 lg:grid-cols-2 xl:grid-cols-3">
              {targets.map((t, ti) => {
                const states = progress[t.serverId] ?? [];
                const failed = states.includes("failed");
                const done = states.every((s) => s !== "pending" && s !== "running") && states.length > 0;
                return (
                  <div key={t.serverId} className="rounded-md border border-border bg-surface-2/40 p-2.5">
                    <div className="mb-2 flex items-center justify-between">
                      <span className="mono font-medium">{t.serverName}</span>
                      {failed ? (
                        <Pill tone="warn" dot>
                          Rolled Back
                        </Pill>
                      ) : done ? (
                        <Pill tone="ok" dot>
                          Successful
                        </Pill>
                      ) : states.some((s) => s === "running" || s === "ok") ? (
                        <Pill tone="info" dot>
                          Running
                        </Pill>
                      ) : (
                        <Pill tone="neutral">Pending</Pill>
                      )}
                    </div>
                    <div className="space-y-0.5">
                      {stepLabels.map((l, i) => (
                        <div key={l} className="flex items-center gap-2 text-[12px]">
                          <StepIcon state={states[i] ?? "pending"} />
                          <span
                            className={cn(
                              states[i] === "failed" && "text-danger",
                              states[i] === "skipped" && "text-muted-foreground line-through",
                            )}
                          >
                            {l}
                          </span>
                        </div>
                      ))}
                    </div>
                    {failed && (
                      <div className="mt-2 space-y-2">
                        <pre className="mono overflow-x-auto rounded-sm border border-danger/40 bg-danger-soft p-2 text-[11px] text-danger">
{`nginx: [emerg] cannot load certificate
"${t.certPath}": PEM_read_bio_X509_AUX() failed`}
                        </pre>
                        <div className="flex items-center gap-1.5 text-[11.5px] text-warn">
                          <RotateCcw className="size-3.5" /> Automatic rollback performed — previous
                          certificate restored, nginx reloaded
                        </div>
                      </div>
                    )}
                    {ti === 1 && failed && (
                      <Link
                        to="/deployments/$id"
                        params={{ id: "dep-20260910-1432" }}
                        className="mt-2 inline-block text-[11.5px] text-primary hover:underline"
                      >
                        Open rollback timeline →
                      </Link>
                    )}
                  </div>
                );
              })}
            </div>
          </Panel>
          <div className="flex gap-2">
            <Link
              to="/deployments/$id"
              params={{ id: "dep-20260910-1432" }}
              className="inline-flex h-8 items-center gap-1.5 rounded-md bg-primary px-3 text-[12.5px] font-medium text-primary-foreground hover:opacity-90"
            >
              View deployment detail
            </Link>
            <Link
              to="/certificates/$id"
              params={{ id: cert.id }}
              className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-surface px-3 text-[12.5px] hover:border-primary hover:text-primary"
            >
              Back to certificate
            </Link>
          </div>
        </div>
      )}

      {step < 3 && (
        <div className="mt-3 flex items-center justify-between">
          <button
            onClick={() => setStep((s) => Math.max(0, s - 1))}
            disabled={step === 0}
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-surface px-3 text-[12.5px] disabled:opacity-40"
          >
            <ArrowLeft className="size-3.5" /> Back
          </button>
          <button
            onClick={() => setStep((s) => s + 1)}
            disabled={!canNext}
            className="inline-flex h-8 items-center gap-1.5 rounded-md bg-primary px-3 text-[12.5px] font-medium text-primary-foreground disabled:cursor-not-allowed disabled:opacity-40 hover:opacity-90"
          >
            Continue <ArrowRight className="size-3.5" />
          </button>
        </div>
      )}
      {step === 3 && (
        <div className="mt-3">
          <button
            onClick={() => setStep(2)}
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-surface px-3 text-[12.5px]"
          >
            <ArrowLeft className="size-3.5" /> Back
          </button>
        </div>
      )}

      <Dialog open={modal} onOpenChange={setModal}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-danger">
              <ShieldAlert className="size-4" /> Production deployment confirmation
            </DialogTitle>
            <DialogDescription>
              You are about to replace certificate files on{" "}
              {targets.filter((t) => t.environment === "Production").length} production servers and
              reload Nginx.
            </DialogDescription>
          </DialogHeader>
          <div className="mono rounded-md border border-border bg-surface-2/50 p-2 text-[11.5px]">
            {targets.map((t) => (
              <div key={t.serverId}>
                {t.serverName} — {t.certPath}
              </div>
            ))}
          </div>
          <DialogFooter>
            <button
              onClick={() => setModal(false)}
              className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-surface px-3 text-[12.5px]"
            >
              <X className="size-3.5" /> Cancel
            </button>
            <button
              onClick={startDeployment}
              className="inline-flex h-8 items-center gap-1.5 rounded-md bg-destructive px-3 text-[12.5px] font-medium text-destructive-foreground hover:opacity-90"
            >
              <Upload className="size-3.5" /> Deploy to production
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </AppShell>
  );
}
