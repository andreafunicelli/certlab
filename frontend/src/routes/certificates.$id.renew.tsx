import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  FileKey2,
  FileText,
  Layers,
  Lock,
  ShieldAlert,
  Upload,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { DriftBadge, EnvBadge, Pill } from "@/components/ui/status";
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
import { FindingsList } from "@/components/deployments/FindingsList";
import { PlanView } from "@/components/deployments/PlanView";
import { DeploymentLive } from "@/components/deployments/DeploymentLive";
import { notDeployableReason } from "@/components/certificates/InstallationsTable";
import { cn } from "@/lib/utils";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  api,
  useCertificate,
  useCreateDeployment,
  usePlanDeployment,
  useSettings,
  type DeploymentRequest,
} from "@/lib/api/queries";
import { isApiError } from "@/lib/api/client";
import { useQueryClient } from "@tanstack/react-query";
import type { DeploymentPlan, Finding, UploadedVersion } from "@/lib/api/types";
import { useCan } from "@/lib/auth";
import { fmtDate, fmtDateTime, shortFp } from "@/lib/format";

export const Route = createFileRoute("/certificates/$id/renew")({
  validateSearch: (s: Record<string, unknown>): { deployment?: string } =>
    typeof s["deployment"] === "string" && s["deployment"] ? { deployment: s["deployment"] } : {},
  head: () => ({
    meta: [
      { title: "Replace Certificate — Certificate Manager" },
      {
        name: "description",
        content: "Upload, validate and deploy a renewed certificate to its servers.",
      },
    ],
  }),
  component: RenewWizard,
});

const steps = ["Upload", "Validation", "Target Servers", "Deployment Plan", "Deployment"];

// ---------------------------------------------------------------------------------------------
function Dropzone({
  icon: Icon,
  label,
  formats,
  file,
  onFile,
  disabled,
  testId,
  accept,
}: {
  icon: typeof FileText;
  label: string;
  formats: string;
  file: File | null;
  onFile: (f: File | null) => void;
  disabled?: boolean;
  testId: string;
  accept?: string;
}) {
  const [over, setOver] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        const f = e.dataTransfer.files?.[0];
        if (!disabled && f) onFile(f);
      }}
      className={cn(
        "flex w-full flex-col items-center gap-1.5 rounded-md border border-dashed p-5 text-center transition-colors",
        over ? "border-primary bg-primary/5" : "border-border bg-surface-2/40",
        file && "border-ok/50 bg-ok-soft/40",
        disabled && "opacity-50",
      )}
    >
      <Icon className={cn("size-5", file ? "text-ok" : "text-muted-foreground")} />
      <div className="text-[12.5px] font-medium">{label}</div>
      {file ? (
        <div className="flex items-center gap-1.5">
          <span className="mono text-ok">{file.name}</span>
          <button
            type="button"
            aria-label={`Remove ${label}`}
            onClick={() => {
              onFile(null);
              if (input.current) input.current.value = "";
            }}
            className="text-muted-foreground hover:text-danger"
          >
            <X className="size-3.5" />
          </button>
        </div>
      ) : (
        <>
          <button
            type="button"
            disabled={disabled}
            onClick={() => input.current?.click()}
            className="text-[11.5px] text-primary hover:underline disabled:pointer-events-none"
          >
            Choose file or drag &amp; drop
          </button>
          <span className="mono text-[10.5px] text-muted-foreground">{formats}</span>
        </>
      )}
      <input
        ref={input}
        type="file"
        className="sr-only"
        aria-label={label}
        data-testid={testId}
        disabled={disabled}
        {...(accept ? { accept } : {})}
        onChange={(e) => onFile(e.target.files?.[0] ?? null)}
      />
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex flex-col gap-0.5 border-b border-border/60 py-1.5 last:border-0 sm:flex-row sm:gap-3">
      <div className="w-40 shrink-0 text-[11.5px] uppercase tracking-[0.05em] text-muted-foreground">
        {k}
      </div>
      <div className="mono break-all text-foreground">{v}</div>
    </div>
  );
}

const newKey = () =>
  typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;

// ---------------------------------------------------------------------------------------------
function RenewWizard() {
  const { id } = Route.useParams();
  const search = Route.useSearch();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const canUpload = useCan("versions:upload");
  const canPlan = useCan("deployments:plan");
  const canDeploy = useCan("deployments:create");
  const canAdmin = useCan("deployments:approve");
  const certQ = useCertificate(id);
  const cert = certQ.data;
  const sshSettings = useSettings().data?.ssh.data;

  const deploymentId = search.deployment ?? null;
  const [step, setStep] = useState(deploymentId ? 4 : 0);

  // ---- step 1 (files live only until submit; nothing is read into strings, nothing is persisted)
  const [pfxMode, setPfxMode] = useState(false);
  const [certFile, setCertFile] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [chainFile, setChainFile] = useState<File | null>(null);
  const [pfxFile, setPfxFile] = useState<File | null>(null);
  const [pfxPassword, setPfxPassword] = useState("");
  const [reuseKey, setReuseKey] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<unknown>(null);
  const [uploadedNames, setUploadedNames] = useState<string[]>([]);
  const [formKey, setFormKey] = useState(0);

  // ---- step 2/3
  const [version, setVersion] = useState<UploadedVersion | null>(null);
  const [acked, setAcked] = useState<ReadonlySet<string>>(new Set());
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [validating, setValidating] = useState(false);
  const [validateError, setValidateError] = useState<unknown>(null);
  const [selFindings, setSelFindings] = useState<Finding[] | null>(null);

  // ---- step 4
  const [mode, setMode] = useState<"canary" | "batch" | "all">("canary");
  const [concurrency, setConcurrency] = useState(3);
  const [threshold, setThreshold] = useState(1);
  const [continueOnFailure, setContinueOnFailure] = useState(false);
  const [allowRestart, setAllowRestart] = useState(false);
  const [fileOnly, setFileOnly] = useState(false);
  const [plan, setPlan] = useState<DeploymentPlan | null>(null);
  const [planSig, setPlanSig] = useState("");
  const planM = usePlanDeployment();
  const create = useCreateDeployment();
  const [confirm, setConfirm] = useState(false);
  const [dryRunDone, setDryRunDone] = useState(false);
  const idem = useRef<{ key: string; sig: string } | null>(null);

  useEffect(() => {
    if (!sshSettings) return;
    setMode(sshSettings["canary"] === false ? "batch" : "canary");
    const c = Number(sshSettings["deployment_concurrency"]);
    const f = Number(sshSettings["failure_threshold"]);
    if (Number.isFinite(c) && c >= 1) setConcurrency(c);
    if (Number.isFinite(f) && f >= 0) setThreshold(f);
  }, [sshSettings]);

  useEffect(() => {
    if (deploymentId) setStep(4);
  }, [deploymentId]);

  const installs = useMemo(() => cert?.installations ?? [], [cert]);
  const eligible = useMemo(
    () => installs.filter((i) => notDeployableReason(i) === null),
    [installs],
  );
  const serverOf = (iid: string) => installs.find((i) => i.id === iid)?.server_name ?? undefined;
  const selectedIds = useMemo(() => [...selected].sort(), [selected]);

  const request = (ack: ReadonlySet<string>): DeploymentRequest => ({
    version_id: version?.id ?? "",
    installation_ids: selectedIds,
    strategy: {
      mode,
      concurrency,
      failure_threshold: threshold,
      continue_on_failure: continueOnFailure,
      allow_restart: allowRestart,
      allow_file_only_verification: fileOnly,
    },
    acknowledged_warnings: [...ack].sort(),
  });
  const sigOf = (ack: ReadonlySet<string>) => JSON.stringify(request(ack));

  const toggleSet = (set: ReadonlySet<string>, v: string): ReadonlySet<string> => {
    const n = new Set(set);
    if (n.has(v)) n.delete(v);
    else n.add(v);
    return n;
  };

  // ---------------------------------------------------------------- step 1: upload
  const pemReady = !!certFile && (!!keyFile || reuseKey);
  const pfxReady = !!pfxFile;
  const canSubmitUpload = pfxMode ? pfxReady : pemReady;

  const submitUpload = async () => {
    setUploading(true);
    setUploadError(null);
    const f = new FormData();
    f.set("certificate_id", id);
    const names: string[] = [];
    if (pfxMode && pfxFile) {
      f.set("pkcs12", pfxFile);
      if (pfxPassword) f.set("password", pfxPassword);
      names.push(pfxFile.name);
    } else {
      if (certFile) {
        f.set("certificate", certFile);
        names.push(certFile.name);
      }
      if (keyFile) {
        f.set("private_key", keyFile);
        names.push(`${keyFile.name} (private key)`);
      } else names.push("existing private key reused");
      if (chainFile) {
        f.set("chain", chainFile);
        names.push(chainFile.name);
      }
    }
    try {
      const v = await api.certificateVersions.upload(f);
      // Drop every reference to the key material and password immediately after the request.
      setKeyFile(null);
      setCertFile(null);
      setChainFile(null);
      setPfxFile(null);
      setPfxPassword("");
      setFormKey((k) => k + 1);
      setUploadedNames(names);
      setVersion(v);
      setAcked(new Set());
      setSelFindings(null);
      setPlan(null);
      setDryRunDone(false);
      setStep(1);
    } catch (e) {
      setUploadError(e);
      setPfxPassword("");
    } finally {
      setUploading(false);
    }
  };

  // ---------------------------------------------------------------- step 3 -> 4: validate for the chosen targets
  const findings = selFindings ?? version?.findings ?? [];
  const blocking = findings.filter((f) => f.severity === "blocking");
  const warnings = findings.filter((f) => f.severity === "warning");
  const warnCodes = [...new Set(warnings.map((w) => w.code))];
  const unackedWarn = warnCodes.filter((c) => !acked.has(c));

  const validateSelection = async () => {
    if (!version) return;
    setValidating(true);
    setValidateError(null);
    try {
      const v = await api.certificateVersions.validate(version.id, selectedIds);
      setVersion(v);
      setSelFindings(v.findings);
      const b = v.findings.filter((f) => f.severity === "blocking").length;
      const w = [...new Set(v.findings.filter((f) => f.severity === "warning").map((f) => f.code))];
      if (b === 0 && w.every((c) => acked.has(c))) {
        setStep(3);
        void runPlan(acked, v.id);
      }
    } catch (e) {
      setValidateError(e);
    } finally {
      setValidating(false);
    }
  };

  // ---------------------------------------------------------------- step 4: plan
  const runPlan = async (ack: ReadonlySet<string>, versionId?: string) => {
    const body = { ...request(ack), version_id: versionId ?? version?.id ?? "" };
    try {
      const p = await planM.mutateAsync(body);
      setPlan(p);
      setPlanSig(JSON.stringify(body));
    } catch (e) {
      setPlan(null);
      toast.error("Could not build the deployment plan", { description: errorMessage(e) });
    }
  };
  const planFresh = !!plan && planSig === sigOf(acked);
  const planFindings = plan?.findings ?? [];
  const planBlocking = planFindings.filter((f) => f.severity === "blocking");
  const planWarnCodes = [
    ...new Set(planFindings.filter((f) => f.severity === "warning").map((f) => f.code)),
  ];
  const planUnacked = planWarnCodes.filter((c) => !acked.has(c));
  const canDeployNow =
    canDeploy &&
    planFresh &&
    !!plan?.summary.can_proceed &&
    planBlocking.length === 0 &&
    planUnacked.length === 0;

  const toggleAckInPlan = (code: string) => {
    const next = toggleSet(acked, code);
    setAcked(next);
    void runPlan(next);
  };

  const deploy = () => {
    if (!plan || !version) return;
    const sig = sigOf(acked);
    // One Idempotency-Key per submission of the same request: a retry after a network error replays, never duplicates.
    if (!idem.current || idem.current.sig !== sig) idem.current = { key: newKey(), sig };
    create.mutate(
      { body: request(acked), key: idem.current.key },
      {
        onSuccess: (job) => {
          setConfirm(false);
          toast.success(
            job.status === "awaiting_approval"
              ? "Deployment created, awaiting approval"
              : "Deployment started",
          );
          void navigate({
            to: "/certificates/$id/renew",
            params: { id },
            search: { deployment: job.id },
            replace: true,
          });
        },
      },
    );
  };

  const hasProduction =
    plan?.targets.some((t) => t.environment === "Production") ??
    installs.some((i) => selected.has(i.id) && i.environment === "Production");

  // ---------------------------------------------------------------- render
  if (certQ.isLoading)
    return (
      <AppShell>
        <LoadingBlock label="Loading certificate…" />
      </AppShell>
    );
  if (certQ.isError || !cert)
    return (
      <AppShell>
        {isApiError(certQ.error) && certQ.error.status === 404 ? (
          <EmptyState title="Certificate not found" />
        ) : (
          <ErrorState error={certQ.error} onRetry={() => void certQ.refetch()} />
        )}
      </AppShell>
    );

  const back = (
    <Link
      to="/certificates/$id"
      params={{ id: cert.id }}
      className="mb-2 inline-flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground"
    >
      <ArrowLeft className="size-3.5" /> {cert.common_name}
    </Link>
  );

  if (!canUpload)
    return (
      <AppShell>
        {back}
        <EmptyState
          title="You cannot upload certificates"
          hint="Replacing a certificate requires the operator or administrator role."
        />
      </AppShell>
    );

  const uploadErrFindings: Finding[] =
    isApiError(uploadError) &&
    Array.isArray((uploadError.details as { findings?: Finding[] } | null)?.findings)
      ? ((uploadError.details as { findings: Finding[] }).findings ?? [])
      : [];

  const leaf = version?.leaf;

  return (
    <AppShell>
      {back}

      <PageHeader
        title="Replace / Renew Certificate"
        subtitle={
          <>
            Replacing <span className="mono text-foreground">{cert.common_name}</span> · filenames
            and filesystem paths are preserved so no service configuration change is required
          </>
        }
      />

      <ol className="mb-3 flex flex-wrap items-center gap-1 rounded-md border border-border bg-surface p-1.5">
        {steps.map((s, i) => (
          <li
            key={s}
            className="flex items-center gap-1"
            aria-current={i === step ? "step" : undefined}
          >
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
                  i < step
                    ? "bg-ok text-background"
                    : i === step
                      ? "bg-primary text-primary-foreground"
                      : "bg-muted",
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

      {/* ------------------------------------------------------------------ 1 upload */}
      {step === 0 && (
        <Panel
          title="Step 1 — Upload New Certificate"
          actions={
            <label className="flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
              <input
                type="checkbox"
                checked={pfxMode}
                onChange={(e) => setPfxMode(e.target.checked)}
                className="accent-[var(--color-primary)]"
                data-testid="pfx-toggle"
              />
              Use a PKCS#12 (.pfx / .p12) bundle instead
            </label>
          }
        >
          <div key={formKey}>
            {pfxMode ? (
              <div className="grid gap-3 p-3 md:grid-cols-2">
                <Dropzone
                  icon={Layers}
                  label="PKCS#12 bundle"
                  formats="PFX · P12"
                  file={pfxFile}
                  onFile={setPfxFile}
                  testId="file-pfx"
                  accept=".pfx,.p12,application/x-pkcs12"
                />
                <div>
                  <label className={labelCls} htmlFor="pfx-pass">
                    Bundle password
                  </label>
                  <input
                    id="pfx-pass"
                    type="password"
                    autoComplete="off"
                    className={inputCls}
                    value={pfxPassword}
                    onChange={(e) => setPfxPassword(e.target.value)}
                  />
                  <p className="mt-1 text-[11.5px] text-muted-foreground">
                    Sent once with the upload and never stored in the browser.
                  </p>
                </div>
              </div>
            ) : (
              <>
                <div className="grid gap-3 p-3 md:grid-cols-3">
                  <Dropzone
                    icon={FileText}
                    label="Certificate"
                    formats="PEM · CER · CRT · DER"
                    file={certFile}
                    onFile={setCertFile}
                    testId="file-cert"
                  />
                  <Dropzone
                    icon={FileKey2}
                    label="Private Key"
                    formats="PEM · KEY"
                    file={keyFile}
                    onFile={setKeyFile}
                    disabled={reuseKey}
                    testId="file-key"
                  />
                  <Dropzone
                    icon={Layers}
                    label="Intermediate Certificate / Chain (optional)"
                    formats="PEM · CER · CRT"
                    file={chainFile}
                    onFile={setChainFile}
                    testId="file-chain"
                  />
                </div>
                <div className="px-3 pb-3">
                  <label className="flex items-start gap-2 text-[12.5px]">
                    <input
                      type="checkbox"
                      checked={reuseKey}
                      onChange={(e) => {
                        setReuseKey(e.target.checked);
                        if (e.target.checked) setKeyFile(null);
                      }}
                      className="mt-0.5 accent-[var(--color-primary)]"
                      data-testid="reuse-key"
                    />
                    <span>
                      Reuse the private key already installed on the servers
                      <span className="block text-[11.5px] text-muted-foreground">
                        Only valid if the new certificate was issued for the same key pair (same
                        CSR). The public key is compared during validation and again on every server
                        before deploying.
                      </span>
                    </span>
                  </label>
                </div>
              </>
            )}
          </div>

          {uploadError != null && (
            <div className="mx-3 mb-3 space-y-2" role="alert">
              <div className="rounded-md border border-danger/40 bg-danger-soft p-2 text-[12px] text-danger">
                {errorMessage(uploadError)}
              </div>
              {uploadErrFindings.length > 0 && (
                <FindingsList findings={uploadErrFindings} acked={new Set()} onToggle={() => {}} />
              )}
            </div>
          )}

          <div className="flex items-center justify-between gap-2 border-t border-border px-3 py-2">
            <div className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
              <Lock className="size-3.5" /> The private key is encrypted on upload and never
              displayed or downloadable.
            </div>
            <button
              className={btnPrimaryCls}
              disabled={!canSubmitUpload || uploading}
              onClick={() => void submitUpload()}
            >
              {uploading ? <Spinner /> : <Upload className="size-3.5" />} Upload &amp; validate
            </button>
          </div>
        </Panel>
      )}

      {/* ------------------------------------------------------------------ 2 validation */}
      {step === 1 && version && leaf && (
        <div className="grid gap-3 lg:grid-cols-2">
          <Panel title="Parsed Certificate">
            <div className="px-3 py-1.5" data-testid="leaf-details">
              <Row k="Common Name" v={leaf.common_name ?? "—"} />
              <Row k="SANs" v={leaf.sans.join(", ") || "—"} />
              <Row k="Issuer" v={leaf.issuer} />
              <Row k="Valid from" v={fmtDateTime(leaf.not_before)} />
              <Row
                k="Expiration"
                v={`${fmtDateTime(leaf.not_after)} (${leaf.days_remaining} days)`}
              />
              <Row
                k="Key"
                v={`${leaf.public_key_algorithm} ${leaf.public_key_size ?? ""}`.trim()}
              />
              <Row k="Signature" v={leaf.signature_algorithm} />
              <Row k="Serial" v={leaf.serial_number} />
              <Row k="Fingerprint" v={leaf.fingerprint_sha256} />
              <Row
                k="Private key"
                v={
                  version.has_private_key
                    ? "uploaded and matches certificate"
                    : "not uploaded: existing key will be reused"
                }
              />
              <Row
                k="Chain"
                v={
                  version.chain.length
                    ? version.chain.map((c) => c.common_name ?? c.subject).join(" → ")
                    : "none supplied"
                }
              />
              <Row k="Files" v={uploadedNames.join(", ")} />
            </div>
          </Panel>

          <Panel
            title="Validation Checks"
            actions={
              <Pill tone={blocking.length ? "danger" : warnings.length ? "warn" : "ok"} dot>
                {blocking.length
                  ? `${blocking.length} blocking`
                  : warnings.length
                    ? `${warnings.length} warning${warnings.length === 1 ? "" : "s"}`
                    : "Passed"}
              </Pill>
            }
          >
            {findings.length === 0 ? (
              <div className="flex items-center gap-2 p-3 text-[12.5px]">
                <CheckCircle2 className="size-4 text-ok" /> All checks passed: certificate valid,
                not expired, chain complete and the private key matches.
              </div>
            ) : (
              <FindingsList
                findings={findings}
                acked={acked}
                onToggle={(c) => setAcked((a) => toggleSet(a, c))}
                where={serverOf}
              />
            )}
            {blocking.length > 0 && (
              <div className="m-3 flex items-start gap-2 rounded-md border border-danger/40 bg-danger-soft p-2.5">
                <ShieldAlert className="mt-0.5 size-4 shrink-0 text-danger" />
                <div className="text-[12.5px] font-semibold text-danger">
                  Blocking problems found. Deployment cannot continue; upload a corrected
                  certificate.
                </div>
              </div>
            )}
          </Panel>
        </div>
      )}

      {/* ------------------------------------------------------------------ 3 targets */}
      {step === 2 && (
        <div className="space-y-3">
          <Panel
            title="Step 3 — Select Target Servers"
            actions={
              <span className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
                Servers currently running the previous certificate
                <button
                  className={btnCls}
                  onClick={() => {
                    setSelected(new Set(eligible.map((i) => i.id)));
                    setSelFindings(null);
                  }}
                  disabled={eligible.length === 0}
                >
                  Select all eligible
                </button>
                <button
                  className={btnCls}
                  onClick={() => {
                    setSelected(new Set());
                    setSelFindings(null);
                  }}
                >
                  Clear
                </button>
              </span>
            }
          >
            {installs.length === 0 ? (
              <EmptyState
                title="No installations"
                hint="This certificate was not found on any server. Run a certificate scan on the servers first."
              />
            ) : (
              <DTable>
                <THead>
                  <TH className="w-8" />
                  <TH>Server</TH>
                  <TH>Environment</TH>
                  <TH>Service</TH>
                  <TH>Certificate Path</TH>
                  <TH>Key Path</TH>
                  <TH>Drift</TH>
                  <TH>Eligibility</TH>
                </THead>
                <tbody>
                  {installs.map((i) => {
                    const why = notDeployableReason(i);
                    const on = selected.has(i.id);
                    return (
                      <TRow
                        key={i.id}
                        className={cn(on && "bg-primary/5", why && "opacity-70")}
                        onClick={
                          why
                            ? undefined
                            : () => {
                                setSelected((s) => toggleSet(s, i.id));
                                setSelFindings(null);
                              }
                        }
                      >
                        <TD>
                          <input
                            type="checkbox"
                            checked={on}
                            disabled={!!why}
                            aria-label={`Select ${i.server_name} ${i.cert_path}`}
                            data-testid={`select-${i.service_type}`}
                            onClick={(e) => e.stopPropagation()}
                            onChange={() => {
                              setSelected((s) => toggleSet(s, i.id));
                              setSelFindings(null);
                            }}
                            className="accent-[var(--color-primary)]"
                          />
                        </TD>
                        <TD className="mono font-medium">{i.server_name}</TD>
                        <TD>{i.environment ? <EnvBadge env={i.environment} /> : "—"}</TD>
                        <TD className="mono">
                          {i.service_type}
                          {i.vhost && (
                            <div className="text-[11px] text-muted-foreground">{i.vhost}</div>
                          )}
                        </TD>
                        <TD className="mono">{i.cert_path ?? "—"}</TD>
                        <TD className="mono">
                          {i.is_combined_pem ? "(combined PEM)" : (i.key_path ?? "—")}
                        </TD>
                        <TD>
                          <DriftBadge value={i.drift_status} />
                        </TD>
                        <TD className="max-w-72 whitespace-normal text-[11.5px]">
                          {why ? (
                            <span className="text-warn">{why}</span>
                          ) : (
                            <Pill tone="ok" dot>
                              Eligible
                            </Pill>
                          )}
                        </TD>
                      </TRow>
                    );
                  })}
                </tbody>
              </DTable>
            )}
            <div className="border-t border-border px-3 py-2 text-[11.5px] text-muted-foreground">
              {selected.size} of {eligible.length} eligible installation
              {eligible.length === 1 ? "" : "s"} selected · paths are per-server and will not be
              modified
            </div>
          </Panel>

          {selFindings && (blocking.length > 0 || warnings.length > 0) && (
            <Panel title="Validation for the selected servers">
              <FindingsList
                findings={findings}
                acked={acked}
                onToggle={(c) => setAcked((a) => toggleSet(a, c))}
                where={serverOf}
              />
            </Panel>
          )}
          {validateError != null && (
            <div
              className="rounded-md border border-danger/40 bg-danger-soft p-2 text-[12px] text-danger"
              role="alert"
            >
              {errorMessage(validateError)}
            </div>
          )}
        </div>
      )}

      {/* ------------------------------------------------------------------ 4 plan */}
      {step === 3 && (
        <div className="space-y-3">
          <Panel title="Strategy">
            <div className="grid gap-3 p-3 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <label className={labelCls} htmlFor="st-mode">
                  Rollout mode
                </label>
                <select
                  id="st-mode"
                  className={inputCls}
                  value={mode}
                  onChange={(e) => setMode(e.target.value as typeof mode)}
                >
                  <option value="canary">Canary: first server, then the rest</option>
                  <option value="batch">Batch: groups of the concurrency size</option>
                  <option value="all">All at once (up to concurrency)</option>
                </select>
              </div>
              <div>
                <label className={labelCls} htmlFor="st-conc">
                  Concurrency
                </label>
                <input
                  id="st-conc"
                  type="number"
                  min={1}
                  max={50}
                  className={inputCls}
                  value={concurrency}
                  onChange={(e) =>
                    setConcurrency(Math.max(1, Math.min(50, Number(e.target.value) || 1)))
                  }
                />
              </div>
              <div>
                <label className={labelCls} htmlFor="st-thr">
                  Stop after N failures (0 = never)
                </label>
                <input
                  id="st-thr"
                  type="number"
                  min={0}
                  max={100}
                  className={inputCls}
                  value={threshold}
                  onChange={(e) =>
                    setThreshold(Math.max(0, Math.min(100, Number(e.target.value) || 0)))
                  }
                />
              </div>
              <div className="space-y-1.5 text-[12.5px]">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={continueOnFailure}
                    disabled={!canAdmin}
                    onChange={(e) => setContinueOnFailure(e.target.checked)}
                    className="accent-[var(--color-primary)]"
                  />
                  Continue after a failure
                  {!canAdmin && (
                    <span className="text-[11px] text-muted-foreground">(admin only)</span>
                  )}
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={allowRestart}
                    onChange={(e) => setAllowRestart(e.target.checked)}
                    className="accent-[var(--color-primary)]"
                    data-testid="allow-restart"
                  />
                  Allow service restart
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={fileOnly}
                    onChange={(e) => setFileOnly(e.target.checked)}
                    className="accent-[var(--color-primary)]"
                  />
                  Allow file-only verification
                </label>
              </div>
            </div>
            <div className="flex items-center justify-between border-t border-border px-3 py-2">
              <span className="text-[11.5px] text-muted-foreground">
                Restart is off by default: a graceful reload keeps existing connections alive.
              </span>
              <button
                className={btnCls}
                onClick={() => void runPlan(acked)}
                disabled={planM.isPending || !canPlan}
              >
                {planM.isPending && <Spinner />}{" "}
                {plan ? "Update dry-run plan" : "Build dry-run plan"}
              </button>
            </div>
          </Panel>

          {planM.isPending && !plan && (
            <LoadingBlock label="Inspecting target servers (read-only)…" />
          )}
          {plan && !planFresh && !planM.isPending && (
            <div className="rounded-md border border-warn/40 bg-warn-soft p-2 text-[12px]">
              Strategy or acknowledgements changed since this plan was built. Update the plan before
              deploying.
            </div>
          )}
          {plan && <PlanView plan={plan} />}
          {plan && planFindings.length > 0 && (
            <Panel title="Plan findings">
              <FindingsList
                findings={planFindings}
                acked={acked}
                onToggle={toggleAckInPlan}
                where={(iid) => plan.targets.find((t) => t.installation_id === iid)?.server_name}
                disabled={planM.isPending}
              />
            </Panel>
          )}

          <Panel>
            <div className="space-y-2.5 p-3">
              <div className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft p-2.5 text-[12px]">
                <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warn" />
                <span>
                  Every step is recorded in the audit log. If the config test, reload or TLS
                  verification fails, the previous files are restored from the verified backup
                  automatically.
                </span>
              </div>
              {!canDeploy && (
                <p className="text-[12px] text-muted-foreground">
                  Your role cannot create deployments; the dry run above is for review only.
                </p>
              )}
              <div className="flex flex-wrap items-center gap-2">
                <button
                  disabled={!canDeployNow}
                  onClick={() => setConfirm(true)}
                  className={btnPrimaryCls + " h-8 px-3"}
                  data-testid="deploy-button"
                >
                  Deploy Certificate
                </button>
                <button
                  className={btnCls + " h-8"}
                  onClick={() => setDryRunDone(true)}
                  data-testid="dry-run-only"
                >
                  Finish with dry run only
                </button>
                {dryRunDone && (
                  <span className="text-[12px] text-muted-foreground">
                    Dry run complete: nothing was deployed.{" "}
                    <Link
                      to="/certificates/$id"
                      params={{ id: cert.id }}
                      className="text-primary hover:underline"
                    >
                      Back to certificate
                    </Link>
                  </span>
                )}
              </div>
            </div>
          </Panel>
        </div>
      )}

      {/* ------------------------------------------------------------------ 5 deployment */}
      {step === 4 && deploymentId && (
        <div className="space-y-3">
          <DeploymentLive id={deploymentId} />
          <div className="flex gap-2">
            <Link
              to="/deployments/$id"
              params={{ id: deploymentId }}
              className="inline-flex h-8 items-center gap-1.5 rounded-md bg-primary px-3 text-[12.5px] font-medium text-primary-foreground hover:opacity-90"
            >
              View deployment detail
            </Link>
            <Link
              to="/certificates/$id"
              params={{ id: cert.id }}
              onClick={() => void qc.invalidateQueries({ queryKey: ["certificates"] })}
              className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-surface px-3 text-[12.5px] hover:border-primary hover:text-primary"
            >
              Back to certificate
            </Link>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------ nav */}
      {step < 3 && (
        <div className="mt-3 flex items-center justify-between">
          <button
            onClick={() => setStep((s) => Math.max(0, s - 1))}
            disabled={step === 0}
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-surface px-3 text-[12.5px] disabled:opacity-40"
          >
            <ArrowLeft className="size-3.5" /> Back
          </button>
          {step === 1 && (
            <button
              onClick={() => setStep(2)}
              disabled={!version || blocking.length > 0 || unackedWarn.length > 0}
              className="inline-flex h-8 items-center gap-1.5 rounded-md bg-primary px-3 text-[12.5px] font-medium text-primary-foreground disabled:cursor-not-allowed disabled:opacity-40 hover:opacity-90"
              data-testid="continue-validation"
            >
              Continue <ArrowRight className="size-3.5" />
            </button>
          )}
          {step === 2 && (
            <button
              onClick={() => {
                const ok = selFindings && blocking.length === 0 && unackedWarn.length === 0;
                if (ok) {
                  setStep(3);
                  void runPlan(acked);
                } else void validateSelection();
              }}
              disabled={selected.size === 0 || validating || !canPlan}
              className="inline-flex h-8 items-center gap-1.5 rounded-md bg-primary px-3 text-[12.5px] font-medium text-primary-foreground disabled:cursor-not-allowed disabled:opacity-40 hover:opacity-90"
              data-testid="continue-targets"
            >
              {validating && <Spinner />} Continue <ArrowRight className="size-3.5" />
            </button>
          )}
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

      <Dialog
        open={confirm}
        onOpenChange={(o) => {
          setConfirm(o);
          if (!o) create.reset();
        }}
      >
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className={cn("flex items-center gap-2", hasProduction && "text-danger")}>
              <ShieldAlert className="size-4" /> Confirm deployment
            </DialogTitle>
            <DialogDescription>
              You are about to replace certificate files on {plan?.targets.length ?? 0} server
              installation{plan?.targets.length === 1 ? "" : "s"}
              {hasProduction ? ", including PRODUCTION," : ""} and{" "}
              {allowRestart ? "restart" : "reload"} the service. Environments that require approval
              will wait for an administrator before anything is changed.
            </DialogDescription>
          </DialogHeader>
          <div className="mono max-h-48 overflow-auto rounded-md border border-border bg-surface-2/50 p-2 text-[11.5px]">
            {plan?.targets.map((t) => (
              <div key={t.installation_id}>
                {t.server_name} ({t.environment}) —{" "}
                {t.files
                  .filter((f) => f.action === "replace")
                  .map((f) => f.dest_path)
                  .join(", ")}
              </div>
            ))}
          </div>
          <div className="text-[11.5px] text-muted-foreground">
            New fingerprint <span className="mono">{shortFp(version?.fingerprint_sha256)}</span> ·
            expires {fmtDate(version?.leaf.not_after)}
          </div>
          {create.error != null && (
            <div
              className="space-y-1 rounded-md border border-danger/30 bg-danger-soft p-2 text-[12px] text-danger"
              role="alert"
            >
              <div>{errorMessage(create.error)}</div>
              {isApiError(create.error) &&
                Array.isArray(
                  (create.error.details as { findings?: Finding[] } | null)?.findings,
                ) && (
                  <ul className="list-disc pl-4">
                    {((create.error.details as { findings: Finding[] }).findings ?? []).map(
                      (f, i) => (
                        <li key={i}>
                          <span className="mono">{f.code}</span>: {f.message}
                        </li>
                      ),
                    )}
                  </ul>
                )}
            </div>
          )}
          <DialogFooter>
            <button
              className={btnCls + " h-8"}
              onClick={() => setConfirm(false)}
              disabled={create.isPending}
            >
              <X className="size-3.5" /> Cancel
            </button>
            <button
              onClick={deploy}
              disabled={create.isPending}
              data-testid="confirm-deploy"
              className={cn(
                "inline-flex h-8 items-center gap-1.5 rounded-md px-3 text-[12.5px] font-medium hover:opacity-90 disabled:opacity-50",
                hasProduction
                  ? "bg-destructive text-destructive-foreground"
                  : "bg-primary text-primary-foreground",
              )}
            >
              {create.isPending ? <Spinner /> : <Upload className="size-3.5" />} Deploy
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </AppShell>
  );
}
