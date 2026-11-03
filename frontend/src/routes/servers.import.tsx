import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  Download,
  Fingerprint,
  Radar,
  ShieldCheck,
  Upload,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { Pill, type Tone } from "@/components/ui/status";
import { ConfirmDialog } from "@/components/ui/confirm";
import {
  btnCls,
  btnPrimaryCls,
  EmptyState,
  errorMessage,
  inputCls,
  labelCls,
  Spinner,
} from "@/components/ui/feedback";
import { api, useEnrollHostKeys, useImportServers, useScanHostKeys } from "@/lib/api/queries";
import { isApiError } from "@/lib/api/client";
import type {
  HostKeyEnrollResult,
  HostKeyScanItem,
  ImportHostKeyStatus,
  ImportOnConflict,
  ImportResult,
  ImportRow,
} from "@/lib/api/types";
import { useCan, useSession } from "@/lib/auth";

export const Route = createFileRoute("/servers/import")({
  head: () => ({
    meta: [
      { title: "Import Servers — Certificate Manager" },
      {
        name: "description",
        content:
          "Bulk-register servers from a CSV file, then verify and enroll their SSH host keys.",
      },
    ],
  }),
  component: ImportServers,
});

const MAX_BYTES = 1024 * 1024;

const COLUMNS: { name: string; required?: boolean; desc: string }[] = [
  { name: "name", required: true, desc: "Unique server name." },
  { name: "hostname", required: true, desc: "DNS name or IP used for SSH." },
  { name: "address", desc: "Optional IP address (if different from the hostname)." },
  { name: "ssh_port", desc: "SSH port, default 22." },
  { name: "ssh_username", required: true, desc: "Login user, for example cdpdeploy." },
  { name: "environment", required: true, desc: "Existing environment name." },
  { name: "credential", desc: "Name of an existing SSH credential." },
  { name: "privilege_mode", desc: "helper-sudo (default) or none." },
  { name: "bastion", desc: "Name of an existing server to jump through." },
  { name: "tags", desc: "Several tags separated by “;” or “|”." },
  { name: "description", desc: "Free text." },
  {
    name: "host_key_fingerprint",
    desc: "Optional SHA256 fingerprint verified out-of-band; checked against the live host key.",
  },
];

const rowTone: Record<string, Tone> = {
  valid: "ok",
  created: "ok",
  error: "danger",
  skipped: "neutral",
};
const hkTone: Record<ImportHostKeyStatus, { tone: Tone; label: string }> = {
  not_provided: { tone: "neutral", label: "No fingerprint given" },
  enrolled: { tone: "ok", label: "Enrolled" },
  mismatch: { tone: "danger", label: "Fingerprint mismatch" },
  unreachable: { tone: "warn", label: "Unreachable" },
  pending: { tone: "warn", label: "Needs verification" },
};
const NEEDS_VERIFY = new Set<ImportHostKeyStatus>(["pending", "mismatch", "unreachable"]);

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <Panel
      title={
        <span className="flex items-center gap-2">
          <span className="grid size-5 place-content-center rounded-full bg-primary text-[11px] font-semibold text-primary-foreground">
            {n}
          </span>
          {title}
        </span>
      }
    >
      {children}
    </Panel>
  );
}

function ImportServers() {
  const { me } = useSession();
  const canWrite = useCan("servers:write");
  const canHostKey = useCan("servers:hostkey");
  const canDiscover = useCan("discovery:run");
  const importMut = useImportServers();

  const fileInput = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [onConflict, setOnConflict] = useState<ImportOnConflict>("error");
  const [preview, setPreview] = useState<ImportResult | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [downloading, setDownloading] = useState(false);

  if (me && !canWrite)
    return (
      <AppShell>
        <EmptyState
          title="Not allowed"
          hint="Importing servers requires the servers:write permission."
        />
      </AppShell>
    );

  const download = async () => {
    setDownloading(true);
    try {
      saveBlob(await api.servers.importTemplate(), "servers-template.csv");
    } catch (e) {
      toast.error("Could not download the template", { description: errorMessage(e) });
    } finally {
      setDownloading(false);
    }
  };

  const onPick = (f: File | null) => {
    setPreview(null);
    setResult(null);
    importMut.reset();
    if (!f) {
      setFile(null);
      setFileError(null);
      return;
    }
    if (f.size > MAX_BYTES) {
      setFile(null);
      setFileError(`File is ${(f.size / 1024 / 1024).toFixed(1)} MiB; the limit is 1 MiB.`);
      return;
    }
    if (f.size === 0) {
      setFile(null);
      setFileError("The file is empty.");
      return;
    }
    setFileError(null);
    setFile(f);
  };

  const check = () => {
    if (!file) return;
    importMut.mutate({ file, dryRun: true, onConflict }, { onSuccess: setPreview });
  };

  const commit = () => {
    if (!file) return;
    importMut.mutate(
      { file, dryRun: false, onConflict },
      {
        onSuccess: (r) => {
          setConfirmOpen(false);
          setResult(r);
          toast.success(`Imported ${r.created} server${r.created === 1 ? "" : "s"}`);
        },
        onError: (e) => {
          if (isApiError(e) && e.code === "IMPORT_HAS_ERRORS" && e.details) {
            setConfirmOpen(false);
            setPreview(e.details as ImportResult);
            toast.error("The file has errors; nothing was imported");
          }
        },
      },
    );
  };

  const shown = result ?? preview;

  return (
    <AppShell>
      <Link
        to="/servers"
        className="mb-2 inline-flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3.5" /> Servers
      </Link>
      <PageHeader
        title="Import servers from CSV"
        subtitle="Register many servers at once. Host keys are never trusted automatically."
      />

      <div className="space-y-3">
        <Step n={1} title="Prepare the file">
          <div className="space-y-3 p-3 text-[12.5px]">
            <p className="text-muted-foreground">
              Start from the template. The delimiter (<span className="mono">,</span> or{" "}
              <span className="mono">;</span>) is detected automatically. Tags are separated by{" "}
              <span className="mono">;</span> or <span className="mono">|</span> (use{" "}
              <span className="mono">|</span> when the file itself uses{" "}
              <span className="mono">;</span> as delimiter). Maximum file size is 1 MiB.
            </p>
            <button className={btnCls} onClick={() => void download()} disabled={downloading}>
              {downloading ? <Spinner /> : <Download className="size-3.5" />} Download template
            </button>
            <div className="overflow-x-auto rounded-md border border-border">
              <DTable>
                <THead>
                  <TH>Column</TH>
                  <TH>Required</TH>
                  <TH>Description</TH>
                </THead>
                <tbody>
                  {COLUMNS.map((c) => (
                    <TRow key={c.name}>
                      <TD className="mono font-medium">{c.name}</TD>
                      <TD>{c.required ? <Pill tone="info">required</Pill> : "optional"}</TD>
                      <TD className="text-muted-foreground">{c.desc}</TD>
                    </TRow>
                  ))}
                </tbody>
              </DTable>
            </div>
          </div>
        </Step>

        <Step n={2} title="Upload and check">
          <div className="space-y-3 p-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className={labelCls} htmlFor="csv-file">
                  CSV file
                </label>
                <input
                  id="csv-file"
                  ref={fileInput}
                  type="file"
                  accept=".csv,text/csv"
                  className={inputCls + " py-1"}
                  onChange={(e) => onPick(e.target.files?.[0] ?? null)}
                />
                {fileError && (
                  <p className="mt-1 text-[12px] text-danger" role="alert">
                    {fileError}
                  </p>
                )}
              </div>
              <div>
                <label className={labelCls} htmlFor="csv-conflict">
                  If a server name already exists
                </label>
                <select
                  id="csv-conflict"
                  className={inputCls}
                  value={onConflict}
                  onChange={(e) => {
                    setOnConflict(e.target.value as ImportOnConflict);
                    setPreview(null);
                    setResult(null);
                  }}
                >
                  <option value="error">Report an error</option>
                  <option value="skip">Skip the row</option>
                </select>
              </div>
            </div>
            {importMut.error && !confirmOpen && (
              <p
                className="rounded-md border border-danger/30 bg-danger-soft p-2 text-[12px] text-danger"
                role="alert"
              >
                {errorMessage(importMut.error)}
              </p>
            )}
            <button
              className={btnPrimaryCls}
              onClick={check}
              disabled={!file || importMut.isPending}
            >
              {importMut.isPending && !confirmOpen ? <Spinner /> : <Upload className="size-3.5" />}
              Check file (dry run)
            </button>
          </div>
        </Step>

        {shown && (
          <Step n={3} title={result ? "Import result" : "Preview"}>
            <RowsTable data={shown} committed={!!result} />
            {!result && (
              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border p-3">
                <span className="text-[12px] text-muted-foreground">
                  {shown.invalid > 0
                    ? "Fix the errors in the file and check it again. Nothing is imported while there are errors."
                    : shown.valid === 0
                      ? "There is nothing to import."
                      : "Nothing has been created yet."}
                </span>
                <button
                  className={btnPrimaryCls}
                  disabled={shown.invalid > 0 || shown.valid === 0}
                  onClick={() => {
                    importMut.reset();
                    setConfirmOpen(true);
                  }}
                >
                  Import {shown.valid} server{shown.valid === 1 ? "" : "s"}
                </button>
              </div>
            )}
          </Step>
        )}

        {result && (
          <HostKeyStep result={result} canHostKey={canHostKey} canDiscover={canDiscover} />
        )}
      </div>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={`Import ${preview?.valid ?? 0} servers?`}
        description="The servers are created without trusted host keys unless a verified fingerprint matched. You verify and enroll keys in the next step."
        confirmLabel="Import"
        pending={importMut.isPending}
        error={importMut.error && !isImportErrors(importMut.error) ? importMut.error : null}
        onConfirm={commit}
      />
    </AppShell>
  );
}

const isImportErrors = (e: unknown) => isApiError(e) && e.code === "IMPORT_HAS_ERRORS";

function RowsTable({ data, committed }: { data: ImportResult; committed: boolean }) {
  const showHost = data.rows.some((r) => r.hostname);
  return (
    <div data-testid={committed ? "import-result" : "import-preview"}>
      <div className="flex flex-wrap gap-2 border-b border-border p-3 text-[12px]">
        <Pill tone="neutral">{data.total} rows</Pill>
        {committed ? (
          <Pill tone="ok">{data.created} created</Pill>
        ) : (
          <Pill tone="ok">{data.valid} valid</Pill>
        )}
        <Pill tone={data.invalid > 0 ? "danger" : "neutral"}>{data.invalid} with errors</Pill>
        <Pill tone="neutral">{data.skipped} skipped</Pill>
        <span className="text-muted-foreground">
          delimiter “<span className="mono">{data.delimiter}</span>”
        </span>
      </div>
      <div className="overflow-x-auto">
        <DTable>
          <THead>
            <TH>Row</TH>
            <TH>Name</TH>
            {showHost && <TH>Hostname</TH>}
            <TH>Status</TH>
            <TH>{committed ? "Host key" : "Errors"}</TH>
          </THead>
          <tbody>
            {data.rows.map((r) => (
              <TRow key={r.row}>
                <TD className="mono tabular-nums">{r.row}</TD>
                <TD className="mono">{r.name ?? "—"}</TD>
                {showHost && <TD className="mono">{r.hostname ?? "—"}</TD>}
                <TD>
                  <Pill tone={rowTone[r.status] ?? "neutral"} dot>
                    {r.status}
                  </Pill>
                </TD>
                <TD>
                  {r.errors.length > 0 && (
                    <ul className="space-y-0.5 text-[12px] text-danger">
                      {r.errors.map((e, i) => (
                        <li key={i}>
                          {e.field && <span className="mono font-medium">{e.field}: </span>}
                          {e.message}
                        </li>
                      ))}
                    </ul>
                  )}
                  {committed && r.host_key && <HostKeyCell hk={r.host_key} />}
                </TD>
              </TRow>
            ))}
          </tbody>
        </DTable>
      </div>
    </div>
  );
}

function HostKeyCell({ hk }: { hk: NonNullable<ImportRow["host_key"]> }) {
  const m = hkTone[hk.status];
  return (
    <div className="space-y-0.5">
      <Pill tone={m.tone} dot>
        {m.label}
      </Pill>
      {hk.error && <div className="text-[11.5px] text-muted-foreground">{hk.error}</div>}
      {hk.status === "mismatch" && (
        <div className="mono break-all text-[11px] text-muted-foreground">
          expected {hk.fingerprint_expected}
          <br />
          seen {hk.fingerprint_seen}
        </div>
      )}
    </div>
  );
}

function HostKeyStep({
  result,
  canHostKey,
  canDiscover,
}: {
  result: ImportResult;
  canHostKey: boolean;
  canDiscover: boolean;
}) {
  const scan = useScanHostKeys();
  const enroll = useEnrollHostKeys();
  const [scanned, setScanned] = useState<HostKeyScanItem[] | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [enrollRes, setEnrollRes] = useState<Record<string, HostKeyEnrollResult>>({});
  const [selectAllOpen, setSelectAllOpen] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [discoveryStarted, setDiscoveryStarted] = useState(false);

  const created = useMemo(
    () => result.rows.filter((r) => r.status === "created" && r.server_id),
    [result],
  );
  const pending = created.filter((r) => r.host_key && NEEDS_VERIFY.has(r.host_key.status));
  const rowById = useMemo(() => new Map(created.map((r) => [r.server_id as string, r])), [created]);
  const enrolledIds = useMemo(() => {
    const ids = new Set<string>();
    for (const r of created) if (r.host_key?.status === "enrolled") ids.add(r.server_id as string);
    for (const [id, e] of Object.entries(enrollRes)) if (e.status === "enrolled") ids.add(id);
    return ids;
  }, [created, enrollRes]);

  const eligible = (it: HostKeyScanItem) =>
    !it.error_code &&
    !it.error &&
    !!it.public_key &&
    !!it.fingerprint_sha256 &&
    rowById.get(it.server_id)?.host_key?.status !== "mismatch" &&
    enrollRes[it.server_id]?.status !== "enrolled";

  const doScan = () =>
    scan.mutate(
      pending.map((r) => r.server_id as string),
      {
        onSuccess: (r) => {
          setScanned(r.items);
          setSelected(new Set());
          setEnrollRes({});
        },
      },
    );

  const toggle = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  const doEnroll = () => {
    if (!scanned) return;
    const items = scanned
      .filter((it) => selected.has(it.server_id) && eligible(it))
      .map((it) => ({
        server_id: it.server_id,
        public_key: it.public_key as string,
        fingerprint_sha256: it.fingerprint_sha256 as string,
      }));
    enroll.mutate(
      { items },
      {
        onSuccess: (r) => {
          setEnrollRes((prev) => ({
            ...prev,
            ...Object.fromEntries(r.items.map((i) => [i.server_id, i])),
          }));
          setSelected(new Set());
          const ok = r.items.filter((i) => i.status === "enrolled").length;
          if (ok) toast.success(`Enrolled ${ok} host key${ok === 1 ? "" : "s"}`);
          if (ok < r.items.length) toast.error(`${r.items.length - ok} host key(s) failed`);
        },
      },
    );
  };

  const runDiscovery = async () => {
    setDiscovering(true);
    try {
      await api.discoveryJobs.bulk([...enrolledIds]);
      setDiscoveryStarted(true);
      toast.success("Discovery started", {
        description: `${enrolledIds.size} server${enrolledIds.size === 1 ? "" : "s"}`,
      });
    } catch (e) {
      toast.error("Could not start discovery", { description: errorMessage(e) });
    } finally {
      setDiscovering(false);
    }
  };

  const eligibleCount = scanned?.filter(eligible).length ?? 0;

  return (
    <>
      {pending.length > 0 && (
        <Step n={4} title="Verify host keys">
          <div className="space-y-3 p-3 text-[12.5px]" data-testid="hostkey-step">
            <p className="text-muted-foreground">
              {pending.length} imported server{pending.length === 1 ? " has" : "s have"} no trusted
              host key. Scan them, compare each fingerprint with the one on the host (
              <span className="mono">ssh-keygen -lf /etc/ssh/ssh_host_*.pub</span>) through a
              trusted channel, and tick only the keys you verified.
            </p>
            {!canHostKey ? (
              <p className="text-[12px] text-warn">
                Enrolling host keys requires the servers:hostkey permission. Ask an administrator,
                or enroll them later from each server page.
              </p>
            ) : (
              <button className={btnCls} onClick={doScan} disabled={scan.isPending}>
                {scan.isPending ? <Spinner /> : <Fingerprint className="size-3.5" />}
                {scanned ? "Scan again" : "Scan host keys"}
              </button>
            )}
            {scan.error && (
              <p className="text-[12px] text-danger" role="alert">
                {errorMessage(scan.error)}
              </p>
            )}

            {scanned && (
              <>
                <div className="overflow-x-auto rounded-md border border-border">
                  <DTable>
                    <THead>
                      <TH>Enroll</TH>
                      <TH>Server</TH>
                      <TH>Endpoint</TH>
                      <TH>Key type</TH>
                      <TH>SHA256 fingerprint</TH>
                      <TH>Result</TH>
                    </THead>
                    <tbody>
                      {scanned.map((it) => {
                        const ok = eligible(it);
                        const er = enrollRes[it.server_id];
                        const imp = rowById.get(it.server_id);
                        return (
                          <TRow key={it.server_id}>
                            <TD>
                              <input
                                type="checkbox"
                                aria-label={`Enroll host key of ${it.server_name}`}
                                checked={selected.has(it.server_id)}
                                disabled={!ok}
                                onChange={() => toggle(it.server_id)}
                              />
                            </TD>
                            <TD className="mono">
                              <Link
                                to="/servers/$id"
                                params={{ id: it.server_id }}
                                className="hover:text-primary hover:underline"
                              >
                                {it.server_name}
                              </Link>
                            </TD>
                            <TD className="mono">{it.endpoint ?? "—"}</TD>
                            <TD className="mono">{it.key_type ?? "—"}</TD>
                            <TD>
                              {it.fingerprint_sha256 ? (
                                <span
                                  className="mono break-all text-[11.5px]"
                                  data-testid="scan-fingerprint"
                                >
                                  {it.fingerprint_sha256}
                                </span>
                              ) : (
                                "—"
                              )}
                            </TD>
                            <TD>
                              {er ? (
                                er.status === "enrolled" ? (
                                  <Pill tone="ok" dot>
                                    Enrolled
                                  </Pill>
                                ) : (
                                  <span className="text-[12px] text-danger">
                                    {er.error_code ? `${er.error_code}: ` : ""}
                                    {er.error ?? "Failed"}
                                  </span>
                                )
                              ) : it.error || it.error_code ? (
                                <span className="text-[12px] text-danger">
                                  {it.error_code ? `${it.error_code}: ` : ""}
                                  {it.error ?? "Scan failed"}
                                </span>
                              ) : imp?.host_key?.status === "mismatch" ? (
                                <span className="text-[12px] text-danger">
                                  Differs from the fingerprint in the CSV. Review it on the server
                                  page.
                                </span>
                              ) : it.matches_enrolled === false ? (
                                <span className="text-[12px] text-warn">
                                  Differs from the enrolled key
                                </span>
                              ) : (
                                <span className="text-[12px] text-muted-foreground">
                                  Awaiting your verification
                                </span>
                              )}
                            </TD>
                          </TRow>
                        );
                      })}
                    </tbody>
                  </DTable>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    className={btnCls}
                    disabled={eligibleCount === 0}
                    onClick={() => setSelectAllOpen(true)}
                  >
                    Select all…
                  </button>
                  <button
                    className={btnPrimaryCls}
                    disabled={selected.size === 0 || enroll.isPending}
                    onClick={doEnroll}
                  >
                    {enroll.isPending ? <Spinner /> : <ShieldCheck className="size-3.5" />}
                    Enroll selected ({selected.size})
                  </button>
                  {enroll.error && (
                    <span className="text-[12px] text-danger" role="alert">
                      {errorMessage(enroll.error)}
                    </span>
                  )}
                </div>
              </>
            )}
          </div>
        </Step>
      )}

      <Step n={pending.length > 0 ? 5 : 4} title="Next steps">
        <div className="flex flex-wrap items-center gap-2 p-3 text-[12.5px]">
          {canDiscover && (
            <button
              className={btnPrimaryCls}
              disabled={enrolledIds.size === 0 || discovering || discoveryStarted}
              onClick={() => void runDiscovery()}
              title={enrolledIds.size === 0 ? "Enroll at least one host key first" : undefined}
            >
              {discovering ? <Spinner /> : <Radar className="size-3.5" />}
              Run discovery on imported servers ({enrolledIds.size})
            </button>
          )}
          <Link to="/servers" className={btnCls}>
            Go to servers
          </Link>
          {created.length === 0 && (
            <span className="flex items-center gap-1.5 text-muted-foreground">
              <XCircle className="size-3.5" /> No servers were created.
            </span>
          )}
        </div>
      </Step>

      <ConfirmDialog
        open={selectAllOpen}
        onOpenChange={setSelectAllOpen}
        title="Select all host keys?"
        description="Enrolling a host key makes the app trust it from now on. Only select all if you have verified every fingerprint listed, out-of-band, on the hosts themselves. Unverified keys can let an attacker impersonate a server."
        confirmLabel="I verified them, select all"
        onConfirm={() => {
          setSelected(new Set((scanned ?? []).filter(eligible).map((i) => i.server_id)));
          setSelectAllOpen(false);
        }}
      />
    </>
  );
}
