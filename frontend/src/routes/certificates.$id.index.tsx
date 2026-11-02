import { createFileRoute, Link, notFound } from "@tanstack/react-router";
import {
  ArrowLeft,
  CheckCircle2,
  Download,
  FileKey2,
  FileText,
  Layers,
  Lock,
  RefreshCw,
  Rocket,
} from "lucide-react";
import { toast } from "sonner";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { CertStatusBadge, DaysLeft, EnvBadge, Pill } from "@/components/ui/status";
import { getCertificate } from "@/lib/mock-data";

export const Route = createFileRoute("/certificates/$id/")({
  loader: ({ params }) => {
    const cert = getCertificate(params.id);
    if (!cert) throw notFound();
    return { cert };
  },
  head: ({ loaderData }) => {
    if (!loaderData) {
      return {
        meta: [
          { title: "Certificate unavailable — Certificate Manager" },
          { name: "robots", content: "noindex" },
        ],
      };
    }
    const t = `${loaderData.cert.commonName} — Certificate Manager`;
    const d = `Certificate details, files and installations for ${loaderData.cert.commonName} issued by ${loaderData.cert.ca}.`;
    return {
      meta: [
        { title: t },
        { name: "description", content: d },
        { property: "og:title", content: t },
        { property: "og:description", content: d },
      ],
    };
  },
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

function FileRow({
  icon: Icon,
  label,
  file,
  secret,
}: {
  icon: typeof FileText;
  label: string;
  file: string;
  secret?: boolean;
}) {
  return (
    <div className="flex items-center gap-2.5 border-b border-border/60 px-3 py-2 last:border-0">
      <Icon className="size-4 shrink-0 text-muted-foreground" />
      <div className="min-w-0 flex-1">
        <div className="text-[11.5px] uppercase tracking-[0.05em] text-muted-foreground">{label}</div>
        <div className="mono truncate text-foreground">{file}</div>
      </div>
      {secret ? (
        <Pill tone="info">
          <Lock className="size-3" /> Stored securely
        </Pill>
      ) : (
        <button
          onClick={() => toast.success("Download started", { description: file })}
          className="inline-flex items-center gap-1.5 rounded-sm border border-border px-1.5 py-0.5 text-[11.5px] hover:border-primary hover:text-primary"
        >
          <Download className="size-3" /> Download
        </button>
      )}
    </div>
  );
}

function CertificateDetail() {
  const { cert } = Route.useLoaderData();

  const checks = [
    { label: "Certificate", value: "Valid" },
    { label: "Private Key Match", value: "Valid" },
    { label: "Chain", value: "Valid" },
    { label: "Expiration", value: cert.daysRemaining < 0 ? "Expired" : "Valid" },
  ];

  return (
    <AppShell>
      <Link
        to="/certificates"
        className="mb-2 inline-flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3.5" /> Certificates
      </Link>

      <PageHeader
        title={<span className="mono text-[17px]">{cert.commonName}</span>}
        badge={<CertStatusBadge status={cert.status} />}
        subtitle={`${cert.name} · ${cert.ca} · installed on ${cert.installations.length} servers`}
        actions={
          <>
            <button
              onClick={() => toast.info("Re-validating certificate chain…")}
              className="inline-flex h-7.5 items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 text-[12.5px] hover:border-primary hover:text-primary"
            >
              <CheckCircle2 className="size-3.5" /> Re-validate
            </button>
            <Link
              to="/certificates/$id/renew"
              params={{ id: cert.id }}
              className="inline-flex h-7.5 items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 text-[12.5px] hover:border-primary hover:text-primary"
            >
              <Rocket className="size-3.5" /> Deploy
            </Link>
            <Link
              to="/certificates/$id/renew"
              params={{ id: cert.id }}
              className="inline-flex h-7.5 items-center gap-1.5 rounded-md bg-primary px-2.5 text-[12.5px] font-medium text-primary-foreground hover:opacity-90"
            >
              <RefreshCw className="size-3.5" /> Replace / Renew
            </Link>
          </>
        }
      />

      <div className="grid gap-3 xl:grid-cols-3">
        <Panel title="Certificate Information" className="xl:col-span-2">
          <div className="px-3 py-1.5">
            <Field label="Common Name" value={cert.commonName} mono />
            <Field label="Subject Alternative Names" value={cert.sans.join(", ")} mono />
            <Field label="Issuer" value={cert.issuer} />
            <Field label="Serial Number" value={cert.serial} mono />
            <Field label="SHA-256 Fingerprint" value={cert.fingerprint} mono />
            <Field label="Signature Algorithm" value={cert.signatureAlgorithm} />
            <Field label="Public Key Algorithm" value={cert.publicKeyAlgorithm} />
            <Field label="Key Size" value={`${cert.publicKeyAlgorithm} ${cert.keySize}`} mono />
            <Field label="Valid From" value={cert.validFrom} mono />
            <Field label="Valid Until" value={cert.expiration} mono />
            <div className="flex items-baseline gap-3 py-1.5">
              <div className="w-52 shrink-0 text-[11.5px] uppercase tracking-[0.05em] text-muted-foreground">
                Days Remaining
              </div>
              <DaysLeft days={cert.daysRemaining} />
            </div>
          </div>
        </Panel>

        <div className="space-y-3">
          <Panel title="Files" bodyClassName="">
            <FileRow icon={FileText} label="Certificate" file={cert.files.cert} />
            <FileRow icon={FileKey2} label="Private Key" file={cert.files.key} secret />
            <FileRow icon={Layers} label="Intermediate Chain" file={cert.files.chain} />
            <FileRow icon={Layers} label="Full Chain" file={cert.files.fullchain} />
          </Panel>

          <Panel title="Validation">
            <div className="p-3">
              {checks.map((c) => (
                <div
                  key={c.label}
                  className="flex items-center justify-between border-b border-border/60 py-1.5 last:border-0"
                >
                  <span className="text-[12.5px] text-muted-foreground">{c.label}</span>
                  <Pill tone={c.value === "Valid" ? "ok" : "danger"} dot>
                    {c.value}
                  </Pill>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>

      <div className="mt-3">
        <Panel
          title="Installed On"
          actions={
            <span className="text-[11.5px] text-muted-foreground">
              Paths are configurable per deployment target
            </span>
          }
        >
          <DTable>
            <THead>
              <TH>Server</TH>
              <TH>Hostname</TH>
              <TH>Environment</TH>
              <TH>Certificate Path</TH>
              <TH>Key Path</TH>
              <TH>Web Server</TH>
              <TH>Current Status</TH>
            </THead>
            <tbody>
              {cert.installations.map((i) => (
                <TRow key={i.serverId}>
                  <TD>
                    <Link
                      to="/servers/$id"
                      params={{ id: i.serverId }}
                      className="mono font-medium text-foreground hover:text-primary hover:underline"
                    >
                      {i.serverName}
                    </Link>
                  </TD>
                  <TD className="mono">{i.ip}</TD>
                  <TD>
                    <EnvBadge env={i.environment} />
                  </TD>
                  <TD className="mono">{i.certPath}</TD>
                  <TD className="mono">{i.keyPath}</TD>
                  <TD className="text-muted-foreground">{i.webServer}</TD>
                  <TD>
                    <Pill
                      tone={
                        i.syncStatus === "Synced" ? "ok" : i.syncStatus === "Out of sync" ? "warn" : "neutral"
                      }
                      dot
                    >
                      {i.syncStatus}
                    </Pill>
                  </TD>
                </TRow>
              ))}
            </tbody>
          </DTable>
        </Panel>
      </div>
    </AppShell>
  );
}
