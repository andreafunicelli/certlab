import { createFileRoute, Link, notFound } from "@tanstack/react-router";
import { useState } from "react";
import { ArrowLeft, FileCode2, PlugZap, Radar, Download, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { CertStatusBadge, EnvBadge, Pill, SshBadge } from "@/components/ui/status";
import { certificates, discoveredCertificates, getServer } from "@/lib/mock-data";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export const Route = createFileRoute("/servers/$id")({
  loader: ({ params }) => {
    const server = getServer(params.id);
    if (!server) throw notFound();
    return { server };
  },
  head: ({ loaderData }) => {
    if (!loaderData) {
      return {
        meta: [
          { title: "Server unavailable — Certificate Manager" },
          { name: "robots", content: "noindex" },
        ],
      };
    }
    const t = `${loaderData.server.name} — Certificate Manager`;
    const d = `Nginx server ${loaderData.server.hostname} (${loaderData.server.ip}): SSH status, installed certificates and file paths.`;
    return {
      meta: [
        { title: t },
        { name: "description", content: d },
        { property: "og:title", content: t },
        { property: "og:description", content: d },
      ],
    };
  },
  component: ServerDetail,
});

const nginxConf = `server {
    listen 443 ssl http2;
    server_name alfaintes.youco.cloud;

    ssl_certificate     /etc/ssl/certs/star.youco.cloud.cer;
    ssl_certificate_key /etc/ssl/private/star.youco.cloud.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    location / {
        proxy_pass http://10.20.30.11:8080;
    }
}`;

function ServerDetail() {
  const { server } = Route.useLoaderData();
  const [scanning, setScanning] = useState(false);
  const [scanned, setScanned] = useState(false);
  const [showConf, setShowConf] = useState(false);

  const installed = certificates
    .flatMap((c) => c.installations.map((i) => ({ cert: c, inst: i })))
    .filter((x) => x.inst.serverId === server.id);

  const runScan = () => {
    setScanning(true);
    setTimeout(() => {
      setScanning(false);
      setScanned(true);
      toast.success("Scan completed", { description: "3 certificate references found in Nginx config" });
    }, 1300);
  };

  return (
    <AppShell>
      <Link
        to="/servers"
        className="mb-2 inline-flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3.5" /> Servers
      </Link>

      <PageHeader
        title={<span className="mono text-[17px]">{server.name}</span>}
        badge={<SshBadge status={server.sshStatus} />}
        subtitle={`${server.hostname} · ${server.os} · ${server.nginxVersion}`}
        actions={
          <>
            <button
              onClick={runScan}
              className="inline-flex h-7.5 items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 text-[12.5px] hover:border-primary hover:text-primary"
            >
              {scanning ? <Loader2 className="size-3.5 animate-spin" /> : <Radar className="size-3.5" />}
              Scan Certificates
            </button>
            <button
              onClick={() => toast.success("SSH connection successful", { description: `${server.hostname}:${server.sshPort}` })}
              className="inline-flex h-7.5 items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 text-[12.5px] hover:border-primary hover:text-primary"
            >
              <PlugZap className="size-3.5" /> Test SSH
            </button>
            <button
              onClick={() => setShowConf(true)}
              className="inline-flex h-7.5 items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 text-[12.5px] hover:border-primary hover:text-primary"
            >
              <FileCode2 className="size-3.5" /> View Nginx Configuration
            </button>
          </>
        }
      />

      <div className="grid gap-3 xl:grid-cols-4">
        <Panel title="Server Information" className="xl:col-span-1">
          <div className="space-y-1.5 p-3 text-[12.5px]">
            {[
              ["Hostname", server.hostname],
              ["IP Address", server.ip],
              ["Operating System", server.os],
              ["Nginx version", server.nginxVersion],
              ["SSH", `${server.sshUser}@${server.hostname}:${server.sshPort}`],
              ["Last connection", server.lastConnection],
              ["Last check", server.lastCheck],
            ].map(([k, v]) => (
              <div key={k} className="flex items-baseline justify-between gap-3 border-b border-border/60 pb-1.5 last:border-0">
                <span className="shrink-0 text-muted-foreground">{k}</span>
                <span className="mono break-all text-right text-foreground">{v}</span>
              </div>
            ))}
            <div className="flex items-center justify-between pt-1">
              <span className="text-muted-foreground">Environment</span>
              <EnvBadge env={server.environment} />
            </div>
          </div>
        </Panel>

        <Panel title="Certificates installed on this server" className="xl:col-span-3">
          <DTable>
            <THead>
              <TH>Domain</TH>
              <TH>Certificate Path</TH>
              <TH>Key Path</TH>
              <TH>Expiration</TH>
              <TH>Status</TH>
              <TH>Managed</TH>
            </THead>
            <tbody>
              {installed.map(({ cert, inst }) => (
                <TRow key={cert.id}>
                  <TD>
                    <Link
                      to="/certificates/$id"
                      params={{ id: cert.id }}
                      className="mono text-foreground hover:text-primary hover:underline"
                    >
                      {cert.commonName}
                    </Link>
                  </TD>
                  <TD className="mono">{inst.certPath}</TD>
                  <TD className="mono">{inst.keyPath}</TD>
                  <TD className="mono">{cert.expiration}</TD>
                  <TD>
                    <CertStatusBadge status={cert.status} />
                  </TD>
                  <TD>
                    <Pill tone="ok">Managed</Pill>
                  </TD>
                </TRow>
              ))}
            </tbody>
          </DTable>
        </Panel>
      </div>

      {scanned && (
        <div className="mt-3">
          <Panel
            title="Certificate Discovery — results"
            actions={
              <span className="text-[11.5px] text-muted-foreground">
                Parsed from Nginx vhosts (ssl_certificate / ssl_certificate_key)
              </span>
            }
          >
            <DTable>
              <THead>
                <TH>Domain</TH>
                <TH>Nginx Config</TH>
                <TH>Certificate</TH>
                <TH>Private Key</TH>
                <TH>Issuer</TH>
                <TH>Expiration</TH>
                <TH align="right">Action</TH>
              </THead>
              <tbody>
                {discoveredCertificates.map((d) => (
                  <TRow key={d.domain}>
                    <TD className="mono">{d.domain}</TD>
                    <TD className="mono">{d.vhost}</TD>
                    <TD className="mono">{d.cert}</TD>
                    <TD className="mono">{d.key}</TD>
                    <TD className="max-w-56 truncate text-muted-foreground">{d.issuer}</TD>
                    <TD className="mono">{d.expiration}</TD>
                    <TD align="right">
                      {d.known ? (
                        <Pill tone="neutral">Already managed</Pill>
                      ) : (
                        <button
                          onClick={() =>
                            toast.success("Imported into Certificate Manager", { description: d.domain })
                          }
                          className="inline-flex items-center gap-1.5 rounded-sm border border-border px-1.5 py-0.5 text-[11.5px] hover:border-primary hover:text-primary"
                        >
                          <Download className="size-3" /> Import
                        </button>
                      )}
                    </TD>
                  </TRow>
                ))}
              </tbody>
            </DTable>
          </Panel>
        </div>
      )}

      <Dialog open={showConf} onOpenChange={setShowConf}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle className="mono text-[13px]">
              /etc/nginx/sites-enabled/alfaintes.conf
            </DialogTitle>
            <DialogDescription>Read-only view · configuration is never modified during renewals.</DialogDescription>
          </DialogHeader>
          <pre className="mono max-h-96 overflow-auto rounded-md border border-border bg-surface-2/50 p-3 text-[11.5px] leading-5">
{nginxConf}
          </pre>
        </DialogContent>
      </Dialog>
    </AppShell>
  );
}
