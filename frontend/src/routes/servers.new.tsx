import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { ArrowLeft, KeyRound, Loader2, PlugZap, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { Pill } from "@/components/ui/status";

export const Route = createFileRoute("/servers/new")({
  head: () => ({
    meta: [
      { title: "Add Server — Certificate Manager" },
      {
        name: "description",
        content: "Register a Linux/Nginx server with SSH key authentication as a deployment target.",
      },
      { property: "og:title", content: "Add Server — Certificate Manager" },
      {
        property: "og:description",
        content: "Register an Nginx server with SSH key authentication.",
      },
    ],
  }),
  component: AddServer,
});

const inputCls =
  "h-8 w-full rounded-md border border-input bg-surface px-2 text-[12.5px] outline-none placeholder:text-muted-foreground focus:border-ring";
const labelCls = "mb-1 block text-[11.5px] uppercase tracking-[0.05em] text-muted-foreground";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className={labelCls}>{label}</label>
      {children}
    </div>
  );
}

function AddServer() {
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState(false);

  const runTest = () => {
    setTesting(true);
    setResult(false);
    setTimeout(() => {
      setTesting(false);
      setResult(true);
      toast.success("SSH connection successful", { description: "web03.youco.local:22 as certmgr" });
    }, 1200);
  };

  return (
    <AppShell>
      <Link
        to="/servers"
        className="mb-2 inline-flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3.5" /> Servers
      </Link>
      <PageHeader title="Add Server" subtitle="Deployment targets authenticate with SSH keys only" />

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel title="Server" className="lg:col-span-2">
          <div className="grid gap-3 p-3 sm:grid-cols-2">
            <Row label="Server Name">
              <input className={inputCls} placeholder="WEB-PROD-03" />
            </Row>
            <Row label="Hostname / IP">
              <input className={inputCls} placeholder="web03.youco.local" />
            </Row>
            <Row label="SSH Port">
              <input className={inputCls} defaultValue="22" />
            </Row>
            <Row label="SSH Username">
              <input className={inputCls} placeholder="certmgr" />
            </Row>
            <Row label="Environment">
              <select className={inputCls}>
                <option>Production</option>
                <option>Staging</option>
                <option>Test</option>
                <option>Development</option>
              </select>
            </Row>
            <Row label="Operating System">
              <select className={inputCls}>
                <option>Ubuntu 24.04 LTS</option>
                <option>Ubuntu 22.04 LTS</option>
                <option>Debian 12</option>
                <option>Rocky Linux 9</option>
              </select>
            </Row>
            <Row label="Web Server">
              <select className={inputCls}>
                <option>Nginx</option>
                <option>Nginx (OpenResty)</option>
              </select>
            </Row>
            <Row label="Authentication">
              <div className="flex h-8 items-center gap-2 rounded-md border border-input bg-surface-2/50 px-2 text-[12.5px]">
                <KeyRound className="size-3.5 text-muted-foreground" /> SSH Key
                <Pill tone="info" className="ml-auto">
                  Password auth disabled
                </Pill>
              </div>
            </Row>
          </div>
          <div className="flex flex-wrap items-center gap-2 border-t border-border px-3 py-2">
            <button
              onClick={runTest}
              className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border bg-surface px-3 text-[12.5px] hover:border-primary hover:text-primary"
            >
              {testing ? <Loader2 className="size-3.5 animate-spin" /> : <PlugZap className="size-3.5" />}
              Test SSH Connection
            </button>
            <button className="inline-flex h-8 items-center gap-1.5 rounded-md bg-primary px-3 text-[12.5px] font-medium text-primary-foreground hover:opacity-90">
              Save Server
            </button>
            <span className="text-[11.5px] text-muted-foreground">
              Root password authentication is never requested or stored.
            </span>
          </div>
        </Panel>

        <div className="space-y-3">
          <Panel title="SSH Key">
            <div className="space-y-2 p-3 text-[12.5px]">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Platform key</span>
                <span className="mono">ed25519 · certmgr@certificate-manager</span>
              </div>
              <div className="mono break-all rounded-md border border-border bg-surface-2/50 p-2 text-[11px] text-muted-foreground">
                SHA256:9Zc1r8u+7Q2mXlD4hK0pB6nT3yVaE8sWq1fJ5oGtZbA
              </div>
              <div className="flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
                <ShieldCheck className="size-3.5" /> Only the public key is exposed. Private key material
                is never displayed.
              </div>
            </div>
          </Panel>

          {result && (
            <Panel title="Connection Result">
              <div className="space-y-1.5 p-3 text-[12.5px]">
                {[
                  ["Hostname", "web03.youco.local"],
                  ["Operating System", "Ubuntu 24.04.1 LTS"],
                  ["Nginx version", "nginx/1.24.0"],
                  ["Sudo access", "NOPASSWD: systemctl reload nginx"],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-3">
                    <span className="text-muted-foreground">{k}</span>
                    <span className="mono text-foreground">{v}</span>
                  </div>
                ))}
                <div className="pt-1.5 text-[11px] uppercase tracking-[0.06em] text-muted-foreground">
                  Certificate directories detected
                </div>
                <div className="mono space-y-0.5 rounded-md border border-border bg-surface-2/50 p-2">
                  <div>/etc/ssl</div>
                  <div>/etc/nginx/ssl</div>
                  <div>/etc/nginx/certs</div>
                  <div>/var/certificates</div>
                </div>
                <p className="text-[11.5px] text-muted-foreground">
                  Detected directories are suggestions only — each deployment keeps its own configured
                  certificate and key path.
                </p>
              </div>
            </Panel>
          )}
        </div>
      </div>
    </AppShell>
  );
}
