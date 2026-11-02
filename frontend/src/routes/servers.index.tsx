import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { Plus, Search, Radar } from "lucide-react";
import { toast } from "sonner";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { EnvBadge, SshBadge } from "@/components/ui/status";
import { servers } from "@/lib/mock-data";

export const Route = createFileRoute("/servers/")({
  head: () => ({
    meta: [
      { title: "Servers — Certificate Manager" },
      {
        name: "description",
        content:
          "Inventory of Linux web servers running Nginx, their SSH reachability and installed certificates.",
      },
      { property: "og:title", content: "Servers — Certificate Manager" },
      {
        property: "og:description",
        content: "Linux/Nginx server inventory with SSH status and certificate counts.",
      },
    ],
  }),
  component: ServersPage,
});

function ServersPage() {
  const [q, setQ] = useState("");
  const [env, setEnv] = useState("all");

  const rows = servers.filter(
    (s) =>
      (env === "all" || s.environment === env) &&
      `${s.name} ${s.hostname} ${s.ip} ${s.os}`.toLowerCase().includes(q.toLowerCase()),
  );

  return (
    <AppShell>
      <PageHeader
        title="Servers"
        subtitle="Linux web servers managed over SSH · certificate deployment targets"
        actions={
          <>
            <button
              onClick={() => toast.info("Scanning all servers for certificate references…")}
              className="inline-flex h-7.5 items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 text-[12.5px] hover:border-primary hover:text-primary"
            >
              <Radar className="size-3.5" /> Scan All
            </button>
            <Link
              to="/servers/new"
              className="inline-flex h-7.5 items-center gap-1.5 rounded-md bg-primary px-2.5 text-[12.5px] font-medium text-primary-foreground hover:opacity-90"
            >
              <Plus className="size-3.5" /> Add Server
            </Link>
          </>
        }
      />

      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-2">
          <div className="relative min-w-52 flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Filter by name, hostname, IP…"
              className="h-7.5 w-full rounded-md border border-input bg-surface pl-8 pr-2 text-[12.5px] outline-none placeholder:text-muted-foreground focus:border-ring"
            />
          </div>
          <select
            value={env}
            onChange={(e) => setEnv(e.target.value)}
            className="h-7.5 rounded-md border border-input bg-surface px-2 text-[12.5px] outline-none focus:border-ring"
          >
            <option value="all">All environments</option>
            <option>Production</option>
            <option>Staging</option>
            <option>Test</option>
            <option>Development</option>
          </select>
        </div>

        <DTable>
          <THead>
            <TH>Name</TH>
            <TH>Hostname</TH>
            <TH>IP Address</TH>
            <TH>Environment</TH>
            <TH>OS</TH>
            <TH>Web Server</TH>
            <TH>SSH Status</TH>
            <TH align="right">Certificates</TH>
            <TH>Last Check</TH>
          </THead>
          <tbody>
            {rows.map((s) => (
              <TRow key={s.id}>
                <TD>
                  <Link
                    to="/servers/$id"
                    params={{ id: s.id }}
                    className="mono font-medium text-foreground hover:text-primary hover:underline"
                  >
                    {s.name}
                  </Link>
                </TD>
                <TD className="mono">{s.hostname}</TD>
                <TD className="mono">{s.ip}</TD>
                <TD>
                  <EnvBadge env={s.environment} />
                </TD>
                <TD className="text-muted-foreground">{s.os}</TD>
                <TD className="mono">{s.nginxVersion}</TD>
                <TD>
                  <SshBadge status={s.sshStatus} />
                </TD>
                <TD align="right" className="mono tabular-nums">
                  {s.certCount}
                </TD>
                <TD className="mono">{s.lastCheck}</TD>
              </TRow>
            ))}
          </tbody>
        </DTable>
      </Panel>
    </AppShell>
  );
}
