import { createFileRoute, Link } from "@tanstack/react-router";
import {
  ShieldCheck,
  Clock,
  ShieldX,
  Server as ServerIcon,
  AlertTriangle,
  ArrowRight,
} from "lucide-react";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { CertStatusBadge, DaysLeft, Mono, Pill } from "@/components/ui/status";
import {
  certificates,
  deployments,
  expirationBuckets,
  statsSummary,
} from "@/lib/mock-data";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Dashboard — Certificate Manager" },
      {
        name: "description",
        content:
          "Operational overview of PKI certificates, expirations, servers and Nginx deployment results.",
      },
      { property: "og:title", content: "Dashboard — Certificate Manager" },
      {
        property: "og:description",
        content: "Operational overview of PKI certificates, expirations and deployments.",
      },
    ],
  }),
  component: Dashboard,
});

const cards = [
  { label: "Total Certificates", value: statsSummary.total, icon: ShieldCheck, tone: "text-foreground" },
  { label: "Expiring Soon", value: statsSummary.expiring, icon: Clock, tone: "text-warn" },
  { label: "Expired", value: statsSummary.expired, icon: ShieldX, tone: "text-danger" },
  { label: "Servers", value: statsSummary.servers, icon: ServerIcon, tone: "text-foreground" },
  { label: "Failed Deployments", value: statsSummary.failedDeployments, icon: AlertTriangle, tone: "text-crit" },
];

const barTone: Record<string, string> = {
  danger: "bg-danger",
  crit: "bg-crit",
  warn: "bg-warn",
  info: "bg-info",
  ok: "bg-ok",
};

function Dashboard() {
  const attention = [...certificates]
    .sort((a, b) => a.daysRemaining - b.daysRemaining)
    .slice(0, 6);
  const maxBucket = Math.max(...expirationBuckets.map((b) => b.count));

  return (
    <AppShell>
      <PageHeader
        title="Dashboard"
        subtitle="Fleet-wide certificate and deployment status · last inventory sync 10 Sep 2026 14:05"
      />

      <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-5">
        {cards.map((c) => (
          <div key={c.label} className="panel px-3 py-2.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase tracking-[0.06em] text-muted-foreground">
                {c.label}
              </span>
              <c.icon className={cn("size-3.5", c.tone)} />
            </div>
            <div className={cn("mt-1 text-2xl font-semibold tabular-nums", c.tone)}>{c.value}</div>
          </div>
        ))}
      </div>

      <div className="mt-3 grid gap-3 xl:grid-cols-3">
        <Panel title="Expiration Distribution" className="xl:col-span-1">
          <div className="space-y-2.5 p-3">
            {expirationBuckets.map((b) => (
              <div key={b.bucket}>
                <div className="mb-1 flex items-center justify-between text-[12px]">
                  <span className="text-muted-foreground">{b.bucket}</span>
                  <span className="mono tabular-nums text-foreground">{b.count}</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-muted">
                  <div
                    className={cn("h-1.5 rounded-full", barTone[b.tone])}
                    style={{ width: `${Math.max(4, (b.count / maxBucket) * 100)}%` }}
                  />
                </div>
              </div>
            ))}
            <div className="border-t border-border pt-2 text-[11.5px] text-muted-foreground">
              Warning threshold: <span className="mono text-foreground">30 days</span> · notifications
              at 90/60/30/15/7/1 days
            </div>
          </div>
        </Panel>

        <Panel
          title="Certificates Requiring Attention"
          className="xl:col-span-2"
          actions={
            <Link
              to="/expirations"
              className="flex items-center gap-1 text-[11.5px] text-primary hover:underline"
            >
              View expirations <ArrowRight className="size-3" />
            </Link>
          }
        >
          <DTable>
            <THead>
              <TH>Domain</TH>
              <TH>Issuer</TH>
              <TH>Expiration</TH>
              <TH align="right">Days</TH>
              <TH align="right">Servers</TH>
              <TH>Status</TH>
              <TH align="right">Action</TH>
            </THead>
            <tbody>
              {attention.map((c) => (
                <TRow key={c.id}>
                  <TD>
                    <Link
                      to="/certificates/$id"
                      params={{ id: c.id }}
                      className="mono text-foreground hover:text-primary hover:underline"
                    >
                      {c.commonName}
                    </Link>
                  </TD>
                  <TD className="text-muted-foreground">{c.ca}</TD>
                  <TD className="mono">{c.expiration}</TD>
                  <TD align="right">
                    <DaysLeft days={c.daysRemaining} />
                  </TD>
                  <TD align="right" className="mono tabular-nums text-muted-foreground">
                    {c.installations.length}
                  </TD>
                  <TD>
                    <CertStatusBadge status={c.status} />
                  </TD>
                  <TD align="right">
                    <Link
                      to="/certificates/$id/renew"
                      params={{ id: c.id }}
                      className="rounded-sm border border-border px-1.5 py-0.5 text-[11.5px] text-foreground hover:border-primary hover:text-primary"
                    >
                      Replace
                    </Link>
                  </TD>
                </TRow>
              ))}
            </tbody>
          </DTable>
        </Panel>
      </div>

      <div className="mt-3">
        <Panel
          title="Recent Deployments"
          actions={
            <Link
              to="/deployments"
              className="flex items-center gap-1 text-[11.5px] text-primary hover:underline"
            >
              All deployments <ArrowRight className="size-3" />
            </Link>
          }
        >
          <DTable>
            <THead>
              <TH>Certificate</TH>
              <TH>Target Servers</TH>
              <TH>Date</TH>
              <TH>User</TH>
              <TH>Duration</TH>
              <TH>Result</TH>
            </THead>
            <tbody>
              {deployments.map((d) => (
                <TRow key={d.id}>
                  <TD>
                    <Link
                      to="/deployments/$id"
                      params={{ id: d.id }}
                      className="mono text-foreground hover:text-primary hover:underline"
                    >
                      {d.certificate}
                    </Link>
                  </TD>
                  <TD className="text-muted-foreground">
                    {d.detail.map((t) => t.serverName).join(", ")}
                  </TD>
                  <TD>
                    <Mono>{d.date}</Mono>
                  </TD>
                  <TD className="text-muted-foreground">{d.user}</TD>
                  <TD>
                    <Mono>{d.duration}</Mono>
                  </TD>
                  <TD>
                    <Pill
                      tone={
                        d.status === "Success"
                          ? "ok"
                          : d.status === "Partial Failure"
                            ? "warn"
                            : d.status === "Failed"
                              ? "danger"
                              : "info"
                      }
                      dot
                    >
                      {d.status}
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
