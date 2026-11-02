import { createFileRoute, Link } from "@tanstack/react-router";
import {
  ShieldCheck,
  Clock,
  ShieldX,
  Server as ServerIcon,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
} from "lucide-react";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { Mono, OutcomePill, Pill, type Tone } from "@/components/ui/status";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/ui/feedback";
import { useDashboardSummary, useExpiryTrend, useSettings } from "@/lib/api/queries";
import { fmtAgo, fmtDateTime } from "@/lib/format";
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

const barTone: Record<string, string> = {
  danger: "bg-danger",
  crit: "bg-crit",
  warn: "bg-warn",
  info: "bg-info",
  ok: "bg-ok",
};

const deployTone = (status: string): Tone =>
  status === "completed"
    ? "ok"
    : ["failed", "manual_intervention_required"].includes(status)
      ? "danger"
      : ["partially_failed", "rolled_back", "cancelled"].includes(status)
        ? "warn"
        : "info";

function Dashboard() {
  const summary = useDashboardSummary();
  const trend = useExpiryTrend();
  const settings = useSettings();
  const s = summary.data;
  const buckets = trend.data?.buckets ?? [];
  const maxBucket = Math.max(1, ...buckets.map((b) => b.count));
  const monthly = trend.data?.monthly ?? [];
  const maxMonth = Math.max(1, ...monthly.map((m) => m.count));
  const thresholds = settings.data?.notifications.data["thresholds"] as
    Record<string, number> | undefined;

  const cards = [
    {
      label: "Total Certificates",
      value: s?.certificates_total,
      icon: ShieldCheck,
      tone: "text-foreground",
    },
    { label: "Expiring Soon", value: s?.certificates_expiring_30, icon: Clock, tone: "text-warn" },
    { label: "Expired", value: s?.certificates_expired, icon: ShieldX, tone: "text-danger" },
    { label: "Servers", value: s?.servers_total, icon: ServerIcon, tone: "text-foreground" },
    {
      label: "Failed Deployments",
      value: s?.failed_deployments_30d,
      icon: AlertTriangle,
      tone: "text-crit",
    },
  ];

  const attention = s
    ? [
        {
          label: "Certificates expiring within 7 days",
          n: s.certificates_expiring_7,
          to: "/expirations" as const,
        },
        { label: "Expired certificates", n: s.certificates_expired, to: "/expirations" as const },
        { label: "Unreachable servers", n: s.servers_unreachable, to: "/servers" as const },
        { label: "Servers with discovery errors", n: s.discovery_errors, to: "/servers" as const },
        {
          label: "Installations with errors",
          n: s.installation_errors,
          to: "/certificates" as const,
        },
        { label: "Configuration drift detected", n: s.drift, to: "/certificates" as const },
        {
          label: "Failed deployments (30 days)",
          n: s.failed_deployments_30d,
          to: "/deployments" as const,
        },
      ].filter((a) => a.n > 0)
    : [];

  return (
    <AppShell>
      <PageHeader
        title="Dashboard"
        subtitle={
          s
            ? `Fleet-wide certificate and deployment status · generated ${fmtDateTime(s.generated_at)}`
            : "Fleet-wide certificate and deployment status"
        }
      />

      {summary.isError ? (
        <Panel>
          <ErrorState error={summary.error} onRetry={() => void summary.refetch()} />
        </Panel>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-5">
            {cards.map((c) => (
              <div key={c.label} className="panel px-3 py-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] uppercase tracking-[0.06em] text-muted-foreground">
                    {c.label}
                  </span>
                  <c.icon className={cn("size-3.5", c.tone)} />
                </div>
                <div className={cn("mt-1 text-2xl font-semibold tabular-nums", c.tone)}>
                  {c.value ?? "—"}
                </div>
              </div>
            ))}
          </div>

          <div className="mt-3 grid gap-3 xl:grid-cols-3">
            <Panel title="Expiration Distribution" className="xl:col-span-1">
              {trend.isLoading ? (
                <LoadingBlock />
              ) : trend.isError ? (
                <ErrorState error={trend.error} onRetry={() => void trend.refetch()} />
              ) : (
                <div className="space-y-2.5 p-3">
                  {buckets.every((b) => b.count === 0) ? (
                    <EmptyState
                      title="No certificates yet"
                      hint="Distribution appears once certificates are discovered or uploaded."
                    />
                  ) : (
                    buckets.map((b) => (
                      <div key={b.bucket}>
                        <div className="mb-1 flex items-center justify-between text-[12px]">
                          <span className="text-muted-foreground">{b.bucket}</span>
                          <span className="mono tabular-nums text-foreground">{b.count}</span>
                        </div>
                        <div className="h-1.5 w-full rounded-full bg-muted">
                          <div
                            className={cn("h-1.5 rounded-full", barTone[b.tone])}
                            style={{
                              width:
                                b.count === 0
                                  ? "0%"
                                  : `${Math.max(4, (b.count / maxBucket) * 100)}%`,
                            }}
                          />
                        </div>
                      </div>
                    ))
                  )}
                  {thresholds && (
                    <div className="border-t border-border pt-2 text-[11.5px] text-muted-foreground">
                      Warning threshold:{" "}
                      <span className="mono text-foreground">{thresholds["warning"]} days</span> ·
                      notifications at{" "}
                      {[
                        thresholds["info"],
                        thresholds["warning"],
                        thresholds["high"],
                        thresholds["critical"],
                      ].join("/")}{" "}
                      days
                    </div>
                  )}
                </div>
              )}
            </Panel>

            <Panel
              title="Requires Attention"
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
              {summary.isLoading ? (
                <LoadingBlock />
              ) : attention.length === 0 ? (
                <div className="flex items-center justify-center gap-2 p-8 text-[12.5px] text-muted-foreground">
                  <CheckCircle2 className="size-4 text-ok" /> Nothing needs attention right now.
                </div>
              ) : (
                <ul className="divide-y divide-border/70">
                  {attention.map((a) => (
                    <li key={a.label}>
                      <Link
                        to={a.to}
                        className="flex items-center justify-between px-3 py-2 text-[12.5px] hover:bg-muted/40"
                      >
                        <span>{a.label}</span>
                        <span className="mono tabular-nums text-crit">{a.n}</span>
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          </div>

          <div className="mt-3 grid gap-3 xl:grid-cols-3">
            <Panel title="Expirations by month" className="xl:col-span-1">
              {monthly.length === 0 ? (
                <EmptyState
                  title="No upcoming expirations"
                  hint="Nothing expires within the next 12 months."
                />
              ) : (
                <div
                  className="flex h-36 items-end gap-1.5 p-3"
                  role="img"
                  aria-label="Certificates expiring per month"
                >
                  {monthly.map((m) => (
                    <div key={m.month} className="flex min-w-0 flex-1 flex-col items-center gap-1">
                      <span className="mono text-[10.5px] tabular-nums text-muted-foreground">
                        {m.count}
                      </span>
                      <div
                        className="w-full rounded-sm bg-primary/70"
                        style={{ height: `${Math.max(6, (m.count / maxMonth) * 80)}px` }}
                      />
                      <span className="mono text-[9.5px] text-muted-foreground">
                        {m.month.slice(2)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </Panel>

            <Panel
              title="Recent Deployments"
              className="xl:col-span-2"
              actions={
                <Link
                  to="/deployments"
                  className="flex items-center gap-1 text-[11.5px] text-primary hover:underline"
                >
                  All deployments <ArrowRight className="size-3" />
                </Link>
              }
            >
              {!s ? (
                <LoadingBlock />
              ) : s.recent_deployments.length === 0 ? (
                <EmptyState
                  title="No deployments yet"
                  hint="Deployments appear here once a certificate is rolled out."
                />
              ) : (
                <DTable>
                  <THead>
                    <TH>Deployment</TH>
                    <TH>Started</TH>
                    <TH>Finished</TH>
                    <TH>Result</TH>
                  </THead>
                  <tbody>
                    {s.recent_deployments.map((d) => (
                      <TRow key={d.id}>
                        <TD className="mono">{d.id.slice(0, 8)}</TD>
                        <TD>
                          <Mono>{fmtAgo(d.created_at)}</Mono>
                        </TD>
                        <TD>
                          <Mono>{d.finished_at ? fmtAgo(d.finished_at) : "—"}</Mono>
                        </TD>
                        <TD>
                          <Pill tone={deployTone(d.status)} dot>
                            {d.status.replace(/_/g, " ")}
                          </Pill>
                        </TD>
                      </TRow>
                    ))}
                  </tbody>
                </DTable>
              )}
            </Panel>
          </div>

          <div className="mt-3">
            <Panel
              title="Recent Activity"
              actions={
                <Link
                  to="/audit"
                  className="flex items-center gap-1 text-[11.5px] text-primary hover:underline"
                >
                  Audit log <ArrowRight className="size-3" />
                </Link>
              }
            >
              {!s ? (
                <LoadingBlock />
              ) : s.recent_activity.length === 0 ? (
                <EmptyState title="No activity recorded yet" />
              ) : (
                <DTable>
                  <THead>
                    <TH>When</TH>
                    <TH>User</TH>
                    <TH>Action</TH>
                    <TH>Resource</TH>
                    <TH>Result</TH>
                  </THead>
                  <tbody>
                    {s.recent_activity.map((a) => (
                      <TRow key={a.id}>
                        <TD className="mono">{fmtDateTime(a.ts)}</TD>
                        <TD className="text-muted-foreground">{a.actor_name ?? "system"}</TD>
                        <TD className="mono font-medium">{a.action}</TD>
                        <TD className="mono">{a.resource_type ?? "—"}</TD>
                        <TD>
                          <OutcomePill outcome={a.outcome} />
                        </TD>
                      </TRow>
                    ))}
                  </tbody>
                </DTable>
              )}
            </Panel>
          </div>
        </>
      )}
    </AppShell>
  );
}
