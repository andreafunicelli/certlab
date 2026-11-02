import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import {
  addMonths,
  eachDayOfInterval,
  endOfMonth,
  endOfWeek,
  format,
  isSameMonth,
  startOfMonth,
  startOfWeek,
} from "date-fns";
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts";
import { CalendarDays, ChevronLeft, ChevronRight, List, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { CertStatusBadge, DaysLeft } from "@/components/ui/status";
import {
  btnCls,
  EmptyState,
  ErrorState,
  errorMessage,
  LoadingBlock,
  selectCls,
  Spinner,
} from "@/components/ui/feedback";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import {
  useCertificates,
  useExpiryTrend,
  useSettings,
  useVerifyCertificate,
} from "@/lib/api/queries";
import type { CertificateSummary } from "@/lib/api/types";
import { useCan } from "@/lib/auth";
import { fmtDate } from "@/lib/format";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/expirations")({
  head: () => ({
    meta: [
      { title: "Expirations — Certificate Manager" },
      {
        name: "description",
        content: "Monitor upcoming PKI certificate expirations by 7, 30, 60 and 90 day windows.",
      },
      { property: "og:title", content: "Expirations — Certificate Manager" },
      {
        property: "og:description",
        content: "Certificate expiration monitoring with urgency windows and responsible owners.",
      },
    ],
  }),
  component: ExpirationsPage,
});

const windows = [
  { id: "expired", label: "Expired" },
  { id: "7", label: "Next 7 days" },
  { id: "30", label: "Next 30 days" },
  { id: "60", label: "Next 60 days" },
  { id: "90", label: "Next 90 days" },
  { id: "all", label: "All" },
];

const chartConfig = {
  count: { label: "Certificates", color: "var(--color-primary)" },
} satisfies ChartConfig;

const dayTone: Record<string, string> = {
  expired: "border-danger/40 bg-danger-soft text-danger",
  critical: "border-crit/40 bg-crit-soft text-crit",
  high: "border-crit/40 bg-crit-soft text-crit",
  warning: "border-warn/40 bg-warn-soft text-warn",
  info: "border-info/30 bg-info-soft text-info",
  valid: "border-ok/30 bg-ok-soft text-ok",
};

function CalendarView({
  rows,
  month,
  setMonth,
}: {
  rows: CertificateSummary[];
  month: Date;
  setMonth: (d: Date) => void;
}) {
  const days = eachDayOfInterval({
    start: startOfWeek(startOfMonth(month), { weekStartsOn: 1 }),
    end: endOfWeek(endOfMonth(month), { weekStartsOn: 1 }),
  });
  const byDay = useMemo(() => {
    const m = new Map<string, CertificateSummary[]>();
    for (const c of rows) {
      const k = format(new Date(c.not_after), "yyyy-MM-dd");
      m.set(k, [...(m.get(k) ?? []), c]);
    }
    return m;
  }, [rows]);
  return (
    <div className="p-3" data-testid="expiry-calendar">
      <div className="mb-2 flex items-center justify-between">
        <button
          className={btnCls}
          onClick={() => setMonth(addMonths(month, -1))}
          aria-label="Previous month"
        >
          <ChevronLeft className="size-3.5" />
        </button>
        <span className="text-[13px] font-medium">{format(month, "MMMM yyyy")}</span>
        <button
          className={btnCls}
          onClick={() => setMonth(addMonths(month, 1))}
          aria-label="Next month"
        >
          <ChevronRight className="size-3.5" />
        </button>
      </div>
      <div className="grid grid-cols-7 gap-px overflow-hidden rounded-md border border-border bg-border text-[11px]">
        {["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map((d) => (
          <div
            key={d}
            className="bg-surface-2 px-1.5 py-1 text-center uppercase tracking-[0.06em] text-muted-foreground"
          >
            {d}
          </div>
        ))}
        {days.map((d) => {
          const k = format(d, "yyyy-MM-dd");
          const items = byDay.get(k) ?? [];
          return (
            <div
              key={k}
              className={cn(
                "min-h-20 bg-surface p-1",
                !isSameMonth(d, month) && "bg-surface-2/50 text-muted-foreground/60",
              )}
            >
              <div className="mono text-right text-[10.5px] text-muted-foreground">
                {format(d, "d")}
              </div>
              <div className="space-y-0.5">
                {items.slice(0, 3).map((c) => (
                  <Link
                    key={c.id}
                    to="/certificates/$id"
                    params={{ id: c.id }}
                    title={`${c.common_name} · ${c.days_remaining}d`}
                    className={cn(
                      "mono block truncate rounded-sm border px-1 text-[10.5px]",
                      dayTone[c.expiry_status],
                    )}
                  >
                    {c.common_name}
                  </Link>
                ))}
                {items.length > 3 && (
                  <div className="text-[10.5px] text-muted-foreground">
                    +{items.length - 3} more
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ExpirationsPage() {
  const [win, setWin] = useState("all");
  const [sev, setSev] = useState("all");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [view, setView] = useState<"table" | "calendar">("table");
  const [month, setMonth] = useState(() => startOfMonth(new Date()));
  const canVerify = useCan("certificates:verify");
  const canRenew = useCan("versions:upload");
  const verify = useVerifyCertificate();
  const trend = useExpiryTrend();
  const thresholds = useSettings().data?.notifications.data["thresholds"] as
    Record<string, number> | undefined;

  const list = useCertificates({
    status: win === "expired" ? "expired" : sev === "all" ? undefined : sev,
    expiring_within: win === "all" || win === "expired" ? undefined : Number(win),
    sort: "not_after",
    page_size: 200,
  });

  const rows = useMemo(() => {
    const f = from ? new Date(`${from}T00:00:00`).getTime() : -Infinity;
    const t = to ? new Date(`${to}T23:59:59`).getTime() : Infinity;
    return (list.data?.items ?? []).filter((c) => {
      const ts = new Date(c.not_after).getTime();
      return ts >= f && ts <= t;
    });
  }, [list.data, from, to]);

  const runVerify = (c: CertificateSummary) =>
    verify.mutate(c.id, {
      onSuccess: (r) => {
        if (r.summary.total === 0) toast.info("Nothing to verify", { description: c.common_name });
        else if (r.summary.mismatching || r.summary.failed)
          toast.warning(`${c.common_name}: problems found`, {
            description: `${r.summary.matching}/${r.summary.total} endpoints match`,
          });
        else
          toast.success(
            `${c.common_name}: ${r.summary.matching}/${r.summary.total} endpoints verified`,
          );
      },
      onError: (e) => toast.error("Verification failed", { description: errorMessage(e) }),
    });

  return (
    <AppShell>
      <PageHeader
        title="Expirations"
        subtitle={`Renewal planning across all certificates${thresholds?.["warning"] ? ` · warning threshold ${thresholds["warning"]} days` : ""}`}
        actions={
          <div className="flex rounded-md border border-border bg-surface p-0.5">
            {(
              [
                ["table", List, "Table"],
                ["calendar", CalendarDays, "Calendar"],
              ] as const
            ).map(([v, Icon, label]) => (
              <button
                key={v}
                onClick={() => setView(v)}
                aria-pressed={view === v}
                className={cn(
                  "inline-flex h-6.5 items-center gap-1.5 rounded-sm px-2 text-[12px]",
                  view === v
                    ? "bg-primary/12 text-primary"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                <Icon className="size-3.5" /> {label}
              </button>
            ))}
          </div>
        }
      />

      <div className="mb-3 flex flex-wrap items-center gap-1.5">
        {windows.map((x) => (
          <button
            key={x.id}
            onClick={() => setWin(x.id)}
            className={cn(
              "h-7 rounded-md border px-2.5 text-[12px] transition-colors",
              win === x.id
                ? "border-primary/40 bg-primary/12 text-primary"
                : "border-border bg-surface text-muted-foreground hover:text-foreground",
            )}
          >
            {x.label}
          </button>
        ))}
        <select
          value={sev}
          onChange={(e) => setSev(e.target.value)}
          className={selectCls + " ml-2"}
          aria-label="Severity"
          disabled={win === "expired"}
        >
          <option value="all">Any severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="warning">Warning</option>
          <option value="info">Renew soon</option>
          <option value="valid">Valid</option>
        </select>
        <label className="flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
          Expires from
          <input
            type="date"
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            className={selectCls}
          />
        </label>
        <label className="flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
          to
          <input
            type="date"
            value={to}
            onChange={(e) => setTo(e.target.value)}
            className={selectCls}
          />
        </label>
      </div>

      <div className="grid gap-3 xl:grid-cols-4">
        <div className="space-y-3 xl:col-span-1">
          <Panel title="Expirations per month">
            {trend.isLoading ? (
              <LoadingBlock />
            ) : trend.isError ? (
              <ErrorState error={trend.error} onRetry={() => void trend.refetch()} />
            ) : (trend.data?.monthly.length ?? 0) === 0 ? (
              <EmptyState title="No data yet" />
            ) : (
              <ChartContainer config={chartConfig} className="h-44 w-full p-2">
                <BarChart data={trend.data?.monthly ?? []}>
                  <CartesianGrid vertical={false} strokeDasharray="3 3" />
                  <XAxis dataKey="month" tickLine={false} axisLine={false} fontSize={10} />
                  <YAxis
                    allowDecimals={false}
                    width={24}
                    tickLine={false}
                    axisLine={false}
                    fontSize={10}
                  />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="count" fill="var(--color-count)" radius={2} />
                </BarChart>
              </ChartContainer>
            )}
          </Panel>
          <Panel title="Distribution">
            <ul className="space-y-1 p-3 text-[12px]">
              {(trend.data?.buckets ?? []).map((b) => (
                <li key={b.bucket} className="flex items-center justify-between">
                  <span className="text-muted-foreground">{b.bucket}</span>
                  <span className="mono tabular-nums">{b.count}</span>
                </li>
              ))}
            </ul>
          </Panel>
        </div>

        <Panel
          title={view === "table" ? "Expiring Certificates" : "Expiration Calendar"}
          className="xl:col-span-3"
          actions={<span className="text-[11.5px] text-muted-foreground">{rows.length} shown</span>}
        >
          {list.isLoading ? (
            <LoadingBlock />
          ) : list.isError ? (
            <ErrorState error={list.error} onRetry={() => void list.refetch()} />
          ) : view === "calendar" ? (
            <CalendarView rows={rows} month={month} setMonth={setMonth} />
          ) : rows.length === 0 ? (
            <EmptyState title="Nothing expiring in this window" />
          ) : (
            <DTable>
              <THead>
                <TH>Domain</TH>
                <TH>Issuer</TH>
                <TH>Expiration</TH>
                <TH align="right">Days Left</TH>
                <TH align="right">Servers</TH>
                <TH>Owner</TH>
                <TH>Status</TH>
                <TH align="right">Action</TH>
              </THead>
              <tbody>
                {rows.map((c) => (
                  <TRow key={c.id}>
                    <TD>
                      <Link
                        to="/certificates/$id"
                        params={{ id: c.id }}
                        className="mono text-foreground hover:text-primary hover:underline"
                      >
                        {c.common_name}
                      </Link>
                    </TD>
                    <TD className="max-w-36 truncate text-muted-foreground">
                      <span title={c.issuer}>{c.issuer}</span>
                    </TD>
                    <TD className="mono">{fmtDate(c.not_after)}</TD>
                    <TD align="right">
                      <DaysLeft days={c.days_remaining} />
                    </TD>
                    <TD align="right" className="mono tabular-nums text-muted-foreground">
                      <span title={`${c.installation_count} installations`}>{c.server_count}</span>
                    </TD>
                    <TD className="text-muted-foreground">{c.owner ?? "—"}</TD>
                    <TD>
                      <CertStatusBadge status={c.expiry_status} />
                    </TD>
                    <TD align="right">
                      <span className="flex justify-end gap-1.5">
                        {canVerify && (
                          <button
                            className={btnCls}
                            disabled={verify.isPending || c.installation_count === 0}
                            onClick={() => runVerify(c)}
                            aria-label={`Verify ${c.common_name}`}
                          >
                            {verify.isPending && verify.variables === c.id ? (
                              <Spinner />
                            ) : (
                              <ShieldCheck className="size-3.5" />
                            )}
                            Verify
                          </button>
                        )}
                        {canRenew && (
                          <Link
                            to="/certificates/$id/renew"
                            params={{ id: c.id }}
                            className="inline-flex h-7.5 items-center rounded-md border border-border px-2 text-[12px] hover:border-primary hover:text-primary"
                          >
                            Renew
                          </Link>
                        )}
                      </span>
                    </TD>
                  </TRow>
                ))}
              </tbody>
            </DTable>
          )}
        </Panel>
      </div>
    </AppShell>
  );
}
