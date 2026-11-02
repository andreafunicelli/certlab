import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { CertStatusBadge, DaysLeft } from "@/components/ui/status";
import { certificates } from "@/lib/mock-data";
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

const filters = [
  { id: "expired", label: "Expired" },
  { id: "7", label: "Next 7 days" },
  { id: "30", label: "Next 30 days" },
  { id: "60", label: "Next 60 days" },
  { id: "90", label: "Next 90 days" },
  { id: "all", label: "All" },
];

function ExpirationsPage() {
  const [f, setF] = useState("all");

  const rows = certificates
    .filter((c) => {
      const d = c.daysRemaining;
      if (f === "all") return true;
      if (f === "expired") return d < 0;
      return d >= 0 && d <= Number(f);
    })
    .sort((a, b) => a.daysRemaining - b.daysRemaining);

  const months = [
    { label: "Sep 2026", items: certificates.filter((c) => c.expiration.includes("Sep 2026")) },
    { label: "Oct 2026", items: certificates.filter((c) => c.expiration.includes("Oct 2026")) },
    { label: "Jan 2027", items: certificates.filter((c) => c.expiration.includes("Jan 2027")) },
    { label: "Mar 2027", items: certificates.filter((c) => c.expiration.includes("Mar 2027")) },
  ];

  return (
    <AppShell>
      <PageHeader
        title="Expirations"
        subtitle="Renewal planning across all managed certificates · warning threshold 30 days"
      />

      <div className="mb-3 flex flex-wrap gap-1.5">
        {filters.map((x) => (
          <button
            key={x.id}
            onClick={() => setF(x.id)}
            className={cn(
              "h-7 rounded-md border px-2.5 text-[12px] transition-colors",
              f === x.id
                ? "border-primary/40 bg-primary/12 text-primary"
                : "border-border bg-surface text-muted-foreground hover:text-foreground",
            )}
          >
            {x.label}
          </button>
        ))}
      </div>

      <div className="grid gap-3 xl:grid-cols-4">
        <Panel title="Renewal Calendar" className="xl:col-span-1">
          <div className="space-y-3 p-3">
            {months.map((m) => (
              <div key={m.label}>
                <div className="mb-1 text-[11px] uppercase tracking-[0.06em] text-muted-foreground">
                  {m.label}
                </div>
                {m.items.length === 0 ? (
                  <div className="text-[12px] text-muted-foreground">No expirations</div>
                ) : (
                  <div className="space-y-1">
                    {m.items.map((c) => (
                      <Link
                        key={c.id}
                        to="/certificates/$id"
                        params={{ id: c.id }}
                        className="flex items-center justify-between gap-2 rounded-sm border border-border bg-surface-2/40 px-2 py-1 hover:border-primary/50"
                      >
                        <span className="mono truncate text-[11.5px]">{c.commonName}</span>
                        <DaysLeft days={c.daysRemaining} />
                      </Link>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Expiring Certificates" className="xl:col-span-3">
          <DTable>
            <THead>
              <TH>Domain</TH>
              <TH>Issuer</TH>
              <TH>Expiration</TH>
              <TH align="right">Days Left</TH>
              <TH align="right">Servers</TH>
              <TH>Responsible User</TH>
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
                  <TD className="text-muted-foreground">{c.owner}</TD>
                  <TD>
                    <CertStatusBadge status={c.status} />
                  </TD>
                  <TD align="right">
                    <Link
                      to="/certificates/$id/renew"
                      params={{ id: c.id }}
                      className="rounded-sm border border-border px-1.5 py-0.5 text-[11.5px] hover:border-primary hover:text-primary"
                    >
                      Renew
                    </Link>
                  </TD>
                </TRow>
              ))}
              {rows.length === 0 && (
                <TRow>
                  <TD colSpan={8} className="py-8 text-center text-muted-foreground">
                    Nothing expiring in this window.
                  </TD>
                </TRow>
              )}
            </tbody>
          </DTable>
        </Panel>
      </div>
    </AppShell>
  );
}
