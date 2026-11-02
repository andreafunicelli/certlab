import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Lock, Search } from "lucide-react";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { Pill } from "@/components/ui/status";
import { auditLog } from "@/lib/mock-data";

export const Route = createFileRoute("/audit")({
  head: () => ({
    meta: [
      { title: "Audit Log — Certificate Manager" },
      {
        name: "description",
        content:
          "Immutable audit trail of certificate uploads, deployments, rollbacks, Nginx reloads and server changes.",
      },
      { property: "og:title", content: "Audit Log — Certificate Manager" },
      {
        property: "og:description",
        content: "Immutable audit trail of every certificate and server operation.",
      },
    ],
  }),
  component: AuditPage,
});

const actions = Array.from(new Set(auditLog.map((a) => a.action)));

function AuditPage() {
  const [q, setQ] = useState("");
  const [action, setAction] = useState("all");

  const rows = auditLog.filter(
    (a) =>
      (action === "all" || a.action === action) &&
      `${a.user} ${a.action} ${a.certificate} ${a.server} ${a.ip}`.toLowerCase().includes(q.toLowerCase()),
  );

  return (
    <AppShell>
      <PageHeader
        title="Audit Log"
        subtitle="Append-only record · entries cannot be edited or deleted from the interface"
        actions={
          <Pill tone="info">
            <Lock className="size-3" /> Immutable
          </Pill>
        }
      />

      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-2">
          <div className="relative min-w-52 flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Filter by user, certificate, server, source IP…"
              className="h-7.5 w-full rounded-md border border-input bg-surface pl-8 pr-2 text-[12.5px] outline-none placeholder:text-muted-foreground focus:border-ring"
            />
          </div>
          <select
            value={action}
            onChange={(e) => setAction(e.target.value)}
            className="h-7.5 rounded-md border border-input bg-surface px-2 text-[12.5px] outline-none focus:border-ring"
          >
            <option value="all">All actions</option>
            {actions.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </div>

        <DTable>
          <THead>
            <TH>Timestamp</TH>
            <TH>User</TH>
            <TH>Action</TH>
            <TH>Certificate</TH>
            <TH>Server</TH>
            <TH>Source IP</TH>
            <TH>Result</TH>
          </THead>
          <tbody>
            {rows.map((a, i) => (
              <TRow key={i}>
                <TD className="mono">{a.timestamp}</TD>
                <TD className="text-muted-foreground">{a.user}</TD>
                <TD className="mono font-medium">{a.action}</TD>
                <TD className="mono">{a.certificate}</TD>
                <TD className="mono">{a.server}</TD>
                <TD className="mono">{a.ip}</TD>
                <TD>
                  <Pill
                    tone={a.result === "SUCCESS" ? "ok" : a.result === "WARNING" ? "warn" : "danger"}
                    dot
                  >
                    {a.result}
                  </Pill>
                </TD>
              </TRow>
            ))}
          </tbody>
        </DTable>
      </Panel>
    </AppShell>
  );
}
