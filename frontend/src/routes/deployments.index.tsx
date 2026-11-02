import { createFileRoute, Link } from "@tanstack/react-router";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { Pill } from "@/components/ui/status";
import { deployments } from "@/lib/mock-data";

export const Route = createFileRoute("/deployments/")({
  head: () => ({
    meta: [
      { title: "Deployments — Certificate Manager" },
      {
        name: "description",
        content: "History of certificate deployments to Nginx servers, with per-server results and logs.",
      },
      { property: "og:title", content: "Deployments — Certificate Manager" },
      {
        property: "og:description",
        content: "Certificate deployment history with success, failure and rollback outcomes.",
      },
    ],
  }),
  component: DeploymentsPage,
});

export function statusTone(status: string) {
  return status === "Success"
    ? "ok"
    : status === "Partial Failure"
      ? "warn"
      : status === "Failed"
        ? "danger"
        : "info";
}

function DeploymentsPage() {
  return (
    <AppShell>
      <PageHeader
        title="Deployments"
        subtitle="Every deployment is atomic per server: backup → copy → nginx -t → reload → TLS verify"
      />
      <Panel>
        <DTable>
          <THead>
            <TH>Date</TH>
            <TH>Certificate</TH>
            <TH>User</TH>
            <TH align="right">Targets</TH>
            <TH align="right">Success</TH>
            <TH align="right">Failed</TH>
            <TH align="right">Duration</TH>
            <TH>Status</TH>
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
                    {d.date}
                  </Link>
                </TD>
                <TD className="mono">{d.certificate}</TD>
                <TD className="text-muted-foreground">{d.user}</TD>
                <TD align="right" className="mono tabular-nums">
                  {d.targets}
                </TD>
                <TD align="right" className="mono tabular-nums text-ok">
                  {d.succeeded}
                </TD>
                <TD align="right" className="mono tabular-nums text-danger">
                  {d.failed}
                </TD>
                <TD align="right" className="mono">
                  {d.duration}
                </TD>
                <TD>
                  <Pill tone={statusTone(d.status)} dot>
                    {d.status}
                  </Pill>
                </TD>
              </TRow>
            ))}
          </tbody>
        </DTable>
      </Panel>
      <p className="mt-2 text-[11.5px] text-muted-foreground">
        Select a deployment to open its complete per-server log and rollback timeline.
      </p>
    </AppShell>
  );
}
