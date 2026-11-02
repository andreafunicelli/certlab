import { createFileRoute, Link, notFound } from "@tanstack/react-router";
import {
  ArrowLeft,
  CheckCircle2,
  CircleDashed,
  RotateCcw,
  XCircle,
  MinusCircle,
} from "lucide-react";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { Pill } from "@/components/ui/status";
import { getDeployment } from "@/lib/mock-data";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/deployments/$id")({
  loader: ({ params }) => {
    const deployment = getDeployment(params.id);
    if (!deployment) throw notFound();
    return { deployment };
  },
  head: ({ loaderData }) => {
    if (!loaderData) {
      return {
        meta: [
          { title: "Deployment unavailable — Certificate Manager" },
          { name: "robots", content: "noindex" },
        ],
      };
    }
    const t = `Deployment ${loaderData.deployment.certificate} — Certificate Manager`;
    const d = `Per-server steps, logs and rollback timeline for the ${loaderData.deployment.certificate} deployment on ${loaderData.deployment.date}.`;
    return {
      meta: [
        { title: t },
        { name: "description", content: d },
        { property: "og:title", content: t },
        { property: "og:description", content: d },
      ],
    };
  },
  component: DeploymentDetail,
});

function StepIcon({ state }: { state: string }) {
  if (state === "ok") return <CheckCircle2 className="size-3.5 text-ok" />;
  if (state === "failed") return <XCircle className="size-3.5 text-danger" />;
  if (state === "skipped") return <MinusCircle className="size-3.5 text-muted-foreground" />;
  return <CircleDashed className="size-3.5 text-muted-foreground" />;
}

const targetTone = {
  success: { tone: "ok" as const, label: "Deployment Successful" },
  failed: { tone: "danger" as const, label: "Deployment Failed" },
  rolledback: { tone: "warn" as const, label: "Deployment Failed – Automatic Rollback Performed" },
  running: { tone: "info" as const, label: "Running" },
  pending: { tone: "neutral" as const, label: "Pending" },
};

function DeploymentDetail() {
  const { deployment } = Route.useLoaderData();

  return (
    <AppShell>
      <Link
        to="/deployments"
        className="mb-2 inline-flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3.5" /> Deployments
      </Link>

      <PageHeader
        title={
          <span>
            Deploying <span className="mono">{deployment.certificate}</span>
          </span>
        }
        badge={
          <Pill
            tone={
              deployment.status === "Success"
                ? "ok"
                : deployment.status === "Partial Failure"
                  ? "warn"
                  : "danger"
            }
            dot
          >
            {deployment.status}
          </Pill>
        }
        subtitle={`${deployment.date} · by ${deployment.user} · ${deployment.targets} target servers · ${deployment.duration}`}
        actions={
          <Link
            to="/certificates/$id"
            params={{ id: deployment.certificateId }}
            className="inline-flex h-7.5 items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 text-[12.5px] hover:border-primary hover:text-primary"
          >
            Open certificate
          </Link>
        }
      />

      <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
        {deployment.detail.map((t) => {
          const meta = targetTone[t.status];
          return (
            <Panel
              key={t.serverName}
              title={
                <span className="flex items-center gap-2">
                  <span className="mono">{t.serverName}</span>
                  <span className="mono text-muted-foreground">{t.ip}</span>
                </span>
              }
              actions={
                <Pill tone={meta.tone} dot>
                  {t.status === "rolledback" ? "Rolled Back" : meta.label}
                </Pill>
              }
            >
              <div className="space-y-0.5 p-3">
                {t.steps.map((s) => (
                  <div key={s.label} className="flex items-start gap-2 text-[12px]">
                    <span className="mt-0.5">
                      <StepIcon state={s.state} />
                    </span>
                    <div>
                      <span
                        className={cn(
                          s.state === "failed" && "text-danger",
                          s.state === "skipped" && "text-muted-foreground line-through",
                        )}
                      >
                        {s.label}
                      </span>
                      {s.detail && <div className="mono text-[11px] text-muted-foreground">{s.detail}</div>}
                    </div>
                  </div>
                ))}

                {t.error && (
                  <pre className="mono mt-2 overflow-x-auto rounded-sm border border-danger/40 bg-danger-soft p-2 text-[11px] text-danger">
{t.error}
                  </pre>
                )}

                {t.status === "rolledback" && (
                  <div className="mt-2 flex items-center gap-1.5 text-[11.5px] text-warn">
                    <RotateCcw className="size-3.5" /> Previous certificate and key restored from backup
                  </div>
                )}

                {t.timeline && (
                  <div className="mt-3 border-t border-border pt-2">
                    <div className="mb-1.5 text-[11px] uppercase tracking-[0.06em] text-muted-foreground">
                      Timeline
                    </div>
                    <ol className="space-y-1">
                      {t.timeline.map((e, i) => (
                        <li key={i} className="flex gap-2 text-[11.5px]">
                          <span className="mono shrink-0 text-muted-foreground">{e.time}</span>
                          <span
                            className={cn(
                              "mono",
                              e.kind === "fail" && "text-danger",
                              e.kind === "warn" && "text-warn",
                              e.kind === "ok" && "text-foreground",
                            )}
                          >
                            {e.text}
                          </span>
                        </li>
                      ))}
                    </ol>
                  </div>
                )}
              </div>
            </Panel>
          );
        })}
      </div>
    </AppShell>
  );
}
