import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Bell, Lock, Server, SlidersHorizontal, ShieldCheck } from "lucide-react";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { Pill } from "@/components/ui/status";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/settings")({
  head: () => ({
    meta: [
      { title: "Settings — Certificate Manager" },
      {
        name: "description",
        content:
          "Configure expiration warnings, notification rules, roles, session security and global SSH defaults.",
      },
      { property: "og:title", content: "Settings — Certificate Manager" },
      {
        property: "og:description",
        content: "Application, notification, security and SSH configuration.",
      },
    ],
  }),
  component: SettingsPage,
});

const inputCls =
  "h-8 w-full rounded-md border border-input bg-surface px-2 text-[12.5px] outline-none focus:border-ring";
const labelCls = "mb-1 block text-[11.5px] uppercase tracking-[0.05em] text-muted-foreground";

const tabs = [
  { id: "general", label: "General", icon: SlidersHorizontal },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "security", label: "Security", icon: ShieldCheck },
  { id: "ssh", label: "SSH", icon: Server },
];

function Toggle({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!on)}
      className={cn(
        "h-4.5 w-8 rounded-full border transition-colors",
        on ? "border-primary bg-primary/70" : "border-border bg-muted",
      )}
    >
      <span
        className={cn(
          "block size-3 rounded-full bg-background transition-transform",
          on ? "translate-x-4" : "translate-x-0.5",
        )}
      />
    </button>
  );
}

function SettingsPage() {
  const [tab, setTab] = useState("general");
  const [rules, setRules] = useState<Record<string, boolean>>({
    "90": true,
    "60": true,
    "30": true,
    "15": true,
    "7": true,
    "1": true,
  });
  const [channels, setChannels] = useState<Record<string, boolean>>({
    Email: true,
    Telegram: false,
    Webhook: false,
  });
  const [mfa, setMfa] = useState(true);
  const [hostKey, setHostKey] = useState(true);

  return (
    <AppShell>
      <PageHeader title="Settings" subtitle="Platform configuration · changes are recorded in the audit log" />

      <div className="flex flex-wrap gap-1.5 border-b border-border pb-2">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={cn(
              "inline-flex h-7 items-center gap-1.5 rounded-md border px-2.5 text-[12px]",
              tab === t.id
                ? "border-primary/40 bg-primary/12 text-primary"
                : "border-border bg-surface text-muted-foreground hover:text-foreground",
            )}
          >
            <t.icon className="size-3.5" /> {t.label}
          </button>
        ))}
      </div>

      <div className="mt-3 grid gap-3 lg:grid-cols-2">
        {tab === "general" && (
          <Panel title="General">
            <div className="grid gap-3 p-3 sm:grid-cols-2">
              <div>
                <label className={labelCls}>Application Name</label>
                <input className={inputCls} defaultValue="Certificate Manager" />
              </div>
              <div>
                <label className={labelCls}>Timezone</label>
                <select className={inputCls} defaultValue="Europe/Rome">
                  <option>Europe/Rome</option>
                  <option>UTC</option>
                  <option>Europe/London</option>
                </select>
              </div>
              <div>
                <label className={labelCls}>Default Expiration Warning</label>
                <select className={inputCls} defaultValue="30 days">
                  <option>15 days</option>
                  <option>30 days</option>
                  <option>60 days</option>
                </select>
              </div>
              <div>
                <label className={labelCls}>Inventory Scan Schedule</label>
                <select className={inputCls} defaultValue="Daily 02:00">
                  <option>Hourly</option>
                  <option>Daily 02:00</option>
                  <option>Weekly</option>
                </select>
              </div>
            </div>
          </Panel>
        )}

        {tab === "notifications" && (
          <>
            <Panel title="Notification Rules">
              <div className="p-3">
                <p className="mb-2 text-[12px] text-muted-foreground">
                  Notify when a certificate has the following days remaining:
                </p>
                {Object.keys(rules).map((d) => (
                  <div
                    key={d}
                    className="flex items-center justify-between border-b border-border/60 py-1.5 last:border-0"
                  >
                    <span className="text-[12.5px]">
                      <span className="mono">{d}</span> days remaining
                    </span>
                    <Toggle on={rules[d]!} onChange={(v) => setRules((r) => ({ ...r, [d]: v }))} />
                  </div>
                ))}
              </div>
            </Panel>
            <Panel title="Channels">
              <div className="p-3">
                {Object.keys(channels).map((c) => (
                  <div
                    key={c}
                    className="flex items-center justify-between border-b border-border/60 py-2 last:border-0"
                  >
                    <div>
                      <div className="text-[12.5px]">{c}</div>
                      <div className="text-[11.5px] text-muted-foreground">
                        {c === "Email"
                          ? "it-infra@youco.cloud"
                          : c === "Telegram"
                            ? "Bot integration (planned)"
                            : "POST JSON to an internal endpoint (planned)"}
                      </div>
                    </div>
                    <Toggle on={channels[c]!} onChange={(v) => setChannels((s) => ({ ...s, [c]: v }))} />
                  </div>
                ))}
              </div>
            </Panel>
          </>
        )}

        {tab === "security" && (
          <>
            <Panel title="Session & Authentication">
              <div className="space-y-3 p-3">
                <div>
                  <label className={labelCls}>Session Timeout</label>
                  <select className={inputCls} defaultValue="30 minutes">
                    <option>15 minutes</option>
                    <option>30 minutes</option>
                    <option>8 hours</option>
                  </select>
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-[12.5px]">Multi-factor authentication</div>
                    <div className="text-[11.5px] text-muted-foreground">TOTP required for Administrators</div>
                  </div>
                  <Toggle on={mfa} onChange={setMfa} />
                </div>
              </div>
            </Panel>
            <Panel title="Role Based Access Control">
              <div className="p-3">
                {[
                  ["Administrator", "Full access: servers, certificates, deployments, settings", "danger"],
                  ["Operator", "Upload and deploy certificates; cannot change servers or settings", "warn"],
                  ["Read Only", "Inventory and audit visibility only", "info"],
                ].map(([r, d, tone]) => (
                  <div
                    key={r}
                    className="flex items-start justify-between gap-3 border-b border-border/60 py-2 last:border-0"
                  >
                    <div>
                      <div className="text-[12.5px] font-medium">{r}</div>
                      <div className="text-[11.5px] text-muted-foreground">{d}</div>
                    </div>
                    <Pill tone={tone as "danger" | "warn" | "info"}>{r === "Administrator" ? "2 users" : r === "Operator" ? "5 users" : "9 users"}</Pill>
                  </div>
                ))}
              </div>
            </Panel>
          </>
        )}

        {tab === "ssh" && (
          <Panel title="SSH Defaults">
            <div className="grid gap-3 p-3 sm:grid-cols-2">
              <div>
                <label className={labelCls}>Global SSH Timeout</label>
                <input className={inputCls} defaultValue="15 seconds" />
              </div>
              <div>
                <label className={labelCls}>Default SSH Port</label>
                <input className={inputCls} defaultValue="22" />
              </div>
              <div className="sm:col-span-2 flex items-center justify-between rounded-md border border-border bg-surface-2/40 p-2.5">
                <div>
                  <div className="text-[12.5px]">SSH Host Key Verification</div>
                  <div className="text-[11.5px] text-muted-foreground">
                    Reject connections to servers with unknown or changed host keys
                  </div>
                </div>
                <Toggle on={hostKey} onChange={setHostKey} />
              </div>
              <div className="sm:col-span-2 flex items-center gap-2 rounded-md border border-info/30 bg-info-soft p-2.5 text-[11.5px]">
                <Lock className="size-3.5 shrink-0 text-info" />
                Private SSH key material is stored encrypted and is never exposed through the interface or
                the API.
              </div>
            </div>
          </Panel>
        )}
      </div>
    </AppShell>
  );
}
