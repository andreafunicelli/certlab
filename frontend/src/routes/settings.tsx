import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import {
  Bell,
  KeyRound,
  Layers,
  Lock,
  Server,
  ShieldCheck,
  SlidersHorizontal,
  Users,
} from "lucide-react";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { Pill } from "@/components/ui/status";
import { EmptyState, ErrorState, LoadingBlock } from "@/components/ui/feedback";
import { SectionForm, type FieldDef } from "@/components/settings/SectionForm";
import { EnvironmentsPanel } from "@/components/settings/EnvironmentsPanel";
import { UsersPanel } from "@/components/settings/UsersPanel";
import { CredentialsPanel } from "@/components/settings/CredentialsPanel";
import { useSettings, useUsers } from "@/lib/api/queries";
import type { SettingsSectionName } from "@/lib/api/types";
import { useCan } from "@/lib/auth";
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

const GENERAL: FieldDef[] = [
  { path: "app_name", label: "Application Name", kind: "text" },
  { path: "timezone", label: "Timezone", kind: "timezone", help: "IANA name, e.g. Europe/Rome" },
  {
    path: "inventory_refresh_minutes",
    label: "Inventory refresh (minutes)",
    kind: "number",
    min: 5,
    max: 10080,
  },
  {
    path: "backup_retention_days",
    label: "Backup retention (days)",
    kind: "number",
    min: 1,
    max: 3650,
  },
];
const NOTIFICATIONS: FieldDef[] = [
  { path: "thresholds.info", label: "Info threshold (days)", kind: "number", min: 1, max: 730 },
  {
    path: "thresholds.warning",
    label: "Warning threshold (days)",
    kind: "number",
    min: 1,
    max: 730,
  },
  { path: "thresholds.high", label: "High threshold (days)", kind: "number", min: 1, max: 730 },
  {
    path: "thresholds.critical",
    label: "Critical threshold (days)",
    kind: "number",
    min: 1,
    max: 730,
    help: "Must satisfy info > warning > high > critical.",
  },
];
const SECURITY: FieldDef[] = [
  {
    path: "session_minutes",
    label: "Session timeout (minutes)",
    kind: "number",
    min: 5,
    max: 43200,
  },
  {
    path: "reauth_minutes",
    label: "Re-authentication window (minutes)",
    kind: "number",
    min: 1,
    max: 240,
    help: "How long a password confirmation stays valid for sensitive actions.",
  },
  {
    path: "require_production_approval",
    label: "Require approval for production deployments",
    kind: "toggle",
    help: "A second user must approve deployments to production environments.",
  },
];
const SSH: FieldDef[] = [
  { path: "default_port", label: "Default SSH Port", kind: "number", min: 1, max: 65535 },
  { path: "connect_timeout", label: "Connect timeout (s)", kind: "number", min: 1, max: 120 },
  { path: "command_timeout", label: "Command timeout (s)", kind: "number", min: 1, max: 3600 },
  {
    path: "deployment_concurrency",
    label: "Deployment concurrency",
    kind: "number",
    min: 1,
    max: 50,
  },
  { path: "failure_threshold", label: "Failure threshold", kind: "number", min: 0, max: 100 },
  { path: "discovery_max_depth", label: "Discovery max depth", kind: "number", min: 1, max: 20 },
  {
    path: "discovery_max_files",
    label: "Discovery max files",
    kind: "number",
    min: 10,
    max: 100000,
  },
  {
    path: "canary",
    label: "Canary first target",
    kind: "toggle",
    help: "Deploy to a single target first and continue only if it verifies.",
  },
  { path: "discovery_roots", label: "Discovery roots (one per line)", kind: "lines", wide: true },
  {
    path: "discovery_exclude",
    label: "Discovery exclude patterns (one per line)",
    kind: "lines",
    wide: true,
  },
];

const FIELDS: Record<SettingsSectionName, { title: string; fields: FieldDef[] }> = {
  general: { title: "General", fields: GENERAL },
  notifications: { title: "Expiration thresholds", fields: NOTIFICATIONS },
  security: { title: "Session & Security", fields: SECURITY },
  ssh: { title: "SSH Defaults", fields: SSH },
};

function RbacPanel() {
  const canUsers = useCan("users:read");
  const users = useUsers({ page_size: 200 }, canUsers);
  const count = (r: string) => users.data?.items.filter((u) => u.roles.includes(r)).length;
  return (
    <Panel title="Role Based Access Control">
      <div className="p-3">
        {(
          [
            [
              "admin",
              "Administrator",
              "Full access: servers, credentials, certificates, deployments, settings, users",
              "danger",
            ],
            [
              "operator",
              "Operator",
              "Upload and deploy certificates, run discovery and tests; cannot change servers or settings",
              "warn",
            ],
            ["viewer", "Read Only", "Inventory, deployments and audit visibility only", "info"],
          ] as const
        ).map(([r, label, d, tone]) => (
          <div
            key={r}
            className="flex items-start justify-between gap-3 border-b border-border/60 py-2 last:border-0"
          >
            <div>
              <div className="text-[12.5px] font-medium">{label}</div>
              <div className="text-[11.5px] text-muted-foreground">{d}</div>
            </div>
            {count(r) !== undefined && <Pill tone={tone}>{count(r)} users</Pill>}
          </div>
        ))}
      </div>
    </Panel>
  );
}

function NotificationChannelsPlaceholder() {
  return (
    <Panel title="Channels">
      <EmptyState
        title="Notification channels are not configured yet"
        hint="Email, webhook and Telegram delivery will be managed here once the notifications service is enabled."
      />
    </Panel>
  );
}

function SettingsPage() {
  const [tab, setTab] = useState<string>("general");
  const settings = useSettings();
  const canWrite = useCan("settings:write");
  const canUsers = useCan("users:read");
  const canCreds = useCan("credentials:read");
  const [conflict, setConflict] = useState<Record<string, boolean>>({});

  const tabs = [
    { id: "general", label: "General", icon: SlidersHorizontal },
    { id: "notifications", label: "Notifications", icon: Bell },
    { id: "security", label: "Security", icon: ShieldCheck },
    { id: "ssh", label: "SSH", icon: Server },
    { id: "environments", label: "Environments", icon: Layers },
    ...(canUsers ? [{ id: "users", label: "Users & Roles", icon: Users }] : []),
    ...(canCreds ? [{ id: "credentials", label: "Credentials", icon: KeyRound }] : []),
  ];

  const isSection = (t: string): t is SettingsSectionName => t in FIELDS;

  return (
    <AppShell>
      <PageHeader
        title="Settings"
        subtitle="Platform configuration · changes are recorded in the audit log"
      />

      <div className="flex flex-wrap gap-1.5 border-b border-border pb-2" role="tablist">
        {tabs.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
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
        {isSection(tab) &&
          (settings.isLoading ? (
            <Panel className="lg:col-span-2">
              <LoadingBlock />
            </Panel>
          ) : settings.isError || !settings.data ? (
            <Panel className="lg:col-span-2">
              <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />
            </Panel>
          ) : (
            <>
              {conflict[tab] && (
                <div
                  className="rounded-md border border-warn/40 bg-warn-soft p-2.5 text-[12px] text-warn lg:col-span-2"
                  role="alert"
                >
                  This section was modified by someone else while you were editing. Your changes
                  were not saved and the latest values are shown.
                </div>
              )}
              <SectionForm
                key={`${tab}-${settings.data[tab].version}`}
                section={tab}
                title={FIELDS[tab].title}
                fields={FIELDS[tab].fields}
                data={settings.data[tab]}
                canWrite={canWrite}
                onConflict={() => setConflict((c) => ({ ...c, [tab]: true }))}
                onSaved={() => setConflict((c) => ({ ...c, [tab]: false }))}
              />
              {tab === "notifications" && <NotificationChannelsPlaceholder />}
              {tab === "security" && <RbacPanel />}
              {tab === "ssh" && (
                <div className="flex items-start gap-2 self-start rounded-md border border-info/30 bg-info-soft p-2.5 text-[11.5px]">
                  <Lock className="mt-0.5 size-3.5 shrink-0 text-info" />
                  Host keys are always verified strictly: unknown or changed keys are refused.
                  Private SSH keys are stored encrypted and are never exposed through the interface
                  or the API.
                </div>
              )}
            </>
          ))}
        {tab === "environments" && <EnvironmentsPanel />}
        {tab === "users" && canUsers && <UsersPanel />}
        {tab === "credentials" && canCreds && <CredentialsPanel />}
      </div>
    </AppShell>
  );
}
