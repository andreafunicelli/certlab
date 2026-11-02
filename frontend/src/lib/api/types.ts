import type { Schemas } from "./client";

export type Page<T> = { items: T[]; total: number; page: number; page_size: number };

export type Me = Schemas["MeResponse"];
export type User = Schemas["UserOut"];
export type Server = Schemas["ServerOut"];
export type ServerCreate = Schemas["ServerCreate"];
export type ServerUpdate = Schemas["ServerUpdate"];
export type HostKeyScan = Schemas["HostKeyScanOut"];
export type Environment = Schemas["EnvironmentOut"];
export type EnvironmentCreate = Schemas["EnvironmentCreate"];
export type EnvironmentUpdate = Schemas["EnvironmentUpdate"];
export type Credential = Schemas["CredentialOut"];
export type AuditEvent = Schemas["AuditEventOut"];
export type SettingsSection = Schemas["SettingsSectionOut"];
export type SettingsSectionName = "general" | "notifications" | "security" | "ssh";

// Responses the OpenAPI spec leaves untyped (dict[str, Any]) --------------------------------

export interface ConnectionStep {
  name: string;
  status: string; // ok | failed | skipped | ...
  detail?: string | null;
  duration_ms?: number | null;
  [k: string]: unknown;
}
export interface ConnectionTestResult {
  ok: boolean;
  steps: ConnectionStep[];
  probe: Record<string, unknown> | null;
  error_code: string | null;
  error_message: string | null;
}

export interface DashboardSummary {
  certificates_total: number;
  installations_total: number;
  certificates_expiring_30: number;
  certificates_expiring_7: number;
  certificates_expired: number;
  servers_total: number;
  servers_enabled: number;
  servers_unreachable: number;
  discovery_errors: number;
  installation_errors: number;
  drift: number;
  failed_deployments_30d: number;
  running_deployments: number;
  recent_deployments: {
    id: string;
    status: string;
    created_at: string;
    finished_at: string | null;
    initiated_by: string | null;
  }[];
  recent_activity: {
    id: string;
    ts: string;
    actor_name: string | null;
    action: string;
    resource_type: string | null;
    resource_id: string | null;
    outcome: string;
  }[];
  generated_at: string;
}
export interface ExpiryTrend {
  buckets: { bucket: string; count: number; tone: "danger" | "crit" | "warn" | "info" | "ok" }[];
  monthly: { month: string; count: number }[];
  generated_at: string;
}

/** Discovery job as returned by POST /servers/{id}/discover (shape owned by the discovery stream). */
export interface DiscoveryJob {
  id: string;
  status: string;
  server_id?: string;
  [k: string]: unknown;
}

/** Loose shapes for endpoints that are not wired yet (certificates, installations, deployments, ...). */
export type Row = Record<string, unknown> & { id: string };
