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

// -------------------------------------------------------------------------------------------
// Inventory / deployments. The backend returns plain dicts for these (not in the OpenAPI schema), so the
// shapes are declared here from backend/app/services/{inventory,uploads,deployments,discovery,backups}.py.

export type ExpiryStatus = "valid" | "info" | "warning" | "high" | "critical" | "expired";
export type Classification =
  "managed" | "unmanaged" | "requires_mapping" | "unsupported" | "unreadable" | "error";
export type DriftStatus = "in_sync" | "drifted" | "missing" | "unknown";

export interface CertificateSummary {
  id: string;
  common_name: string;
  subject: string;
  issuer: string;
  sans: string[];
  serial_number: string;
  fingerprint_sha256: string;
  not_before: string;
  not_after: string;
  public_key_algorithm: string;
  public_key_size: number | null;
  signature_algorithm: string;
  certificate_type: string;
  status: string;
  days_remaining: number;
  expiry_status: ExpiryStatus;
  installation_count: number;
  server_count: number;
  owner: string | null;
  tags: string[];
  discovery_source: string | null;
  created_at: string;
  updated_at: string;
}

export interface VerificationRecord {
  installation_id?: string;
  endpoint: { host: string; port: number; sni: string | null } | null;
  ok: boolean;
  error: string | null;
  served_fingerprint: string | null;
  served_not_after?: string | null;
  served_common_name?: string | null;
  expected_fingerprint?: string | null;
  matches_file: boolean | null;
  chain_valid: boolean | null;
  hostname_matches: boolean | null;
  tls_version?: string | null;
  checked_at: string;
  [k: string]: unknown;
}

export interface Installation {
  id: string;
  certificate_id: string | null;
  certificate: {
    id: string;
    common_name: string;
    fingerprint_sha256: string;
    not_after: string;
    days_remaining: number;
    expiry_status: ExpiryStatus;
  } | null;
  server_id: string;
  server_name: string | null;
  server_address: string | null;
  environment: string | null;
  service_type: string;
  service_identifier: string | null;
  cert_path: string | null;
  key_path: string | null;
  chain_path: string | null;
  is_combined_pem: boolean;
  listen_port: number | null;
  config_file: string | null;
  vhost: string | null;
  server_names: string[];
  last_observed_fingerprint: string | null;
  last_observed_at: string | null;
  last_deployment_id: string | null;
  drift_status: DriftStatus;
  classification: Classification;
  discovery_confidence: number | null;
  managed_by_certbot: boolean;
  verify_host: string | null;
  verify_port: number | null;
  verify_sni: string | null;
  last_verification: VerificationRecord | null;
  missing_since: string | null;
  owner: string | null;
  tags: string[];
  file_metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface CertificateVersionRow {
  id: string;
  fingerprint_sha256: string;
  validation_status: string;
  status: string;
  reuses_existing_key: boolean;
  uploaded_by: string | null;
  created_at: string;
  not_after: string | null;
  common_name: string | null;
}
export interface CertDeploymentRow {
  id: string;
  status: string;
  created_at: string;
  finished_at: string | null;
  version_id: string;
  target_id: string;
  target_status: string;
  installation_id: string;
  server_id: string;
  previous_fingerprint: string | null;
  new_fingerprint: string | null;
}
export interface BackupRow {
  id: string;
  server_id: string;
  installation_id: string | null;
  created_at: string;
  verified: boolean;
  restore_status: string | null;
  retention_until: string | null;
}
export interface CertificateDetail extends CertificateSummary {
  pem: string;
  chain_info: unknown;
  is_ca: boolean;
  installations: Installation[];
  versions: CertificateVersionRow[];
  deployments: CertDeploymentRow[];
  backups: BackupRow[];
  drift: Record<DriftStatus, number> & { installation_ids: string[] };
}

export interface CertificateVerifyResult {
  certificate_id: string;
  summary: { total: number; matching: number; mismatching: number; failed: number };
  results: VerificationRecord[];
}

export type FindingSeverity = "blocking" | "warning" | "info";
export interface Finding {
  code: string;
  severity: FindingSeverity;
  message: string;
  details?: Record<string, unknown>;
  installation_id?: string | null;
}
export interface LeafInfo {
  subject: string;
  issuer: string;
  common_name: string | null;
  sans: string[];
  serial_number: string;
  fingerprint_sha256: string;
  not_before: string;
  not_after: string;
  days_remaining: number;
  public_key_algorithm: string;
  public_key_size: number | null;
  public_key_sha256?: string;
  signature_algorithm: string;
  is_ca?: boolean;
  is_self_signed?: boolean;
}
export interface UploadedVersion {
  id: string;
  certificate_id: string | null;
  fingerprint_sha256: string;
  leaf: LeafInfo;
  chain: LeafInfo[];
  findings: Finding[];
  validation_status: string; // valid | warnings | invalid
  status: string;
  reuses_existing_key: boolean;
  has_private_key: boolean;
  created_at: string;
}

// ---- deployments
export type DeploymentStatus =
  | "pending"
  | "awaiting_approval"
  | "preflight"
  | "activating"
  | "completed"
  | "partially_failed"
  | "failed"
  | "rolled_back"
  | "manual_intervention_required"
  | "cancelled";

export interface DeploymentStrategy {
  mode: "canary" | "batch" | "all";
  concurrency: number;
  failure_threshold: number;
  continue_on_failure: boolean;
  allow_restart: boolean;
  allow_file_only_verification: boolean;
  [k: string]: unknown;
}

export interface TargetStep {
  name: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  detail: Record<string, unknown> | string | null;
  error_code: string | null;
}
export interface TargetFile {
  dest_path: string;
  realpath: string | null;
  artifact: string;
  action: string;
  mode: string | number | null;
  owner: string | null;
  group: string | null;
  is_symlink: boolean;
}
export interface TargetVerification {
  mode: string;
  expected_fingerprint?: string;
  endpoints: {
    host: string;
    port: number;
    sni?: string | null;
    reachable?: boolean;
    served_fingerprint?: string | null;
    chain_valid?: boolean | null;
    hostname_matches?: boolean | null;
    error?: string | null;
    file_only?: boolean;
    attempts?: number;
  }[];
  files: { path: string; sha256: string; mode: string | number | null; owner: string | null }[];
  chain_valid?: boolean | null;
  verified_at?: string;
}
export interface DeploymentTarget {
  id: string;
  job_id: string;
  installation_id: string | null;
  server_id: string;
  server_name: string | null;
  service_type: string | null;
  vhost: string | null;
  cert_path: string | null;
  batch_index: number;
  is_canary: boolean;
  status: string;
  current_step: string | null;
  previous_fingerprint: string | null;
  new_fingerprint: string | null;
  backup_id: string | null;
  rollback_attempts: number;
  verification: TargetVerification | null;
  error_code: string | null;
  error_message: string | null;
  shared_with: unknown[];
  steps?: TargetStep[];
  log?: { ts: string; level: string; message: string }[];
  files?: TargetFile[];
  created_at: string;
  updated_at: string;
}
export interface DeploymentJob {
  id: string;
  version_id: string;
  certificate_id: string | null;
  new_fingerprint: string | null;
  status: DeploymentStatus | string;
  strategy: Partial<DeploymentStrategy> | null;
  approval_required: boolean;
  approved_by: string | null;
  approved_at: string | null;
  initiated_by: string | null;
  initiated_by_name: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  rollback_status: string | null;
  error_summary: string | null;
  cancel_requested: boolean;
  acknowledged_warnings: string[];
  retry_of: string | null;
  target_counts: Record<string, number>;
  target_total: number;
  targets?: DeploymentTarget[];
  plan?: unknown;
}

export interface PlanFile {
  dest_path: string;
  realpath: string | null;
  artifact: string;
  action: "replace" | "keep";
  is_symlink?: boolean;
  symlink_target?: string | null;
  mode?: string | number | null;
  owner?: string | null;
  group?: string | null;
  contains_private_key?: boolean;
  current_sha256?: string | null;
  new_sha256?: string;
  size?: number;
  selinux_context?: string | null;
}
export interface PlanTarget {
  installation_id: string;
  server_id: string;
  server_name: string;
  environment: string;
  service_type: string;
  vhost: string | null;
  server_names: string[];
  files: PlanFile[];
  backups: string[];
  reload: { service: string; mode: string; allow_restart: boolean } | null;
  config_test: { supported: boolean; current_ok: boolean; output: string } | null;
  verify_endpoints: {
    host: string;
    port: number;
    sni?: string | null;
    reachable?: boolean;
    served_fingerprint?: string | null;
    error?: string | null;
  }[];
  rollback: string | null;
  disk: { free_bytes: number; required_bytes: number } | null;
  privilege: { mode: string; helper_version: string | null; os: string | null } | null;
  current_fingerprint: string | null;
  new_fingerprint: string;
  shared_with: unknown[];
  unit: string | null;
  is_canary: boolean;
  batch_index: number;
  verification_mode: string;
}
export interface DeploymentPlan {
  generated_at: string;
  version: {
    id: string;
    fingerprint_sha256: string;
    subject: string;
    sans: string[];
    not_after: string;
    reuses_existing_key: boolean;
    has_private_key: boolean;
  };
  strategy: DeploymentStrategy;
  targets: PlanTarget[];
  findings: Finding[];
  summary: {
    targets: number;
    blocking: number;
    warnings: number;
    unacknowledged_warnings: string[];
    can_proceed: boolean;
  };
  read_only: boolean;
}

export interface BackupFile {
  path?: string;
  dest_path?: string;
  sha256?: string;
  mode?: string | number | null;
  owner?: string | null;
  group?: string | null;
  size?: number;
  [k: string]: unknown;
}
export interface Backup {
  id: string;
  server_id: string;
  installation_id: string | null;
  deployment_target_id: string | null;
  deployment_id: string | null;
  created_at: string;
  verified: boolean;
  retention_until: string | null;
  restore_status: string | null;
  restored_at: string | null;
  integrity_sha256: string | null;
  file_count: number;
  files: BackupFile[];
}

// ---- discovery
export interface DiscoveryFindingRow {
  id: string;
  path: string;
  classification: string;
  message: string | null;
  details: Record<string, unknown> | null;
  created_at: string;
}
export interface DiscoveryStats {
  findings?: number;
  services?: string[];
  references?: number;
  duration_ms?: number;
  marked_missing?: number;
  failed_services?: Record<string, string>;
  by_classification?: Record<string, number>;
  certificates_created?: number;
  installations_created?: number;
  installations_updated?: number;
}
export type DiscoveryJobStatus =
  "pending" | "running" | "completed" | "partial" | "failed" | "cancelled";
export type DiscoveryStepStatus = "pending" | "running" | "ok" | "warning" | "failed" | "skipped";
export interface DiscoveryStep {
  name: string;
  label: string;
  status: DiscoveryStepStatus | string;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  detail: Record<string, unknown> | null;
  error_code: string | null;
}
export interface DiscoveryLogEntry {
  ts: string;
  level: "info" | "warning" | "error" | string;
  step: string | null;
  message: string;
  details?: Record<string, unknown> | null;
}
/** Row of GET /servers/{id}/discovery-jobs. */
export interface DiscoveryJobSummary {
  id: string;
  status: DiscoveryJobStatus | string;
  requested_by_name: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  error: string | null;
  error_code: string | null;
  hint: string | null;
  warnings_count: number;
  stats: DiscoveryStats | null;
}
/** Discovery job as returned by POST /servers/{id}/discover, GET /discovery-jobs/{id}. */
export interface DiscoveryJob extends DiscoveryJobSummary {
  server_id: string;
  server_name?: string | null;
  requested_by?: string | null;
  scheduled?: boolean;
  steps?: DiscoveryStep[] | undefined;
  log?: DiscoveryLogEntry[] | undefined;
  findings?: DiscoveryFindingRow[] | undefined;
}
export interface DiscoveryProgress {
  type: string;
  status?: string;
  stage?: string;
  percent?: number;
  message?: string;
  [k: string]: unknown;
}

/** Loose shape kept for endpoints that are not modelled. */
export type Row = Record<string, unknown> & { id: string };

// ---- server update / host keys / CSV import
export type ServerUpdateResult = Server & { host_key_reset?: boolean };

export interface HostKeyScanItem {
  server_id: string;
  server_name: string;
  endpoint: string | null;
  key_type: string | null;
  fingerprint_sha256: string | null;
  public_key: string | null;
  enrolled_fingerprint: string | null;
  matches_enrolled: boolean | null;
  error_code: string | null;
  error: string | null;
}
export interface HostKeyEnrollItem {
  server_id: string;
  public_key: string;
  fingerprint_sha256: string;
}
export interface HostKeyEnrollResult {
  server_id: string;
  status: "enrolled" | "error";
  error_code: string | null;
  error: string | null;
}

export type ImportOnConflict = "error" | "skip";
export type ImportRowStatus = "valid" | "error" | "skipped" | "created";
export type ImportHostKeyStatus =
  "not_provided" | "enrolled" | "mismatch" | "unreachable" | "pending";
export interface ImportRow {
  row: number;
  name: string | null;
  hostname?: string | null;
  status: ImportRowStatus;
  errors: { field: string | null; message: string }[];
  server_id: string | null;
  host_key: {
    status: ImportHostKeyStatus;
    fingerprint_expected: string | null;
    fingerprint_seen: string | null;
    error: string | null;
  } | null;
}
export interface ImportResult {
  dry_run: boolean;
  delimiter: string;
  total: number;
  valid: number;
  invalid: number;
  skipped: number;
  created: number;
  rows: ImportRow[];
}
