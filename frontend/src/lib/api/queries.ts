/**
 * Plain API functions (`api.*`) + TanStack Query hooks. Only call hooks from components (client side):
 * the SSR pass must never hit the API.
 */
import {
  useMutation,
  useQuery,
  useQueryClient,
  keepPreviousData,
  type QueryClient,
} from "@tanstack/react-query";
import {
  API_BASE,
  ApiError,
  del,
  get,
  patch,
  post,
  postForm,
  request,
  setCsrfToken,
  type Query,
} from "./client";
import type {
  AuditEvent,
  Backup,
  CertificateDetail,
  CertificateSummary,
  CertificateVerifyResult,
  ConnectionTestResult,
  Credential,
  DashboardSummary,
  DeploymentJob,
  DeploymentPlan,
  DiscoveryJob,
  Environment,
  EnvironmentCreate,
  EnvironmentUpdate,
  ExpiryTrend,
  HostKeyScan,
  Installation,
  Me,
  Page,
  Server,
  ServerCreate,
  ServerUpdate,
  SettingsSection,
  SettingsSectionName,
  UploadedVersion,
  User,
  VerificationRecord,
} from "./types";

// -------------------------------------------------------------------------------------------
// Query keys
export const qk = {
  me: ["me"] as const,
  users: (p?: Query) => ["users", p ?? {}] as const,
  credentials: ["credentials"] as const,
  servers: {
    all: ["servers"] as const,
    list: (p?: Query) => ["servers", "list", p ?? {}] as const,
    detail: (id: string) => ["servers", "detail", id] as const,
    installations: (id: string) => ["servers", id, "installations"] as const,
  },
  environments: ["environments"] as const,
  settings: ["settings"] as const,
  audit: (p?: Query) => ["audit-events", p ?? {}] as const,
  dashboard: {
    summary: ["dashboard", "summary"] as const,
    trend: ["dashboard", "expiry-trend"] as const,
  },
  certificates: {
    all: ["certificates"] as const,
    list: (p?: Query) => ["certificates", "list", p ?? {}] as const,
    detail: (id: string) => ["certificates", "detail", id] as const,
  },
  installations: {
    all: ["installations"] as const,
    list: (p?: Query) => ["installations", "list", p ?? {}] as const,
  },
  deployments: {
    all: ["deployments"] as const,
    list: (p?: Query) => ["deployments", "list", p ?? {}] as const,
    detail: (id: string) => ["deployments", "detail", id] as const,
    forServer: (id: string, p?: Query) => ["deployments", "server", id, p ?? {}] as const,
  },
  backups: {
    all: ["backups"] as const,
    list: (p?: Query) => ["backups", "list", p ?? {}] as const,
  },
  discoveryJobs: {
    all: ["discovery-jobs"] as const,
    detail: (id: string) => ["discovery-jobs", "detail", id] as const,
    forServer: (id: string) => ["discovery-jobs", "server", id] as const,
  },
  notifications: {
    channels: ["notifications", "channels"] as const,
    rules: ["notifications", "rules"] as const,
    deliveries: ["notifications", "deliveries"] as const,
  },
};

// -------------------------------------------------------------------------------------------
// Plain functions
const enc = encodeURIComponent;

export const api = {
  auth: {
    login: async (b: { username: string; password: string; totp?: string | undefined }) => {
      const me = await post<Me>("/auth/login", b, { noAuthRedirect: true });
      setCsrfToken(me.csrf_token);
      return me;
    },
    me: async () => {
      const me = await get<Me>("/auth/me");
      setCsrfToken(me.csrf_token);
      return me;
    },
    logout: async () => {
      await post<void>("/auth/logout");
      setCsrfToken(null);
    },
    reauth: (b: { password: string; totp?: string | undefined }) =>
      post<void>("/auth/reauth", b, { noAuthRedirect: true }),
    /** Browser navigation target (302 to the IdP); returns 404/501 if OIDC is not configured. */
    oidcLoginUrl: "/api/v1/auth/oidc/login",
  },
  users: {
    list: (q?: Query) => get<Page<User>>("/users", q),
    create: (b: {
      username: string;
      email: string;
      display_name: string;
      password: string;
      roles: string[];
      enabled?: boolean;
    }) => post<User>("/users", b),
    update: (
      id: string,
      b: { email?: string; display_name?: string; enabled?: boolean; password?: string },
    ) => patch<User>(`/users/${id}`, b),
    setRoles: (id: string, roles: string[]) => patch<User>(`/users/${id}/roles`, { roles }),
    remove: (id: string) => del(`/users/${id}`),
  },
  credentials: {
    list: () => get<Credential[]>("/credentials"),
    /** Private key is sent once, as multipart; callers must not keep it in state afterwards. */
    create: (b: { name: string; private_key: string; passphrase?: string | undefined }) => {
      const f = new FormData();
      f.set("name", b.name);
      f.set("private_key", b.private_key);
      if (b.passphrase) f.set("passphrase", b.passphrase);
      return postForm<Credential>("/credentials", f);
    },
    rotate: (id: string, b: { private_key: string; passphrase?: string | undefined }) => {
      const f = new FormData();
      f.set("private_key", b.private_key);
      if (b.passphrase) f.set("passphrase", b.passphrase);
      return postForm<Credential>(`/credentials/${id}/rotate`, f);
    },
    remove: (id: string) => del(`/credentials/${id}`),
  },
  servers: {
    list: (q?: Query) => get<Page<Server>>("/servers", q),
    get: (id: string) => get<Server>(`/servers/${id}`),
    create: (b: ServerCreate) => post<Server>("/servers", b),
    update: (id: string, b: ServerUpdate) => patch<Server>(`/servers/${id}`, b),
    remove: (id: string) => del(`/servers/${id}`),
    enable: (id: string) => post<Server>(`/servers/${id}/enable`),
    disable: (id: string) => post<Server>(`/servers/${id}/disable`),
    scanHostKey: (id: string) => post<HostKeyScan>(`/servers/${id}/host-key/scan`),
    enrollHostKey: (
      id: string,
      b: { public_key: string; fingerprint_sha256: string; replace?: boolean },
    ) => post<Server>(`/servers/${id}/host-key/enroll`, b),
    testConnection: (id: string) => post<ConnectionTestResult>(`/servers/${id}/test-connection`),
    discover: (id: string) => post<DiscoveryJob>(`/servers/${id}/discover`),
    installations: (id: string, q?: Query) =>
      get<Page<Installation>>(`/servers/${id}/installations`, { page_size: 200, ...q }),
    deployments: (id: string, q?: Query) =>
      get<Page<DeploymentJob>>(`/servers/${id}/deployments`, q),
    discoveryJobs: (id: string, q?: Query) =>
      get<Page<DiscoveryJob>>(`/servers/${id}/discovery-jobs`, q),
  },
  environments: {
    list: () => get<Environment[]>("/environments"),
    create: (b: EnvironmentCreate) => post<Environment>("/environments", b),
    update: (id: string, b: EnvironmentUpdate) => patch<Environment>(`/environments/${id}`, b),
    remove: (id: string) => del(`/environments/${id}`),
  },
  settings: {
    getAll: () => get<Record<SettingsSectionName, SettingsSection>>("/settings"),
    patch: (section: SettingsSectionName, version: number, data: Record<string, unknown>) =>
      patch<SettingsSection>(`/settings/${section}`, { version, data }),
  },
  audit: { list: (q?: Query) => get<Page<AuditEvent>>("/audit-events", q) },
  dashboard: {
    summary: () => get<DashboardSummary>("/dashboard/summary"),
    expiryTrend: () => get<ExpiryTrend>("/dashboard/expiry-trend"),
  },

  certificates: {
    list: (q?: Query) => get<Page<CertificateSummary>>("/certificates", q),
    get: (id: string) => get<CertificateDetail>(`/certificates/${id}`),
    verify: (id: string) => post<CertificateVerifyResult>(`/certificates/${id}/verify`),
  },
  installations: {
    list: (q?: Query) => get<Page<Installation>>("/installations", q),
    get: (id: string) => get<Installation>(`/installations/${id}`),
    update: (id: string, b: Record<string, unknown>) =>
      patch<Installation>(`/installations/${id}`, b),
    verify: (id: string) => post<VerificationRecord>(`/installations/${id}/verify`),
  },
  certificateVersions: {
    /** Key material is sent once, as multipart; callers must not keep it in state afterwards. */
    upload: (form: FormData) => postForm<UploadedVersion>("/certificate-versions", form),
    get: (id: string) => get<UploadedVersion>(`/certificate-versions/${id}`),
    validate: (id: string, installation_ids: string[]) =>
      post<UploadedVersion>(`/certificate-versions/${id}/validate`, { installation_ids }),
  },
  deployments: {
    list: (q?: Query) => get<Page<DeploymentJob>>("/deployments", q),
    get: (id: string) => get<DeploymentJob>(`/deployments/${id}`),
    plan: (b: DeploymentRequest) => post<DeploymentPlan>("/deployments/plan", b),
    create: (b: DeploymentRequest, idempotencyKey: string) =>
      request<DeploymentJob>("/deployments", {
        method: "POST",
        json: b,
        headers: { "Idempotency-Key": idempotencyKey },
      }),
    approve: (id: string) => post<DeploymentJob>(`/deployments/${id}/approve`),
    cancel: (id: string) => post<DeploymentJob>(`/deployments/${id}/cancel`),
    retry: (id: string) => post<DeploymentJob>(`/deployments/${id}/retry`),
    rollback: (id: string, targetId: string) =>
      post<RestoreQueued>(`/deployments/${id}/targets/${enc(targetId)}/rollback`),
    /** SSE endpoint URL for EventSource (same origin, cookie auth). */
    eventsUrl: (id: string) => `${API_BASE}/deployments/${id}/events`,
  },
  backups: {
    list: (q?: Query) => get<Page<Backup>>("/backups", q),
    get: (id: string) => get<Backup>(`/backups/${id}`),
    restore: (id: string) => post<RestoreQueued & { backup: Backup }>(`/backups/${id}/restore`),
  },
  discoveryJobs: {
    list: (q?: Query) => get<Page<DiscoveryJob>>("/discovery-jobs", q),
    get: (id: string) => get<DiscoveryJob>(`/discovery-jobs/${id}`),
    bulk: (server_ids: string[]) => post<unknown>("/discovery-jobs/bulk", { server_ids }),
    eventsUrl: (id: string) => `${API_BASE}/discovery-jobs/${id}/events`,
  },
  notifications: {
    channels: () => get<unknown[] | Page<unknown>>("/notifications/channels"),
    rules: () => get<unknown[] | Page<unknown>>("/notifications/rules"),
    deliveries: (q?: Query) => get<Page<unknown>>("/notifications/deliveries", q),
    testChannel: (id: string) => post<unknown>(`/notifications/channels/${id}/test`),
  },
};

// -------------------------------------------------------------------------------------------
// Hooks: queries
export const useMe = () =>
  useQuery({
    queryKey: qk.me,
    queryFn: api.auth.me,
    retry: false,
    staleTime: 60_000,
    refetchOnWindowFocus: true,
  });

export const useServers = (params?: Query) =>
  useQuery({
    queryKey: qk.servers.list(params),
    queryFn: () => api.servers.list(params),
    placeholderData: keepPreviousData,
  });
export const useServer = (id: string) =>
  useQuery({ queryKey: qk.servers.detail(id), queryFn: () => api.servers.get(id) });
export const useServerInstallations = (id: string) =>
  useQuery({
    queryKey: qk.servers.installations(id),
    queryFn: async () => (await api.servers.installations(id)).items,
  });
export const useEnvironments = () =>
  useQuery({ queryKey: qk.environments, queryFn: api.environments.list });
export const useCredentials = (enabled = true) =>
  useQuery({ queryKey: qk.credentials, queryFn: api.credentials.list, enabled });
export const useUsers = (params?: Query, enabled = true) =>
  useQuery({ queryKey: qk.users(params), queryFn: () => api.users.list(params), enabled });
export const useSettings = () => useQuery({ queryKey: qk.settings, queryFn: api.settings.getAll });
export const useAuditEvents = (params?: Query) =>
  useQuery({
    queryKey: qk.audit(params),
    queryFn: () => api.audit.list(params),
    placeholderData: keepPreviousData,
  });
export const useDashboardSummary = () =>
  useQuery({ queryKey: qk.dashboard.summary, queryFn: api.dashboard.summary });
export const useExpiryTrend = () =>
  useQuery({ queryKey: qk.dashboard.trend, queryFn: api.dashboard.expiryTrend });

// -------------------------------------------------------------------------------------------
// Hooks: mutations (each invalidates what it changes)
const invalidateServers = (qc: QueryClient) => {
  void qc.invalidateQueries({ queryKey: qk.servers.all });
  void qc.invalidateQueries({ queryKey: qk.dashboard.summary });
  void qc.invalidateQueries({ queryKey: ["audit-events"] });
};

export function useLogin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.auth.login,
    onSuccess: (me) => qc.setQueryData(qk.me, me),
  });
}
export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.auth.logout,
    onSettled: () => qc.clear(),
  });
}
export const useReauth = () => useMutation({ mutationFn: api.auth.reauth });

export function useCreateServer() {
  const qc = useQueryClient();
  return useMutation({ mutationFn: api.servers.create, onSuccess: () => invalidateServers(qc) });
}
export function useUpdateServer(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (b: ServerUpdate) => api.servers.update(id, b),
    onSuccess: () => invalidateServers(qc),
  });
}
export function useDeleteServer() {
  const qc = useQueryClient();
  return useMutation({ mutationFn: api.servers.remove, onSuccess: () => invalidateServers(qc) });
}
export function useSetServerEnabled() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      enabled ? api.servers.enable(id) : api.servers.disable(id),
    onSuccess: () => invalidateServers(qc),
  });
}
export function useScanHostKey() {
  return useMutation({ mutationFn: api.servers.scanHostKey });
}
export function useEnrollHostKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      ...b
    }: {
      id: string;
      public_key: string;
      fingerprint_sha256: string;
      replace?: boolean;
    }) => api.servers.enrollHostKey(id, b),
    onSuccess: () => invalidateServers(qc),
  });
}
export function useTestConnection() {
  const qc = useQueryClient();
  // The backend persists connection_status / last_connected_at / probe, so refresh the server views.
  return useMutation({
    mutationFn: api.servers.testConnection,
    onSettled: () => invalidateServers(qc),
  });
}
export function useDiscoverServer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.servers.discover,
    onSettled: (_d, _e, id) => {
      invalidateServers(qc);
      void qc.invalidateQueries({ queryKey: qk.discoveryJobs.forServer(id) });
    },
  });
}

export function useCreateCredential() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.credentials.create,
    onSuccess: () => void qc.invalidateQueries({ queryKey: qk.credentials }),
  });
}
export function useRotateCredential() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      ...b
    }: {
      id: string;
      private_key: string;
      passphrase?: string | undefined;
    }) => api.credentials.rotate(id, b),
    onSuccess: () => void qc.invalidateQueries({ queryKey: qk.credentials }),
  });
}
export function useDeleteCredential() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.credentials.remove,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.credentials });
      invalidateServers(qc);
    },
  });
}

export function useEnvironmentMutations() {
  const qc = useQueryClient();
  const done = () => {
    void qc.invalidateQueries({ queryKey: qk.environments });
    void qc.invalidateQueries({ queryKey: ["audit-events"] });
  };
  return {
    create: useMutation({ mutationFn: api.environments.create, onSuccess: done }),
    update: useMutation({
      mutationFn: ({ id, ...b }: { id: string } & EnvironmentUpdate) =>
        api.environments.update(id, b),
      onSuccess: done,
    }),
    remove: useMutation({ mutationFn: api.environments.remove, onSuccess: done }),
  };
}

export function useUserMutations() {
  const qc = useQueryClient();
  const done = () => void qc.invalidateQueries({ queryKey: ["users"] });
  return {
    create: useMutation({ mutationFn: api.users.create, onSuccess: done }),
    update: useMutation({
      mutationFn: ({
        id,
        ...b
      }: {
        id: string;
        enabled?: boolean;
        display_name?: string;
        email?: string;
      }) => api.users.update(id, b),
      onSuccess: done,
    }),
    setRoles: useMutation({
      mutationFn: ({ id, roles }: { id: string; roles: string[] }) => api.users.setRoles(id, roles),
      onSuccess: done,
    }),
    remove: useMutation({ mutationFn: api.users.remove, onSuccess: done }),
  };
}

/** PATCH a settings section with optimistic concurrency. A 409 (`ApiError.status === 409`) means someone else saved first. */
export function useUpdateSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      section,
      version,
      data,
    }: {
      section: SettingsSectionName;
      version: number;
      data: Record<string, unknown>;
    }) => api.settings.patch(section, version, data),
    onSuccess: () => void qc.invalidateQueries({ queryKey: qk.settings }),
    onError: (e) => {
      if (e instanceof ApiError && e.status === 409)
        void qc.invalidateQueries({ queryKey: qk.settings });
    },
  });
}

// -------------------------------------------------------------------------------------------
// Certificates, installations, versions
export const useCertificates = (params?: Query) =>
  useQuery({
    queryKey: qk.certificates.list(params),
    queryFn: () => api.certificates.list(params),
    placeholderData: keepPreviousData,
  });
export const useCertificate = (id: string | null | undefined) =>
  useQuery({
    queryKey: qk.certificates.detail(id ?? ""),
    queryFn: () => api.certificates.get(id as string),
    enabled: !!id,
    // Restores run in a worker: poll while one is in progress so the status settles on screen.
    refetchInterval: (q) =>
      (
        q.state.data as { backups?: { restore_status?: string | null }[] } | undefined
      )?.backups?.some((b) => b.restore_status === "in_progress")
        ? 3000
        : false,
  });

/** Everything that may change after inventory-affecting writes (verify, deploy, restore, discovery). */
export const invalidateInventory = (qc: QueryClient) => {
  void qc.invalidateQueries({ queryKey: qk.certificates.all });
  void qc.invalidateQueries({ queryKey: qk.installations.all });
  void qc.invalidateQueries({ queryKey: qk.servers.all });
  void qc.invalidateQueries({ queryKey: qk.dashboard.summary });
  void qc.invalidateQueries({ queryKey: qk.dashboard.trend });
  void qc.invalidateQueries({ queryKey: ["audit-events"] });
};

export function useVerifyCertificate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.certificates.verify,
    onSettled: () => invalidateInventory(qc),
  });
}
export function useVerifyInstallation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.installations.verify,
    onSettled: () => invalidateInventory(qc),
  });
}
export function useUpdateInstallation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...b }: { id: string } & Record<string, unknown>) =>
      api.installations.update(id, b),
    onSuccess: () => invalidateInventory(qc),
  });
}

// -------------------------------------------------------------------------------------------
// Deployments
export interface DeploymentRequest {
  version_id: string;
  installation_ids: string[];
  strategy: {
    mode: "canary" | "batch" | "all";
    concurrency: number;
    failure_threshold: number;
    continue_on_failure: boolean;
    allow_restart: boolean;
    allow_file_only_verification: boolean;
  };
  acknowledged_warnings: string[];
}

export const useDeployments = (params?: Query) =>
  useQuery({
    queryKey: qk.deployments.list(params),
    queryFn: () => api.deployments.list(params),
    placeholderData: keepPreviousData,
  });
export const useDeployment = (id: string) =>
  useQuery({ queryKey: qk.deployments.detail(id), queryFn: () => api.deployments.get(id) });
export const useServerDeployments = (id: string) =>
  useQuery({
    queryKey: qk.deployments.forServer(id),
    queryFn: () => api.servers.deployments(id, { page_size: 10 }),
  });

export const invalidateDeployments = (qc: QueryClient) => {
  void qc.invalidateQueries({ queryKey: qk.deployments.all });
  void qc.invalidateQueries({ queryKey: qk.backups.all });
  invalidateInventory(qc);
};

export function usePlanDeployment() {
  return useMutation({ mutationFn: api.deployments.plan });
}
export function useCreateDeployment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ body, key }: { body: DeploymentRequest; key: string }) =>
      api.deployments.create(body, key),
    onSuccess: (job) => {
      qc.setQueryData(qk.deployments.detail(job.id), job);
      invalidateDeployments(qc);
    },
  });
}
export function useDeploymentActions() {
  const qc = useQueryClient();
  const done = () => invalidateDeployments(qc);
  return {
    approve: useMutation({ mutationFn: api.deployments.approve, onSuccess: done }),
    cancel: useMutation({ mutationFn: api.deployments.cancel, onSuccess: done }),
    retry: useMutation({ mutationFn: api.deployments.retry, onSuccess: done }),
    rollback: useMutation({
      mutationFn: ({ id, targetId }: { id: string; targetId: string }) =>
        api.deployments.rollback(id, targetId),
      onSettled: done,
    }),
  };
}

export const useBackups = (params?: Query, enabled = true) =>
  useQuery({
    queryKey: qk.backups.list(params),
    queryFn: () => api.backups.list(params),
    enabled,
  });
/** Restores and manual rollbacks are queued (HTTP 202) and run in a worker; follow
 * backup.restore_status and the target status for the outcome. */
export interface RestoreQueued {
  accepted: boolean;
  backup_id: string;
  target_id: string | null;
  job_id: string | null;
  restore_status: string;
  message: string;
}

export function useRestoreBackup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.backups.restore,
    onSettled: () => invalidateDeployments(qc),
  });
}

export const useServerDiscoveryJobs = (id: string) =>
  useQuery({
    queryKey: qk.discoveryJobs.forServer(id),
    queryFn: () => api.servers.discoveryJobs(id, { page_size: 5 }),
  });
