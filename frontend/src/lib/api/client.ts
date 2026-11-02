/**
 * Typed fetch wrapper for the Cert Deploy Pro API (same origin, `/api/v1`).
 *
 * - Session is an HttpOnly cookie; we never touch it. `credentials: "include"` is set explicitly.
 * - The CSRF token comes from the `/auth/me` / `/auth/login` response body and is kept in memory only
 *   (never localStorage/sessionStorage) and sent as `X-CSRF-Token` on unsafe methods.
 * - Errors are normalised to {@link ApiError} (`{"error":{code,message,correlation_id,details}}`).
 */
import type { components } from "./schema";

export const API_BASE = "/api/v1";

export type Schemas = components["schemas"];

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly correlationId: string | null;
  readonly details: unknown;

  constructor(opts: {
    status: number;
    code: string;
    message: string;
    correlationId?: string | null;
    details?: unknown;
  }) {
    super(opts.message);
    this.name = "ApiError";
    this.status = opts.status;
    this.code = opts.code;
    this.correlationId = opts.correlationId ?? null;
    this.details = opts.details;
  }

  /** Field level messages from a VALIDATION_ERROR response, if any. */
  get fieldErrors(): { loc: string[]; msg: string }[] {
    const d = this.details as { errors?: { loc: unknown[]; msg: string }[] } | null | undefined;
    return (d?.errors ?? []).map((e) => ({ loc: e.loc.map(String), msg: e.msg }));
  }
}

export const isApiError = (e: unknown): e is ApiError => e instanceof ApiError;
export const isReauthRequired = (e: unknown) => isApiError(e) && e.code === "REAUTH_REQUIRED";

// ---------------------------------------------------------------------------------------------
// CSRF token (memory only)
let csrfToken: string | null = null;
export const setCsrfToken = (t: string | null) => {
  csrfToken = t;
};
export const getCsrfToken = () => csrfToken;

// ---------------------------------------------------------------------------------------------
// 401 handling
let unauthorizedHandler: (() => void) | null = null;
/** Router integration point; the default is a hard redirect to /login. */
export const setUnauthorizedHandler = (fn: (() => void) | null) => {
  unauthorizedHandler = fn;
};

function redirectToLogin() {
  if (typeof window === "undefined") return;
  csrfToken = null;
  if (unauthorizedHandler) return unauthorizedHandler();
  if (window.location.pathname.startsWith("/login")) return;
  const next = window.location.pathname + window.location.search;
  window.location.assign(`/login?next=${encodeURIComponent(next)}`);
}

// ---------------------------------------------------------------------------------------------
export type Query = Record<string, string | number | boolean | null | undefined | string[]>;

export interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  query?: Query | undefined;
  /** JSON body */
  json?: unknown;
  /** multipart/form-data body (Content-Type is set by the browser) */
  form?: FormData;
  headers?: Record<string, string>;
  signal?: AbortSignal | undefined;
  /** Do not redirect to /login on 401 (used by login/reauth where 401 means "wrong credentials"). */
  noAuthRedirect?: boolean;
}

function buildUrl(path: string, query?: Query): string {
  const url = `${API_BASE}${path}`;
  if (!query) return url;
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) v.forEach((x) => sp.append(k, x));
    else sp.set(k, String(v));
  }
  const qs = sp.toString();
  return qs ? `${url}?${qs}` : url;
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  if (typeof window === "undefined") {
    // Data fetching is client-side only: SSR has no cookies for the API.
    throw new ApiError({
      status: 0,
      code: "SSR_NO_FETCH",
      message: "API is only available in the browser",
    });
  }
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json", ...opts.headers };
  let body: BodyInit | null = null;
  if (opts.form) body = opts.form;
  else if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.json);
  }
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;

  let res: Response;
  try {
    res = await fetch(buildUrl(path, opts.query), {
      method,
      headers,
      body,
      credentials: "include",
      ...(opts.signal ? { signal: opts.signal } : {}),
    });
  } catch (e) {
    if ((e as Error)?.name === "AbortError") throw e;
    throw new ApiError({
      status: 0,
      code: "NETWORK_ERROR",
      message: "Cannot reach the API. Check your connection.",
    });
  }

  const correlationId = res.headers.get("X-Correlation-ID");
  if (res.status === 204) return undefined as T;

  const text = await res.text();
  let data: unknown = undefined;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = undefined;
    }
  }

  if (!res.ok) {
    const env = (
      data as {
        error?: { code?: string; message?: string; correlation_id?: string; details?: unknown };
      }
    )?.error;
    const err = new ApiError({
      status: res.status,
      code: env?.code ?? `HTTP_${res.status}`,
      message:
        env?.message ?? (res.status >= 500 ? "Server error" : res.statusText || "Request failed"),
      correlationId: env?.correlation_id ?? correlationId,
      details: env?.details,
    });
    if (res.status === 401 && !opts.noAuthRedirect) redirectToLogin();
    throw err;
  }
  return data as T;
}

export const get = <T>(path: string, query?: Query, signal?: AbortSignal) =>
  request<T>(path, { query, ...(signal ? { signal } : {}) });
export const post = <T>(path: string, json?: unknown, o: RequestOptions = {}) =>
  request<T>(path, { ...o, method: "POST", json });
export const patch = <T>(path: string, json?: unknown, o: RequestOptions = {}) =>
  request<T>(path, { ...o, method: "PATCH", json });
export const del = <T = void>(path: string, o: RequestOptions = {}) =>
  request<T>(path, { ...o, method: "DELETE" });
export const postForm = <T>(path: string, form: FormData, o: RequestOptions = {}) =>
  request<T>(path, { ...o, method: "POST", form });
