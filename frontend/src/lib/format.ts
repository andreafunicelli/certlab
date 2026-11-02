import { formatDistanceToNowStrict } from "date-fns";

export function fmtDateTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export function fmtAgo(iso?: string | null): string {
  if (!iso) return "never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return `${formatDistanceToNowStrict(d)} ago`;
}

export interface DetectedService {
  service: string;
  installed?: boolean;
  version?: string | null;
  running?: boolean;
  binary?: string | null;
}

/** Normalises the free-form `detected_services` JSON stored on a server. */
export function detectedServices(ds: unknown): DetectedService[] {
  const list = (ds as { services?: unknown } | null | undefined)?.services;
  if (!Array.isArray(list)) return [];
  return list.filter((s): s is DetectedService => !!s && typeof s === "object" && "service" in s);
}

export function servicesLabel(ds: unknown): string {
  const s = detectedServices(ds).filter((x) => x.installed !== false);
  return s.length
    ? s.map((x) => `${x.service}${x.version ? ` ${x.version.split("-")[0]}` : ""}`).join(", ")
    : "—";
}

export function fmtDate(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** Duration between two ISO timestamps (end defaults to now): `1m 05s`, `42s`. */
export function fmtDuration(start?: string | null, end?: string | null): string {
  if (!start) return "—";
  const a = new Date(start).getTime();
  const b = end ? new Date(end).getTime() : Date.now();
  if (Number.isNaN(a) || Number.isNaN(b)) return "—";
  const s = Math.max(0, Math.round((b - a) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, "0")}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

/** First/last chars of a hex fingerprint: `ab12cd34…ef56`. */
export function shortFp(fp?: string | null): string {
  if (!fp) return "—";
  const f = fp.replace(/^sha256:/i, "");
  return f.length > 20 ? `${f.slice(0, 12)}…${f.slice(-6)}` : f;
}

export function fmtMode(mode: string | number | null | undefined): string {
  if (mode === null || mode === undefined) return "—";
  if (typeof mode === "number") return mode.toString(8).padStart(4, "0");
  return mode;
}
