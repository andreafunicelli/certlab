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
