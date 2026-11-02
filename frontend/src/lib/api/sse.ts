/**
 * Server-sent events for long running jobs (deployments, discovery).
 *
 * Contract (backend/app/services/events.py): the stream starts with `event: snapshot` (full job state, so a reload
 * resumes), then `event: progress` frames, then `event: end`. State is persisted server-side, so when the
 * EventSource errors we fall back to polling the job endpoint every 3 s until it reaches a terminal status.
 */
import { useEffect, useRef, useState } from "react";

export type StreamMode = "connecting" | "live" | "polling" | "closed";

export interface JobStreamOptions<S> {
  /** SSE URL; pass null to disable the stream entirely. */
  url: string | null;
  /** Called with the parsed `snapshot` payload. */
  onSnapshot?: (snap: S) => void;
  /** Called for each `progress` frame. */
  onProgress?: (p: Record<string, unknown>) => void;
  /** Called once when the job ends (SSE `end`, or the polled job became terminal). */
  onEnd?: () => void;
  /** Polling fallback: fetch the job once; return true when it is terminal. */
  poll: () => Promise<boolean>;
  pollMs?: number;
}

function parse<T>(data: string): T | null {
  try {
    return JSON.parse(data) as T;
  } catch {
    return null;
  }
}

export function useJobStream<S = Record<string, unknown>>(opts: JobStreamOptions<S>): StreamMode {
  const [mode, setMode] = useState<StreamMode>(opts.url ? "connecting" : "closed");
  const ref = useRef(opts);
  ref.current = opts;
  const { url } = opts;

  useEffect(() => {
    if (!url || typeof window === "undefined") {
      setMode("closed");
      return;
    }
    let disposed = false;
    let es: EventSource | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let ended = false;

    const finish = () => {
      if (ended) return;
      ended = true;
      setMode("closed");
      ref.current.onEnd?.();
    };

    const startPolling = () => {
      if (disposed || ended) return;
      setMode("polling");
      const tick = async () => {
        if (disposed || ended) return;
        let terminal = false;
        try {
          terminal = await ref.current.poll();
        } catch {
          /* transient; keep polling */
        }
        if (disposed) return;
        if (terminal) finish();
        else timer = setTimeout(() => void tick(), ref.current.pollMs ?? 3000);
      };
      void tick();
    };

    if (typeof EventSource === "undefined") {
      startPolling();
    } else {
      es = new EventSource(url, { withCredentials: true });
      es.addEventListener("open", () => !disposed && setMode("live"));
      es.addEventListener("snapshot", (ev) => {
        const d = parse<S>((ev as MessageEvent<string>).data);
        if (d) ref.current.onSnapshot?.(d);
      });
      es.addEventListener("progress", (ev) => {
        const d = parse<Record<string, unknown>>((ev as MessageEvent<string>).data);
        if (d) ref.current.onProgress?.(d);
      });
      es.addEventListener("end", () => {
        es?.close();
        finish();
      });
      es.addEventListener("error", () => {
        // Either a transport error or an `event: error` frame (job not found). Don't reconnect blindly:
        // poll instead, which also surfaces 401/404 through the normal API error path.
        if (ended || disposed) return;
        es?.close();
        es = null;
        startPolling();
      });
    }
    return () => {
      disposed = true;
      es?.close();
      if (timer) clearTimeout(timer);
    };
  }, [url]);

  return mode;
}
