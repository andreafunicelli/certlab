import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Panel } from "@/components/layout/AppShell";
import {
  btnPrimaryCls,
  btnCls,
  errorMessage,
  inputCls,
  labelCls,
  Spinner,
} from "@/components/ui/feedback";
import { useUpdateSettings } from "@/lib/api/queries";
import type { SettingsSection, SettingsSectionName } from "@/lib/api/types";
import { ApiError } from "@/lib/api/client";
import { fmtDateTime } from "@/lib/format";
import { cn } from "@/lib/utils";

export type FieldDef = {
  path: string; // dotted path in section data
  label: string;
  kind: "number" | "text" | "toggle" | "lines" | "timezone";
  help?: string;
  min?: number;
  max?: number;
  wide?: boolean;
};

function getPath(o: unknown, path: string): unknown {
  return path
    .split(".")
    .reduce<unknown>(
      (a, k) => (a && typeof a === "object" ? (a as Record<string, unknown>)[k] : undefined),
      o,
    );
}
function setPath(o: Record<string, unknown>, path: string, v: unknown): Record<string, unknown> {
  const [k, ...rest] = path.split(".");
  const copy = { ...o };
  copy[k!] = rest.length
    ? setPath((copy[k!] as Record<string, unknown>) ?? {}, rest.join("."), v)
    : v;
  return copy;
}

export function Toggle({
  on,
  onChange,
  disabled,
  label,
}: {
  on: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  label?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!on)}
      className={cn(
        "h-4.5 w-8 shrink-0 rounded-full border transition-colors disabled:opacity-50",
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

/**
 * Edits one settings section. Sends `version` for optimistic concurrency; on HTTP 409 the parent is told
 * (`onConflict`) and the latest server values are reloaded (the form remounts via its `key`).
 */
export function SectionForm({
  section,
  title,
  fields,
  data,
  canWrite,
  onConflict,
  onSaved,
  children,
}: {
  section: SettingsSectionName;
  title: string;
  fields: FieldDef[];
  data: SettingsSection;
  canWrite: boolean;
  onConflict: () => void;
  onSaved: () => void;
  children?: React.ReactNode;
}) {
  const [draft, setDraft] = useState<Record<string, unknown>>(() => structuredClone(data.data));
  const update = useUpdateSettings();
  const dirty = useMemo(
    () => JSON.stringify(draft) !== JSON.stringify(data.data),
    [draft, data.data],
  );
  const tzs = useMemo(
    () =>
      typeof Intl !== "undefined" && "supportedValuesOf" in Intl
        ? (Intl as unknown as { supportedValuesOf: (k: string) => string[] }).supportedValuesOf(
            "timeZone",
          )
        : [],
    [],
  );

  const save = () =>
    update.mutate(
      { section, version: data.version, data: draft },
      {
        onSuccess: () => {
          toast.success(`${title} settings saved`);
          onSaved();
        },
        onError: (e) => {
          if (e instanceof ApiError && e.status === 409) {
            toast.warning("Settings were changed by someone else", {
              description: "The latest values have been loaded.",
            });
            onConflict();
          }
        },
      },
    );

  return (
    <Panel
      title={title}
      actions={
        <span className="text-[11px] text-muted-foreground">
          v{data.version} · {fmtDateTime(data.updated_at)}
        </span>
      }
    >
      <div className="grid gap-3 p-3 sm:grid-cols-2">
        {fields.map((f) => {
          const id = `${section}-${f.path}`;
          const v = getPath(draft, f.path);
          const set = (nv: unknown) => setDraft((d) => setPath(d, f.path, nv));
          return (
            <div
              key={f.path}
              className={cn(f.wide && "sm:col-span-2", f.kind === "toggle" && "sm:col-span-2")}
            >
              {f.kind === "toggle" ? (
                <div className="flex items-center justify-between rounded-md border border-border bg-surface-2/40 p-2.5">
                  <div>
                    <div className="text-[12.5px]">{f.label}</div>
                    {f.help && <div className="text-[11.5px] text-muted-foreground">{f.help}</div>}
                  </div>
                  <Toggle on={!!v} onChange={set} disabled={!canWrite} label={f.label} />
                </div>
              ) : (
                <>
                  <label className={labelCls} htmlFor={id}>
                    {f.label}
                  </label>
                  {f.kind === "number" ? (
                    <input
                      id={id}
                      type="number"
                      className={inputCls}
                      disabled={!canWrite}
                      min={f.min}
                      max={f.max}
                      value={typeof v === "number" ? v : ""}
                      onChange={(e) => set(e.target.value === "" ? "" : Number(e.target.value))}
                    />
                  ) : f.kind === "lines" ? (
                    <textarea
                      id={id}
                      rows={5}
                      className="mono w-full rounded-md border border-input bg-surface p-2 text-[12px] outline-none focus:border-ring disabled:opacity-60"
                      disabled={!canWrite}
                      value={Array.isArray(v) ? (v as string[]).join("\n") : ""}
                      onChange={(e) =>
                        set(
                          e.target.value
                            .split("\n")
                            .map((l) => l.trim())
                            .filter(Boolean),
                        )
                      }
                    />
                  ) : (
                    <>
                      <input
                        id={id}
                        className={inputCls}
                        disabled={!canWrite}
                        list={f.kind === "timezone" ? "tz-list" : undefined}
                        value={typeof v === "string" ? v : ""}
                        onChange={(e) => set(e.target.value)}
                      />
                      {f.kind === "timezone" && (
                        <datalist id="tz-list">
                          {tzs.map((t) => (
                            <option key={t} value={t} />
                          ))}
                        </datalist>
                      )}
                    </>
                  )}
                  {f.help && <p className="mt-1 text-[11px] text-muted-foreground">{f.help}</p>}
                </>
              )}
            </div>
          );
        })}
        {children}
      </div>
      {update.error && !(update.error instanceof ApiError && update.error.status === 409) && (
        <p
          className="mx-3 mb-2 rounded-md border border-danger/30 bg-danger-soft p-2 text-[12px] text-danger"
          role="alert"
        >
          {errorMessage(update.error)}
        </p>
      )}
      {canWrite ? (
        <div className="flex items-center gap-2 border-t border-border px-3 py-2">
          <button className={btnPrimaryCls} disabled={!dirty || update.isPending} onClick={save}>
            {update.isPending && <Spinner />} Save changes
          </button>
          <button
            className={btnCls}
            disabled={!dirty || update.isPending}
            onClick={() => setDraft(structuredClone(data.data))}
          >
            Reset
          </button>
          {dirty && <span className="text-[11.5px] text-muted-foreground">Unsaved changes</span>}
        </div>
      ) : (
        <div className="border-t border-border px-3 py-2 text-[11.5px] text-muted-foreground">
          Read-only: changing settings requires the administrator role.
        </div>
      )}
    </Panel>
  );
}
