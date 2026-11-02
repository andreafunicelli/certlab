import { useRef, useState } from "react";
import { isReauthRequired } from "@/lib/api/client";
import { ReauthDialog } from "@/components/auth/ReauthDialog";

/**
 * Runs a sensitive mutation; when the API answers REAUTH_REQUIRED it opens the re-authentication dialog and
 * retries the same call once the password was confirmed. Other errors go to `onError`.
 *
 *   const { attempt, dialog } = useReauthGate("Approving a deployment requires re-authentication.");
 *   attempt(() => approve.mutateAsync(id), (e) => toast.error(errorMessage(e)));
 *   ... render {dialog}
 */
export function useReauthGate(reason?: string) {
  const [open, setOpen] = useState(false);
  const pending = useRef<{ fn: () => Promise<unknown>; onError?: (e: unknown) => void } | null>(
    null,
  );

  const run = async (fn: () => Promise<unknown>, onError?: (e: unknown) => void) => {
    try {
      await fn();
    } catch (e) {
      if (isReauthRequired(e)) {
        pending.current = onError ? { fn, onError } : { fn };
        setOpen(true);
      } else onError?.(e);
    }
  };

  const dialog = (
    <ReauthDialog
      open={open}
      onOpenChange={setOpen}
      {...(reason ? { reason } : {})}
      onSuccess={() => {
        const p = pending.current;
        pending.current = null;
        if (p) void run(p.fn, p.onError);
      }}
    />
  );
  return { attempt: run, dialog };
}
