import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useReauth } from "@/lib/api/queries";
import {
  btnCls,
  btnPrimaryCls,
  errorMessage,
  inputCls,
  labelCls,
  Spinner,
} from "@/components/ui/feedback";

/**
 * Re-authentication prompt for sensitive operations (POST /auth/reauth).
 * Usage: when a mutation fails with `isReauthRequired(err)`, open this dialog and retry in `onSuccess`.
 */
export function ReauthDialog({
  open,
  onOpenChange,
  onSuccess,
  reason = "This action requires a recent re-authentication.",
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onSuccess: () => void;
  reason?: string;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const m = useReauth();

  const close = (o: boolean) => {
    if (!o) {
      setPassword("");
      setTotp("");
      m.reset();
    }
    onOpenChange(o);
  };

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    m.mutate(
      { password, totp: totp || undefined },
      {
        onSuccess: () => {
          close(false);
          onSuccess();
        },
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>Confirm your identity</DialogTitle>
          <DialogDescription>{reason}</DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="space-y-3">
          <div>
            <label className={labelCls} htmlFor="reauth-password">
              Password
            </label>
            <input
              id="reauth-password"
              type="password"
              autoComplete="current-password"
              autoFocus
              className={inputCls}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <div>
            <label className={labelCls} htmlFor="reauth-totp">
              Authenticator code (if enabled)
            </label>
            <input
              id="reauth-totp"
              inputMode="numeric"
              autoComplete="one-time-code"
              className={inputCls}
              value={totp}
              onChange={(e) => setTotp(e.target.value)}
              maxLength={8}
            />
          </div>
          {m.error && (
            <p className="text-[12px] text-danger" role="alert">
              {errorMessage(m.error)}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <button type="button" className={btnCls} onClick={() => close(false)}>
              Cancel
            </button>
            <button type="submit" className={btnPrimaryCls} disabled={m.isPending || !password}>
              {m.isPending && <Spinner />} Confirm
            </button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
