import type { ReactNode } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  btnCls,
  btnDangerCls,
  btnPrimaryCls,
  errorMessage,
  Spinner,
} from "@/components/ui/feedback";

/** Confirmation dialog for destructive / sensitive actions. Stays open while pending and shows API errors. */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = "Confirm",
  destructive,
  pending,
  error,
  onConfirm,
  children,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: string;
  description?: ReactNode;
  confirmLabel?: string;
  destructive?: boolean;
  pending?: boolean;
  error?: unknown;
  onConfirm: () => void;
  children?: ReactNode;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        {children}
        {error != null && (
          <p
            className="rounded-md border border-danger/30 bg-danger-soft p-2 text-[12px] text-danger"
            role="alert"
          >
            {errorMessage(error)}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button className={btnCls} onClick={() => onOpenChange(false)} disabled={pending}>
            Cancel
          </button>
          <button
            className={destructive ? btnDangerCls : btnPrimaryCls}
            onClick={onConfirm}
            disabled={pending}
          >
            {pending && <Spinner />} {confirmLabel}
          </button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
