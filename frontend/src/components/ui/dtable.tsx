import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function DTable({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className="w-full overflow-x-auto">
      <table className={cn("w-full min-w-max border-collapse whitespace-nowrap text-[12.5px]", className)}>{children}</table>
    </div>
  );
}

export function THead({ children }: { children: ReactNode }) {
  return (
    <thead className="bg-surface-2/70">
      <tr className="border-b border-border text-left">{children}</tr>
    </thead>
  );
}

export function TH({
  children,
  className,
  align,
}: {
  children?: ReactNode;
  className?: string | undefined;
  align?: "right" | "center";
}) {
  return (
    <th
      className={cn(
        "px-2.5 py-1.5 text-[10.5px] font-semibold uppercase tracking-[0.06em] text-muted-foreground",
        align === "right" && "text-right",
        align === "center" && "text-center",
        className,
      )}
    >
      {children}
    </th>
  );
}

export function TRow({
  children,
  className,
  onClick,
}: {
  children: ReactNode;
  className?: string | undefined;
  onClick?: (() => void) | undefined;
}) {
  return (
    <tr
      onClick={onClick}
      className={cn(
        "row-hover border-b border-border/70 last:border-0 transition-colors",
        onClick && "cursor-pointer",
        className,
      )}
    >
      {children}
    </tr>
  );
}

export function TD({
  children,
  className,
  align,
  colSpan,
}: {
  children?: ReactNode;
  className?: string | undefined;
  align?: "right" | "center";
  colSpan?: number;
}) {
  return (
    <td
      colSpan={colSpan}
      className={cn(
        "px-2.5 py-1.5 align-middle",
        align === "right" && "text-right",
        align === "center" && "text-center",
        className,
      )}
    >
      {children}
    </td>
  );
}
