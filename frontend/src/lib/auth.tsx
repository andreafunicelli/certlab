import { useNavigate } from "@tanstack/react-router";
import { useEffect } from "react";
import { setUnauthorizedHandler, isApiError } from "@/lib/api/client";
import { useMe } from "@/lib/api/queries";

/** Current session (from GET /auth/me). `me` is undefined while loading / unauthenticated. */
export function useSession() {
  const q = useMe();
  return { me: q.data, isLoading: q.isLoading, error: q.error, refetch: q.refetch };
}

/** RBAC helper: `useCan("servers:write")`. Server-side checks remain authoritative. */
export function useCan(permission: string): boolean {
  const { me } = useSession();
  if (!me) return false;
  return me.permissions.includes(permission) || me.permissions.includes("*");
}

export function useHasRole(role: string): boolean {
  const { me } = useSession();
  return !!me?.roles.includes(role);
}

/** Registers a soft (router based) redirect for 401 responses. Mounted once in the authenticated shell. */
export function useUnauthorizedRedirect() {
  const navigate = useNavigate();
  useEffect(() => {
    setUnauthorizedHandler(() => {
      if (window.location.pathname.startsWith("/login")) return;
      const next = window.location.pathname + window.location.search;
      void navigate({ to: "/login", search: { next } });
    });
    return () => setUnauthorizedHandler(null);
  }, [navigate]);
}

export const isUnauthenticated = (e: unknown) => isApiError(e) && e.status === 401;

export function roleLabel(roles: string[]): string {
  if (roles.includes("admin")) return "Administrator";
  if (roles.includes("operator")) return "Operator";
  if (roles.includes("viewer")) return "Read Only";
  return roles.join(", ") || "—";
}
