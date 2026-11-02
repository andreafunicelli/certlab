import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { KeyRound, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "@/lib/api/queries";
import { useLogin } from "@/lib/api/queries";
import { isApiError } from "@/lib/api/client";
import {
  btnPrimaryCls,
  btnCls,
  errorMessage,
  inputCls,
  labelCls,
  Spinner,
} from "@/components/ui/feedback";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/login")({
  validateSearch: (s: Record<string, unknown>): { next?: string } => {
    const n = typeof s["next"] === "string" ? s["next"] : undefined;
    // only same-origin relative paths
    return n && n.startsWith("/") && !n.startsWith("//") && !n.startsWith("/login")
      ? { next: n }
      : {};
  },
  head: () => ({
    meta: [{ title: "Sign in — Certificate Manager" }, { name: "robots", content: "noindex" }],
  }),
  component: LoginPage,
});

/** OIDC is enabled when the login endpoint answers with a redirect (404 otherwise). Client side only. */
function useOidcEnabled() {
  return useQuery({
    queryKey: ["oidc-enabled"],
    staleTime: Infinity,
    retry: false,
    queryFn: async () => {
      try {
        const r = await fetch(api.auth.oidcLoginUrl, {
          redirect: "manual",
          credentials: "include",
        });
        return r.type === "opaqueredirect" || (r.status >= 300 && r.status < 400);
      } catch {
        return false;
      }
    },
  });
}

function LoginPage() {
  const { next } = Route.useSearch();
  const navigate = useNavigate();
  const login = useLogin();
  const oidc = useOidcEnabled();
  // Credentials must never be submitted by the browser itself (GET would put them in the URL):
  // the form is POST-only and the button stays disabled until React has hydrated and owns submit.
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => setHydrated(true), []);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [needTotp, setNeedTotp] = useState(false);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    login.mutate(
      { username, password, totp: totp || undefined },
      {
        onSuccess: () => void navigate({ to: next ?? "/", replace: true }),
        onError: (err) => {
          if (isApiError(err) && /TOTP|MFA/i.test(err.code)) setNeedTotp(true);
        },
      },
    );
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm">
        <div className="mb-4 flex items-center justify-center gap-2.5">
          <div className="flex size-9 items-center justify-center rounded-md bg-primary/12 text-primary ring-1 ring-primary/25">
            <ShieldAlert className="size-5" />
          </div>
          <div>
            <div className="text-[14px] font-semibold tracking-tight">Certificate Manager</div>
            <div className="text-[10.5px] uppercase tracking-[0.08em] text-muted-foreground">
              PKI Deployment Platform
            </div>
          </div>
        </div>

        <section className="panel overflow-hidden">
          <div className="panel-header">
            <h1 className="text-[12.5px] font-semibold tracking-tight">Sign in</h1>
          </div>
          <form method="post" onSubmit={submit} className="space-y-3 p-3.5">
            <div>
              <label className={labelCls} htmlFor="username">
                Username
              </label>
              <input
                id="username"
                name="username"
                autoComplete="username"
                autoFocus
                className={inputCls}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            <div>
              <label className={labelCls} htmlFor="password">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                className={inputCls}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <div>
              <label className={labelCls} htmlFor="totp">
                Authenticator code {needTotp ? "" : "(if MFA is enabled)"}
              </label>
              <input
                id="totp"
                name="totp"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={8}
                className={cn(inputCls, "mono tracking-widest")}
                value={totp}
                onChange={(e) => setTotp(e.target.value)}
                placeholder="123456"
              />
            </div>
            {login.error && (
              <p
                className="rounded-md border border-danger/30 bg-danger-soft p-2 text-[12px] text-danger"
                role="alert"
              >
                {errorMessage(login.error)}
              </p>
            )}
            <button
              type="submit"
              className={cn(btnPrimaryCls, "h-8 w-full justify-center")}
              disabled={!hydrated || login.isPending}
            >
              {login.isPending && <Spinner />} Sign in
            </button>
            {oidc.data && (
              <>
                <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                  <span className="h-px flex-1 bg-border" /> or{" "}
                  <span className="h-px flex-1 bg-border" />
                </div>
                <a href={api.auth.oidcLoginUrl} className={cn(btnCls, "h-8 w-full justify-center")}>
                  <KeyRound className="size-3.5" /> Sign in with single sign-on
                </a>
              </>
            )}
          </form>
        </section>
        <p className="mt-3 text-center text-[11.5px] text-muted-foreground">
          Sessions are recorded in the audit log.
        </p>
      </div>
    </div>
  );
}
