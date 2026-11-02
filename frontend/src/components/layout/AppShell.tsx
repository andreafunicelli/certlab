import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import {
  LayoutDashboard,
  ShieldCheck,
  Server,
  Rocket,
  CalendarClock,
  ScrollText,
  Settings,
  LogOut,
  Sun,
  Moon,
  Search,
  ShieldAlert,
  Menu,
} from "lucide-react";
import { useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { useTheme } from "@/components/theme";
import { roleLabel, useSession, useUnauthorizedRedirect, isUnauthenticated } from "@/lib/auth";
import { useLogout, useSettings } from "@/lib/api/queries";
import { ErrorState, LoadingBlock } from "@/components/ui/feedback";
import { useQuery } from "@tanstack/react-query";
import { get } from "@/lib/api/client";
import { Pill } from "@/components/ui/status";

type NavPath =
  "/" | "/certificates" | "/servers" | "/deployments" | "/expirations" | "/audit" | "/settings";

const nav: {
  to: NavPath;
  label: string;
  icon: typeof LayoutDashboard;
  exact?: boolean;
}[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, exact: true },
  { to: "/certificates", label: "Certificates", icon: ShieldCheck },
  { to: "/servers", label: "Servers", icon: Server },
  { to: "/deployments", label: "Deployments", icon: Rocket },
  { to: "/expirations", label: "Expirations", icon: CalendarClock },
  { to: "/audit", label: "Audit Log", icon: ScrollText },
  { to: "/settings", label: "Settings", icon: Settings },
];

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const { theme, setTheme } = useTheme();
  const { me } = useSession();
  const logout = useLogout();
  const navigate = useNavigate();
  const name = me?.user.display_name || me?.user.username || "";
  const initials = name
    .split(/[\s._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]!.toUpperCase())
    .join("");

  return (
    <div className="flex h-full flex-col bg-sidebar">
      <div className="flex items-center gap-2.5 border-b border-sidebar-border px-3.5 py-3">
        <div className="flex size-8 items-center justify-center rounded-md bg-primary/12 text-primary ring-1 ring-primary/25">
          <ShieldAlert className="size-4.5" />
        </div>
        <div className="min-w-0">
          <div className="truncate text-[13px] font-semibold tracking-tight text-sidebar-foreground">
            Certificate Manager
          </div>
          <div className="truncate text-[10.5px] uppercase tracking-[0.08em] text-muted-foreground">
            PKI Deployment Platform
          </div>
        </div>
      </div>

      <nav className="flex-1 space-y-0.5 overflow-y-auto p-2">
        {nav.map((item) => {
          const active = item.exact ? pathname === item.to : pathname.startsWith(item.to);
          return (
            <Link
              key={item.to}
              to={item.to}
              onClick={onNavigate}
              className={cn(
                "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] transition-colors",
                active
                  ? "bg-sidebar-accent font-medium text-sidebar-accent-foreground shadow-[inset_2px_0_0_0_var(--color-primary)]"
                  : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-foreground",
              )}
            >
              <item.icon className="size-4 shrink-0" />
              <span className="truncate">{item.label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-sidebar-border p-2">
        <div className="mb-2 flex items-center gap-1 rounded-md border border-sidebar-border bg-background/40 p-0.5">
          <button
            onClick={() => setTheme("light")}
            className={cn(
              "flex flex-1 items-center justify-center gap-1.5 rounded-sm px-2 py-1 text-[11.5px] transition-colors",
              theme === "light"
                ? "bg-sidebar-accent text-sidebar-accent-foreground"
                : "text-muted-foreground hover:text-sidebar-foreground",
            )}
          >
            <Sun className="size-3.5" /> Light
          </button>
          <button
            onClick={() => setTheme("dark")}
            className={cn(
              "flex flex-1 items-center justify-center gap-1.5 rounded-sm px-2 py-1 text-[11.5px] transition-colors",
              theme === "dark"
                ? "bg-sidebar-accent text-sidebar-accent-foreground"
                : "text-muted-foreground hover:text-sidebar-foreground",
            )}
          >
            <Moon className="size-3.5" /> Dark
          </button>
        </div>

        <div className="flex items-center gap-2.5 rounded-md px-1.5 py-1.5">
          <div className="flex size-7 shrink-0 items-center justify-center rounded-full bg-primary/15 text-[11px] font-semibold text-primary">
            {initials || "?"}
          </div>
          <div className="min-w-0 flex-1">
            <div className="truncate text-[12.5px] font-medium text-sidebar-foreground">{name}</div>
            <div className="text-[10.5px] text-muted-foreground">{roleLabel(me?.roles ?? [])}</div>
          </div>
          <button
            title="Log out"
            aria-label="Log out"
            onClick={() =>
              logout.mutate(undefined, {
                onSettled: () => void navigate({ to: "/login", search: {} }),
              })
            }
            className="rounded-sm p-1.5 text-muted-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-foreground"
          >
            <LogOut className="size-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}

function HeaderStatus() {
  const settings = useSettings();
  const ready = useQuery({
    queryKey: ["readyz"],
    queryFn: () => get<{ status: string }>("/readyz"),
    refetchInterval: 30_000,
    retry: false,
  });
  const tz = settings.data?.general.data["timezone"];
  return (
    <>
      <Pill tone={ready.isError ? "warn" : ready.data ? "ok" : "neutral"} dot>
        {ready.isError ? "API degraded" : ready.data ? "API ready" : "API …"}
      </Pill>
      {typeof tz === "string" && <Pill tone="neutral">{tz}</Pill>}
    </>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const { me, isLoading, error, refetch } = useSession();
  useUnauthorizedRedirect();

  // Session gate. SSR and the first client render show the same placeholder (no API call on the server).
  if (!me) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        {isLoading || isUnauthenticated(error) || !error ? (
          <LoadingBlock label="Checking session…" />
        ) : (
          <ErrorState error={error} onRetry={() => void refetch()} />
        )}
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-background">
      <aside className="hidden w-60 shrink-0 border-r border-sidebar-border lg:block">
        <div className="sticky top-0 h-screen">
          <SidebarContent />
        </div>
      </aside>

      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button
            aria-label="Close navigation"
            className="absolute inset-0 bg-background/70 backdrop-blur-sm"
            onClick={() => setMobileOpen(false)}
          />
          <div className="absolute inset-y-0 left-0 w-60 border-r border-sidebar-border">
            <SidebarContent onNavigate={() => setMobileOpen(false)} />
          </div>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-12 items-center gap-3 border-b border-border bg-background/85 px-3 backdrop-blur sm:px-4">
          <button
            className="rounded-sm p-1.5 text-muted-foreground hover:bg-muted lg:hidden"
            onClick={() => setMobileOpen(true)}
            aria-label="Open navigation"
          >
            <Menu className="size-4" />
          </button>
          <div className="relative hidden max-w-sm flex-1 sm:block">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              placeholder="Search certificates, domains, servers…"
              className="h-7.5 w-full rounded-md border border-input bg-surface pl-8 pr-2 text-[12.5px] outline-none placeholder:text-muted-foreground focus:border-ring"
            />
          </div>
          <div className="ml-auto flex items-center gap-2">
            <HeaderStatus />
          </div>
        </header>

        <main className="min-w-0 flex-1 p-3 sm:p-4">{children}</main>
      </div>
    </div>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
  badge,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  badge?: ReactNode;
}) {
  return (
    <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="truncate text-[17px] font-semibold tracking-tight">{title}</h1>
          {badge}
        </div>
        {subtitle && <p className="mt-0.5 text-[12.5px] text-muted-foreground">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Panel({
  title,
  actions,
  children,
  className,
  bodyClassName,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={cn("panel overflow-hidden", className)}>
      {title && (
        <div className="panel-header">
          <h2 className="text-[12.5px] font-semibold tracking-tight">{title}</h2>
          {actions}
        </div>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}
