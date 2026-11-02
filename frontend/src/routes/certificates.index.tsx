import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { Search, MoreHorizontal, Eye, RefreshCw, ShieldCheck, History, Lock } from "lucide-react";
import { toast } from "sonner";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { CertStatusBadge, DaysLeft, Pill } from "@/components/ui/status";
import {
  btnCls,
  EmptyState,
  ErrorState,
  errorMessage,
  inputCls,
  LoadingBlock,
  selectCls,
} from "@/components/ui/feedback";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  useCertificates,
  useEnvironments,
  useServers,
  useVerifyCertificate,
} from "@/lib/api/queries";
import { useCan } from "@/lib/auth";
import { fmtDate } from "@/lib/format";
import { useDebounced } from "@/lib/use-debounced";

export const Route = createFileRoute("/certificates/")({
  head: () => ({
    meta: [
      { title: "Certificates — Certificate Manager" },
      {
        name: "description",
        content:
          "Inventory of manually issued PKI SSL/TLS certificates from Actalis, Sectigo, DigiCert, GlobalSign and Entrust.",
      },
      { property: "og:title", content: "Certificates — Certificate Manager" },
      {
        property: "og:description",
        content: "Inventory of enterprise CA certificates and where they are installed.",
      },
    ],
  }),
  component: CertificatesPage,
});

const PAGE_SIZE = 25;

function CertificatesPage() {
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("all");
  const [server, setServer] = useState("all");
  const [env, setEnv] = useState("all");
  const [window_, setWindow] = useState("all");
  const [sort, setSort] = useState("not_after");
  const [page, setPage] = useState(1);
  const dq = useDebounced(q.trim(), 300);
  const canVerify = useCan("certificates:verify");
  const canUpload = useCan("versions:upload");

  const list = useCertificates({
    q: dq || undefined,
    status: status === "all" ? undefined : status,
    server_id: server === "all" ? undefined : server,
    environment: env === "all" ? undefined : env,
    expiring_within: window_ === "all" ? undefined : Number(window_),
    sort,
    page,
    page_size: PAGE_SIZE,
  });
  const servers = useServers({ page_size: 200 });
  const envs = useEnvironments();
  const verify = useVerifyCertificate();
  const rows = list.data?.items ?? [];
  const total = list.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const reset =
    <T,>(set: (v: T) => void) =>
    (v: T) => {
      set(v);
      setPage(1);
    };

  const runVerify = (id: string, cn: string) =>
    verify.mutate(id, {
      onSuccess: (r) => {
        const s = r.summary;
        const msg = `${s.matching}/${s.total} endpoints serve the installed certificate`;
        if (s.total === 0)
          toast.info("Nothing to verify", { description: "No verifiable installations." });
        else if (s.mismatching || s.failed)
          toast.warning(`${cn}: verification found problems`, { description: msg });
        else toast.success(`${cn}: verified`, { description: msg });
      },
      onError: (e) => toast.error("Verification failed", { description: errorMessage(e) }),
    });

  return (
    <AppShell>
      <PageHeader
        title="Certificates"
        subtitle={`${total} certificates · discovered on servers or uploaded for deployment`}
      />

      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-2">
          <div className="relative min-w-52 flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              value={q}
              onChange={(e) => reset(setQ)(e.target.value)}
              placeholder="Filter by domain, SAN, issuer, serial, fingerprint…"
              aria-label="Search certificates"
              className={inputCls + " pl-8"}
            />
          </div>
          <select
            value={status}
            onChange={(e) => reset(setStatus)(e.target.value)}
            className={selectCls}
            aria-label="Status"
          >
            <option value="all">All statuses</option>
            <option value="valid">Valid</option>
            <option value="info">Renew soon</option>
            <option value="warning">Expiring soon</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
            <option value="expired">Expired</option>
          </select>
          <select
            value={window_}
            onChange={(e) => reset(setWindow)(e.target.value)}
            className={selectCls}
            aria-label="Expiration window"
          >
            <option value="all">Any expiration</option>
            <option value="7">Within 7 days</option>
            <option value="30">Within 30 days</option>
            <option value="90">Within 90 days</option>
          </select>
          <select
            value={env}
            onChange={(e) => reset(setEnv)(e.target.value)}
            className={selectCls}
            aria-label="Environment"
          >
            <option value="all">All environments</option>
            {envs.data?.map((e) => (
              <option key={e.id} value={e.name}>
                {e.name}
              </option>
            ))}
          </select>
          <select
            value={server}
            onChange={(e) => reset(setServer)(e.target.value)}
            className={selectCls}
            aria-label="Server"
          >
            <option value="all">All servers</option>
            {servers.data?.items.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
          <select
            value={sort}
            onChange={(e) => reset(setSort)(e.target.value)}
            className={selectCls}
            aria-label="Sort"
          >
            <option value="not_after">Expires: soonest first</option>
            <option value="-not_after">Expires: latest first</option>
            <option value="common_name">Name A-Z</option>
            <option value="-common_name">Name Z-A</option>
            <option value="-installations">Most installed</option>
            <option value="-created_at">Recently added</option>
          </select>
        </div>

        {list.isLoading ? (
          <LoadingBlock label="Loading certificates…" />
        ) : list.isError ? (
          <ErrorState error={list.error} onRetry={() => void list.refetch()} />
        ) : rows.length === 0 ? (
          <EmptyState
            title={
              dq || status !== "all" || server !== "all" || env !== "all" || window_ !== "all"
                ? "No certificates match the current filters"
                : "No certificates yet"
            }
            hint="Certificates appear after a server's certificate scan finds them. Run “Scan Certificates” on a server."
          />
        ) : (
          <DTable>
            <THead>
              <TH>Common Name</TH>
              <TH>SANs</TH>
              <TH>Issuer</TH>
              <TH>Valid From</TH>
              <TH>Expiration</TH>
              <TH align="right">Days</TH>
              <TH align="right">Installs</TH>
              <TH align="right">Servers</TH>
              <TH>Status</TH>
              <TH align="right">Actions</TH>
            </THead>
            <tbody>
              {rows.map((c) => (
                <TRow key={c.id}>
                  <TD>
                    <Link
                      to="/certificates/$id"
                      params={{ id: c.id }}
                      className="mono font-medium text-foreground hover:text-primary hover:underline"
                    >
                      {c.common_name}
                    </Link>
                  </TD>
                  <TD>
                    <div className="flex flex-wrap gap-1">
                      {c.sans.slice(0, 2).map((s) => (
                        <Pill key={s} tone="neutral" className="mono">
                          {s}
                        </Pill>
                      ))}
                      {c.sans.length > 2 && <Pill tone="neutral">+{c.sans.length - 2}</Pill>}
                    </div>
                  </TD>
                  <TD className="max-w-56 truncate text-muted-foreground">
                    <span title={c.issuer}>{c.issuer}</span>
                  </TD>
                  <TD className="mono">{fmtDate(c.not_before)}</TD>
                  <TD className="mono">{fmtDate(c.not_after)}</TD>
                  <TD align="right">
                    <DaysLeft days={c.days_remaining} />
                  </TD>
                  <TD align="right" className="mono tabular-nums text-muted-foreground">
                    {c.installation_count}
                  </TD>
                  <TD align="right" className="mono tabular-nums text-muted-foreground">
                    {c.server_count}
                  </TD>
                  <TD>
                    <CertStatusBadge status={c.expiry_status} />
                  </TD>
                  <TD align="right">
                    <DropdownMenu>
                      <DropdownMenuTrigger
                        aria-label={`Actions for ${c.common_name}`}
                        className="rounded-sm p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                      >
                        <MoreHorizontal className="size-4" />
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-56 text-[12.5px]">
                        <DropdownMenuItem asChild>
                          <Link to="/certificates/$id" params={{ id: c.id }}>
                            <Eye className="size-3.5" /> View
                          </Link>
                        </DropdownMenuItem>
                        {canUpload && (
                          <DropdownMenuItem asChild>
                            <Link to="/certificates/$id/renew" params={{ id: c.id }}>
                              <RefreshCw className="size-3.5" /> Replace / Renew
                            </Link>
                          </DropdownMenuItem>
                        )}
                        {canVerify && (
                          <DropdownMenuItem
                            disabled={verify.isPending || c.installation_count === 0}
                            onClick={() => runVerify(c.id, c.common_name)}
                          >
                            <ShieldCheck className="size-3.5" /> Verify endpoints
                          </DropdownMenuItem>
                        )}
                        <DropdownMenuItem asChild>
                          <Link to="/deployments">
                            <History className="size-3.5" /> View Deployments
                          </Link>
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem disabled className="opacity-70">
                          <Lock className="size-3.5" /> Private key export disabled
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TD>
                </TRow>
              ))}
            </tbody>
          </DTable>
        )}

        {total > PAGE_SIZE && (
          <div className="flex items-center justify-between border-t border-border px-3 py-1.5 text-[12px] text-muted-foreground">
            <span>
              {total} certificates · page {page} / {pages}
            </span>
            <div className="flex gap-1.5">
              <button className={btnCls} disabled={page <= 1} onClick={() => setPage(page - 1)}>
                Previous
              </button>
              <button className={btnCls} disabled={page >= pages} onClick={() => setPage(page + 1)}>
                Next
              </button>
            </div>
          </div>
        )}
      </Panel>

      <p className="mt-2 flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
        <Lock className="size-3" /> Private keys are stored encrypted at rest and can never be
        downloaded from the interface.
      </p>
    </AppShell>
  );
}
