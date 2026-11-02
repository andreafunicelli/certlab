import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import {
  Plus,
  Upload,
  Rocket,
  Search,
  MoreHorizontal,
  Eye,
  RefreshCw,
  Download,
  History,
  Trash2,
  Lock,
} from "lucide-react";
import { toast } from "sonner";
import { AppShell, PageHeader, Panel } from "@/components/layout/AppShell";
import { DTable, THead, TH, TRow, TD } from "@/components/ui/dtable";
import { CertStatusBadge, DaysLeft, Pill } from "@/components/ui/status";
import { certificates, servers } from "@/lib/mock-data";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

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

const selectCls =
  "h-7.5 rounded-md border border-input bg-surface px-2 text-[12.5px] outline-none focus:border-ring";

function CertificatesPage() {
  const [q, setQ] = useState("");
  const [ca, setCa] = useState("all");
  const [status, setStatus] = useState("all");
  const [server, setServer] = useState("all");
  const [window_, setWindow] = useState("all");

  const cas = useMemo(() => Array.from(new Set(certificates.map((c) => c.ca))), []);

  const rows = certificates.filter((c) => {
    if (q && !`${c.name} ${c.commonName} ${c.sans.join(" ")} ${c.issuer}`.toLowerCase().includes(q.toLowerCase()))
      return false;
    if (ca !== "all" && c.ca !== ca) return false;
    if (status !== "all" && c.status !== status) return false;
    if (server !== "all" && !c.installations.some((i) => i.serverId === server)) return false;
    if (window_ !== "all") {
      const d = c.daysRemaining;
      if (window_ === "expired" && d >= 0) return false;
      if (window_ === "30" && !(d >= 0 && d <= 30)) return false;
      if (window_ === "90" && !(d >= 0 && d <= 90)) return false;
    }
    return true;
  });

  return (
    <AppShell>
      <PageHeader
        title="Certificates"
        subtitle={`${certificates.length} managed certificates · issued by external Certification Authorities`}
        actions={
          <>
            <button
              onClick={() => toast.info("Add Certificate", { description: "Mockup action" })}
              className="inline-flex h-7.5 items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 text-[12.5px] hover:border-primary hover:text-primary"
            >
              <Plus className="size-3.5" /> Add Certificate
            </button>
            <button
              onClick={() => toast.info("Import Certificate", { description: "Mockup action" })}
              className="inline-flex h-7.5 items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 text-[12.5px] hover:border-primary hover:text-primary"
            >
              <Upload className="size-3.5" /> Import
            </button>
            <Link
              to="/certificates/$id/renew"
              params={{ id: "star-youco-cloud" }}
              className="inline-flex h-7.5 items-center gap-1.5 rounded-md bg-primary px-2.5 text-[12.5px] font-medium text-primary-foreground hover:opacity-90"
            >
              <Rocket className="size-3.5" /> Deploy Certificate
            </Link>
          </>
        }
      />

      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-2">
          <div className="relative min-w-52 flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Filter by domain, SAN, issuer…"
              className="h-7.5 w-full rounded-md border border-input bg-surface pl-8 pr-2 text-[12.5px] outline-none placeholder:text-muted-foreground focus:border-ring"
            />
          </div>
          <select value={ca} onChange={(e) => setCa(e.target.value)} className={selectCls}>
            <option value="all">All CAs</option>
            {cas.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
          <select value={status} onChange={(e) => setStatus(e.target.value)} className={selectCls}>
            <option value="all">All statuses</option>
            <option value="valid">Valid</option>
            <option value="expiring">Expiring Soon</option>
            <option value="critical">Critical</option>
            <option value="expired">Expired</option>
            <option value="error">Deployment Error</option>
          </select>
          <select value={window_} onChange={(e) => setWindow(e.target.value)} className={selectCls}>
            <option value="all">Any expiration</option>
            <option value="expired">Already expired</option>
            <option value="30">Next 30 days</option>
            <option value="90">Next 90 days</option>
          </select>
          <select value={server} onChange={(e) => setServer(e.target.value)} className={selectCls}>
            <option value="all">All servers</option>
            {servers.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
        </div>

        <DTable>
          <THead>
            <TH>Certificate Name</TH>
            <TH>Common Name</TH>
            <TH>SANs</TH>
            <TH>Issuer</TH>
            <TH>Valid From</TH>
            <TH>Expiration</TH>
            <TH align="right">Days</TH>
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
                    {c.name}
                  </Link>
                </TD>
                <TD className="mono">{c.commonName}</TD>
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
                <TD className="max-w-56 truncate text-muted-foreground" >{c.issuer}</TD>
                <TD className="mono">{c.validFrom}</TD>
                <TD className="mono">{c.expiration}</TD>
                <TD align="right">
                  <DaysLeft days={c.daysRemaining} />
                </TD>
                <TD align="right" className="mono tabular-nums text-muted-foreground">
                  {c.installations.length}
                </TD>
                <TD>
                  <CertStatusBadge status={c.status} />
                </TD>
                <TD align="right">
                  <DropdownMenu>
                    <DropdownMenuTrigger className="rounded-sm p-1 text-muted-foreground hover:bg-muted hover:text-foreground">
                      <MoreHorizontal className="size-4" />
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-56 text-[12.5px]">
                      <DropdownMenuItem asChild>
                        <Link to="/certificates/$id" params={{ id: c.id }}>
                          <Eye className="size-3.5" /> View
                        </Link>
                      </DropdownMenuItem>
                      <DropdownMenuItem asChild>
                        <Link to="/certificates/$id/renew" params={{ id: c.id }}>
                          <Rocket className="size-3.5" /> Deploy
                        </Link>
                      </DropdownMenuItem>
                      <DropdownMenuItem asChild>
                        <Link to="/certificates/$id/renew" params={{ id: c.id }}>
                          <RefreshCw className="size-3.5" /> Replace / Renew
                        </Link>
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() =>
                          toast.success("Public certificate downloaded", {
                            description: c.files.cert,
                          })
                        }
                      >
                        <Download className="size-3.5" /> Download Public Certificate
                      </DropdownMenuItem>
                      <DropdownMenuItem asChild>
                        <Link to="/deployments">
                          <History className="size-3.5" /> View Deployments
                        </Link>
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem disabled className="opacity-70">
                        <Lock className="size-3.5" /> Private key export disabled
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        className="text-danger focus:text-danger"
                        onClick={() =>
                          toast.error("Delete requires confirmation", {
                            description: `${c.name} is installed on ${c.installations.length} servers.`,
                          })
                        }
                      >
                        <Trash2 className="size-3.5" /> Delete
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TD>
              </TRow>
            ))}
            {rows.length === 0 && (
              <TRow>
                <TD colSpan={10} className="py-8 text-center text-muted-foreground">
                  No certificates match the current filters.
                </TD>
              </TRow>
            )}
          </tbody>
        </DTable>
      </Panel>

      <p className="mt-2 flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
        <Lock className="size-3" /> Private keys are stored encrypted at rest and can never be
        downloaded from the interface.
      </p>
    </AppShell>
  );
}
