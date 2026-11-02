/**
 * End-to-end: register a server, enroll its host key, discover certificates, then renew the nginx certificate through the
 * 5-step wizard against the live backend + Celery worker + disposable SSH target (infra/test-target), and verify with
 * `openssl s_client` that the new certificate is really served. The original nginx files are restored in afterAll.
 *
 * Needs: backend :8000 (+ worker, Redis, Postgres), `vite dev` on E2E_BASE_URL, target on 127.0.0.1:2222 (root in this
 * container: the CA lives in /etc/ssl/cdp-test/ca). Set PW_CHROMIUM_PATH to use a system Chromium.
 */
import { expect, test, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SHOTS = process.env["E2E_SHOTS"] ?? "e2e/shots";
const ADMIN_USER = process.env["E2E_ADMIN_USER"] ?? "admin";
const ADMIN_PASS = process.env["E2E_ADMIN_PASSWORD"] ?? "admin-dev-password-123";
const KEY_FILE = process.env["E2E_SSH_KEY_FILE"] ?? "/var/lib/cdp-test/id_ed25519";
const SSH_PORT = process.env["E2E_SSH_PORT"] ?? "2222";
const SSH_USER = process.env["E2E_SSH_USER"] ?? "cdpdeploy";
const CA_DIR = process.env["E2E_CA_DIR"] ?? "/etc/ssl/cdp-test/ca";
const NGINX_DIR = process.env["E2E_NGINX_DIR"] ?? "/etc/ssl/cdp-test/nginx";
const NGINX_PORT = process.env["E2E_NGINX_PORT"] ?? "8443";
const CN = "nginx.test.local";
const CERT_PATH = `${NGINX_DIR}/fullchain.pem`;
const KEY_PATH = `${NGINX_DIR}/privkey.pem`;
const suffix = Date.now().toString(36);
const serverName = `e2e-deploy-${suffix}`;

let work = "";
let backupDir = "";
let newFp = "";
let origFp = "";

const sh = (cmd: string, args: string[], input?: string) =>
  execFileSync(cmd, args, {
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
    ...(input !== undefined ? { input } : {}),
  });
const fpOfFile = (file: string) =>
  sh("openssl", ["x509", "-in", file, "-noout", "-fingerprint", "-sha256"])
    .trim()
    .split("=")[1]!
    .replace(/:/g, "")
    .toLowerCase();
/** Fingerprint of the leaf certificate nginx actually serves right now. */
const servedFp = () => {
  const pem = sh(
    "openssl",
    ["s_client", "-connect", `127.0.0.1:${NGINX_PORT}`, "-servername", CN],
    "",
  );
  const m = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/.exec(pem);
  if (!m) throw new Error("no certificate served");
  return sh("openssl", ["x509", "-noout", "-fingerprint", "-sha256"], m[0])
    .trim()
    .split("=")[1]!
    .replace(/:/g, "")
    .toLowerCase();
};

test.beforeAll(() => {
  mkdirSync(SHOTS, { recursive: true });
  work = mkdtempSync(join(tmpdir(), "cdp-e2e-"));
  backupDir = mkdtempSync(join(tmpdir(), "cdp-e2e-orig-"));
  // keep the original files (cp -p keeps mode/owner) so afterAll can put them back
  for (const f of ["fullchain.pem", "privkey.pem"])
    sh("cp", ["-p", `${NGINX_DIR}/${f}`, `${backupDir}/${f}`]);
  origFp = servedFp();

  // new leaf for nginx.test.local signed by the test intermediate CA (new key pair, valid 400 days)
  sh("openssl", [
    "req",
    "-new",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    join(work, "key.pem"),
    "-subj",
    `/CN=${CN}`,
    "-out",
    join(work, "req.csr"),
  ]);
  const ext = join(work, "ext.cnf");
  writeFileSync(
    ext,
    `basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:${CN}\n`,
  );
  sh("openssl", [
    "x509",
    "-req",
    "-in",
    join(work, "req.csr"),
    "-CA",
    `${CA_DIR}/inter.pem`,
    "-CAkey",
    `${CA_DIR}/inter.key`,
    "-set_serial",
    `0x1${randomBytes(15).toString("hex")}`,
    "-days",
    "400",
    "-sha256",
    "-extfile",
    ext,
    "-out",
    join(work, "cert.pem"),
  ]);
  copyFileSync(`${CA_DIR}/inter.pem`, join(work, "chain.pem"));
  newFp = fpOfFile(join(work, "cert.pem"));
  expect(newFp).not.toBe(origFp);
});

test.afterAll(() => {
  try {
    for (const f of ["fullchain.pem", "privkey.pem"])
      sh("cp", ["-p", `${backupDir}/${f}`, `${NGINX_DIR}/${f}`]);
    sh("nginx", ["-s", "reload"]);
    execFileSync("sleep", ["1"]);
    const now = servedFp();
    console.log(
      `restored original nginx certificate: served ${now.slice(0, 12)} (orig ${origFp.slice(0, 12)})`,
    );
    expect(now).toBe(origFp);
  } finally {
    for (const d of [work, backupDir]) if (d) rmSync(d, { recursive: true, force: true });
  }
});

/** Dev-mode hydration can lag; a native form submit would put the password in the URL, so retry until it lands. */
async function login(page: Page) {
  await page.goto("/login");
  for (let attempt = 0; attempt < 6; attempt++) {
    await page.getByLabel("Username").fill(ADMIN_USER);
    await page.getByLabel("Password").fill(ADMIN_PASS);
    await page.getByRole("button", { name: "Sign in" }).click();
    try {
      await page.waitForURL((u) => !u.pathname.startsWith("/login"), { timeout: 4000 });
      return;
    } catch {
      await page.goto("/login");
      await page.waitForTimeout(1500);
    }
  }
  throw new Error("could not sign in");
}

test("register server, discover, renew nginx certificate end to end, verify with openssl", async ({
  page,
}) => {
  test.setTimeout(240_000);
  const shot = (n: string) => page.screenshot({ path: `${SHOTS}/${n}.png`, fullPage: true });

  await login(page);

  // ------------------------------------------------------------------ register + enroll host key
  await page.goto("/servers/new");
  await page.getByLabel("Server Name").fill(serverName);
  await page.getByLabel("Hostname / IP").fill("127.0.0.1");
  await page.getByLabel("SSH Port").fill(SSH_PORT);
  await page.getByLabel("SSH Username").fill(SSH_USER);
  await page.getByLabel("Environment").selectOption("Test");
  await page.getByRole("button", { name: /New credential/ }).click();
  await page.getByLabel("Credential name").fill(`cred-${suffix}`);
  await page.locator('input[type="file"]').setInputFiles(KEY_FILE);
  await expect(page.locator("#newcred-pem")).not.toHaveValue("");
  await page.getByRole("button", { name: "Save Server" }).click();
  await expect(page.getByText("Server registered")).toBeVisible();
  await page.getByRole("button", { name: "Scan host key" }).click();
  await expect(page.getByTestId("hostkey-fingerprint")).toContainText("SHA256:");
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Trust and enroll key" }).click();
  await expect(page.getByText("Enrolled", { exact: true }).first()).toBeVisible();
  await page.getByRole("button", { name: "Open server" }).click();
  await expect(page.getByRole("heading", { name: serverName })).toBeVisible();

  // ------------------------------------------------------------------ discovery with live progress
  await expect(page.getByTestId("stale-inventory")).toBeVisible(); // never scanned
  await page.getByRole("button", { name: "Scan Certificates" }).click();
  const job = page.getByTestId("discovery-job");
  await expect(job).toBeVisible();
  await shot("20-discovery-running");
  await expect(job).toHaveAttribute("data-status", "completed", { timeout: 90_000 });
  await expect(page.getByTestId("stale-inventory")).toHaveCount(0);
  const nginxRow = page.locator("tr", { hasText: CERT_PATH });
  await expect(nginxRow).toBeVisible();
  await expect(nginxRow).toContainText("nginx");
  await expect(nginxRow).toContainText("Managed");
  await shot("21-discovery-done-installations");

  // ------------------------------------------------------------------ open the certificate, start the wizard
  await nginxRow.getByRole("link", { name: CN }).click();
  await expect(page.getByRole("heading", { name: CN })).toBeVisible();
  // the same certificate may already be known from earlier runs/servers: scope lookups to this server
  await expect(
    page.locator("tr", { hasText: CERT_PATH }).filter({ hasText: serverName }),
  ).toContainText("Managed");
  await shot("22-certificate-detail");
  await page.getByRole("link", { name: /Upload \/ Replace/ }).click();
  await expect(page.getByText("Step 1 — Upload New Certificate")).toBeVisible();

  // 1 upload
  await expect(page.getByRole("button", { name: "Upload & validate" })).toBeDisabled();
  await page.getByTestId("file-cert").setInputFiles(join(work, "cert.pem"));
  await page.getByTestId("file-key").setInputFiles(join(work, "key.pem"));
  await page.getByTestId("file-chain").setInputFiles(join(work, "chain.pem"));
  await shot("23-wizard-1-upload");
  await page.getByRole("button", { name: "Upload & validate" }).click();

  // 2 validation (real findings, leaf details); warnings need an explicit acknowledgement
  const leaf = page.getByTestId("leaf-details");
  await expect(leaf).toContainText(CN);
  await expect(leaf).toContainText(newFp);
  await expect(page.locator('[data-severity="blocking"]')).toHaveCount(0);
  const cont = page.getByTestId("continue-validation");
  for (const box of await page.locator('[data-testid^="ack-"]').all()) await box.check();
  await shot("24-wizard-2-validation");
  await expect(cont).toBeEnabled();
  await cont.click();

  // 3 targets: only the managed nginx installation is selectable, others say why
  await expect(page.getByText("Step 3 — Select Target Servers")).toBeVisible();
  await expect(
    page.getByRole("checkbox", { name: `Select ${serverName} ${NGINX_DIR}/cert.pem` }),
  ).toBeDisabled(); // filesystem copy: unmanaged
  await expect(page.getByText(/Marked unmanaged/).first()).toBeVisible();
  await page.getByRole("checkbox", { name: `Select ${serverName} ${CERT_PATH}` }).check();
  await shot("25-wizard-3-targets");
  await page.getByTestId("continue-targets").click();

  // 4 plan: truthful dry run
  const plan = page.getByTestId("plan");
  await expect(plan).toBeVisible({ timeout: 60_000 });
  await expect(plan).toContainText("Dry run: nothing has been changed");
  const target = plan.getByTestId("plan-target");
  await expect(target).toContainText(CERT_PATH);
  await expect(target).toContainText(KEY_PATH);
  await expect(target).toContainText("replace");
  await expect(target).toContainText(/graceful reload of nginx/);
  // acknowledge plan-level warnings (each toggle re-plans); then Deploy must become available
  for (let i = 0; i < 5; i++) {
    const unchecked = page.locator('[data-testid^="ack-"]:not(:checked)');
    if ((await unchecked.count()) === 0) break;
    await unchecked.first().check();
    await expect(page.getByTestId("plan")).toBeVisible();
    await page.waitForTimeout(1500);
  }
  await page.waitForTimeout(500);
  await shot("26-wizard-4-plan-state");
  await expect(page.getByTestId("deploy-button")).toBeEnabled({ timeout: 60_000 });
  await shot("26-wizard-4-plan");
  await page.getByTestId("deploy-button").click();
  await expect(page.getByText("Confirm deployment")).toBeVisible();
  await shot("27-wizard-confirm");
  await page.getByTestId("confirm-deploy").click();

  // 5 live deployment
  await expect(page).toHaveURL(/deployment=/);
  const targets = page.getByTestId("deploy-targets");
  await expect(targets).toBeVisible();
  await expect(page.getByTestId("deploy-target")).toContainText("nginx");
  await expect(
    page.getByTestId("deploy-target").getByText("Completed", { exact: true }),
  ).toBeVisible({
    timeout: 120_000,
  });
  await expect(
    page.getByTestId("deploy-steps").locator('li[data-step="verify"][data-status="ok"]'),
  ).toHaveCount(1);
  await shot("28-wizard-5-progress-completed");

  // reload resumes from server state
  await page.reload();
  await expect(
    page.getByTestId("deploy-target").getByText("Completed", { exact: true }),
  ).toBeVisible();

  // ------------------------------------------------------------------ detail page: verified fingerprint
  await page.getByRole("link", { name: "View deployment detail" }).click();
  await expect(page).toHaveURL(/\/deployments\/[0-9a-f-]+$/);
  const verification = page.getByTestId("verification");
  await expect(verification).toContainText("Live TLS probe");
  await expect(verification).toContainText("Fingerprint verified");
  await expect(verification.getByTestId("served-fingerprint")).toContainText(newFp.slice(0, 12));
  await expect(
    page
      .getByTestId("deploy-steps")
      .locator("li")
      .filter({ hasText: /Back up/ }),
  ).toHaveCount(1);
  await shot("29-deployment-detail");

  // history lists it
  await page.goto("/deployments");
  await expect(page.getByRole("link", { name: /\d{4}-\d{2}-\d{2}/ }).first()).toBeVisible();
  await expect(page.locator("tbody").getByText("Completed").first()).toBeVisible();
  await shot("30-deployments-history");

  // ------------------------------------------------------------------ the target really serves the new certificate
  expect(servedFp()).toBe(newFp);
  expect(fpOfFile(CERT_PATH)).toBe(newFp); // fullchain.pem starts with the new leaf
  expect(readFileSync(KEY_PATH, "utf8")).toContain("PRIVATE KEY");
  const cn = sh("sh", [
    "-c",
    `echo | openssl s_client -connect 127.0.0.1:${NGINX_PORT} -servername ${CN} 2>/dev/null | openssl x509 -noout -subject -fingerprint -sha256`,
  ]);
  expect(cn).toContain(CN);
  expect(cn.replace(/:/g, "").toLowerCase()).toContain(newFp);

  // expirations + server detail still render real data
  await page.goto("/expirations");
  await expect(page.getByText("Expiring Certificates")).toBeVisible();
  await page.getByRole("button", { name: "Calendar" }).click();
  await expect(page.getByTestId("expiry-calendar")).toBeVisible();
  await shot("31-expirations-calendar");
});
