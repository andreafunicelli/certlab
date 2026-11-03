import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";

const ADMIN_USER = process.env["E2E_ADMIN_USER"] ?? "admin";
const ADMIN_PASS = process.env["E2E_ADMIN_PASSWORD"] ?? "admin-dev-password-123";
const KEY_FILE = process.env["E2E_SSH_KEY_FILE"] ?? "/var/lib/cdp-test/id_ed25519";
const SSH_PORT = process.env["E2E_SSH_PORT"] ?? "2222";
const SSH_USER = process.env["E2E_SSH_USER"] ?? "cdpdeploy";
const suffix = Date.now().toString(36);
const credName = `imp-cred-${suffix}`;
const goodName = `imp-ok-${suffix}`;
const badName = `imp-bad-${suffix}`;

const HEADER =
  "name,hostname,address,ssh_port,ssh_username,environment,credential,privilege_mode,bastion,tags,description,host_key_fingerprint";
const goodRow = `${goodName},127.0.0.1,,${SSH_PORT},${SSH_USER},Test,${credName},helper-sudo,,e2e|import,e2e import,`;
// invalid: missing hostname, unknown environment
const badRow = `${badName},,,${SSH_PORT},${SSH_USER},NoSuchEnv,${credName},helper-sudo,,,,`;

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
      await page.waitForSelector("button[type=submit]:not([disabled])");
      await page.waitForTimeout(1000);
    }
  }
  throw new Error("could not sign in");
}

test("CSV import: template, dry-run errors, import, host key verify+enroll, scan history", async ({
  page,
}) => {
  await login(page);

  // credential via API (CSRF token comes from /auth/me)
  const me = (await (await page.request.get("/api/v1/auth/me")).json()) as { csrf_token: string };
  const cred = await page.request.post("/api/v1/credentials", {
    headers: { "X-CSRF-Token": me.csrf_token },
    multipart: { name: credName, private_key: readFileSync(KEY_FILE, "utf8") },
  });
  expect(cred.ok()).toBeTruthy();

  await page.goto("/servers");
  await page.getByRole("link", { name: "Import CSV" }).click();
  await expect(page).toHaveURL(/\/servers\/import/);

  // template download
  const [dl] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Download template" }).click(),
  ]);
  expect(dl.suggestedFilename()).toMatch(/\.csv$/);
  const tpl = readFileSync(await dl.path(), "utf8");
  expect(tpl).toContain("ssh_username");

  // dry run with one bad row: preview shows the error, import is blocked
  await page.locator("#csv-file").setInputFiles({
    name: "bad.csv",
    mimeType: "text/csv",
    buffer: Buffer.from([HEADER, goodRow, badRow].join("\n")),
  });
  await page.getByRole("button", { name: /Check file/ }).click();
  const preview = page.getByTestId("import-preview");
  await expect(preview).toBeVisible();
  await expect(preview).toContainText(badName);
  await expect(preview.getByText("error", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: /^Import \d+ server/ })).toBeDisabled();

  // valid file: import
  await page.locator("#csv-file").setInputFiles({
    name: "ok.csv",
    mimeType: "text/csv",
    buffer: Buffer.from([HEADER, goodRow].join("\n")),
  });
  await page.getByRole("button", { name: /Check file/ }).click();
  await expect(page.getByTestId("import-preview")).toContainText(goodName);
  await page.getByRole("button", { name: "Import 1 server" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Import", exact: true }).click();
  const result = page.getByTestId("import-result");
  await expect(result).toContainText("created");
  await expect(result).toContainText("Needs verification");

  // host key verification: nothing is pre-selected
  await page.getByRole("button", { name: "Scan host keys" }).click();
  const fp = page.getByTestId("scan-fingerprint").first();
  await expect(fp).toContainText("SHA256:");
  const tick = page.getByRole("checkbox", { name: new RegExp(goodName) });
  await expect(tick).not.toBeChecked();
  await expect(page.getByRole("button", { name: /Enroll selected \(0\)/ })).toBeDisabled();
  await tick.check();
  await page.getByRole("button", { name: /Enroll selected \(1\)/ }).click();
  await expect(
    page.getByTestId("hostkey-step").getByText("Enrolled", { exact: true }),
  ).toBeVisible();

  // discovery on the imported server, then the scan history shows steps and log
  await page.getByRole("button", { name: /Run discovery on imported servers/ }).click();
  await page.goto("/servers");
  await page.getByRole("link", { name: goodName }).click();
  const history = page.getByTestId("scan-history");
  await expect(history).toBeVisible();
  await expect
    .poll(async () => history.locator("tbody tr").count(), { timeout: 30_000 })
    .toBeGreaterThan(0);
  await history
    .getByRole("button", { name: /Expand scan/ })
    .first()
    .click();
  await expect(history.getByTestId("discovery-steps")).toBeVisible({ timeout: 30_000 });
  await expect(history.getByTestId("discovery-log")).toBeVisible();
  await expect(page.getByTestId("last-scan")).toBeVisible();
});
