import { expect, test } from "@playwright/test";
import { mkdirSync } from "node:fs";

const SHOTS = process.env["E2E_SHOTS"] ?? "e2e/shots";
const ADMIN_USER = process.env["E2E_ADMIN_USER"] ?? "admin";
const ADMIN_PASS = process.env["E2E_ADMIN_PASSWORD"] ?? "admin-dev-password-123";
const KEY_FILE = process.env["E2E_SSH_KEY_FILE"] ?? "/var/lib/cdp-test/id_ed25519";
const SSH_PORT = process.env["E2E_SSH_PORT"] ?? "2222";
const SSH_USER = process.env["E2E_SSH_USER"] ?? "cdpdeploy";
const suffix = Date.now().toString(36);
const serverName = `e2e-${suffix}`;

test.beforeAll(() => mkdirSync(SHOTS, { recursive: true }));

test("login, dashboard, register server, host-key confirm, real connection test", async ({
  page,
}) => {
  const shot = (n: string) => page.screenshot({ path: `${SHOTS}/${n}.png`, fullPage: true });

  // unauthenticated -> /login
  await page.goto("/servers");
  await expect(page).toHaveURL(/\/login/);
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await shot("01-login");

  // wrong password shows an error and stays on /login
  await page.getByLabel("Username").fill(ADMIN_USER);
  await page.getByLabel("Password").fill("definitely-wrong-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText(/invalid/i);

  await page.getByLabel("Password").fill(ADMIN_PASS);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/servers/); // honours ?next=

  // dashboard
  await page.getByRole("link", { name: "Dashboard" }).click();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("Total Certificates")).toBeVisible();
  await expect(page.getByText("Expiration Distribution")).toBeVisible();
  await expect(page.getByText("Recent Activity")).toBeVisible();
  await page.waitForTimeout(500);
  await shot("02-dashboard");

  // add server with an inline new credential
  await page.getByRole("link", { name: "Servers" }).first().click();
  await page.getByRole("link", { name: "Add Server" }).first().click();
  await page.getByLabel("Server Name").fill(serverName);
  await page.getByLabel("Hostname / IP").fill("127.0.0.1");
  await page.getByLabel("SSH Port").fill(SSH_PORT);
  await page.getByLabel("SSH Username").fill(SSH_USER);
  await page.getByLabel("Environment").selectOption("Test");
  await page.getByRole("button", { name: /New credential/ }).click();
  await page.getByLabel("Credential name").fill(`cred-${suffix}`);
  await page.locator('input[type="file"]').setInputFiles(KEY_FILE);
  await expect(page.locator("#newcred-pem")).not.toHaveValue("");
  await shot("03-new-server-form");
  await page.getByRole("button", { name: "Save Server" }).click();

  // host key: scan -> fingerprint -> explicit confirm -> enroll
  await expect(page.getByText("Server registered")).toBeVisible();
  await page.getByRole("button", { name: "Scan host key" }).click();
  const fp = page.getByTestId("hostkey-fingerprint");
  await expect(fp).toContainText("SHA256:");
  const enroll = page.getByRole("button", { name: "Trust and enroll key" });
  await expect(enroll).toBeDisabled(); // needs explicit confirmation
  await shot("04-hostkey-scan");
  await page.getByRole("checkbox").check();
  await enroll.click();
  await expect(page.getByText("Enrolled", { exact: true }).first()).toBeVisible();

  // real connection test
  await page.getByRole("button", { name: "Test SSH Connection" }).click();
  const steps = page.getByTestId("connection-steps");
  await expect(steps).toBeVisible();
  await expect(steps.locator('li[data-status="ok"]')).toHaveCount(7);
  await expect(steps.locator('li[data-status="failed"]')).toHaveCount(0);
  await expect(steps).toContainText("Authentication");
  await shot("05-connection-test");

  // server details + list
  await page.getByRole("button", { name: "Open server" }).click();
  await expect(page.getByRole("heading", { name: serverName })).toBeVisible();
  await expect(page.getByText("Detected services")).toBeVisible();
  await shot("06-server-detail");
  await page.goto("/servers");
  await expect(page.getByRole("link", { name: serverName })).toBeVisible();
  await shot("07-servers-list");

  // audit + settings render real data
  await page.goto("/audit");
  await expect(page.getByText("SERVER_CREATED").first()).toBeVisible();
  await shot("08-audit");
  await page.goto("/settings");
  await expect(page.getByLabel("Application Name")).toBeVisible();
  await shot("09-settings");

  // logout
  await page.getByRole("button", { name: "Log out" }).click();
  await expect(page).toHaveURL(/\/login/);
});
