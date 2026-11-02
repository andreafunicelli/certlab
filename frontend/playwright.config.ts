import { defineConfig } from "@playwright/test";

// Smoke test expects: backend on :8000 (bootstrap admin), `bun run dev` (proxying /api) on E2E_BASE_URL,
// and the disposable SSH target on 127.0.0.1:2222 (infra/test-target).
export default defineConfig({
  testDir: "./e2e",
  timeout: 90_000,
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: process.env["E2E_BASE_URL"] ?? "http://127.0.0.1:5173",
    viewport: { width: 1440, height: 900 },
    launchOptions: process.env["PW_CHROMIUM_PATH"]
      ? { executablePath: process.env["PW_CHROMIUM_PATH"] }
      : {},
  },
});
