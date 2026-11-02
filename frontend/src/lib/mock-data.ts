// DEMO/TEST ONLY — static fixtures from the original Lovable prototype. Real pages use src/lib/api/*.
// Still imported only by routes that are not wired to the API yet (certificates, expirations, deployments, renew wizard).
export type CertStatus =
  | "valid"
  | "expiring"
  | "critical"
  | "expired"
  | "error";

export type Environment = "Production" | "Staging" | "Test" | "Development";

export interface Installation {
  serverId: string;
  serverName: string;
  hostname: string;
  ip: string;
  environment: Environment;
  certPath: string;
  keyPath: string;
  webServer: string;
  syncStatus: "Synced" | "Out of sync" | "Unknown";
  lastDeployment: string;
}

export interface Certificate {
  id: string;
  name: string;
  commonName: string;
  sans: string[];
  issuer: string;
  ca: string;
  validFrom: string;
  expiration: string;
  daysRemaining: number;
  status: CertStatus;
  serial: string;
  fingerprint: string;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  keySize: number;
  files: { cert: string; key: string; chain: string; fullchain: string };
  installations: Installation[];
  owner: string;
}

export interface Server {
  id: string;
  name: string;
  hostname: string;
  ip: string;
  environment: Environment;
  os: string;
  webServer: string;
  nginxVersion: string;
  sshStatus: "Connected" | "Offline" | "Auth error";
  sshPort: number;
  sshUser: string;
  certCount: number;
  lastCheck: string;
  lastConnection: string;
}

export interface DeploymentStep {
  label: string;
  state: "pending" | "running" | "ok" | "failed" | "skipped";
  detail?: string;
}

export interface DeploymentTarget {
  serverName: string;
  ip: string;
  status: "pending" | "running" | "success" | "failed" | "rolledback";
  steps: DeploymentStep[];
  error?: string;
  timeline?: { time: string; text: string; kind?: "ok" | "fail" | "warn" }[];
}

export interface Deployment {
  id: string;
  date: string;
  certificate: string;
  certificateId: string;
  user: string;
  targets: number;
  succeeded: number;
  failed: number;
  duration: string;
  status: "Success" | "Partial Failure" | "Failed" | "Running";
  detail: DeploymentTarget[];
}

export const currentUser = {
  name: "Andrea Funicelli",
  short: "Andrea",
  role: "Administrator",
  email: "andrea@youco.cloud",
  ip: "10.20.10.100",
};

const okSteps = (): DeploymentStep[] => [
  { label: "SSH Connection", state: "ok" },
  { label: "Backup Existing Certificate", state: "ok" },
  { label: "Backup Existing Private Key", state: "ok" },
  { label: "Upload Certificate", state: "ok" },
  { label: "Upload Private Key", state: "ok" },
  { label: "File Permissions", state: "ok", detail: "0644 / 0600 root:root" },
  { label: "nginx -t", state: "ok", detail: "syntax is ok, test is successful" },
  { label: "Reload Nginx", state: "ok" },
  { label: "TLS Verification (:443)", state: "ok", detail: "CN=*.youco.cloud" },
];

export const servers: Server[] = [
  {
    id: "web-prod-01",
    name: "WEB-PROD-01",
    hostname: "web01.youco.local",
    ip: "10.20.10.21",
    environment: "Production",
    os: "Ubuntu 24.04 LTS",
    webServer: "Nginx",
    nginxVersion: "nginx/1.24.0",
    sshStatus: "Connected",
    sshPort: 22,
    sshUser: "certmgr",
    certCount: 4,
    lastCheck: "10 Sep 2026 14:05",
    lastConnection: "10 Sep 2026 14:32:01",
  },
  {
    id: "web-prod-02",
    name: "WEB-PROD-02",
    hostname: "web02.youco.local",
    ip: "10.20.10.22",
    environment: "Production",
    os: "Ubuntu 24.04 LTS",
    webServer: "Nginx",
    nginxVersion: "nginx/1.24.0",
    sshStatus: "Connected",
    sshPort: 22,
    sshUser: "certmgr",
    certCount: 4,
    lastCheck: "10 Sep 2026 14:05",
    lastConnection: "10 Sep 2026 14:32:04",
  },
  {
    id: "waf-01",
    name: "WAF-01",
    hostname: "waf01.youco.local",
    ip: "10.20.10.30",
    environment: "Production",
    os: "Ubuntu 24.04 LTS",
    webServer: "Nginx",
    nginxVersion: "nginx/1.26.2",
    sshStatus: "Connected",
    sshPort: 22,
    sshUser: "certmgr",
    certCount: 8,
    lastCheck: "10 Sep 2026 14:05",
    lastConnection: "10 Sep 2026 14:32:07",
  },
  {
    id: "reverse-proxy-01",
    name: "REVERSE-PROXY-01",
    hostname: "rp01.youco.local",
    ip: "10.200.40.21",
    environment: "Production",
    os: "Debian 12",
    webServer: "Nginx",
    nginxVersion: "nginx/1.22.1",
    sshStatus: "Connected",
    sshPort: 2222,
    sshUser: "certmgr",
    certCount: 5,
    lastCheck: "10 Sep 2026 13:40",
    lastConnection: "10 Sep 2026 13:40:12",
  },
  {
    id: "web-stage-01",
    name: "WEB-STAGE-01",
    hostname: "stage01.youco.local",
    ip: "10.20.20.11",
    environment: "Staging",
    os: "Ubuntu 24.04 LTS",
    webServer: "Nginx",
    nginxVersion: "nginx/1.24.0",
    sshStatus: "Connected",
    sshPort: 22,
    sshUser: "certmgr",
    certCount: 3,
    lastCheck: "10 Sep 2026 12:55",
    lastConnection: "10 Sep 2026 12:55:33",
  },
  {
    id: "web-test-01",
    name: "WEB-TEST-01",
    hostname: "test01.youco.local",
    ip: "10.20.10.45",
    environment: "Test",
    os: "Ubuntu 22.04 LTS",
    webServer: "Nginx",
    nginxVersion: "nginx/1.18.0",
    sshStatus: "Offline",
    sshPort: 22,
    sshUser: "certmgr",
    certCount: 2,
    lastCheck: "09 Sep 2026 21:10",
    lastConnection: "09 Sep 2026 21:10:02",
  },
];

export const certificates: Certificate[] = [
  {
    id: "star-youco-cloud",
    name: "star-youco-cloud",
    commonName: "*.youco.cloud",
    sans: ["*.youco.cloud", "youco.cloud"],
    issuer: "Actalis Domain Validated TLS Server RSA CA 2025",
    ca: "Actalis",
    validFrom: "07 Mar 2026",
    expiration: "07 Mar 2027",
    daysRemaining: 178,
    status: "valid",
    serial: "4A:9C:11:E0:77:B3:2D:58:90:14:CC:6F:21:AB:03:D7",
    fingerprint:
      "34:80:88:7F:3B:0B:E5:5D:9C:41:2A:6E:D8:73:B0:15:FA:22:9E:4C:71:06:8B:3D:55:E9:12:AF:60:C4:77:1B",
    signatureAlgorithm: "SHA-256 with RSA Encryption",
    publicKeyAlgorithm: "RSA",
    keySize: 2048,
    files: {
      cert: "star.youco.cloud.cer",
      key: "star.youco.cloud.key",
      chain: "actalis_dv_tls_rsa_2025.pem",
      fullchain: "star.youco.cloud.fullchain.pem",
    },
    owner: "Andrea",
    installations: [
      {
        serverId: "web-prod-01",
        serverName: "WEB-PROD-01",
        hostname: "web01.youco.local",
        ip: "10.20.10.21",
        environment: "Production",
        certPath: "/etc/ssl/certs/star.youco.cloud.cer",
        keyPath: "/etc/ssl/private/star.youco.cloud.key",
        webServer: "Nginx",
        syncStatus: "Synced",
        lastDeployment: "07 Mar 2026 09:12",
      },
      {
        serverId: "web-prod-02",
        serverName: "WEB-PROD-02",
        hostname: "web02.youco.local",
        ip: "10.20.10.22",
        environment: "Production",
        certPath: "/etc/ssl/certs/star.youco.cloud.cer",
        keyPath: "/etc/ssl/private/star.youco.cloud.key",
        webServer: "Nginx",
        syncStatus: "Synced",
        lastDeployment: "07 Mar 2026 09:12",
      },
      {
        serverId: "waf-01",
        serverName: "WAF-01",
        hostname: "waf01.youco.local",
        ip: "10.20.10.30",
        environment: "Production",
        certPath: "/var/certificates/youco.cloud/star.youco.cloud.cer",
        keyPath: "/var/certificates/youco.cloud/star.youco.cloud.key",
        webServer: "Nginx",
        syncStatus: "Synced",
        lastDeployment: "07 Mar 2026 09:13",
      },
      {
        serverId: "reverse-proxy-01",
        serverName: "REVERSE-PROXY-01",
        hostname: "rp01.youco.local",
        ip: "10.200.40.21",
        environment: "Production",
        certPath: "/etc/nginx/ssl/star.youco.cloud.cer",
        keyPath: "/etc/nginx/ssl/star.youco.cloud.key",
        webServer: "Nginx",
        syncStatus: "Synced",
        lastDeployment: "07 Mar 2026 09:14",
      },
      {
        serverId: "web-stage-01",
        serverName: "WEB-STAGE-01",
        hostname: "stage01.youco.local",
        ip: "10.20.20.11",
        environment: "Staging",
        certPath: "/etc/nginx/certs/star.youco.cloud.cer",
        keyPath: "/etc/nginx/certs/star.youco.cloud.key",
        webServer: "Nginx",
        syncStatus: "Out of sync",
        lastDeployment: "12 Mar 2026 18:02",
      },
      {
        serverId: "web-test-01",
        serverName: "WEB-TEST-01",
        hostname: "test01.youco.local",
        ip: "10.20.10.45",
        environment: "Test",
        certPath: "/etc/ssl/certs/star.youco.cloud.cer",
        keyPath: "/etc/ssl/private/star.youco.cloud.key",
        webServer: "Nginx",
        syncStatus: "Unknown",
        lastDeployment: "07 Mar 2026 09:20",
      },
    ],
  },
  {
    id: "gruppoimq-www",
    name: "gruppoimq-www",
    commonName: "www.gruppoimq.it",
    sans: ["www.gruppoimq.it", "gruppoimq.it"],
    issuer: "Actalis Organization Validated TLS Server RSA CA 2025",
    ca: "Actalis",
    validFrom: "01 Mar 2026",
    expiration: "01 Mar 2027",
    daysRemaining: 172,
    status: "expiring",
    serial: "1C:55:D2:90:3E:41:78:AA:0B:63:9F:12:CE:74:80:22",
    fingerprint:
      "9B:12:C4:60:AD:75:31:0E:F8:22:5C:9A:41:B7:63:D0:2E:88:14:7F:C3:56:9D:01:BA:47:E2:38:6C:15:90:44",
    signatureAlgorithm: "SHA-256 with RSA Encryption",
    publicKeyAlgorithm: "RSA",
    keySize: 2048,
    files: {
      cert: "www.gruppoimq.it.crt",
      key: "www.gruppoimq.it.key",
      chain: "actalis_ov_tls_rsa_2025.pem",
      fullchain: "www.gruppoimq.it.fullchain.pem",
    },
    owner: "Andrea",
    installations: [
      {
        serverId: "web-prod-01",
        serverName: "WEB-PROD-01",
        hostname: "web01.youco.local",
        ip: "10.20.10.21",
        environment: "Production",
        certPath: "/etc/nginx/ssl/www.gruppoimq.it.crt",
        keyPath: "/etc/nginx/ssl/www.gruppoimq.it.key",
        webServer: "Nginx",
        syncStatus: "Synced",
        lastDeployment: "01 Mar 2026 10:41",
      },
      {
        serverId: "waf-01",
        serverName: "WAF-01",
        hostname: "waf01.youco.local",
        ip: "10.20.10.30",
        environment: "Production",
        certPath: "/var/certificates/gruppoimq/www.gruppoimq.it.crt",
        keyPath: "/var/certificates/gruppoimq/www.gruppoimq.it.key",
        webServer: "Nginx",
        syncStatus: "Synced",
        lastDeployment: "01 Mar 2026 10:42",
      },
    ],
  },
  {
    id: "portal-customer-it",
    name: "portal-customer-it",
    commonName: "portal.customer.it",
    sans: ["portal.customer.it", "api.portal.customer.it"],
    issuer: "Sectigo RSA Organization Validation Secure Server CA",
    ca: "Sectigo",
    validFrom: "18 Sep 2025",
    expiration: "18 Sep 2026",
    daysRemaining: 8,
    status: "critical",
    serial: "77:0A:31:BE:52:6D:19:C8:44:F1:2B:90:35:7E:D6:63",
    fingerprint:
      "5D:71:9E:04:B2:38:CA:66:1F:47:80:E5:3B:29:D4:7A:60:11:8C:F3:92:55:0B:AE:74:26:C1:69:D8:3F:07:B5",
    signatureAlgorithm: "SHA-256 with RSA Encryption",
    publicKeyAlgorithm: "RSA",
    keySize: 2048,
    files: {
      cert: "portal.customer.it.crt",
      key: "portal.customer.it.key",
      chain: "sectigo_rsa_ov.pem",
      fullchain: "portal.customer.it.fullchain.pem",
    },
    owner: "Marco",
    installations: [
      {
        serverId: "reverse-proxy-01",
        serverName: "REVERSE-PROXY-01",
        hostname: "rp01.youco.local",
        ip: "10.200.40.21",
        environment: "Production",
        certPath: "/etc/nginx/ssl/portal.customer.it.crt",
        keyPath: "/etc/nginx/ssl/portal.customer.it.key",
        webServer: "Nginx",
        syncStatus: "Synced",
        lastDeployment: "18 Sep 2025 11:20",
      },
      {
        serverId: "waf-01",
        serverName: "WAF-01",
        hostname: "waf01.youco.local",
        ip: "10.20.10.30",
        environment: "Production",
        certPath: "/var/certificates/customer/portal.customer.it.crt",
        keyPath: "/var/certificates/customer/portal.customer.it.key",
        webServer: "Nginx",
        syncStatus: "Synced",
        lastDeployment: "18 Sep 2025 11:21",
      },
      {
        serverId: "web-prod-02",
        serverName: "WEB-PROD-02",
        hostname: "web02.youco.local",
        ip: "10.20.10.22",
        environment: "Production",
        certPath: "/etc/ssl/certs/portal.customer.it.crt",
        keyPath: "/etc/ssl/private/portal.customer.it.key",
        webServer: "Nginx",
        syncStatus: "Synced",
        lastDeployment: "18 Sep 2025 11:22",
      },
    ],
  },
  {
    id: "vpn-youco-cloud",
    name: "vpn-youco-cloud",
    commonName: "vpn.youco.cloud",
    sans: ["vpn.youco.cloud"],
    issuer: "DigiCert TLS RSA SHA256 2020 CA1",
    ca: "DigiCert",
    validFrom: "02 Sep 2025",
    expiration: "02 Sep 2026",
    daysRemaining: -8,
    status: "expired",
    serial: "0E:44:B1:77:2C:39:65:D0:8A:53:F2:16:9C:20:47:B8",
    fingerprint:
      "C1:38:74:9F:2B:56:E0:11:A7:6D:3C:85:47:F9:20:6B:D4:1E:73:58:0A:92:BF:34:6E:C7:15:80:29:AD:53:F1",
    signatureAlgorithm: "SHA-256 with RSA Encryption",
    publicKeyAlgorithm: "RSA",
    keySize: 4096,
    files: {
      cert: "vpn.youco.cloud.crt",
      key: "vpn.youco.cloud.key",
      chain: "digicert_tls_rsa_sha256_2020_ca1.pem",
      fullchain: "vpn.youco.cloud.fullchain.pem",
    },
    owner: "Andrea",
    installations: [
      {
        serverId: "reverse-proxy-01",
        serverName: "REVERSE-PROXY-01",
        hostname: "rp01.youco.local",
        ip: "10.200.40.21",
        environment: "Production",
        certPath: "/etc/nginx/ssl/vpn.youco.cloud.crt",
        keyPath: "/etc/nginx/ssl/vpn.youco.cloud.key",
        webServer: "Nginx",
        syncStatus: "Out of sync",
        lastDeployment: "02 Sep 2025 08:05",
      },
    ],
  },
  {
    id: "repo-youco-cloud",
    name: "repo-youco-cloud",
    commonName: "repo.youco.cloud",
    sans: ["repo.youco.cloud", "registry.youco.cloud"],
    issuer: "GlobalSign GCC R6 AlphaSSL CA 2023",
    ca: "GlobalSign",
    validFrom: "20 Oct 2025",
    expiration: "20 Oct 2026",
    daysRemaining: 40,
    status: "expiring",
    serial: "3F:80:2A:C6:14:9B:57:E3:70:15:DA:28:6C:B1:44:09",
    fingerprint:
      "A7:52:0C:38:9D:61:74:B5:2E:C0:88:47:15:F3:6A:D9:31:7E:24:B8:50:9C:E1:06:73:AF:12:58:8D:64:30:2C",
    signatureAlgorithm: "SHA-256 with RSA Encryption",
    publicKeyAlgorithm: "RSA",
    keySize: 2048,
    files: {
      cert: "repo.youco.cloud.cer",
      key: "repo.youco.cloud.key",
      chain: "globalsign_r6_alphassl_2023.pem",
      fullchain: "repo.youco.cloud.fullchain.pem",
    },
    owner: "Luca",
    installations: [
      {
        serverId: "web-prod-01",
        serverName: "WEB-PROD-01",
        hostname: "web01.youco.local",
        ip: "10.20.10.21",
        environment: "Production",
        certPath: "/etc/nginx/certs/repo.youco.cloud.cer",
        keyPath: "/etc/nginx/certs/repo.youco.cloud.key",
        webServer: "Nginx",
        syncStatus: "Synced",
        lastDeployment: "20 Oct 2025 16:30",
      },
      {
        serverId: "waf-01",
        serverName: "WAF-01",
        hostname: "waf01.youco.local",
        ip: "10.20.10.30",
        environment: "Production",
        certPath: "/var/certificates/youco.cloud/repo.youco.cloud.cer",
        keyPath: "/var/certificates/youco.cloud/repo.youco.cloud.key",
        webServer: "Nginx",
        syncStatus: "Synced",
        lastDeployment: "20 Oct 2025 16:31",
      },
    ],
  },
  {
    id: "alfaintes-youco-cloud",
    name: "alfaintes-youco-cloud",
    commonName: "alfaintes.youco.cloud",
    sans: ["alfaintes.youco.cloud"],
    issuer: "Entrust Certification Authority - L1K",
    ca: "Entrust",
    validFrom: "28 Jan 2026",
    expiration: "28 Jan 2027",
    daysRemaining: 140,
    status: "error",
    serial: "6B:19:F4:03:8C:27:5A:DE:41:90:B2:76:38:0C:E5:11",
    fingerprint:
      "E3:64:17:9A:5C:20:B8:47:D1:36:0F:72:AE:59:83:14:6D:C2:41:78:0B:95:3E:AF:22:57:D8:60:14:9C:73:2B",
    signatureAlgorithm: "SHA-384 with ECDSA",
    publicKeyAlgorithm: "ECDSA",
    keySize: 384,
    files: {
      cert: "alfaintes.youco.cloud.cer",
      key: "alfaintes.youco.cloud.key",
      chain: "entrust_l1k.pem",
      fullchain: "alfaintes.youco.cloud.fullchain.pem",
    },
    owner: "Andrea",
    installations: [
      {
        serverId: "web-prod-02",
        serverName: "WEB-PROD-02",
        hostname: "web02.youco.local",
        ip: "10.20.10.22",
        environment: "Production",
        certPath: "/etc/ssl/certs/alfaintes.youco.cloud.cer",
        keyPath: "/etc/ssl/private/alfaintes.youco.cloud.key",
        webServer: "Nginx",
        syncStatus: "Out of sync",
        lastDeployment: "10 Sep 2026 14:32",
      },
    ],
  },
];

export const expirationBuckets = [
  { bucket: "Expired", count: 1, tone: "danger" as const },
  { bucket: "< 7 days", count: 2, tone: "crit" as const },
  { bucket: "7–30 days", count: 5, tone: "warn" as const },
  { bucket: "30–90 days", count: 11, tone: "info" as const },
  { bucket: "> 90 days", count: 23, tone: "ok" as const },
];

export const deployments: Deployment[] = [
  {
    id: "dep-20260910-1432",
    date: "10 Sep 2026 14:32",
    certificate: "*.youco.cloud",
    certificateId: "star-youco-cloud",
    user: "Andrea",
    targets: 3,
    succeeded: 2,
    failed: 1,
    duration: "18 sec",
    status: "Partial Failure",
    detail: [
      {
        serverName: "WEB-PROD-01",
        ip: "10.20.10.21",
        status: "success",
        steps: okSteps(),
        timeline: [
          { time: "14:32:01", text: "SSH Connected", kind: "ok" },
          { time: "14:32:02", text: "Certificate Backup Created — star.youco.cloud.cer.bak-20260910-143202", kind: "ok" },
          { time: "14:32:03", text: "Private Key Backup Created — star.youco.cloud.key.bak-20260910-143203", kind: "ok" },
          { time: "14:32:05", text: "New Certificate Uploaded", kind: "ok" },
          { time: "14:32:06", text: "Permissions applied (0644 / 0600)", kind: "ok" },
          { time: "14:32:07", text: "nginx -t OK", kind: "ok" },
          { time: "14:32:08", text: "Nginx Reloaded", kind: "ok" },
          { time: "14:32:10", text: "TLS verification on :443 OK", kind: "ok" },
        ],
      },
      {
        serverName: "WEB-PROD-02",
        ip: "10.20.10.22",
        status: "rolledback",
        error:
          'nginx: [emerg] cannot load certificate "/etc/ssl/certs/star.youco.cloud.cer": PEM_read_bio_X509_AUX() failed (SSL: error:0480006C:PEM routines::no start line)',
        steps: [
          { label: "SSH Connection", state: "ok" },
          { label: "Backup Existing Certificate", state: "ok" },
          { label: "Backup Existing Private Key", state: "ok" },
          { label: "Upload Certificate", state: "ok" },
          { label: "Upload Private Key", state: "ok" },
          { label: "File Permissions", state: "ok" },
          { label: "nginx -t", state: "failed", detail: "cannot load certificate" },
          { label: "Reload Nginx", state: "skipped" },
          { label: "TLS Verification (:443)", state: "skipped" },
        ],
        timeline: [
          { time: "14:32:01", text: "SSH Connected", kind: "ok" },
          { time: "14:32:03", text: "Certificate Backup Created", kind: "ok" },
          { time: "14:32:05", text: "New Certificate Uploaded", kind: "ok" },
          { time: "14:32:07", text: "nginx -t FAILED", kind: "fail" },
          { time: "14:32:08", text: "Rollback Started", kind: "warn" },
          { time: "14:32:10", text: "Previous Certificate Restored", kind: "ok" },
          { time: "14:32:10", text: "Previous Private Key Restored", kind: "ok" },
          { time: "14:32:11", text: "nginx -t OK", kind: "ok" },
          { time: "14:32:12", text: "Nginx Reloaded", kind: "ok" },
          { time: "14:32:13", text: "Rollback Completed", kind: "ok" },
        ],
      },
      {
        serverName: "WAF-01",
        ip: "10.20.10.30",
        status: "success",
        steps: okSteps(),
        timeline: [
          { time: "14:32:02", text: "SSH Connected", kind: "ok" },
          { time: "14:32:04", text: "Certificate Backup Created", kind: "ok" },
          { time: "14:32:06", text: "New Certificate Uploaded", kind: "ok" },
          { time: "14:32:09", text: "nginx -t OK", kind: "ok" },
          { time: "14:32:11", text: "Nginx Reloaded", kind: "ok" },
          { time: "14:32:14", text: "TLS verification on :443 OK", kind: "ok" },
        ],
      },
    ],
  },
  {
    id: "dep-20260904-0912",
    date: "04 Sep 2026 09:12",
    certificate: "repo.youco.cloud",
    certificateId: "repo-youco-cloud",
    user: "Luca",
    targets: 2,
    succeeded: 2,
    failed: 0,
    duration: "11 sec",
    status: "Success",
    detail: [
      { serverName: "WEB-PROD-01", ip: "10.20.10.21", status: "success", steps: okSteps() },
      { serverName: "WAF-01", ip: "10.20.10.30", status: "success", steps: okSteps() },
    ],
  },
  {
    id: "dep-20260828-1745",
    date: "28 Aug 2026 17:45",
    certificate: "www.gruppoimq.it",
    certificateId: "gruppoimq-www",
    user: "Andrea",
    targets: 2,
    succeeded: 2,
    failed: 0,
    duration: "9 sec",
    status: "Success",
    detail: [
      { serverName: "WEB-PROD-01", ip: "10.20.10.21", status: "success", steps: okSteps() },
      { serverName: "WAF-01", ip: "10.20.10.30", status: "success", steps: okSteps() },
    ],
  },
  {
    id: "dep-20260819-1102",
    date: "19 Aug 2026 11:02",
    certificate: "vpn.youco.cloud",
    certificateId: "vpn-youco-cloud",
    user: "Marco",
    targets: 1,
    succeeded: 0,
    failed: 1,
    duration: "6 sec",
    status: "Failed",
    detail: [
      {
        serverName: "REVERSE-PROXY-01",
        ip: "10.200.40.21",
        status: "failed",
        error: "ssh: handshake failed — host key verification failed for rp01.youco.local:2222",
        steps: [
          { label: "SSH Connection", state: "failed", detail: "host key verification failed" },
          { label: "Backup Existing Certificate", state: "skipped" },
          { label: "Upload Certificate", state: "skipped" },
          { label: "nginx -t", state: "skipped" },
          { label: "Reload Nginx", state: "skipped" },
          { label: "TLS Verification (:443)", state: "skipped" },
        ],
      },
    ],
  },
];

export interface AuditEntry {
  timestamp: string;
  user: string;
  action: string;
  certificate: string;
  server: string;
  ip: string;
  result: "SUCCESS" | "FAILED" | "WARNING";
}

export const auditLog: AuditEntry[] = [
  { timestamp: "10 Sep 2026 14:32:13", user: "Andrea", action: "ROLLBACK_COMPLETED", certificate: "*.youco.cloud", server: "WEB-PROD-02", ip: "10.20.10.100", result: "WARNING" },
  { timestamp: "10 Sep 2026 14:32:08", user: "Andrea", action: "ROLLBACK_STARTED", certificate: "*.youco.cloud", server: "WEB-PROD-02", ip: "10.20.10.100", result: "WARNING" },
  { timestamp: "10 Sep 2026 14:32:07", user: "Andrea", action: "DEPLOYMENT_FAILED", certificate: "*.youco.cloud", server: "WEB-PROD-02", ip: "10.20.10.100", result: "FAILED" },
  { timestamp: "10 Sep 2026 14:32:06", user: "Andrea", action: "NGINX_RELOAD", certificate: "*.youco.cloud", server: "WAF-01", ip: "10.20.10.100", result: "SUCCESS" },
  { timestamp: "10 Sep 2026 14:32:02", user: "Andrea", action: "DEPLOY_CERTIFICATE", certificate: "*.youco.cloud", server: "WEB-PROD-01", ip: "10.20.10.100", result: "SUCCESS" },
  { timestamp: "10 Sep 2026 14:31:55", user: "Andrea", action: "DEPLOYMENT_STARTED", certificate: "*.youco.cloud", server: "3 servers", ip: "10.20.10.100", result: "SUCCESS" },
  { timestamp: "10 Sep 2026 14:29:40", user: "Andrea", action: "CERTIFICATE_REPLACED", certificate: "*.youco.cloud", server: "—", ip: "10.20.10.100", result: "SUCCESS" },
  { timestamp: "10 Sep 2026 14:28:11", user: "Andrea", action: "CERTIFICATE_UPLOAD", certificate: "star.youco.cloud.cer", server: "—", ip: "10.20.10.100", result: "SUCCESS" },
  { timestamp: "10 Sep 2026 11:04:23", user: "Luca", action: "SSH_CONNECTION_TEST", certificate: "—", server: "WEB-TEST-01", ip: "10.20.10.114", result: "FAILED" },
  { timestamp: "09 Sep 2026 18:22:07", user: "Marco", action: "SERVER_ADDED", certificate: "—", server: "WEB-STAGE-01", ip: "10.20.10.132", result: "SUCCESS" },
  { timestamp: "08 Sep 2026 09:15:44", user: "Andrea", action: "SERVER_REMOVED", certificate: "—", server: "WEB-OLD-03", ip: "10.20.10.100", result: "SUCCESS" },
  { timestamp: "04 Sep 2026 09:12:31", user: "Luca", action: "DEPLOY_CERTIFICATE", certificate: "repo.youco.cloud", server: "WAF-01", ip: "10.20.10.114", result: "SUCCESS" },
];

export const discoveredCertificates = [
  {
    domain: "alfaintes.youco.cloud",
    vhost: "/etc/nginx/sites-enabled/alfaintes.conf",
    cert: "/etc/ssl/certs/star.youco.cloud.cer",
    key: "/etc/ssl/private/star.youco.cloud.key",
    issuer: "Actalis Domain Validated TLS Server RSA CA 2025",
    expiration: "07 Mar 2027",
    known: true,
  },
  {
    domain: "monitoring.youco.local",
    vhost: "/etc/nginx/sites-enabled/monitoring.conf",
    cert: "/etc/nginx/ssl/monitoring.youco.local.crt",
    key: "/etc/nginx/ssl/monitoring.youco.local.key",
    issuer: "YouCo Internal Issuing CA",
    expiration: "14 Jun 2027",
    known: false,
  },
  {
    domain: "repo.youco.cloud",
    vhost: "/etc/nginx/sites-enabled/repo.conf",
    cert: "/etc/nginx/certs/repo.youco.cloud.cer",
    key: "/etc/nginx/certs/repo.youco.cloud.key",
    issuer: "GlobalSign GCC R6 AlphaSSL CA 2023",
    expiration: "20 Oct 2026",
    known: true,
  },
];

export const statsSummary = {
  total: 42,
  expiring: 7,
  expired: 1,
  servers: 18,
  failedDeployments: 2,
};

export function getCertificate(id: string) {
  return certificates.find((c) => c.id === id);
}
export function getServer(id: string) {
  return servers.find((s) => s.id === id);
}
export function getDeployment(id: string) {
  return deployments.find((d) => d.id === id);
}
