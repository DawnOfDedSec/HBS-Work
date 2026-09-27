/** DocBlock primitives shared by the docs reader and pages. */
export type DocBlock =
  | { type: 'text'; content: string }
  | { type: 'h3'; content: string }
  | { type: 'code'; content: string; lang?: string; title?: string }
  | { type: 'table'; headers: string[]; rows: string[][] }
  | { type: 'list'; items: string[] }
  | { type: 'note'; tone: 'info' | 'warn' | 'tip'; content: string };

export interface DocSection {
  slug: string;
  title: string;
  blurb: string;
  content: DocBlock[];
}

export const DOC_SECTIONS: DocSection[] = [
  {
    slug: 'getting-started',
    title: 'Getting started',
    blurb: 'Install the dashboard, issue a patched extractor, run the read-only scan, deliver the sealed report.',
    content: [
      { type: 'h3', content: '1. The dashboard (hosted on your machine)' },
      {
        type: 'code',
        lang: 'bash',
        title: 'Linux / macOS one-line install',
        content: `curl -fsSL https://raw.githubusercontent.com/PotenFYR-Studios/HBS-Tool/main/scripts/install.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/PotenFYR-Studios/HBS-Tool/main/scripts/install.ps1 | iex`,
      },
      {
        type: 'code',
        lang: 'bash',
        title: 'From a clone',
        content: `cd dashboard
bun install
bun run build                 # emits dist/ (the API server serves the SPA too)
bun server/index.ts           # http://127.0.0.1:3000`,
      },
      {
        type: 'note',
        tone: 'info',
        content:
          'On first launch (no users) the server prints superuser credentials once in the CLI. Sign in and change the password.',
      },
      { type: 'h3', content: '2. Create campaign → location → issuance' },
      {
        type: 'text',
        content:
          'In the UI: Campaigns → New campaign (adds the first location), then Locations → Generate extractor. Or via API:',
      },
      {
        type: 'code',
        lang: 'http',
        content: `POST /api/campaigns                         { "name":"Acme Q3", "locations":[{"name":"DC-East"}] }
POST /api/campaigns/:id/locations/:loc/issuances   { "platform":"linux-amd64" }
GET  /api/issuances/:id/download?token=<downloadToken>`,
      },
      { type: 'h3', content: '3. Run the extractor on the target (offline)' },
      {
        type: 'code',
        lang: 'bash',
        content: `# Linux (amd64), unprivileged; report lands beside the binary
./hbs-extractor --no-elevate --quiet

# Windows (PowerShell/cmd)
hbs-extractor.exe --no-elevate --quiet`,
      },
      { type: 'h3', content: '4. Deliver the report — pick one' },
      {
        type: 'code',
        lang: 'bash',
        content: `# (A) Upload in the dashboard
#     Campaign → Locations & Hosts → drag the .hbs into the drop zone

# (B) Optional push from the extractor (only then does it use the network)
HBS_PUSH_TOKEN=<campaignPushToken> ./hbs-extractor \\
  --no-elevate --quiet --push https://dashboard.example/api/ingest`,
      },
      {
        type: 'note',
        tone: 'tip',
        content:
          'The dashboard derives campaign and location solely from the issuance, keys the host by machine ID, and auto-resolves previously open findings that now pass on a subsequent scan.',
      },
    ],
  },
  {
    slug: 'extractor',
    title: 'Extractor reference',
    blurb: 'Every flag, exit code, and the strict read-only guarantee of the hbs-extractor binary.',
    content: [
      { type: 'h3', content: 'Build' },
      {
        type: 'code',
        lang: 'bash',
        content: `cd extractor
cargo build               # debug (includes the hidden --dev-insecure-key)
cargo build --release     # LTO, stripped, panic=abort, opt-level=z`,
      },
      { type: 'h3', content: 'Command-line flags' },
      {
        type: 'table',
        headers: ['Flag', 'Meaning'],
        rows: [
          ['--list-checks', 'Print every registered testcase (id, severity, category, title) and exit'],
          ['--only <IDS>', 'Run only these check IDs (comma-separated)'],
          ['--category <NAME>', 'Run only one category (e.g. SSH, Account Policy, Server Config)'],
          ['--min-severity <LEVEL>', 'Skip checks below critical | high | medium | low | informational'],
          ['--out <PATH>', 'Report path. Default: beside the extractor binary, never the CWD'],
          ['--push <URL>', 'Also POST the sealed report to a dashboard (http(s)://…/api/ingest)'],
          ['--push-token-file <PATH>', 'Read-only file with the push token (mutually exclusive with HBS_PUSH_TOKEN)'],
          ['--elevate', 'Ask once for elevation to run admin-only checks (Windows UAC; Linux guidance)'],
          ['--no-elevate', 'Never request elevation'],
          ['--no-pause', 'Do not pause at the end (scripted/CI runs)'],
          ['--quiet', 'Suppress progress output (machine-readable lines)'],
        ],
      },
      {
        type: 'note',
        tone: 'warn',
        content:
          'Hidden/internal: --elevated-child (relaunch guard) and, debug builds only, --dev-insecure-key <64-hex> — never present in release builds.',
      },
      { type: 'h3', content: 'Environment variables' },
      {
        type: 'table',
        headers: ['Variable', 'Effect'],
        rows: [['HBS_PUSH_TOKEN', 'Push token (only read when --push is used)']],
      },
      {
        type: 'text',
        content:
          'Supplying both HBS_PUSH_TOKEN and --push-token-file is an error. The token never appears in argv, the URL, logs, the self-audit, the report, or the keyslot.',
      },
      { type: 'h3', content: 'Output & exit codes' },
      {
        type: 'list',
        items: [
          'Output: one sealed .hbs file, written next to the extractor binary by default, or to --out. It is the only file written on the target.',
          '0 — success',
          '2 — unissued/placeholder or expired keyslot',
          '3 — no checks matched the filters, sealing/write failure, or push-token configuration error',
          'A network push failure does not fail the scan: the local report is kept and the summary shows a push-failed status.',
        ],
      },
      { type: 'h3', content: 'Least privilege' },
      {
        type: 'text',
        content:
          'Scans always start unprivileged. Admin-only checks run only under an explicit --elevate (a single Windows UAC consent; Linux never invokes sudo). Declined elevation does not abort: remaining checks use read-only fallbacks and unresolved results become DegradedPartial.',
      },
      { type: 'h3', content: 'Strict read-only guarantee' },
      {
        type: 'text',
        content:
          'Only query-style, allowlisted commands run; secedit /export, temp-file exports, redirects, shell interpreters, and state-changing or network-capable probes are rejected before spawn. DNS/remote forms are refused. The single write on the target is the sealed report. Every attempted read/command is recorded before it happens and included in the report.',
      },
    ],
  },
  {
    slug: 'dashboard',
    title: 'Dashboard reference',
    blurb: 'Hosting flags, roles, the ingest pipeline, console pages and the key API endpoints.',
    content: [
      { type: 'h3', content: 'Install & run' },
      {
        type: 'code',
        lang: 'bash',
        content: `cd dashboard
bun install
bun run dev                  # Vite dev server (SPA) + proxies /api to :3000
bun run build && bun server/index.ts   # production single-process`,
      },
      { type: 'h3', content: 'Hosting & configuration' },
      {
        type: 'table',
        headers: ['HTTP flag', 'Env', 'Meaning'],
        rows: [
          ['--host', 'HOST', 'Bare --host binds all interfaces (0.0.0.0); --host <addr> binds one; default 127.0.0.1'],
          ['--port <n>', 'PORT', 'Listen port (default 3000)'],
          ['--tls-cert / --tls-key', 'HBS_TLS_CERT / HBS_TLS_KEY', 'Enable TLS (fingerprint printed at startup)'],
          ['—', 'HBS_DB_PATH', 'SQLite path (default server/data/hbs.sqlite)'],
          ['—', 'HBS_DATA_ROOT', 'Keys/artifacts root (default server/data)'],
        ],
      },
      { type: 'h3', content: 'First run & users' },
      {
        type: 'list',
        items: [
          'If no users exist, the server creates a super_admin and prints its credentials once in the CLI (random 20-char password).',
          'Disable with HBS_BOOTSTRAP_ADMIN=false → use the /setup wizard instead.',
          'Override with HBS_ADMIN_USERNAME / HBS_ADMIN_PASSWORD.',
          'Roles: super_admin (all), auditor (campaigns, issuances, ingest, treatment, exports), viewer (read-only).',
        ],
      },
      { type: 'h3', content: 'Workflow' },
      {
        type: 'list',
        items: [
          'Campaign + location (creation can include the first location atomically).',
          'Issuance — a unique random extractor_id and independent X25519 keypair; the dashboard patches the binary and stores the immutable artifact + SHA-256.',
          'Download — token or session authenticated; streams the exact stored bytes and verifies the hash.',
          'Scan — air-gapped by default, or --push.',
          'Ingest — bounds → issuance resolution → token auth → AEAD decrypt + bounded decompress → schema/identity cross-binding → dedupe → one transaction → SSE report-arrived.',
          'Triage — treatment workflow with audit history; owners, due dates, justifications.',
          'Export — Excel, CSV, PDF (executive + technical), Word, diagnostic bundle.',
        ],
      },
      { type: 'h3', content: 'Console pages' },
      {
        type: 'table',
        headers: ['Page', 'Audience', 'What it does'],
        rows: [
          ['Executive Summary', 'management', 'Board one-pager, risk gauge, top risks, presentation mode, print/Save as PDF'],
          ['Overview', 'all', 'KPI tiles with drill-down, risk trend, severity donut, top failing checks'],
          ['Campaigns', 'all', 'Campaign workspace, scope selector (latest / report / date range)'],
          ['Locations & Hosts', 'sysadmin', 'Location cards, host inventory, download snippets, batch drop-zone upload'],
          ['Findings', 'analyst', 'Filters (URL-canonical), By Host / By Check pivots, saved views'],
          ['Remediation', 'sysadmin', 'Failing checks grouped into action items with copyable fix commands + exports'],
          ['Telemetry', 'analyst', 'Scan/ingest percentiles, coverage trend, adoption bars, freshness/SLA'],
          ['Standards', 'analyst/auditor', 'CIS / NIST 800-53 / ISO 27001 / PCI-DSS coverage matrix'],
          ['Treatment', 'auditor', 'State board (open/accepted_risk/false_positive/remediated) with history'],
          ['Admin', 'super_admin', 'Users, issuance keys, retention, audit log, encrypted backup/restore'],
        ],
      },
      { type: 'h3', content: 'Key API endpoints' },
      {
        type: 'code',
        lang: 'text',
        content: `GET    /api/health
POST   /api/auth/setup | /api/auth/login | /api/auth/logout        GET /api/auth/status
GET    /api/campaigns      POST /api/campaigns
POST   /api/campaigns/:id/locations/:loc/issuances   GET (list)
GET    /api/issuances/:id/download?token=…
POST   /api/ingest            (extractor push; Bearer push token)
POST   /api/reports/upload    (multipart batch, ≤32 files; session)
GET    /api/events            (SSE report-arrived)
GET    /api/overview | /api/findings | /api/remediation | /api/telemetry | /api/standards | /api/treatment
GET    /api/export/report/:id?format=xlsx|csv|pdf|docx[&template=executive|technical]
GET    /api/export/campaign/:id?format=…`,
      },
      {
        type: 'note',
        tone: 'info',
        content: 'Cross-cutting: command palette (Ctrl/⌘-K), live SSE activity + notifications, light/dark theme, table twins for every chart, and a print stylesheet.',
      },
    ],
  },
  {
    slug: 'security-model',
    title: 'Security model',
    blurb: 'The .hbs v2 envelope, the binary keyslot, and the honest limits of the sealed-report design.',
    content: [
      { type: 'h3', content: '.hbs v2 envelope (93-byte header, little-endian)' },
      {
        type: 'code',
        lang: 'text',
        content: `0   4   magic "HBS2"
4   2   version (u16 = 2)
6   1   suite (0 = X25519+HKDF-SHA256+ChaCha20-Poly1305, 1 = …+AES-256-GCM)
7   2   key_id (u16)
9   16  extractor_id
25  16  scan_id
41  32  ephemeral X25519 public key
73  12  nonce
85  8   ciphertext length (u64)
93  ..  AEAD(zstd(report JSON)) + 16-byte tag`,
      },
      {
        type: 'list',
        items: [
          'The entire header is AEAD AAD → tampering with routing fails authentication.',
          'key = HKDF-SHA256(X25519(eph, recipient), salt = scan_id||eph_pub, info = "HBS-report-v2"||suite||key_id_le||extractor_id).',
          'The dashboard keeps a bounded HBS1 ingest path for migration only and never issues v1.',
        ],
      },
      { type: 'h3', content: 'Keyslot (512 bytes, patched per issuance)' },
      {
        type: 'text',
        content:
          'Magic HBSKSLOT, version, flags, key id, campaign/extractor IDs, issued/expiry timestamps, 32-byte recipient public key, zero pad, SHA-256 checksum. Strict validation rejects absent/duplicate slots, nonzero flags/reserved/pad, nil IDs or key, and issued_at >= expiry. The checksum detects corruption, not trust.',
      },
      { type: 'h3', content: 'Self-diagnosing report' },
      {
        type: 'list',
        items: [
          'results[] — status, severity, evidence, location, repro, impact, recommendation, references, fallbackLog, evidenceBlocks, runContext.',
          'selfAudit.attempts[] — every file read / command / registry / API query with kind, redacted source, status, exitCode, bytes, durationMs, and evidenceRef linking a finding to the log line that produced it.',
          'diagnostics — environment/hypervisor, catalog fingerprint, privilege, peak RSS, phase durations, missingData, and a bounded human-readable log.',
          'All strings are redacted and size-bounded before sealing.',
        ],
      },
      { type: 'h3', content: 'Honest security statement' },
      {
        type: 'text',
        content:
          'Sealed reports provide confidentiality and integrity under modern, audited cryptography (X25519, HKDF-SHA256, ChaCha20-Poly1305 or AES-256-GCM) assuming the dashboard\'s private keys stay protected, the OS RNG is sound, and endpoint memory is secure. We make no "unbreakable" claim. The extractor binary contains only a public key and cannot decrypt anything; a binary cannot be encrypted while still executable, so its logic remains reverse-engineerable despite stripping and obfuscation.',
      },
    ],
  },
  {
    slug: 'testcases',
    title: 'Testcase catalog',
    blurb: 'All 368 hardening testcases: Linux, Windows and shared families with counts and coverage.',
    content: [
      {
        type: 'text',
        content:
          '368 testcases — Linux LIN-* (165), Windows WIN-* (153), and shared GEN-* (50). Checks are applicability-gated, not duplicated: a Linux host runs ~215, a Windows host ~200; the union is 368.',
      },
      {
        type: 'table',
        headers: ['Family', 'Count', 'Coverage'],
        rows: [
          ['LIN-FS', '15', 'Partitions (/tmp, /var, /home, …), mount options, bootloader perms, core dumps'],
          ['LIN-SV', '10', 'Legacy/inetd services, telnet/rsh/tftp clients absent, MTA posture'],
          ['LIN-NET', '20', 'IP forwarding, ICMP, rp_filter, redirects, syncookies, IPv6'],
          ['LIN-FW', '5', 'firewalld/ufw/nftables/iptables default-deny'],
          ['LIN-LOG', '14', 'rsyslog/journald config, permissions, rotation, remote forwarding'],
          ['LIN-AU', '12', 'auditd rules, immutability, retention'],
          ['LIN-SSH', '15', 'sshd: root login, ciphers/MACs/KEX, auth limits, forwarding'],
          ['LIN-PAM', '14', 'pwquality, faillock, pwhistory, password ageing, sudo policy'],
          ['LIN-USER', '20', 'passwd/shadow/group perms, UID 0 uniqueness, umask, home perms'],
          ['LIN-TH', '40', 'Kernel attack surface (eBPF, userns, io_uring, kptr/dmesg, lockdown), persistence hunting, containers/EOL/currency'],
          ['WIN-ACC', '14', 'Account policy (length/age/history/lockout, LSA restrictions, admins)'],
          ['WIN-AU', '10', 'Audit subcategories via auditpol /get (never secedit /export)'],
          ['WIN-SEC', '22', 'UAC, LM/NTLM, SMB signing, screen lock, legal notice, SMBv1'],
          ['WIN-UR', '16', 'User rights via read-only LSA policy APIs'],
          ['WIN-EVT', '6', 'Event log sizes/retention/permissions'],
          ['WIN-DEF', '10', 'Defender AV + ASR + update posture'],
          ['WIN-SVC', '20', 'Legacy/unnecessary services (Telnet, TFTP, RemoteRegistry, Spooler, …)'],
          ['WIN-REG', '10', 'Registry/filesystem ACLs, Run keys, unquoted service paths'],
          ['WIN-NET', '18', 'Firewall profiles, LLMNR/mDNS, RDP, WinRM, LDAP signing, NTLM'],
          ['WIN-TH', '27', 'Credential protection (LSA PPL, Credential Guard, HVCI, WDigest), ASR, persistence (IFEO, WMI, tasks, netsh), EOL/LAPS'],
          ['GEN-INV', '25', 'Inventory: ports, packages, users, tasks, shares, patch, TPM/Secure Boot, EDR/backup, identity'],
          ['GEN-SRV', '24', 'Server config review: time sync, DNS redundancy, updates, backup, log forwarding, pending reboot, certs, firewall, sudo/UAC, free space, swap, LDAP/Kerberos'],
        ],
      },
      {
        type: 'note',
        tone: 'info',
        content:
          'There is also one internal self-test (GEN-TOY-001), which is why the GEN family totals 50 (25 + 24 + 1). --list-checks prints the full set; every check degrades (never false-passes) when evidence is unavailable.',
      },
    ],
  },
  {
    slug: 'validation',
    title: 'Validation & testing',
    blurb: 'Unit suites, the 13-distro Linux sweep, Windows Server Core matrices, and the E2E harnesses.',
    content: [
      { type: 'h3', content: 'Unit / integration' },
      {
        type: 'code',
        lang: 'bash',
        content: `cd extractor && cargo test              # Rust suite (unit + integration + catalog audit)
cd dashboard && bun test                # Bun backend + frontend unit suite
cd dashboard && bunx tsc --noEmit       # strict TypeScript
cd dashboard && bunx playwright test    # browser E2E (gated by HBS_E2E=1)`,
      },
      { type: 'h3', content: 'Real-world matrices' },
      {
        type: 'code',
        lang: 'bash',
        content: `# Linux: static musl extractor inside real distros, root + non-root, --network none
bash scripts/docker-test/run.sh
bun run scripts/docker-test/validate-reports.ts   # decrypt + assert every sealed report

# Linux end-to-end: issue a musl extractor, run it in debian:12, push to dashboard
cd dashboard && bun run ../scripts/e2e-linux.ts

# Windows: Server Core LTSC 2019/2022/2025 via the Docker WINDOWS engine
cd dashboard && bun run ../scripts/docker-e2e-hosts-windows.ts`,
      },
      { type: 'h3', content: 'Harness reference' },
      {
        type: 'table',
        headers: ['Script', 'Purpose'],
        rows: [
          ['scripts/build-all.sh', 'Cross-compile the target matrix (+ size gate)'],
          ['scripts/docker-test/run.sh', '13-distro Linux sweep, root/non-root, --network none'],
          ['scripts/docker-test/validate-reports.ts', 'Decrypt every report; assert content + logs'],
          ['scripts/docker-e2e-hosts.ts', 'Dashboard-hosted Linux sweep (download → run → push/upload)'],
          ['scripts/docker-e2e-hosts-windows.ts', 'Same for Windows Server Core containers'],
          ['scripts/e2e-linux.ts', 'Issue → run in debian:12 → push → assert routing/exports'],
          ['scripts/e2e-loop.ts', 'Windows issued-extractor loop (incl. confidentiality assertions)'],
          ['scripts/windows-validate.ts', 'Native Windows scan matrix (full/filtered/category/list)'],
          ['scripts/check-spa.ts', 'SPA serving smoke (root, deep link, assets, API)'],
        ],
      },
    ],
  },
];

export const LATEST_SECTION = DOC_SECTIONS[0];
