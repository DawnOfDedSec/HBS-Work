/** DocBlock primitives shared by the docs reader and pages. */
export type DocBlock =
  | { type: 'text'; content: string }
  | { type: 'h2'; content: string }
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
    blurb: 'Install the dashboard, sign in, issue a patched extractor, run the read-only scan, and read your first results.',
    content: [
      { type: 'h2', content: '1. Install and open the dashboard' },
      {
        type: 'text',
        content:
          'The dashboard runs on the machine you manage scans from (a workstation or server) and stores all data locally. The installers set it up as a background service and print the console address when done:',
      },
      {
        type: 'code',
        lang: 'bash',
        title: 'Linux / macOS',
        content: `curl -fsSL https://raw.githubusercontent.com/PotenFYR-Studios/HBS-Tool/main/scripts/install.sh | bash`,
      },
      {
        type: 'code',
        lang: 'powershell',
        title: 'Windows (PowerShell)',
        content: `irm https://raw.githubusercontent.com/PotenFYR-Studios/HBS-Tool/main/scripts/install.ps1 | iex`,
      },
      {
        type: 'text',
        content:
          'Open http://127.0.0.1:3000 on the machine running the dashboard. To reach it from another computer, start it with --host and open http://<dashboard-ip>:3000; add TLS (HBS_TLS_CERT / HBS_TLS_KEY) for anything beyond your LAN.',
      },
      {
        type: 'note',
        tone: 'info',
        content:
          'On first launch the server creates a superuser account and prints its credentials once in the terminal or service log. Sign in with those and change the password under Admin → Users; after that everything happens in the browser.',
      },
      { type: 'h2', content: '2. Create a campaign and generate an extractor' },
      {
        type: 'text',
        content:
          'Three levels: Campaign (the review, e.g. "Acme Q3") → Location (a site, e.g. "DC-East") → Issuance (one extractor binary locked to that campaign/location with its own encryption key and expiry).',
      },
      {
        type: 'list',
        items: [
          'Sign in and open Campaigns.',
          'Click New campaign, give it a name, and add your first location.',
          'Open the campaign, go to Locations & Hosts, and click Generate extractor.',
          "Pick the platform of the machines you will scan (linux-amd64 or windows-amd64) and download the file. Reports it produces can only be opened by this dashboard.",
        ],
      },
      { type: 'h2', content: '3. Scan a server (offline, read-only)' },
      {
        type: 'text',
        content:
          'Copy the extractor to the target server any way you already use (SCP, USB stick, network share) and run it there:',
      },
      {
        type: 'code',
        lang: 'bash',
        content: `# Linux (amd64), unprivileged; report lands beside the binary
./hbs-extractor --no-elevate --quiet

# Windows (PowerShell/cmd)
hbs-extractor.exe --no-elevate --quiet`,
      },
      {
        type: 'note',
        tone: 'tip',
        content:
          'That is the whole scan: strictly read-only, no internet access, exactly one file written (hbs-report-*.hbs). On Windows, double-clicking the .exe also works; use --elevate for admin-only checks (declining the UAC prompt is safe).',
      },
      { type: 'h2', content: '4. Get the report into the dashboard' },
      {
        type: 'list',
        items: [
          'Manual upload (default): copy the .hbs file back, open Campaigns → your campaign → Locations & Hosts, and drag it into the drop zone (batch uploads up to 32 files).',
          'Direct push (optional): copy the push token from the issuance page and run the extractor with --push https://<dashboard-host>:3000/api/ingest. This is the only situation in which the extractor touches the network.',
        ],
      },
      {
        type: 'text',
        content:
          'The host appears immediately via live notification. Campaign and location are derived from the issuance, and re-scanning a server auto-resolves findings that now pass.',
      },
      { type: 'h2', content: '5. Read the results' },
      {
        type: 'table',
        headers: ['You are...', 'Open...', 'You get...'],
        rows: [
          ['Management', 'Executive Summary', 'One-page risk overview, plain-language narrative, print/PDF for the board'],
          ['Sysadmin', 'Remediation', 'Every failing check grouped into fix actions with copyable commands'],
          ['Analyst', 'Findings', 'Filter/pivot by host or check, open evidence, diff hosts against each other'],
          ['Auditor', 'Standards + Treatment', 'CIS / NIST 800-53 / ISO 27001 / PCI-DSS coverage, accepted-risk board'],
        ],
      },
    ],
  },
  {
    slug: 'first-scan',
    title: 'First scan walkthrough',
    blurb: 'From zero to your first reviewed server report in about 15 minutes, entirely in the browser.',
    content: [
      {
        type: 'text',
        content:
          'This walkthrough takes one dashboard machine and one target server (here: Ubuntu) from nothing to a reviewed, exported report. Every step except copying files is a click in the browser.',
      },
      { type: 'h2', content: 'Step 1: start the dashboard (5 minutes, one time)' },
      {
        type: 'code',
        lang: 'bash',
        title: 'on the machine that will store the reports',
        content: `curl -fsSL https://raw.githubusercontent.com/PotenFYR-Studios/HBS-Tool/main/scripts/install.sh | bash`,
      },
      {
        type: 'text',
        content:
          'The installer finishes with the console address (http://127.0.0.1:3000 on this machine) and one-time superuser credentials. Open the address in a browser, sign in, and change the password under Admin → Users.',
      },
      { type: 'h2', content: 'Step 2: campaign, location, extractor (2 minutes)' },
      {
        type: 'list',
        items: [
          'Campaigns → New campaign → name it (e.g. "First look") → add a location (e.g. "Office").',
          'Open the campaign → Locations & Hosts → Generate extractor.',
          "Platform: linux-amd64 (or windows-amd64 for Windows servers) → download the binary.",
        ],
      },
      {
        type: 'note',
        tone: 'info',
        content:
          'The downloaded file is tied to this issuance: it expires on schedule, can be revoked from the same page, and its reports can only be decrypted by this dashboard.',
      },
      { type: 'h2', content: 'Step 3: scan the target server (2 minutes)' },
      {
        type: 'code',
        lang: 'bash',
        title: 'copy the binary to the server, then on the server',
        content: `chmod +x hbs-extractor
./hbs-extractor --no-elevate --quiet`,
      },
      {
        type: 'text',
        content:
          'Unprivileged, offline, and done in about two minutes for the full catalog. It leaves exactly one new file next to itself: hbs-report-*.hbs. Copy that file back to the dashboard machine.',
      },
      { type: 'h2', content: 'Step 4: upload and see results (1 minute)' },
      {
        type: 'text',
        content:
          'Back in the browser: Locations & Hosts → drop the .hbs into the upload zone. The host appears within seconds and the console notifies you when ingestion finishes. Then look at:',
      },
      {
        type: 'list',
        items: [
          'Overview: KPI tiles and the severity donut for what was just ingested.',
          'Remediation: the concrete fix list, ordered by severity, with copyable commands.',
          'Executive Summary: the same result as a one-page narrative, ready to print or save as PDF.',
        ],
      },
      { type: 'h2', content: 'Step 5: what to do next' },
      {
        type: 'list',
        items: [
          'Add more locations and generate one extractor per site; batch-upload a whole fleet of reports at once (up to 32 files per drop).',
          'Fix something on the server, scan it again, upload: previously open findings that now pass are auto-resolved, and the diff is kept per host.',
          'Record accepted risks on the Treatment board so they stop counting as open findings.',
          'Invite teammates as auditor or viewer under Admin → Users; everyone works in the browser.',
        ],
      },
      {
        type: 'note',
        tone: 'tip',
        content:
          'Report did not arrive? Run the extractor without --quiet to see progress, and check the Troubleshooting section of the README. Push failures never lose data: the local report is always kept.',
      },
    ],
  },
  {
    slug: 'extractor',
    title: 'Extractor reference',
    blurb: 'Every flag, exit code, and the strict read-only guarantee of the hbs-extractor binary.',
    content: [
      { type: 'h2', content: 'Build' },
      {
        type: 'code',
        lang: 'bash',
        content: `cd extractor
cargo build               # debug (includes the hidden --dev-insecure-key)
cargo build --release     # LTO, stripped, panic=abort, opt-level=z`,
      },
      { type: 'h2', content: 'Command-line flags' },
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
          'Hidden/internal: --elevated-child (relaunch guard) and, debug builds only, --dev-insecure-key <64-hex> - never present in release builds.',
      },
      { type: 'h2', content: 'Environment variables' },
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
      { type: 'h2', content: 'Output & exit codes' },
      {
        type: 'list',
        items: [
          'Output: one sealed .hbs file, written next to the extractor binary by default, or to --out. It is the only file written on the target.',
          '0 - success',
          '2 - unissued/placeholder or expired keyslot',
          '3 - no checks matched the filters, sealing/write failure, or push-token configuration error',
          'A network push failure does not fail the scan: the local report is kept and the summary shows a push-failed status.',
        ],
      },
      { type: 'h2', content: 'Least privilege' },
      {
        type: 'text',
        content:
          'Scans always start unprivileged. Admin-only checks run only under an explicit --elevate (a single Windows UAC consent; Linux never invokes sudo). Declined elevation does not abort: remaining checks use read-only fallbacks and unresolved results become DegradedPartial.',
      },
      { type: 'h2', content: 'Strict read-only guarantee' },
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
      { type: 'h2', content: 'Install & run' },
      {
        type: 'code',
        lang: 'bash',
        content: `cd dashboard
bun install
bun run dev                  # Vite dev server (SPA) + proxies /api to :3000
bun run build && bun server/index.ts   # production single-process`,
      },
      { type: 'h2', content: 'Hosting & configuration' },
      {
        type: 'table',
        headers: ['HTTP flag', 'Env', 'Meaning'],
        rows: [
          ['--host', 'HOST', 'Bare --host binds all interfaces (0.0.0.0); --host <addr> binds one; default 127.0.0.1'],
          ['--port <n>', 'PORT', 'Listen port (default 3000)'],
          ['--tls-cert / --tls-key', 'HBS_TLS_CERT / HBS_TLS_KEY', 'Enable TLS (fingerprint printed at startup)'],
          ['-', 'HBS_DB_PATH', 'SQLite path (default server/data/hbs.sqlite)'],
          ['-', 'HBS_DATA_ROOT', 'Keys/artifacts root (default server/data)'],
        ],
      },
      { type: 'h2', content: 'First run & users' },
      {
        type: 'list',
        items: [
          'If no users exist, the server creates a super_admin and prints its credentials once in the CLI (random 20-char password).',
          'Disable with HBS_BOOTSTRAP_ADMIN=false → use the /setup wizard instead.',
          'Override with HBS_ADMIN_USERNAME / HBS_ADMIN_PASSWORD.',
          'Roles: super_admin (all), auditor (campaigns, issuances, ingest, treatment, exports), viewer (read-only).',
        ],
      },
      { type: 'h2', content: 'Workflow' },
      {
        type: 'list',
        items: [
          'Campaign + location (creation can include the first location atomically).',
          'Issuance - a unique random extractor_id and independent X25519 keypair; the dashboard patches the binary and stores the immutable artifact + SHA-256.',
          'Download - token or session authenticated; streams the exact stored bytes and verifies the hash.',
          'Scan - air-gapped by default, or --push.',
          'Ingest - bounds → issuance resolution → token auth → AEAD decrypt + bounded decompress → schema/identity cross-binding → dedupe → one transaction → SSE report-arrived.',
          'Triage - treatment workflow with audit history; owners, due dates, justifications.',
          'Export - Excel, CSV, PDF (executive + technical), Word, diagnostic bundle.',
        ],
      },
      { type: 'h2', content: 'Console pages' },
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
      { type: 'h2', content: 'Key API endpoints' },
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
      { type: 'h2', content: '.hbs v2 envelope (93-byte header, little-endian)' },
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
      { type: 'h2', content: 'Keyslot (512 bytes, patched per issuance)' },
      {
        type: 'text',
        content:
          'Magic HBSKSLOT, version, flags, key id, campaign/extractor IDs, issued/expiry timestamps, 32-byte recipient public key, zero pad, SHA-256 checksum. Strict validation rejects absent/duplicate slots, nonzero flags/reserved/pad, nil IDs or key, and issued_at >= expiry. The checksum detects corruption, not trust.',
      },
      { type: 'h2', content: 'Self-diagnosing report' },
      {
        type: 'list',
        items: [
          'results[] - status, severity, evidence, location, repro, impact, recommendation, references, fallbackLog, evidenceBlocks, runContext.',
          'selfAudit.attempts[] - every file read / command / registry / API query with kind, redacted source, status, exitCode, bytes, durationMs, and evidenceRef linking a finding to the log line that produced it.',
          'diagnostics - environment/hypervisor, catalog fingerprint, privilege, peak RSS, phase durations, missingData, and a bounded human-readable log.',
          'All strings are redacted and size-bounded before sealing.',
        ],
      },
      { type: 'h2', content: 'Honest security statement' },
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
          '368 testcases - Linux LIN-* (165), Windows WIN-* (153), and shared GEN-* (50). Checks are applicability-gated, not duplicated: a Linux host runs ~215, a Windows host ~200; the union is 368.',
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
      { type: 'h2', content: 'Unit / integration' },
      {
        type: 'code',
        lang: 'bash',
        content: `cd extractor && cargo test              # Rust suite (unit + integration + catalog audit)
cd dashboard && bun test                # Bun backend + frontend unit suite
cd dashboard && bunx tsc --noEmit       # strict TypeScript
cd dashboard && bunx playwright test    # browser E2E (gated by HBS_E2E=1)`,
      },
      { type: 'h2', content: 'Real-world matrices' },
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
      { type: 'h2', content: 'Harness reference' },
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
