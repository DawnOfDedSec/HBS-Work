# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.0 (main) | ✅ |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use GitHub's **private vulnerability reporting** for this repository:

1. Go to the **Security** tab of [PotenFYR-Studios/HBS-Tool](https://github.com/PotenFYR-Studios/HBS-Tool/security)
2. Click **Report a vulnerability**
3. Describe the issue and how to reproduce it

If private vulnerability reporting is not available, contact the maintainers directly through [PotenFYR Studios](https://potenfyr.in).

Please include as much of the following as you can:

- The component and version (extractor build, or dashboard commit/release)
- A minimal reproduction (command line, report file, or HTTP request)
- Your assessment of severity and impact

## What to Expect

We will acknowledge reports as soon as possible, work with you to understand and reproduce the issue, and credit you in the fix release if you'd like.

## Credential storage

- Passwords are stored only as **Argon2id** hashes with explicit memory-hard
  parameters (64 MiB, 3 passes) and a per-hash random salt
  (`dashboard/server/password.ts`). Verification reads the parameters back out
  of the stored hash, so strengthening them never invalidates existing rows.
- Hashes are additionally **peppered** with a random secret kept outside the
  database (`<data root>/pepper.key`, mode `0600`, or `HBS_PASSWORD_PEPPER` from
  your secret manager). A leaked database on its own verifies nothing and
  cracks nothing without that secret.
- Session tokens are stored as SHA-256 hashes; the session cookie is
  `HttpOnly`, `SameSite=Lax`, and `Secure` whenever the console is served over
  TLS. State-changing requests with a cookie from another site's origin are
  rejected, and `/api/*` responses are sent `no-store`.
- New passwords must satisfy a server-side policy (at least 12 characters,
  public-breach and keyboard-run rejection, no reuse of the username); the
  browser form mirrors it but is not trusted. The first administrator is
  created by the console's setup wizard - nothing is generated for you, and no
  credential is ever printed or logged unless you explicitly ask for
  `HBS_BOOTSTRAP_ADMIN=true` in an unattended install.
- Plaintext passwords exist only inside the request that receives them. They
  are never logged, never persisted, and never held in module state; the pepper
  is re-read per operation rather than cached. (JavaScript strings cannot be
  reliably zeroed, so the goal is single-copy, short-lived exposure.)

## Endpoint security (EDR / XDR / antivirus / Defender)

See [docs/security/edr-compatibility.md](docs/security/edr-compatibility.md):
verified per-component behaviour, the design guarantees (no process injection,
no credential or LSASS access, no packet capture, no kernel components, no
elevation, no obfuscation or packing, no silent self-update), the exact
install-time footprint, and allowlisting recipes for Microsoft Defender and
Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Cortex XDR, Sophos,
macOS Gatekeeper and SELinux/AppArmor.

## Scope Notes

HBS is a security tool, so reports about its own guarantees are exactly what we want:

- **Extractor read-only guarantee**: anything that mutates host state, spawns a non-allowlisted or state-changing command, performs DNS/network resolution, or writes more than the single sealed report is a critical-severity report.
- **Sealed-report confidentiality/integrity**: breaks in the AEAD envelope, AAD binding, keyslot validation, issuance expiry/revocation, or `(extractor_id, scan_id)` dedupe are in scope.
- **Dashboard**: auth bypass, privilege escalation between `super_admin`/`auditor`/`viewer`, ingest path weaknesses (bounds, decompression, schema cross-binding), and backup/restore handling are in scope.

Deployment mistakes (an unencrypted `--host` binding on a public interface, a leaked push token) are operational errors, not product vulnerabilities - but documentation gaps that invite them are welcome reports. The [honest security statement](https://hbs-tool.docs.potenfyr.in/docs/security-model) lists the assumptions the sealed-report model makes; violations of those assumptions in code are in scope.
