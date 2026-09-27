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

## Scope Notes

HBS is a security tool, so reports about its own guarantees are exactly what we want:

- **Extractor read-only guarantee**: anything that mutates host state, spawns a non-allowlisted or state-changing command, performs DNS/network resolution, or writes more than the single sealed report is a critical-severity report.
- **Sealed-report confidentiality/integrity**: breaks in the AEAD envelope, AAD binding, keyslot validation, issuance expiry/revocation, or `(extractor_id, scan_id)` dedupe are in scope.
- **Dashboard**: auth bypass, privilege escalation between `super_admin`/`auditor`/`viewer`, ingest path weaknesses (bounds, decompression, schema cross-binding), and backup/restore handling are in scope.

Deployment mistakes (an unencrypted `--host` binding on a public interface, a leaked push token) are operational errors, not product vulnerabilities — but documentation gaps that invite them are welcome reports. The [honest security statement](https://hbs-tool.docs.potenfyr.in/docs/security-model) lists the assumptions the sealed-report model makes; violations of those assumptions in code are in scope.
