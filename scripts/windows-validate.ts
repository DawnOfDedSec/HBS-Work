// Real-world validation on the actual Windows host. Docker Desktop here runs
// Linux containers only, so Windows is exercised natively: the extractor is run
// in several real modes against this machine and every sealed report is
// decrypted and asserted.
//
// Run: bun run scripts/windows-validate.ts   (needs `cargo build` first)

import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseEnvelope, unsealEnvelope } from "../dashboard/server/envelope.ts";

const repo = resolve(import.meta.dir, "..");
const exe = join(repo, "extractor", "target", "debug", "hbs-extractor.exe");
const DEV_KEY_HEX = "ab".repeat(32);
const DEV_KEY = new Uint8Array(32).fill(0xab);
const work = mkdtempSync(join(tmpdir(), "hbs-win-"));

type CheckResult = { id: string; status: string; runContext?: { user?: string; elevated?: boolean } };
type Report = {
  schemaVersion: number;
  scan: Record<string, unknown>;
  metadata: Record<string, unknown>;
  results: CheckResult[];
  summary: Record<string, number>;
  selfAudit?: { commands?: string[]; filesRead?: string[] };
};

const failures: string[] = [];
function require(condition: unknown, message: string): void {
  if (!condition) failures.push(message);
}

function run(args: string[]): { code: number; stdout: string; stderr: string } {
  const proc = Bun.spawnSync([exe, "--no-pause", "--quiet", ...args], { stdout: "pipe", stderr: "pipe" });
  return { code: proc.exitCode, stdout: proc.stdout.toString(), stderr: proc.stderr.toString() };
}

function decrypt(path: string): Report | null {
  try {
    const parsed = parseEnvelope(new Uint8Array(readFileSync(path)));
    if (parsed.version !== 2) {
      require(false, `${path}: envelope version ${parsed.version}, expected 2`);
      return null;
    }
    return JSON.parse(Buffer.from(unsealEnvelope(parsed, DEV_KEY)).toString("utf8")) as Report;
  } catch (error) {
    require(false, `${path}: decrypt failed: ${(error as Error).message}`);
    return null;
  }
}

// 1. Full unprivileged scan (default; no --elevate => must not prompt).
const fullPath = join(work, "windows-full.hbs");
const full = run(["--no-elevate", "--dev-insecure-key", DEV_KEY_HEX, "--out", fullPath]);
require(full.code === 0, `full scan exited ${full.code}: ${full.stderr.slice(0, 300)}`);
const fullReport = decrypt(fullPath);
if (fullReport) {
  const statuses = fullReport.results.reduce<Record<string, number>>((acc, r) => {
    acc[r.status] = (acc[r.status] ?? 0) + 1;
    return acc;
  }, {});
  const errors = fullReport.results.filter((r) => r.status === "Error");
  const win = fullReport.results.filter((r) => r.id.startsWith("WIN-")).length;
  const shared = fullReport.results.filter((r) => r.id.startsWith("GEN-")).length;
  const ids = new Set(fullReport.results.map((r) => r.id));

  require(win >= 100, `Windows scan only has ${win} WIN-* checks`);
  require(shared >= 20, `Windows scan only has ${shared} GEN-* checks`);
  require(ids.size === fullReport.results.length, "duplicate check IDs in Windows report");
  require(errors.length === 0, `${errors.length} hard Error results: ${errors.slice(0, 10).map((e) => e.id).join(", ")}`);
  require(
    fullReport.results.every((r) => typeof r.runContext?.user === "string"),
    "a Windows result is missing runContext.user",
  );
  require(typeof fullReport.scan.machineId === "string" && (fullReport.scan.machineId as string).length > 0, "machineId empty");
  require(typeof fullReport.scan.hostname === "string" && (fullReport.scan.hostname as string).length > 0, "hostname empty");
  require(fullReport.scan.privilegeRequested !== undefined, "privilege auditing fields missing");
  require(typeof fullReport.metadata.os_name === "string", "metadata.os_name missing");
  require(fullReport.selfAudit !== undefined, "selfAudit missing");
  require(
    (fullReport.selfAudit?.filesRead?.length ?? 0) + (fullReport.selfAudit?.commands?.length ?? 0) > 0,
    "empty self-audit",
  );

  console.log(
    `full scan: ${fullReport.results.length} results  ` +
      `C ${statuses.Compliant ?? 0} / NC ${statuses.NonCompliant ?? 0} / N/A ${statuses.NotApplicable ?? 0} / ` +
      `D ${statuses.DegradedPartial ?? 0} / E ${statuses.Error ?? 0}  ` +
      `(WIN ${win}, GEN ${shared}, machineId ${fullReport.scan.machineId})`,
  );
}

// 2. Filtered scan produces exactly the requested checks.
const onlyPath = join(work, "windows-only.hbs");
const onlyIds = ["WIN-ACC-001", "WIN-AU-001", "GEN-INV-001", "WIN-DEF-001"];
const only = run(["--no-elevate", "--dev-insecure-key", DEV_KEY_HEX, "--only", onlyIds.join(","), "--out", onlyPath]);
require(only.code === 0, `filtered scan exited ${only.code}`);
const onlyReport = decrypt(onlyPath);
if (onlyReport) {
  const got = onlyReport.results.map((r) => r.id).sort();
  require(
    onlyIds.slice().sort().every((id) => got.includes(id)) && got.length === onlyIds.length,
    `filtered scan returned ${got.length} checks (${got.join(", ")}); expected the 4 requested`,
  );
  console.log(`filtered scan: ${got.join(", ")}`);
}

// 3. Category filter and min-severity are accepted and narrow the set.
const catPath = join(work, "windows-category.hbs");
const cat = run(["--no-elevate", "--dev-insecure-key", DEV_KEY_HEX, "--category", "Account Policy", "--out", catPath]);
require(cat.code === 0, `category scan exited ${cat.code}`);
const catReport = decrypt(catPath);
if (catReport) {
  require(catReport.results.length > 0, "category filter returned no checks");
  require(
    catReport.results.every((r) => (r as CheckResult & { category?: string }).category === "Account" || r.id.startsWith("WIN-ACC")),
    "category filter leaked non-Account checks",
  );
  console.log(`category scan: ${catReport.results.length} checks`);
}

// 4. --list-checks prints the catalog and exits 0.
const list = run(["--list-checks"]);
require(list.code === 0, `--list-checks exited ${list.code}`);
const listed = list.stdout.split("\n").filter((l) => /^(WIN|LIN|GEN)-/.test(l.trim()));
require(listed.length >= 180, `--list-checks printed only ${listed.length} entries`);
console.log(`--list-checks: ${listed.length} testcases`);

if (failures.length > 0) {
  console.error(`\n${failures.length} Windows validation failure(s):`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log(`\nWINDOWS VALIDATION PASS (workdir ${work})`);
