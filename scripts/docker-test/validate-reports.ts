// Real-world validation of the sealed reports produced by the Docker matrix
// (scripts/docker-test/run.sh). Decrypts every report with the harness dev key
// and asserts the report is a genuine, complete Linux scan.
//
// Run: bun run scripts/docker-test/validate-reports.ts

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { parseEnvelope, unsealEnvelope } from "../../dashboard/server/envelope.ts";

const OUT = join(import.meta.dir, "out");
const DEV_KEY = new Uint8Array(32).fill(0xab);

type CheckResult = {
  id: string;
  status: string;
  severity: string;
  category?: string;
  runContext?: { user?: string; elevated?: boolean };
  evidenceBlocks?: unknown[];
};

type Report = {
  schemaVersion: number;
  scan: Record<string, unknown>;
  metadata: Record<string, unknown>;
  results: CheckResult[];
  summary: Record<string, number>;
  selfAudit?: { commands?: string[]; filesRead?: string[] };
  diagnostics?: Record<string, unknown>;
};

const HARD_FAILURES: string[] = [];
function require(condition: unknown, message: string): void {
  if (!condition) HARD_FAILURES.push(message);
}

const reports = readdirSync(OUT).filter((f) => f.startsWith("report-") && f.endsWith(".hbs"));
if (reports.length === 0) {
  console.error("no reports found in scripts/docker-test/out; run scripts/docker-test/run.sh first");
  process.exit(2);
}

const rows: string[][] = [];
for (const file of reports.sort()) {
  const bytes = new Uint8Array(readFileSync(join(OUT, file)));
  const label = file.replace(/^report-|\.hbs$/g, "");

  let report: Report;
  try {
    const parsed = parseEnvelope(bytes);
    require(parsed.version === 2, `${label}: envelope version is ${parsed.version}, expected 2`);
    require(parsed.suite === 0 || parsed.suite === 1, `${label}: unexpected suite ${parsed.suite}`);
    report = JSON.parse(Buffer.from(unsealEnvelope(parsed, DEV_KEY)).toString("utf8")) as Report;
  } catch (error) {
    console.error(`FAIL ${label}: ${(error as Error).message}`);
    HARD_FAILURES.push(`${label}: cannot decrypt`);
    continue;
  }

  const statuses = report.results.reduce<Record<string, number>>((acc, result) => {
    acc[result.status] = (acc[result.status] ?? 0) + 1;
    return acc;
  }, {});
  const errors = report.results.filter((result) => result.status === "Error");
  const linux = report.results.filter((result) => result.id.startsWith("LIN-")).length;
  const shared = report.results.filter((result) => result.id.startsWith("GEN-")).length;
  const ids = new Set(report.results.map((result) => result.id));

  require(report.schemaVersion >= 1, `${label}: bad schemaVersion`);
  require(report.results.length >= 150, `${label}: only ${report.results.length} results`);
  require(ids.size === report.results.length, `${label}: duplicate check IDs`);
  require(linux >= 100, `${label}: only ${linux} LIN-* checks`);
  require(shared >= 20, `${label}: only ${shared} GEN-* checks`);
  require(errors.length === 0, `${label}: ${errors.length} hard Error results: ${errors.slice(0, 8).map((e) => e.id).join(", ")}`);
  require(
    report.results.every((result) => typeof result.runContext?.user === "string"),
    `${label}: a result is missing runContext.user`,
  );
  require(report.scan.extractorId !== undefined, `${label}: scan.extractorId missing`);
  require(report.scan.keyId !== undefined, `${label}: scan.keyId missing`);
  require(typeof report.scan.machineId === "string" && report.scan.machineId.length > 0, `${label}: machineId empty`);
  require(typeof report.scan.hostname === "string" && report.scan.hostname.length > 0, `${label}: hostname empty`);
  require(report.scan.privilegeRequested !== undefined, `${label}: privilege auditing fields missing`);
  const network = report.metadata?.network as { interfaces?: unknown } | undefined;
  require(Array.isArray(network?.interfaces), `${label}: metadata.network.interfaces missing`);
  require(report.selfAudit !== undefined, `${label}: selfAudit missing`);
  require(
    (report.selfAudit?.filesRead?.length ?? 0) + (report.selfAudit?.commands?.length ?? 0) > 0,
    `${label}: empty self-audit`,
  );

  // In-report logs + diagnostics (single sealed file carries results AND logs).
  const audit = report.selfAudit as {
    attempts?: { kind?: string; status?: string; source?: string }[];
    warnings?: unknown[];
  };
  const diagnostics = report.diagnostics as
    | { log?: unknown[]; missingData?: unknown[]; environment?: unknown }
    | undefined;
  require(Array.isArray(audit.attempts) && audit.attempts.length > 0, `${label}: selfAudit.attempts missing`);
  require(
    (audit.attempts ?? []).every((a) => typeof a.kind === "string" && typeof a.status === "string"),
    `${label}: audit attempt missing kind/status`,
  );
  require(diagnostics !== undefined, `${label}: diagnostics block missing`);
  require((diagnostics?.log?.length ?? 0) > 0, `${label}: diagnostics.log missing`);
  require(Array.isArray(diagnostics?.missingData), `${label}: diagnostics.missingData missing`);
  require(diagnostics?.environment !== undefined, `${label}: diagnostics.environment missing`);

  rows.push([
    label,
    `v${report.schemaVersion}`,
    String(report.results.length),
    `LIN ${linux}/GEN ${shared}`,
    `C ${statuses.Compliant ?? 0} / NC ${statuses.NonCompliant ?? 0}`,
    `D ${statuses.DegradedPartial ?? 0}`,
    `E ${statuses.Error ?? 0}`,
    String(report.scan.machineId ?? ""),
  ]);
}

const headers = ["target", "schema", "results", "families", "compliant", "degraded", "errors", "machineId"];
const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length)));
const line = (cells: string[]) => cells.map((c, i) => c.padEnd(widths[i]!)).join("  ");
console.log(line(headers));
console.log(widths.map((w) => "-".repeat(w)).join("  "));
for (const row of rows) console.log(line(row));

if (HARD_FAILURES.length > 0) {
  console.error(`\n${HARD_FAILURES.length} validation failure(s):`);
  for (const failure of HARD_FAILURES) console.error(`  - ${failure}`);
  process.exit(1);
}
console.log(`\nVALIDATION PASS: ${rows.length} sealed reports decrypted and asserted`);
