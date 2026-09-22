// Verifies first-run CLI credential bootstrap: the server prints superuser
// credentials once, they authenticate, and a second launch does not re-print.
// Run: bun run scripts/check-bootstrap.ts

import { closeSync, mkdtempSync, openSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const dashboardDir = resolve(import.meta.dir, "..", "dashboard");
const work = mkdtempSync(join(tmpdir(), "hbs-boot-"));
const dbPath = join(work, "boot.sqlite");
const logPath = join(work, "server.log");
const port = 20000 + Math.floor(Math.random() * 20000);
const base = `http://127.0.0.1:${port}`;

let failures = 0;
function check(condition: unknown, label: string): void {
  console.log(`${condition ? "ok  " : "FAIL"} - ${label}`);
  if (!condition) failures += 1;
}

function start(): { kill: () => void; fd: number } {
  const fd = openSync(logPath, "w");
  const proc = Bun.spawn(["bun", "server/index.ts"], {
    cwd: dashboardDir,
    env: { ...process.env, HOST: "127.0.0.1", PORT: String(port), HBS_DB_PATH: dbPath, HBS_DATA_ROOT: join(work, "data") },
    stdout: fd,
    stderr: fd,
  });
  return { kill: () => proc.kill(), fd };
}

async function waitForMatch(re: RegExp, tries = 40): Promise<RegExpExecArray | null> {
  for (let i = 0; i < tries; i += 1) {
    await Bun.sleep(250);
    const log = readFileSync(logPath, "utf8");
    const match = re.exec(log);
    if (match) return match;
  }
  return null;
}

const first = start();
const match = await waitForMatch(/username: (\S+)\s+password: (\S+)/);
check(match !== null, "first launch prints superuser credentials in the CLI");

if (match) {
  const [, username, password] = match;
  check(username === "admin", `printed username is 'admin' (got ${username})`);
  check((password?.length ?? 0) >= 16, "printed password is strong (>=16 chars)");
  const login = await fetch(`${base}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  check(login.status === 200, "printed credentials sign in successfully");
}
first.kill();
await Bun.sleep(500);

// Second launch against the same DB must not print credentials again.
closeSync(first.fd);
const second = start();
await waitForMatch(/listening on/, 20);
const log2 = readFileSync(logPath, "utf8");
check(!/first-run superuser created/.test(log2), "credentials are not printed again on later launches");
second.kill();
closeSync(second.fd);

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nBOOTSTRAP CREDENTIALS PASS");
process.exit(0);
