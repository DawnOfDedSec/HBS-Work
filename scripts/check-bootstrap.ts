// Verifies the first-run administrator flow:
//   1. Default launch creates NO account and no printed credentials - the
//      console setup wizard (POST /api/auth/setup) creates the superuser, and
//      that account can then sign in. Setup is refused once a user exists.
//   2. Opt-in launch (HBS_BOOTSTRAP_ADMIN=true) prints credentials once, they
//      authenticate, and a second launch does not re-print them.
// Each launch gets its own port, log and database so the phases cannot
// interfere (phase 3 reuses phase 2's database on purpose).
// Run: bun run scripts/check-bootstrap.ts

import { closeSync, mkdtempSync, openSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const dashboardDir = resolve(import.meta.dir, "..", "dashboard");
const work = mkdtempSync(join(tmpdir(), "hbs-boot-"));

let failures = 0;
function check(condition: unknown, label: string): void {
  console.log(`${condition ? "ok  " : "FAIL"} - ${label}`);
  if (!condition) failures += 1;
}

type Run = { kill: () => void; fd: number; log: string; base: string };

function start(tag: string, extraEnv: Record<string, string> = {}, dbName = tag): Run {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const logFile = join(work, `${tag}-${port}.log`);
  const fd = openSync(logFile, "w");
  const proc = Bun.spawn(["bun", "server/index.ts"], {
    cwd: dashboardDir,
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: String(port),
      HBS_DB_PATH: join(work, `${dbName}.sqlite`),
      HBS_DATA_ROOT: join(work, `${dbName}-data`),
      HBS_BOOTSTRAP_ADMIN: "",
      HBS_ADMIN_USERNAME: "",
      HBS_ADMIN_PASSWORD: "",
      ...extraEnv,
    },
    stdout: fd,
    stderr: fd,
  });
  return { kill: () => proc.kill(), fd, log: logFile, base: `http://127.0.0.1:${port}` };
}

async function waitForMatch(run: Run, re: RegExp, tries = 60): Promise<RegExpExecArray | null> {
  for (let i = 0; i < tries; i += 1) {
    await Bun.sleep(250);
    const match = re.exec(readFileSync(run.log, "utf8"));
    if (match) return match;
  }
  return null;
}

/** The bootstrap prints before the socket is listening, so wait for health. */
async function waitForServer(run: Run): Promise<boolean> {
  for (let i = 0; i < 60; i += 1) {
    try {
      if ((await fetch(`${run.base}/api/health`)).ok) return true;
    } catch {
      /* not listening yet */
    }
    await Bun.sleep(250);
  }
  return false;
}

async function authStatus(base: string): Promise<{ initialized?: boolean } | null> {
  try {
    return await (await fetch(`${base}/api/auth/status`)).json();
  } catch {
    return null;
  }
}

async function login(base: string, username: string, password: string): Promise<number> {
  const response = await fetch(`${base}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  return response.status;
}

function stop(run: Run): void {
  run.kill();
  closeSync(run.fd);
}

// --- 1. default launch: nothing is created, the wizard does it --------------
const defaultRun = start("default");
await waitForMatch(defaultRun, /listening on/);
check(await waitForServer(defaultRun), "server answers /api/health");
const defaultLog = readFileSync(defaultRun.log, "utf8");
check(!/password: \S+/.test(defaultLog), "default launch prints no credentials");
check(!/superuser created/.test(defaultLog), "default launch does not bootstrap a superuser");

const fresh = await authStatus(defaultRun.base);
check(fresh?.initialized === false, "fresh install reports initialized: false (wizard path)");
const noAccount = await login(defaultRun.base, "admin", "anything-at-all");
check(noAccount === 401, `no account exists to sign in with yet (got ${noAccount})`);

const setup = await fetch(`${defaultRun.base}/api/auth/setup`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ username: "Wizard Admin", password: "correct horse battery staple" }),
});
check(setup.status === 201, `setup wizard creates the superuser (got ${setup.status})`);
const wizardLogin = await login(defaultRun.base, "wizard admin", "correct horse battery staple");
check(wizardLogin === 200, `wizard account signs in (got ${wizardLogin})`);

const afterSetup = await authStatus(defaultRun.base);
check(afterSetup?.initialized === true, "install reports initialized: true after setup");
const reopen = await fetch(`${defaultRun.base}/api/auth/setup`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ username: "someone else", password: "password" }),
});
check(reopen.status === 409, `setup is closed once initialized (got ${reopen.status})`);

stop(defaultRun);
await Bun.sleep(500);

// --- 2. opt-in launch: credentials printed once ----------------------------
const optIn = start("optin", { HBS_BOOTSTRAP_ADMIN: "true" });
const printed = await waitForMatch(optIn, /username: (\S+)\s+password: (\S+)/);
check(printed !== null, "HBS_BOOTSTRAP_ADMIN=true prints superuser credentials");
check(await waitForServer(optIn), "opt-in server answers /api/health");

if (printed) {
  const [, username, password] = printed;
  check(username === "admin", `printed username is 'admin' (got ${username})`);
  check((password?.length ?? 0) >= 16, "printed password is strong (>=16 chars)");
  const status = await login(optIn.base, username!, password!);
  check(status === 200, `printed credentials sign in successfully (got ${status})`);
}

stop(optIn);
await Bun.sleep(500);

// A later launch against the same database must not print credentials again.
const again = start("optin-again", { HBS_BOOTSTRAP_ADMIN: "true" }, "optin");
await waitForMatch(again, /listening on/, 30);
check(await waitForServer(again), "second launch answers /api/health");
const againLog = readFileSync(again.log, "utf8");
check(!/password: \S+/.test(againLog), "credentials are not printed again on later launches");
stop(again);

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nFIRST-RUN SETUP PASS");
process.exit(0);
