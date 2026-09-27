// Server startup options. CLI flags take precedence over environment variables.
//
// Hosting:
//   --host              bind to ALL interfaces (0.0.0.0) - exposes the dashboard
//   --host <address>    bind to one interface/address
//   --port <n>          listen port (default 3000)
//   --tls-cert/--tls-key  enable TLS (or HBS_TLS_CERT / HBS_TLS_KEY)

export type ServerOptions = {
  host: string;
  port: number;
  bindAll: boolean;
  dbPath: string;
  tlsCert?: string;
  tlsKey?: string;
};

export type ParseResult =
  | { ok: true; options: ServerOptions }
  | { ok: false; error: string }
  | { ok: true; help: string };

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);
const ALL = new Set(["0.0.0.0", "::", "*"]);

/** Read `--name value`, `--name=value`, or a bare `--name`. Returns null when absent. */
function readFlag(argv: string[], name: string): { present: boolean; value?: string } {
  const eq = argv.find((a) => a.startsWith(`--${name}=`));
  if (eq) return { present: true, value: eq.slice(name.length + 3) };
  const index = argv.indexOf(`--${name}`);
  if (index < 0) return { present: false };
  const next = argv[index + 1];
  if (next === undefined || next.startsWith("--")) return { present: true };
  return { present: true, value: next };
}

export const USAGE = `hbs-dashboard [options]

  --host [address]     Bind the dashboard. Bare --host listens on ALL network
                       interfaces (0.0.0.0); --host <address> binds one.
                       Default: 127.0.0.1 (localhost only).
  --port <n>           Listen port (default 3000; env PORT)
  --tls-cert <path>    TLS certificate (env HBS_TLS_CERT)
  --tls-key <path>     TLS private key (env HBS_TLS_KEY)
  --help               Show this help`;

export function parseServerOptions(
  argv: string[],
  env: Record<string, string | undefined>,
): ParseResult {
  if (argv.includes("--help") || argv.includes("-h")) return { ok: true, help: USAGE };

  // --- host ---
  const hostFlag = readFlag(argv, "host");
  let host = env.HOST?.trim() || "127.0.0.1";
  let bindAll = ALL.has(host);
  if (hostFlag.present) {
    if (hostFlag.value !== undefined && hostFlag.value !== "") {
      host = hostFlag.value;
      bindAll = ALL.has(host);
    } else {
      host = "0.0.0.0";
      bindAll = true;
    }
  }
  if (!host) return { ok: false, error: "--host requires an address or no value" };

  // --- port ---
  const portFlag = readFlag(argv, "port");
  const portRaw = portFlag.present ? portFlag.value : env.PORT;
  const port = portRaw === undefined || portRaw === "" ? 3000 : Number(portRaw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, error: `invalid port: ${portRaw}` };
  }

  // --- TLS ---
  const cert = readFlag(argv, "tls-cert").value ?? env.HBS_TLS_CERT;
  const key = readFlag(argv, "tls-key").value ?? env.HBS_TLS_KEY;
  if (!!cert !== !!key) {
    return { ok: false, error: "TLS requires both --tls-cert and --tls-key (or HBS_TLS_CERT and HBS_TLS_KEY)" };
  }

  const dbPath = env.HBS_DB_PATH?.trim() || "server/data/hbs.sqlite";
  return { ok: true, options: { host, port, bindAll, dbPath, tlsCert: cert, tlsKey: key } };
}

/** True when the dashboard will be reachable from other machines. */
export function isExposed(host: string): boolean {
  return !LOOPBACK.has(host.toLowerCase());
}
