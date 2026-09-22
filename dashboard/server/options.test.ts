import { describe, expect, it } from "bun:test";
import { isExposed, parseServerOptions } from "./options";

function ok(argv: string[], env: Record<string, string | undefined> = {}) {
  const result = parseServerOptions(argv, env);
  if (!result.ok || "help" in result) throw new Error("expected options");
  return result.options;
}

describe("server options", () => {
  it("defaults to localhost only", () => {
    const options = ok([]);
    expect(options.host).toBe("127.0.0.1");
    expect(options.port).toBe(3000);
    expect(options.bindAll).toBe(false);
    expect(isExposed(options.host)).toBeFalse();
  });

  it("bare --host binds all interfaces", () => {
    const options = ok(["--host"]);
    expect(options.host).toBe("0.0.0.0");
    expect(options.bindAll).toBeTrue();
    expect(isExposed(options.host)).toBeTrue();
  });

  it("--host <address> binds one interface", () => {
    expect(ok(["--host", "192.168.1.10"]).host).toBe("192.168.1.10");
    expect(ok(["--host=192.168.1.10"]).host).toBe("192.168.1.10");
    expect(ok(["--host", "::"]).bindAll).toBeTrue();
  });

  it("does not treat the next flag as a host value", () => {
    const options = ok(["--host", "--port", "4000"]);
    expect(options.host).toBe("0.0.0.0");
    expect(options.port).toBe(4000);
  });

  it("reads HOST/PORT from the environment and lets flags win", () => {
    expect(ok([], { HOST: "0.0.0.0", PORT: "8080" }).port).toBe(8080);
    expect(ok([], { HOST: "0.0.0.0" }).bindAll).toBeTrue();
    expect(ok(["--host", "10.0.0.5"], { HOST: "0.0.0.0" }).host).toBe("10.0.0.5");
  });

  it("validates the port", () => {
    const bad = parseServerOptions(["--port", "99999"], {});
    expect(bad.ok).toBeFalse();
    expect(parseServerOptions(["--port", "0"], {}).ok).toBeFalse();
  });

  it("requires both TLS options", () => {
    expect(parseServerOptions(["--tls-cert", "c.pem"], {}).ok).toBeFalse();
    const both = ok(["--tls-cert", "c.pem", "--tls-key", "k.pem"]);
    expect(both.tlsCert).toBe("c.pem");
    expect(both.tlsKey).toBe("k.pem");
  });

  it("prints help", () => {
    const result = parseServerOptions(["--help"], {});
    expect("help" in result && typeof result.help === "string").toBeTrue();
  });
});
