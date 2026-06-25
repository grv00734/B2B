import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as tls from "node:tls";
import type { AddressInfo } from "node:net";
import { CertAuthority } from "../src/ca.js";

function tmp(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

describe("CertAuthority", () => {
  it("mints leaf certs that a client validates against the root over real TLS", async () => {
    const ca = new CertAuthority(tmp("aegis-ca-"));

    const server = tls.createServer(
      {
        key: ca.leafKeyPem,
        cert: `${ca.mintLeaf("localhost")}\n${ca.caCertPem}`,
        SNICallback: (servername, cb) => cb(null, ca.contextFor(servername)),
      },
      (sock) => sock.end("hello-secure"),
    );
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as AddressInfo).port;

    const result = await new Promise<{ authorized: boolean; body: string }>((resolve, reject) => {
      const sock = tls.connect(
        { host: "127.0.0.1", port, servername: "api.anthropic.com", ca: [ca.caCertPem] },
        () => {
          let body = "";
          sock.setEncoding("utf8");
          sock.on("data", (d) => (body += d));
          sock.on("end", () => resolve({ authorized: sock.authorized, body }));
        },
      );
      sock.on("error", reject);
    });
    server.close();

    // authorized === true means the chain validated against our trusted root,
    // and the SAN matched the requested servername.
    expect(result.authorized).toBe(true);
    expect(result.body).toBe("hello-secure");
  });

  it("persists the CA across instances (does not regenerate)", () => {
    const dir = tmp("aegis-ca2-");
    const a = new CertAuthority(dir);
    const b = new CertAuthority(dir);
    expect(b.caCertPem).toBe(a.caCertPem);
    expect(b.leafKeyPem).toBe(a.leafKeyPem);
  });
});
