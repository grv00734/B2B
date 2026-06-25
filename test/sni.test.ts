import { describe, it, expect } from "vitest";
import * as net from "node:net";
import * as tls from "node:tls";
import type { AddressInfo } from "node:net";
import { extractSNI } from "../src/sni.js";
import { plan } from "../src/transparent.js";

describe("extractSNI", () => {
  it("reads the SNI host from a real TLS ClientHello", async () => {
    const host = await new Promise<string | null>((resolve) => {
      const server = net.createServer((sock) => {
        sock.once("data", (buf: Buffer) => {
          const r = extractSNI(buf);
          resolve(r.state === "ok" ? r.host : null);
          sock.destroy();
          server.close();
        });
      });
      server.listen(0, "127.0.0.1", () => {
        const port = (server.address() as AddressInfo).port;
        // Generates a genuine ClientHello with SNI; handshake then fails (ignored).
        const c = tls.connect({ host: "127.0.0.1", port, servername: "api.anthropic.com", rejectUnauthorized: false });
        c.on("error", () => undefined);
      });
    });
    expect(host).toBe("api.anthropic.com");
  });

  it("returns 'none' for non-TLS bytes and 'need-more' for a tiny prefix", () => {
    expect(extractSNI(Buffer.from("GET / HTTP/1.1\r\n")).state).toBe("none");
    expect(extractSNI(Buffer.from([0x16, 0x03])).state).toBe("need-more");
  });
});

describe("transparent iptables plan", () => {
  it("excludes the proxy uid to avoid a redirect loop", () => {
    const p = plan({ port: 8443, uid: 1234 });
    expect(p.install[0]).toContain("-t nat -A OUTPUT");
    expect(p.install[0]).toContain("--dport 443");
    expect(p.install[0]).toContain("! --uid-owner 1234");
    expect(p.install[0]).toContain("REDIRECT --to-ports 8443");
    // Undo mirrors install with -D.
    expect(p.undo[0]).toContain("-D OUTPUT");
  });

  it("warns when no uid is provided", () => {
    expect(plan({ port: 8443 }).note).toContain("WARNING");
  });

  it("emits pf rdr rules for macOS", () => {
    const p = plan({ port: 8443, uid: 502, platform: "darwin" });
    expect(p.platform).toBe("darwin");
    expect(p.anchorContent).toContain("rdr pass proto tcp from any to any port 443 -> 127.0.0.1 port 8443");
    expect(p.anchorContent).toContain("no rdr proto tcp from any to any port 443 user 502");
    expect(p.install.join("\n")).toContain("pfctl -a aegis");
    expect(p.undo.join("\n")).toContain("pfctl -a aegis -F all");
  });
});
