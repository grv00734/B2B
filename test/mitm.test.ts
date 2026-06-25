import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as https from "node:https";
import * as http from "node:http";
import * as tls from "node:tls";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import { CertAuthority } from "../src/ca.js";
import { startMitmProxy } from "../src/mitm.js";
import { DEFAULT_CONFIG } from "../src/config.js";

function tmp(p: string): string {
  return mkdtempSync(join(tmpdir(), p));
}

describe("transparent MITM proxy", () => {
  it("decrypts an allowlisted host, scrubs the request, and restores the response", async () => {
    const SECRET = "sk-ant-abcd1234EFGH5678ijklMNOP";

    // --- Fake upstream provider with its OWN CA ---
    const upstreamCa = new CertAuthority(tmp("aegis-up-"));
    let receivedBody = "";
    const upstream = https.createServer(
      { key: upstreamCa.leafKeyPem, cert: `${upstreamCa.mintLeaf("localhost")}\n${upstreamCa.caCertPem}` },
      (req, res) => {
        let body = "";
        req.on("data", (c) => (body += c));
        req.on("end", () => {
          receivedBody = body;
          const content = JSON.parse(body).messages[0].content as string;
          // Echo the (scrubbed) content back inside a JSON response.
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ echo: content }));
        });
      },
    );
    await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
    const upstreamPort = (upstream.address() as AddressInfo).port;

    // --- Aegis system proxy, redirecting api.anthropic.com -> local upstream ---
    const cfg = { ...DEFAULT_CONFIG, host: "127.0.0.1", blockOn: [] as never[], mitm: { ...DEFAULT_CONFIG.mitm, port: 0 } };
    const { server: proxy, ca: proxyCa } = startMitmProxy(cfg, {
      caDir: tmp("aegis-proxy-"),
      resolveUpstream: () => ({
        host: "127.0.0.1",
        port: upstreamPort,
        secure: true,
        servername: "localhost",
        ca: [upstreamCa.caCertPem],
        rejectUnauthorized: true,
      }),
    });
    await new Promise<void>((r) => proxy.listen(0, "127.0.0.1", () => r()));
    const proxyPort = (proxy.address() as AddressInfo).port;

    // --- Client: CONNECT through the proxy, trust the proxy's root CA ---
    const responseBody = await new Promise<string>((resolve, reject) => {
      const connectReq = http.request({
        host: "127.0.0.1",
        port: proxyPort,
        method: "CONNECT",
        path: "api.anthropic.com:443",
      });
      connectReq.on("connect", (_res, socket) => {
        const tlsSock = tls.connect(
          { socket, servername: "api.anthropic.com", ca: [proxyCa.caCertPem] },
          () => {
            const payload = JSON.stringify({
              model: "claude-opus-4-8",
              messages: [{ role: "user", content: `my key is ${SECRET}` }],
            });
            tlsSock.write(
              `POST /v1/messages HTTP/1.1\r\n` +
                `Host: api.anthropic.com\r\n` +
                `Content-Type: application/json\r\n` +
                `Content-Length: ${Buffer.byteLength(payload)}\r\n` +
                `Connection: close\r\n\r\n` +
                payload,
            );
          },
        );
        let raw = "";
        tlsSock.setEncoding("utf8");
        tlsSock.on("data", (d) => (raw += d));
        tlsSock.on("end", () => resolve(raw.slice(raw.indexOf("\r\n\r\n") + 4)));
        tlsSock.on("error", reject);
      });
      connectReq.on("error", reject);
      connectReq.end();
    });

    proxy.close();
    upstream.close();

    // The provider never saw the real secret...
    expect(receivedBody).not.toContain(SECRET);
    expect(receivedBody).toContain("[[REDACTED:ANTHROPIC_KEY:");
    // ...but the client got it back, restored.
    expect(JSON.parse(responseBody).echo).toContain(SECRET);
  });

  it("blind-tunnels a non-allowlisted host without decrypting it", async () => {
    // A plain TLS server NOT signed by the Aegis CA — if the proxy tried to MITM
    // it, the client (trusting only this server's own cert) would still connect
    // because bytes are passed through untouched.
    const ownCa = new CertAuthority(tmp("aegis-bank-"));
    const secureSite = tls.createServer(
      { key: ownCa.leafKeyPem, cert: `${ownCa.mintLeaf("localhost")}\n${ownCa.caCertPem}` },
      (sock) => sock.end("bank-data"),
    );
    await new Promise<void>((r) => secureSite.listen(0, "127.0.0.1", () => r()));
    const sitePort = (secureSite.address() as AddressInfo).port;

    const cfg = { ...DEFAULT_CONFIG, host: "127.0.0.1", mitm: { ...DEFAULT_CONFIG.mitm, port: 0 } };
    const { server: proxy } = startMitmProxy(cfg, { caDir: tmp("aegis-proxy2-") });
    await new Promise<void>((r) => proxy.listen(0, "127.0.0.1", () => r()));
    const proxyPort = (proxy.address() as AddressInfo).port;

    const body = await new Promise<{ authorized: boolean; data: string }>((resolve, reject) => {
      const connectReq = http.request({
        host: "127.0.0.1",
        port: proxyPort,
        method: "CONNECT",
        path: `127.0.0.1:${sitePort}`,
      });
      connectReq.on("connect", (_res, socket) => {
        const tlsSock = tls.connect(
          { socket, servername: "localhost", ca: [ownCa.caCertPem] },
          () => {
            let data = "";
            tlsSock.setEncoding("utf8");
            tlsSock.on("data", (d) => (data += d));
            tlsSock.on("end", () => resolve({ authorized: tlsSock.authorized, data }));
          },
        );
        tlsSock.on("error", reject);
      });
      connectReq.on("error", reject);
      connectReq.end();
    });

    proxy.close();
    secureSite.close();

    // The client trusts ONLY the site's own CA. A successful authorized
    // handshake proves the proxy did not substitute its own certificate.
    expect(body.authorized).toBe(true);
    expect(body.data).toBe("bank-data");
  });

  it("transparent mode: SNI-routes a redirected connection through MITM scrub/restore", async () => {
    const SECRET = "ghp_0123456789abcdefghijklmnopqrstuvwxyz12";

    const upstreamCa = new CertAuthority(tmp("aegis-tup-"));
    let receivedBody = "";
    const upstream = https.createServer(
      { key: upstreamCa.leafKeyPem, cert: `${upstreamCa.mintLeaf("localhost")}\n${upstreamCa.caCertPem}` },
      (req, res) => {
        let body = "";
        req.on("data", (c) => (body += c));
        req.on("end", () => {
          receivedBody = body;
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ echo: JSON.parse(body).messages[0].content }));
        });
      },
    );
    await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", () => r()));
    const upstreamPort = (upstream.address() as AddressInfo).port;

    const cfg = { ...DEFAULT_CONFIG, host: "127.0.0.1", blockOn: [] as never[], mitm: { ...DEFAULT_CONFIG.mitm, port: 0, transparentPort: 0 } };
    const { server: proxy, transparentServer, ca: proxyCa } = startMitmProxy(cfg, {
      caDir: tmp("aegis-tproxy-"),
      transparentPort: 0,
      resolveUpstream: () => ({ host: "127.0.0.1", port: upstreamPort, secure: true, servername: "localhost", ca: [upstreamCa.caCertPem], rejectUnauthorized: true }),
    });
    if (!transparentServer!.listening) await once(transparentServer!, "listening");
    const tport = (transparentServer!.address() as AddressInfo).port;

    // Connect DIRECTLY to the transparent port (simulating an iptables REDIRECT)
    // with no CONNECT — routing is decided purely from the TLS SNI.
    const responseBody = await new Promise<string>((resolve, reject) => {
      const tlsSock = tls.connect({ host: "127.0.0.1", port: tport, servername: "api.openai.com", ca: [proxyCa.caCertPem] }, () => {
        const payload = JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content: `token ${SECRET}` }] });
        tlsSock.write(
          `POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\n` +
            `Content-Length: ${Buffer.byteLength(payload)}\r\nConnection: close\r\n\r\n${payload}`,
        );
      });
      let raw = "";
      tlsSock.setEncoding("utf8");
      tlsSock.on("data", (d) => (raw += d));
      tlsSock.on("end", () => resolve(raw.slice(raw.indexOf("\r\n\r\n") + 4)));
      tlsSock.on("error", reject);
    });

    proxy.close();
    transparentServer!.close();
    upstream.close();

    expect(receivedBody).not.toContain(SECRET);
    expect(receivedBody).toContain("[[REDACTED:GITHUB_TOKEN:");
    expect(JSON.parse(responseBody).echo).toContain(SECRET);
  });
});
