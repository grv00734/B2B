/**
 * Lightweight liveness probes used by `aegis status`.
 */
import * as http from "node:http";
import * as net from "node:net";

export interface HealthResult {
  up: boolean;
  info?: { status?: string; kind?: string; mode?: string };
}

/** Hit the proxy's /__aegis/health endpoint. */
export function probeHealth(host: string, port: number, timeout = 1500): Promise<HealthResult> {
  return new Promise((resolve) => {
    const req = http.get({ host, port, path: "/__aegis/health", timeout }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (d) => (data += d));
      res.on("end", () => {
        try {
          resolve({ up: res.statusCode === 200, info: JSON.parse(data) });
        } catch {
          resolve({ up: res.statusCode === 200 });
        }
      });
    });
    req.on("error", () => resolve({ up: false }));
    req.on("timeout", () => {
      req.destroy();
      resolve({ up: false });
    });
  });
}

/** Plain TCP reachability (for the transparent listener, which speaks raw TLS). */
export function probeTcp(host: string, port: number, timeout = 1500): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = net.connect({ host, port });
    const done = (v: boolean): void => {
      sock.destroy();
      resolve(v);
    };
    sock.setTimeout(timeout);
    sock.on("connect", () => done(true));
    sock.on("error", () => done(false));
    sock.on("timeout", () => done(false));
  });
}
