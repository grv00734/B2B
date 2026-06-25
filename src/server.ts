import { createServer, type Server } from "node:http";
import type { AegisConfig } from "./types.js";
import { createContext, handleRequest, type ContextOptions } from "./proxy.js";

export function startServer(cfg: AegisConfig, opts: ContextOptions = {}): Server {
  const ctx = createContext(cfg, opts);

  const server = createServer((req, res) => {
    handleRequest(req, res, ctx).catch((err) => {
      console.error("[aegis] handler error:", err);
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
      }
      if (!res.writableEnded) {
        res.end(JSON.stringify({ error: { type: "aegis_internal_error", message: String(err) } }));
      }
    });
  });

  server.listen(cfg.port, cfg.host, () => {
    const enabled = Object.entries(cfg.detectors)
      .filter(([, v]) => v)
      .map(([k]) => k)
      .join(", ");
    console.log(`\n  Aegis DLP guard listening on http://${cfg.host}:${cfg.port}`);
    console.log(`  mode=${cfg.mode}  blockOn=[${cfg.blockOn.join(", ")}]  detectors=[${enabled}]`);
    console.log(`  routes:`);
    for (const r of cfg.routes) console.log(`    ${r.matchPrefix}  ->  ${r.upstream}  (${r.format})`);
    console.log(`\n  Point your agent at this proxy, e.g.:`);
    console.log(`    export ANTHROPIC_BASE_URL=http://${cfg.host}:${cfg.port}\n`);
  });

  return server;
}
