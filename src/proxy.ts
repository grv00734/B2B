import type { IncomingMessage, ServerResponse } from "node:http";
import type { AegisConfig, RouteConfig } from "./types.js";
import { Scrubber, summarize } from "./scrub/index.js";
import { Vault } from "./scrub/placeholders.js";
import { scrubRequestBody } from "./messages.js";
import { SseRestorer } from "./stream.js";
import { AuditLog, type Action, type AuditEntry } from "./audit.js";

export interface ContextOptions {
  /** Route audit entries to a custom sink instead of the console. */
  auditSink?: (entry: AuditEntry) => void;
}

/** Headers we must not forward verbatim (hop-by-hop or recomputed). */
const STRIP_REQUEST_HEADERS = new Set([
  "host",
  "content-length",
  "accept-encoding", // force identity so we can rewrite the body safely
  "connection",
  "proxy-connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
]);

const STRIP_RESPONSE_HEADERS = new Set([
  "content-encoding",
  "content-length",
  "transfer-encoding",
  "connection",
  "keep-alive",
]);

export interface ProxyContext {
  cfg: AegisConfig;
  scrubber: Scrubber;
  audit: AuditLog;
}

export function createContext(cfg: AegisConfig, opts: ContextOptions = {}): ProxyContext {
  return { cfg, scrubber: new Scrubber(cfg), audit: new AuditLog(cfg.auditLog, opts.auditSink) };
}

function matchRoute(cfg: AegisConfig, pathname: string): RouteConfig | null {
  let best: RouteConfig | null = null;
  for (const r of cfg.routes) {
    if (pathname.startsWith(r.matchPrefix)) {
      if (!best || r.matchPrefix.length > best.matchPrefix.length) best = r;
    }
  }
  if (best) return best;
  if (cfg.defaultUpstream) {
    return { matchPrefix: "/", upstream: cfg.defaultUpstream, format: "passthrough" };
  }
  return null;
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function forwardHeaders(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (v == null || STRIP_REQUEST_HEADERS.has(k)) continue;
    out[k] = Array.isArray(v) ? v.join(", ") : v;
  }
  return out;
}

export async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  ctx: ProxyContext,
): Promise<void> {
  const { cfg, scrubber, audit } = ctx;
  const url = new URL(req.url ?? "/", "http://localhost");

  if (url.pathname === "/__aegis/health") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "ok", service: "aegis", kind: "base-url-proxy", mode: cfg.mode }));
    return;
  }

  const route = matchRoute(cfg, url.pathname);

  if (!route) {
    res.writeHead(502, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: { type: "aegis_no_route", message: `No upstream for ${url.pathname}` } }));
    return;
  }

  const rawBody = req.method && !["GET", "HEAD"].includes(req.method) ? await readBody(req) : Buffer.alloc(0);

  // --- Inspect & scrub the request body (JSON only) ---
  const contentType = String(req.headers["content-type"] ?? "");
  const isJson = contentType.includes("application/json") || contentType.includes("+json");

  let forwardBody: Buffer | string | undefined = rawBody.length ? rawBody : undefined;
  let responseVault = new Vault(); // stays empty unless we redact
  let action: Action = "clean";
  let summary = summarize([]);

  if (rawBody.length && isJson) {
    try {
      const parsed = JSON.parse(rawBody.toString("utf8"));
      const scrubVault = new Vault();
      const { body: scrubbed, matches } = scrubRequestBody(parsed, route.format, scrubber, scrubVault);
      summary = summarize(matches);

      const hitsBlockCategory = matches.some((m) => cfg.blockOn.includes(m.category));
      const shouldBlock = matches.length > 0 && (cfg.mode === "block" || hitsBlockCategory);

      if (shouldBlock) {
        action = "blocked";
        await audit.record({
          ts: new Date().toISOString(),
          route: url.pathname,
          format: route.format,
          mode: cfg.mode,
          action,
          summary,
        });
        res.writeHead(403, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            error: {
              type: "aegis_blocked",
              message:
                "Aegis blocked this request: confidential data was detected. Remove the flagged content and retry.",
              findings: summary.byType,
              highestSeverity: summary.highestSeverity,
            },
          }),
        );
        return;
      }

      if (cfg.mode === "warn") {
        // Forward the original, unmodified body but record what we saw.
        action = matches.length > 0 ? "warned" : "clean";
        forwardBody = rawBody;
      } else {
        // redact mode
        action = matches.length > 0 ? "redacted" : "clean";
        forwardBody = JSON.stringify(scrubbed);
        if (matches.length > 0) responseVault = scrubVault;
      }
    } catch {
      // Body wasn't valid JSON after all — forward untouched.
      forwardBody = rawBody;
    }
  }

  // --- Forward upstream ---
  const upstreamUrl = route.upstream.replace(/\/$/, "") + url.pathname + url.search;
  let upstream: Response;
  try {
    upstream = await fetch(upstreamUrl, {
      method: req.method,
      headers: forwardHeaders(req),
      body: forwardBody,
    });
  } catch (err) {
    res.writeHead(502, { "content-type": "application/json" });
    res.end(
      JSON.stringify({ error: { type: "aegis_upstream_error", message: (err as Error).message } }),
    );
    return;
  }

  // Audit after we know the request was accepted for forwarding.
  if (summary.total > 0 || action !== "clean") {
    await audit.record({
      ts: new Date().toISOString(),
      route: url.pathname,
      format: route.format,
      mode: cfg.mode,
      action,
      summary,
    });
  }

  await sendResponse(res, upstream, responseVault);
}

async function sendResponse(res: ServerResponse, upstream: Response, vault: Vault): Promise<void> {
  const respHeaders: Record<string, string> = {};
  upstream.headers.forEach((value, key) => {
    if (!STRIP_RESPONSE_HEADERS.has(key.toLowerCase())) respHeaders[key] = value;
  });

  const ctype = upstream.headers.get("content-type") ?? "";
  const status = upstream.status;

  // Nothing was redacted -> the response can't contain placeholders -> stream raw.
  if (vault.size === 0 || !upstream.body) {
    res.writeHead(status, respHeaders);
    if (upstream.body) {
      for await (const chunk of upstream.body as AsyncIterable<Uint8Array>) res.write(chunk);
    }
    res.end();
    return;
  }

  const decoder = new TextDecoder();

  if (ctype.includes("text/event-stream")) {
    respHeaders["content-type"] = "text/event-stream";
    respHeaders["cache-control"] = "no-cache";
    res.writeHead(status, respHeaders);
    const restorer = new SseRestorer(vault);
    for await (const chunk of upstream.body as AsyncIterable<Uint8Array>) {
      res.write(restorer.feed(decoder.decode(chunk, { stream: true })));
    }
    res.write(restorer.feed(decoder.decode()));
    res.write(restorer.end());
    res.end();
    return;
  }

  if (ctype.includes("application/json") || ctype.includes("+json")) {
    const text = await upstream.text();
    let restored = text;
    try {
      restored = JSON.stringify(vault.restoreDeep(JSON.parse(text)));
    } catch {
      restored = vault.restore(text); // best-effort on non-JSON
    }
    respHeaders["content-type"] = ctype || "application/json";
    res.writeHead(status, respHeaders);
    res.end(restored);
    return;
  }

  // Other content types: restore over the decoded text best-effort.
  const buf = Buffer.from(await upstream.arrayBuffer());
  res.writeHead(status, respHeaders);
  res.end(vault.restore(buf.toString("utf8")));
}
