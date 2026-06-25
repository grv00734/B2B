import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import type { AegisConfig } from "./types.js";

export const DEFAULT_CONFIG: AegisConfig = {
  port: 8787,
  host: "127.0.0.1",
  mode: "redact",
  blockOn: ["secret"],
  detectors: {
    secrets: true,
    pii: true,
    network: true,
    dictionary: true,
    code: true,
  },
  dictionary: [],
  code: {
    markers: ["CONFIDENTIAL", "PROPRIETARY", "INTERNAL USE ONLY", "DO NOT DISTRIBUTE"],
    internalNamespaces: [],
  },
  routes: [
    { matchPrefix: "/v1/messages", upstream: "https://api.anthropic.com", format: "anthropic" },
    { matchPrefix: "/v1/chat/completions", upstream: "https://api.openai.com", format: "openai" },
    { matchPrefix: "/v1/responses", upstream: "https://api.openai.com", format: "openai" },
  ],
  defaultUpstream: "https://api.anthropic.com",
  auditLog: "./aegis-audit.log",
  mitm: {
    port: 8788,
    transparentPort: 8443,
    hosts: [
      "api.anthropic.com",
      "api.openai.com",
      "api.cohere.ai",
      "api.cohere.com",
      "generativelanguage.googleapis.com",
      "api.mistral.ai",
      "api.groq.com",
      "api.perplexity.ai",
      "api.deepseek.com",
      "api.x.ai",
    ],
  },
};

/** Deep-merge a partial user config onto the defaults. */
function merge(base: AegisConfig, override: Partial<AegisConfig>): AegisConfig {
  return {
    ...base,
    ...override,
    detectors: { ...base.detectors, ...(override.detectors ?? {}) },
    code: { ...base.code, ...(override.code ?? {}) },
    mitm: { ...base.mitm, ...(override.mitm ?? {}) },
    // Arrays replace wholesale when provided.
    blockOn: override.blockOn ?? base.blockOn,
    dictionary: override.dictionary ?? base.dictionary,
    routes: override.routes ?? base.routes,
  };
}

export function loadConfig(explicitPath?: string): AegisConfig {
  const candidates = explicitPath
    ? [explicitPath]
    : ["aegis.config.json", "aegis.config.example.json"];

  for (const c of candidates) {
    const p = resolve(process.cwd(), c);
    if (existsSync(p)) {
      try {
        const raw = JSON.parse(readFileSync(p, "utf8")) as Partial<AegisConfig>;
        const cfg = merge(DEFAULT_CONFIG, raw);
        applyEnvOverrides(cfg);
        return cfg;
      } catch (err) {
        throw new Error(`Failed to parse config at ${p}: ${(err as Error).message}`);
      }
    }
  }

  const cfg = merge(DEFAULT_CONFIG, {});
  applyEnvOverrides(cfg);
  return cfg;
}

function applyEnvOverrides(cfg: AegisConfig): void {
  if (process.env.AEGIS_PORT) cfg.port = Number(process.env.AEGIS_PORT);
  if (process.env.AEGIS_HOST) cfg.host = process.env.AEGIS_HOST;
  if (process.env.AEGIS_MODE) cfg.mode = process.env.AEGIS_MODE as AegisConfig["mode"];
}
