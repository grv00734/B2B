import type { AegisConfig, Category, DetectionSummary, Detector, RawMatch, Severity } from "../types.js";
import { Vault } from "./placeholders.js";
import { secretsDetector } from "./detectors/secrets.js";
import { piiDetector } from "./detectors/pii.js";
import { identityDetector } from "./detectors/identity.js";
import { makeNerDetector } from "./detectors/ner.js";
import { networkDetector } from "./detectors/network.js";
import { makeDictionaryDetector } from "./detectors/dictionary.js";
import { makeCodeDetector } from "./detectors/code.js";
import { entropyDetector } from "./detectors/entropy.js";
import { makeSecretClassifier } from "./detectors/mlSecret.js";
import { makeMlNerDetector } from "./detectors/mlNer.js";

const SEVERITY_RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

export interface ScrubResult {
  text: string;
  matches: RawMatch[];
}

/**
 * Drop overlapping matches. Preference order: earliest start, then (for matches
 * that start at the same place) higher severity, then longer span. The severity
 * tie-break means a specific high-severity secret (e.g. a DB-URI password) wins
 * over a generic lower-severity match (e.g. an email) covering the same text.
 */
export function resolveOverlaps(matches: RawMatch[]): RawMatch[] {
  const sorted = [...matches].sort(
    (a, b) => a.start - b.start || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.end - a.end,
  );
  const kept: RawMatch[] = [];
  let lastEnd = -1;
  for (const m of sorted) {
    if (m.start >= lastEnd) {
      kept.push(m);
      lastEnd = m.end;
    }
  }
  return kept;
}

export function summarize(matches: RawMatch[]): DetectionSummary {
  const byCategory: Record<string, number> = {};
  const byType: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  let highest: Severity | null = null;

  for (const m of matches) {
    byCategory[m.category] = (byCategory[m.category] ?? 0) + 1;
    byType[m.type] = (byType[m.type] ?? 0) + 1;
    bySeverity[m.severity] = (bySeverity[m.severity] ?? 0) + 1;
    if (!highest || SEVERITY_RANK[m.severity] > SEVERITY_RANK[highest]) highest = m.severity;
  }

  return {
    total: matches.length,
    byCategory,
    byType,
    bySeverity,
    highestSeverity: highest,
    categoriesPresent: Object.keys(byCategory) as Category[],
  };
}

/**
 * The Scrubber owns the active set of detectors (built from config) and applies
 * them to text. Each call to `scrub` uses a caller-supplied Vault so that the
 * same placeholders can later be restored in the response.
 */
/** Build allowlist matchers from literal strings or /regex/ entries. */
function buildAllow(entries: string[] = []): Array<(v: string) => boolean> {
  const out: Array<(v: string) => boolean> = [];
  for (const e of entries) {
    if (e.length > 1 && e.startsWith("/") && e.endsWith("/")) {
      try {
        const re = new RegExp(e.slice(1, -1));
        out.push((v) => re.test(v));
        continue;
      } catch {
        /* fall through to literal */
      }
    }
    out.push((v) => v === e);
  }
  return out;
}

export class Scrubber {
  private detectors: Detector[];
  private allow: Array<(v: string) => boolean>;
  /** True if any detector requires the async path (e.g. in-process ML). */
  readonly hasAsync: boolean;

  constructor(cfg: AegisConfig) {
    this.allow = buildAllow(cfg.allowlist);
    const d: Detector[] = [];
    if (cfg.detectors.secrets) d.push(secretsDetector);
    if (cfg.detectors.pii) d.push(piiDetector);
    if (cfg.detectors.identity) d.push(identityDetector);
    if (cfg.nerCommand) d.push(makeNerDetector(cfg.nerCommand));
    if (cfg.ml?.secretClassifier?.enabled) d.push(makeSecretClassifier(cfg.ml.secretClassifier.threshold));
    if (cfg.detectors.network) d.push(networkDetector);
    if (cfg.detectors.dictionary) d.push(makeDictionaryDetector(cfg.dictionary));
    if (cfg.detectors.code) d.push(makeCodeDetector(cfg.code.markers, cfg.code.internalNamespaces));
    if (cfg.detectors.entropy) d.push(entropyDetector);
    if (cfg.ml?.ner?.enabled) d.push(makeMlNerDetector(cfg.ml.ner.model));
    this.detectors = d;
    this.hasAsync = d.some((det) => typeof det.runAsync === "function");
  }

  /** Apply overlap resolution + allowlist suppression to a raw match list. */
  private finalize(all: RawMatch[]): RawMatch[] {
    const resolved = resolveOverlaps(all);
    if (this.allow.length === 0) return resolved;
    return resolved.filter((m) => !this.allow.some((fn) => fn(m.value)));
  }

  /** Synchronous detection (skips async-only detectors). */
  detect(text: string): RawMatch[] {
    if (!text) return [];
    const all: RawMatch[] = [];
    for (const det of this.detectors) all.push(...det.run(text));
    return this.finalize(all);
  }

  /** Detection including async detectors (in-process ML). */
  async detectAsync(text: string): Promise<RawMatch[]> {
    if (!text) return [];
    const all: RawMatch[] = [];
    for (const det of this.detectors) {
      all.push(...(det.runAsync ? await det.runAsync(text) : det.run(text)));
    }
    return this.finalize(all);
  }

  private replace(text: string, matches: RawMatch[], vault: Vault): ScrubResult {
    if (matches.length === 0) return { text, matches };
    // Apply replacements right-to-left so earlier offsets stay valid.
    let out = text;
    for (const m of [...matches].sort((a, b) => b.start - a.start)) {
      const token = vault.placeholderFor(m.value, m.type);
      out = out.slice(0, m.start) + token + out.slice(m.end);
    }
    return { text: out, matches };
  }

  /** Replace every detected value with a stable placeholder from the vault. */
  scrub(text: string, vault: Vault): ScrubResult {
    return this.replace(text, this.detect(text), vault);
  }

  /** Async scrub (uses ML detectors when present). */
  async scrubAsync(text: string, vault: Vault): Promise<ScrubResult> {
    return this.replace(text, await this.detectAsync(text), vault);
  }
}

export { Vault };
