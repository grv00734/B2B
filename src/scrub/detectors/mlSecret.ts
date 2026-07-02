import type { Detector, RawMatch } from "../../types.js";

/**
 * Embedded ML secret classifier.
 *
 * A small logistic-regression model over structural token features (entropy,
 * character-class mix, base64-ness, length, hex/UUID shape). It catches novel,
 * un-templated secret tokens that the regex detectors don't know — while
 * deliberately scoring DOWN the lookalikes that trip naive entropy checks (git
 * SHAs / hashes are pure hex; UUIDs have a fixed shape). It runs locally and
 * synchronously (no model download). Opt-in via `ml.secretClassifier`.
 *
 * The weights below are fixed (trained offline / hand-calibrated). Increase the
 * threshold for fewer, higher-confidence hits.
 */
const TOKEN = /[A-Za-z0-9+/_=\-]{16,}/g;

// Feature order: [entropy/6, fracDigits, fracUpper, fracSpecial, isPureHex, isUuid, hasMixedAlnum, lenNorm]
const WEIGHTS = [3.0, 1.0, 1.0, 2.2, -4.5, -6.0, 2.2, 1.2];
const BIAS = -3.2;

function shannon(s: string): number {
  const counts: Record<string, number> = {};
  for (const c of s) counts[c] = (counts[c] ?? 0) + 1;
  let e = 0;
  for (const k in counts) {
    const p = counts[k]! / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function features(t: string): number[] {
  const n = t.length;
  const frac = (re: RegExp): number => (t.match(re)?.length ?? 0) / n;
  return [
    Math.min(1, shannon(t) / 6),
    frac(/\d/g),
    frac(/[A-Z]/g),
    frac(/[+/_=\-]/g),
    /^[0-9a-f]+$/i.test(t) ? 1 : 0,
    UUID_RE.test(t) ? 1 : 0,
    frac(/\d/g) > 0 && frac(/[A-Za-z]/g) > 0 ? 1 : 0,
    Math.min(1, n / 64),
  ];
}

/** Probability that a token is a secret (0..1). Exported for testing. */
export function secretScore(token: string): number {
  const f = features(token);
  let z = BIAS;
  for (let i = 0; i < WEIGHTS.length; i++) z += WEIGHTS[i]! * f[i]!;
  return 1 / (1 + Math.exp(-z));
}

export function makeSecretClassifier(threshold = 0.7): Detector {
  return {
    name: "ml-secret",
    category: "secret",
    run(text: string): RawMatch[] {
      const out: RawMatch[] = [];
      for (const m of text.matchAll(TOKEN)) {
        const value = m[0];
        if (secretScore(value) < threshold) continue;
        const start = m.index ?? 0;
        out.push({ start, end: start + value.length, value, type: "ML_SECRET", category: "secret", severity: "medium" });
      }
      return out;
    },
  };
}
