import type { Category, RawMatch, Severity } from "../../types.js";

export interface PatternSpec {
  type: string;
  severity: Severity;
  /** Regex source. The `g` and `d` flags are added automatically. */
  source: string;
  /** Extra flags such as "i" or "m". Do not include "g" / "d". */
  flags?: string;
  /** Which capture group is the actual secret (0 = whole match). Default 0. */
  group?: number;
}

function ensureFlags(flags = ""): string {
  let f = flags;
  if (!f.includes("g")) f += "g";
  if (!f.includes("d")) f += "d";
  return f;
}

/** Run a single pattern over text and yield raw matches for the chosen group. */
export function runPattern(text: string, spec: PatternSpec, category: Category): RawMatch[] {
  const group = spec.group ?? 0;
  const re = new RegExp(spec.source, ensureFlags(spec.flags));
  const out: RawMatch[] = [];

  for (const m of text.matchAll(re)) {
    // `d` flag gives us per-group indices for precise redaction ranges.
    const indices = (m as RegExpMatchArray & { indices?: Array<[number, number] | undefined> }).indices;
    const span = indices?.[group];
    let start: number;
    let end: number;
    let value: string;

    if (span) {
      [start, end] = span;
      value = text.slice(start, end);
    } else {
      // The chosen group did not participate in this match.
      const whole = m[group];
      if (whole == null) continue;
      start = m.index ?? 0;
      value = whole;
      end = start + value.length;
    }

    if (!value) continue;
    out.push({ start, end, value, type: spec.type, category, severity: spec.severity });
  }

  return out;
}

export function runPatterns(text: string, specs: PatternSpec[], category: Category): RawMatch[] {
  const out: RawMatch[] = [];
  for (const spec of specs) out.push(...runPattern(text, spec, category));
  return out;
}

/** Escape a literal string for safe inclusion in a RegExp. */
export function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
