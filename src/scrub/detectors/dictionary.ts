import type { Detector, RawMatch } from "../../types.js";
import { escapeRegExp } from "./util.js";

/**
 * Company-maintained term list: internal codenames, customer names, internal
 * domains, etc. This is the part competitors can't ship out of the box — it
 * encodes what *this* company considers confidential.
 *
 * Matching is case-insensitive and longest-term-first so that, e.g.,
 * "Project Phoenix" wins over a bare "Phoenix" entry.
 */
export function makeDictionaryDetector(terms: string[]): Detector {
  const cleaned = terms.map((t) => t.trim()).filter((t) => t.length > 0);
  const byLengthDesc = [...new Set(cleaned)].sort((a, b) => b.length - a.length);

  const re =
    byLengthDesc.length > 0
      ? new RegExp(byLengthDesc.map(escapeRegExp).join("|"), "gid")
      : null;

  return {
    name: "dictionary",
    category: "dictionary",
    run(text: string): RawMatch[] {
      if (!re) return [];
      const out: RawMatch[] = [];
      for (const m of text.matchAll(re)) {
        const start = m.index ?? 0;
        const value = m[0];
        out.push({
          start,
          end: start + value.length,
          value,
          type: "COMPANY_TERM",
          category: "dictionary",
          severity: "high",
        });
      }
      return out;
    },
  };
}
