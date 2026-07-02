import type { Detector, RawMatch } from "../../types.js";
import { runPattern, runPatterns, type PatternSpec } from "./util.js";

const PATTERNS: PatternSpec[] = [
  { type: "EMAIL", severity: "medium", source: "\\b[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}\\b" },
  { type: "SSN", severity: "high", source: "\\b\\d{3}-\\d{2}-\\d{4}\\b" },
];

// E.164 / common formatted phone numbers, validated by digit count below.
const PHONE_PATTERN: PatternSpec = {
  type: "PHONE",
  severity: "low",
  source: "(?<![\\d.])(?:\\+\\d{1,3}[\\s.\\-]?)?(?:\\(\\d{2,4}\\)[\\s.\\-]?|\\d{2,4}[\\s.\\-])\\d{3,4}[\\s.\\-]?\\d{3,4}(?![\\d.])",
};

/** Luhn checksum used to weed out random digit runs masquerading as cards. */
function luhnValid(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

const CC_PATTERN: PatternSpec = {
  type: "CREDIT_CARD",
  severity: "high",
  source: "\\b(?:\\d[ \\-]?){13,19}\\b",
};

export const piiDetector: Detector = {
  name: "pii",
  category: "pii",
  run(text: string): RawMatch[] {
    const out = runPatterns(text, PATTERNS, "pii");

    // Phone: keep only candidates with a real phone digit count (7-11), so long
    // digit runs (order numbers, IDs) don't masquerade as phone numbers.
    for (const m of runPattern(text, PHONE_PATTERN, "pii")) {
      const digits = m.value.replace(/[^\d]/g, "").length;
      if (digits >= 7 && digits <= 11) out.push(m);
    }

    // Credit cards: match candidates, then keep only Luhn-valid ones.
    for (const m of runPattern(text, CC_PATTERN, "pii")) {
      const digits = m.value.replace(/[^\d]/g, "");
      if (digits.length >= 13 && digits.length <= 19 && luhnValid(digits)) {
        out.push(m);
      }
    }

    return out;
  },
};
