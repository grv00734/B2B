/**
 * Detection-quality benchmark.
 *
 * Regex + heuristics WILL produce false positives, so we measure them. This is a
 * labeled corpus — positives (text that must trigger a category) and, crucially,
 * negatives (benign "trap" text that must NOT trigger): version strings, UUIDs,
 * git SHAs, non-Luhn card-shaped digits, ordinary capitalized phrases, etc.
 *
 * We compute category-level precision / recall / F1 plus the false-positive rate
 * on benign text, and list every FP/FN so detectors can be tuned. `aegis
 * benchmark` runs it; test/benchmark.test.ts enforces thresholds in CI.
 */
import type { Category } from "./types.js";
import type { Scrubber } from "./scrub/index.js";

export interface BenchCase {
  label: string;
  text: string;
  expect: Category[]; // categories that SHOULD be detected ([] = benign)
}

export interface BenchMetrics {
  cases: number;
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  benignCases: number;
  benignClean: number; // benign cases with zero detections
  byCategory: Record<string, { tp: number; fp: number; fn: number }>;
  falsePositives: { label: string; got: string[] }[];
  falseNegatives: { label: string; missing: string[] }[];
}

/** Labeled corpus. Negatives are the false-positive traps enterprises test. */
export const BENCH_CASES: BenchCase[] = [
  // ---- positives: secrets ----
  { label: "aws access key", text: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", expect: ["secret"] },
  { label: "anthropic key", text: "use sk-ant-abcd1234EFGH5678ijklMNOPqrst", expect: ["secret"] },
  { label: "github token", text: "token ghp_0123456789abcdefghijklmnopqrstuvwxyz12", expect: ["secret"] },
  // prettier-ignore
  { label: "stripe key", text: "STRIPE=" + "sk_" + "live_FAKE0exampleKey1234567890", expect: ["secret"] },
  { label: "jwt", text: "Authorization: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123DEFxyz456ghi", expect: ["secret"] },
  { label: "private key block", text: "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----", expect: ["secret"] },
  { label: "db uri password", text: "postgres://app:S3cretPw@db.example.com:5432/prod", expect: ["secret"] },
  // ---- positives: pii ----
  { label: "ssn", text: "SSN 123-45-6789 on file", expect: ["pii"] },
  { label: "credit card (luhn-valid)", text: "card 4242 4242 4242 4242", expect: ["pii"] },
  { label: "person name", text: "please contact James Wilson tomorrow", expect: ["pii"] },
  { label: "street address", text: "ship to 1600 Pennsylvania Avenue", expect: ["pii"] },
  { label: "iban", text: "wire to DE89370400440532013000", expect: ["pii"] },
  { label: "organization", text: "invoice from Globex Corp attached", expect: ["pii"] },
  { label: "dob", text: "DOB: 04/12/1980", expect: ["pii"] },
  // ---- positives: network ----
  { label: "internal host", text: "deploy to db-primary.corp now", expect: ["network"] },
  // ---- positives: code ----
  { label: "confidential marker", text: "// CONFIDENTIAL — internal only", expect: ["code"] },

  // ---- negatives (false-positive traps) ----
  { label: "semver", text: "released version 1.2.3 yesterday", expect: [] },
  { label: "git sha", text: "fix in commit e29b41d4a716446655440000aabbccddeeff0011", expect: [] },
  { label: "uuid", text: "request id 550e8400-e29b-41d4-a716-446655440000", expect: [] },
  { label: "non-luhn 16 digits", text: "order number 1234 5678 9012 3456 shipped", expect: [] },
  { label: "name-shaped phrase", text: "Mark Down the meeting notes please", expect: [] },
  { label: "place phrase", text: "New York is a great city", expect: [] },
  { label: "hex colors", text: "use #ff8800 and #00aabb in the theme", expect: [] },
  { label: "aspect ratios", text: "support 16:9 and 4:3 layouts", expect: [] },
  { label: "plain prose", text: "The build system runs on Tuesday without issues.", expect: [] },
  { label: "config word no value", text: "the password policy requires rotation", expect: [] },
  { label: "url not email", text: "see https://example.com/docs for details", expect: [] },
  { label: "timeout assignment", text: "set timeout = 30 seconds for retries", expect: [] },
  { label: "phone-shaped id far apart", text: "ticket 12 of 3456 resolved", expect: [] },
];

export function runBenchmark(scrubber: Scrubber, cases: BenchCase[] = BENCH_CASES): BenchMetrics {
  const cat = (): { tp: number; fp: number; fn: number } => ({ tp: 0, fp: 0, fn: 0 });
  const byCategory: Record<string, { tp: number; fp: number; fn: number }> = {};
  const bump = (c: string, k: "tp" | "fp" | "fn"): void => {
    (byCategory[c] ??= cat())[k] += 1;
  };

  let tp = 0;
  let fp = 0;
  let fn = 0;
  let benignCases = 0;
  let benignClean = 0;
  const falsePositives: { label: string; got: string[] }[] = [];
  const falseNegatives: { label: string; missing: string[] }[] = [];

  for (const c of cases) {
    const detected = new Set(scrubber.detect(c.text).map((m) => m.category));
    const expected = new Set(c.expect);
    if (expected.size === 0) {
      benignCases += 1;
      if (detected.size === 0) benignClean += 1;
    }

    const extra: string[] = [];
    const missing: string[] = [];
    for (const d of detected) {
      if (expected.has(d)) {
        tp += 1;
        bump(d, "tp");
      } else {
        fp += 1;
        bump(d, "fp");
        extra.push(d);
      }
    }
    for (const e of expected) {
      if (!detected.has(e)) {
        fn += 1;
        bump(e, "fn");
        missing.push(e);
      }
    }
    if (extra.length) falsePositives.push({ label: c.label, got: extra });
    if (missing.length) falseNegatives.push({ label: c.label, missing });
  }

  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);

  return { cases: cases.length, tp, fp, fn, precision, recall, f1, benignCases, benignClean, byCategory, falsePositives, falseNegatives };
}

export function formatBenchmark(m: BenchMetrics): string {
  const pct = (n: number): string => (n * 100).toFixed(1) + "%";
  const lines: string[] = [];
  lines.push("Aegis detection benchmark");
  lines.push(`  cases: ${m.cases}   TP=${m.tp} FP=${m.fp} FN=${m.fn}`);
  lines.push(`  precision: ${pct(m.precision)}   recall: ${pct(m.recall)}   F1: ${pct(m.f1)}`);
  lines.push(`  benign false-positive rate: ${pct(1 - m.benignClean / Math.max(1, m.benignCases))} (${m.benignCases - m.benignClean}/${m.benignCases} benign cases tripped)`);
  lines.push("");
  lines.push("  by category:");
  for (const [c, v] of Object.entries(m.byCategory)) {
    const p = v.tp + v.fp === 0 ? 1 : v.tp / (v.tp + v.fp);
    const r = v.tp + v.fn === 0 ? 1 : v.tp / (v.tp + v.fn);
    lines.push(`    ${c.padEnd(10)} P=${pct(p)}  R=${pct(r)}  (tp=${v.tp} fp=${v.fp} fn=${v.fn})`);
  }
  if (m.falsePositives.length) {
    lines.push("\n  FALSE POSITIVES:");
    for (const f of m.falsePositives) lines.push(`    [${f.got.join(",")}]  ${f.label}`);
  }
  if (m.falseNegatives.length) {
    lines.push("\n  FALSE NEGATIVES:");
    for (const f of m.falseNegatives) lines.push(`    [${f.missing.join(",")}]  ${f.label}`);
  }
  return lines.join("\n");
}
