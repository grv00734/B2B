import { describe, it, expect } from "vitest";
import { Scrubber } from "../src/scrub/index.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { runBenchmark } from "../src/benchmark.js";

/**
 * Detection-quality gate. These thresholds fail CI if a change regresses
 * precision/recall or starts producing false positives on the benign "trap"
 * corpus — the exact thing enterprise buyers probe.
 */
describe("detection benchmark thresholds", () => {
  const m = runBenchmark(new Scrubber(DEFAULT_CONFIG));

  it("produces zero false positives on the benign trap set", () => {
    expect(m.fp, JSON.stringify(m.falsePositives)).toBe(0);
    expect(m.benignClean).toBe(m.benignCases);
  });

  it("precision >= 0.95", () => {
    expect(m.precision).toBeGreaterThanOrEqual(0.95);
  });

  it("recall >= 0.95", () => {
    expect(m.recall, JSON.stringify(m.falseNegatives)).toBeGreaterThanOrEqual(0.95);
  });

  it("every category has no false positives", () => {
    for (const [c, v] of Object.entries(m.byCategory)) {
      expect(v.fp, `category ${c}`).toBe(0);
    }
  });
});
