import { describe, it, expect } from "vitest";
import { secretScore, makeSecretClassifier } from "../src/scrub/detectors/mlSecret.js";
import { makeMlNerDetector } from "../src/scrub/detectors/mlNer.js";
import { Scrubber } from "../src/scrub/index.js";
import { Vault } from "../src/scrub/placeholders.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { scrubRequestBodyAsync } from "../src/messages.js";
import type { AegisConfig } from "../src/types.js";

const NOVEL_KEY = "kF9xQ2mL7pR4tV8wZ1nB6cD3eH5jA0sG2yU"; // not a known regex format

describe("ML secret classifier (logistic, in-process)", () => {
  it("scores real secret-like tokens high and lookalikes low", () => {
    expect(secretScore("AKIAIOSFODNN7EXAMPLE")).toBeGreaterThan(0.7);
    expect(secretScore(NOVEL_KEY)).toBeGreaterThan(0.7);
    expect(secretScore("e29b41d4a716446655440000aabbccddeeff0011")).toBeLessThan(0.3); // git sha
    expect(secretScore("550e8400-e29b-41d4-a716-446655440000")).toBeLessThan(0.2); // uuid
    expect(secretScore("supercalifragilisticexpialidocious")).toBeLessThan(0.5); // prose
  });

  it("flags a novel secret the regex detectors miss", () => {
    const d = makeSecretClassifier();
    const m = d.run(`token ${NOVEL_KEY} here`);
    expect(m.length).toBe(1);
    expect(m[0]!.type).toBe("ML_SECRET");
    expect(m[0]!.category).toBe("secret");
  });

  it("does not flag git SHAs / UUIDs / prose", () => {
    const d = makeSecretClassifier();
    expect(d.run("commit e29b41d4a716446655440000aabbccddeeff0011").length).toBe(0);
    expect(d.run("id 550e8400-e29b-41d4-a716-446655440000").length).toBe(0);
    expect(d.run("the quick brown fox jumps over the lazy dog").length).toBe(0);
  });
});

function cfg(over: Partial<AegisConfig>): AegisConfig {
  return { ...DEFAULT_CONFIG, ...over };
}

describe("Scrubber async path", () => {
  it("is sync (hasAsync=false) until an async detector is enabled", () => {
    expect(new Scrubber(DEFAULT_CONFIG).hasAsync).toBe(false);
    expect(new Scrubber(cfg({ ml: { secretClassifier: { enabled: true } } })).hasAsync).toBe(false); // classifier is sync
    expect(new Scrubber(cfg({ ml: { ner: { enabled: true } } })).hasAsync).toBe(true); // NER is async
  });

  it("default scrubber misses the novel key; classifier-enabled one catches it", async () => {
    expect(new Scrubber(DEFAULT_CONFIG).detect(`use ${NOVEL_KEY}`).length).toBe(0);
    const s = new Scrubber(cfg({ ml: { secretClassifier: { enabled: true } } }));
    expect(s.detect(`use ${NOVEL_KEY}`).some((m) => m.type === "ML_SECRET")).toBe(true);
    expect((await s.detectAsync(`use ${NOVEL_KEY}`)).some((m) => m.type === "ML_SECRET")).toBe(true);
  });

  it("scrubRequestBodyAsync redacts a novel key in message content", async () => {
    const s = new Scrubber(cfg({ ml: { secretClassifier: { enabled: true } } }));
    const body = { model: "claude-opus-4-8", messages: [{ role: "user", content: `deploy ${NOVEL_KEY}` }] };
    const { body: out, matches } = (await scrubRequestBodyAsync(body, "anthropic", s, new Vault())) as any;
    expect(matches.length).toBeGreaterThanOrEqual(1);
    expect(JSON.stringify(out)).not.toContain(NOVEL_KEY);
    expect(out.model).toBe("claude-opus-4-8");
  });
});

describe("Transformers.js NER detector (optional dep)", () => {
  it("fails open (returns []) when the dependency/model is unavailable", async () => {
    const d = makeMlNerDetector();
    expect(d.run("Contact James Wilson")).toEqual([]); // async-only: sync run is empty
    await expect(d.runAsync!("Contact James Wilson at Globex")).resolves.toEqual([]);
  });
});
