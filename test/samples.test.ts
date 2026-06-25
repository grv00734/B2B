import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Scrubber } from "../src/scrub/index.js";
import { Vault } from "../src/scrub/placeholders.js";
import { DEFAULT_CONFIG } from "../src/config.js";

/** Scrubber configured to match the synthetic fixtures in samples/. */
const scrubber = new Scrubber({
  ...DEFAULT_CONFIG,
  dictionary: ["Project Nightingale", "Globex Corp", "acme-internal.com"],
  code: { ...DEFAULT_CONFIG.code, internalNamespaces: ["com.acme.internal"] },
});

function read(name: string): string {
  return readFileSync(resolve(process.cwd(), "samples", name), "utf8");
}

function countByType(name: string): Record<string, number> {
  const matches = scrubber.detect(read(name));
  const out: Record<string, number> = {};
  for (const m of matches) out[m.type] = (out[m.type] ?? 0) + 1;
  return out;
}

describe("samples/.env.sample", () => {
  const t = countByType(".env.sample");
  it("flags the major credential types", () => {
    for (const type of ["AWS_ACCESS_KEY", "ANTHROPIC_KEY", "OPENAI_KEY", "GITHUB_TOKEN", "STRIPE_KEY", "SLACK_TOKEN", "JWT"]) {
      expect(t[type], type).toBeGreaterThanOrEqual(1);
    }
  });
});

describe("samples/service.py", () => {
  const t = countByType("service.py");
  it("flags confidential markers, codenames, internal namespace and a secret", () => {
    expect(t.CONFIDENTIAL_MARKER).toBeGreaterThanOrEqual(1);
    expect(t.COMPANY_TERM).toBeGreaterThanOrEqual(1);
    expect(t.INTERNAL_NAMESPACE).toBeGreaterThanOrEqual(1);
    expect(t.ANTHROPIC_KEY).toBeGreaterThanOrEqual(1);
    expect(t.CREDIT_CARD).toBeGreaterThanOrEqual(1);
  });
});

describe("samples/customers.csv", () => {
  const t = countByType("customers.csv");
  it("flags every row's PII (3 each of email, ssn, Luhn-valid card)", () => {
    expect(t.EMAIL).toBe(3);
    expect(t.SSN).toBe(3);
    expect(t.CREDIT_CARD).toBe(3);
  });
});

describe("samples/incident-notes.md", () => {
  const t = countByType("incident-notes.md");
  it("flags free-text leaks: codename, key, card, internal IP", () => {
    expect(t.COMPANY_TERM).toBeGreaterThanOrEqual(1);
    expect(t.ANTHROPIC_KEY).toBeGreaterThanOrEqual(1);
    expect(t.CREDIT_CARD).toBeGreaterThanOrEqual(1);
    expect(t.IPV4).toBeGreaterThanOrEqual(1);
  });
});

describe("samples/clean.txt", () => {
  it("produces ZERO findings (no over-redaction)", () => {
    expect(scrubber.detect(read("clean.txt"))).toHaveLength(0);
  });
});

describe("redact then restore round-trips a real file", () => {
  it("returns the exact original after restore", () => {
    const original = read("incident-notes.md");
    const vault = new Vault();
    const { text: scrubbed, matches } = scrubber.scrub(original, vault);
    expect(matches.length).toBeGreaterThan(0);
    expect(scrubbed).not.toContain("sk-ant-");
    expect(vault.restore(scrubbed)).toBe(original);
  });
});
