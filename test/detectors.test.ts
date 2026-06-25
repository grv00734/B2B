import { describe, it, expect } from "vitest";
import { Scrubber } from "../src/scrub/index.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import type { AegisConfig } from "../src/types.js";

function makeScrubber(overrides: Partial<AegisConfig> = {}): Scrubber {
  return new Scrubber({
    ...DEFAULT_CONFIG,
    ...overrides,
    detectors: { ...DEFAULT_CONFIG.detectors, ...(overrides.detectors ?? {}) },
    code: { ...DEFAULT_CONFIG.code, ...(overrides.code ?? {}) },
  });
}

describe("secret detection", () => {
  const s = makeScrubber();

  it("detects AWS access keys", () => {
    const m = s.detect("key = AKIAIOSFODNN7EXAMPLE");
    expect(m.some((x) => x.type === "AWS_ACCESS_KEY")).toBe(true);
  });

  it("detects an OpenAI-style key", () => {
    const m = s.detect("OPENAI_API_KEY=sk-abcdEFGH1234567890ABCDuvwxyz");
    expect(m.some((x) => x.type === "OPENAI_KEY")).toBe(true);
  });

  it("detects a JWT", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123DEFxyz";
    expect(s.detect(jwt).some((x) => x.type === "JWT")).toBe(true);
  });

  it("detects a private key block", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----";
    expect(s.detect(pem).some((x) => x.type === "PRIVATE_KEY")).toBe(true);
  });

  it("captures only the password in a db uri", () => {
    const m = s.detect("postgres://user:S3cretP@ss@db.example.com:5432/app").find((x) => x.type === "DB_URI_PASSWORD");
    expect(m?.value).toBe("S3cretP@ss");
  });
});

describe("pii detection", () => {
  const s = makeScrubber();

  it("detects emails", () => {
    expect(s.detect("contact me at jane.doe@acme.com").some((x) => x.type === "EMAIL")).toBe(true);
  });

  it("validates credit cards with Luhn", () => {
    expect(s.detect("card 4242 4242 4242 4242").some((x) => x.type === "CREDIT_CARD")).toBe(true);
    // 16 digits but fails Luhn -> not flagged as a card
    expect(s.detect("id 1234 5678 9012 3456").some((x) => x.type === "CREDIT_CARD")).toBe(false);
  });

  it("detects SSNs", () => {
    expect(s.detect("ssn 123-45-6789").some((x) => x.type === "SSN")).toBe(true);
  });
});

describe("dictionary + code detection", () => {
  it("flags company terms case-insensitively", () => {
    const s = makeScrubber({ dictionary: ["Project Phoenix"] });
    const m = s.detect("we shipped project phoenix last week");
    expect(m.some((x) => x.type === "COMPANY_TERM")).toBe(true);
  });

  it("flags confidentiality markers", () => {
    const s = makeScrubber({ code: { markers: ["CONFIDENTIAL"], internalNamespaces: [] } });
    expect(s.detect("// CONFIDENTIAL — do not share").some((x) => x.type === "CONFIDENTIAL_MARKER")).toBe(true);
  });
});

describe("overlap resolution", () => {
  it("does not double-count nested matches", () => {
    const s = makeScrubber();
    // The db uri contains an email-looking host; ensure we keep one coherent match set.
    const m = s.detect("postgres://user:pw@host:5432/db and a@b.com");
    const ranges = m.map((x) => [x.start, x.end]);
    for (let i = 0; i < ranges.length; i++) {
      for (let j = i + 1; j < ranges.length; j++) {
        const [aS, aE] = ranges[i]!;
        const [bS, bE] = ranges[j]!;
        expect(aE <= bS || bE <= aS).toBe(true); // no overlap
      }
    }
  });
});
