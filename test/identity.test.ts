import { describe, it, expect } from "vitest";
import { Scrubber } from "../src/scrub/index.js";
import { DEFAULT_CONFIG } from "../src/config.js";

const s = new Scrubber(DEFAULT_CONFIG);
const types = (t: string): Set<string> => new Set(s.detect(t).map((m) => m.type));

describe("identity (unstructured PII) detection", () => {
  it("detects a known given-name + surname", () => {
    expect(types("Please contact James Wilson tomorrow.").has("PERSON_NAME")).toBe(true);
  });
  it("detects an honorific name", () => {
    expect(types("The chart belongs to Dr. Heinz Becker.").has("PERSON_NAME")).toBe(true);
  });
  it("detects a labelled date of birth", () => {
    expect(types("DOB: 04/12/1980").has("DATE_OF_BIRTH")).toBe(true);
  });
  it("detects a street address", () => {
    expect(types("Ship to 1600 Pennsylvania Avenue").has("STREET_ADDRESS")).toBe(true);
  });
  it("detects an IBAN", () => {
    expect(types("Wire to DE89370400440532013000 today").has("IBAN")).toBe(true);
  });
  it("detects a labelled passport number", () => {
    expect(types("passport number X1234567").has("PASSPORT")).toBe(true);
  });
  it("does not flag ordinary capitalised words", () => {
    expect(types("The Build System runs on Tuesday.").has("PERSON_NAME")).toBe(false);
  });
});
